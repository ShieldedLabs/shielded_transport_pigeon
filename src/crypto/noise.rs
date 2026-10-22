//! The STP subset of Noise: IK / 25519 / ChaChaPoly / BLAKE2{s,b}.
//!
//! State transitions and HKDF follow Noise revision 34 and the locked
//! shielded_labs_snow 0.10.0 implementation (MIT OR Apache-2.0; see
//! LICENSE-snow-*). This deliberately does not implement other patterns,
//! fallback, PSKs, negotiation or a generic cryptographic provider interface.
//! Entropy is supplied by the caller; no deterministic RNG is used implicitly.

use super::{aead, blake2b, blake2s, wipe, x25519};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateProblem {
    HandshakeNotFinished,
    HandshakeAlreadyFinished,
    NotTurnToWrite,
    NotTurnToRead,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Input,
    Decrypt,
    Rng,
    State(StateProblem),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519::public_key(secret)
}
pub fn clamp_private(secret: [u8; 32]) -> [u8; 32] {
    x25519::clamp(secret)
}

#[derive(Clone, Copy)]
enum Hash {
    Blake2s,
    Blake2b,
}
impl Hash {
    fn parse(protocol: &str) -> Result<Self, Error> {
        match protocol {
            "Noise_IK_25519_ChaChaPoly_BLAKE2s" => Ok(Self::Blake2s),
            "Noise_IK_25519_ChaChaPoly_BLAKE2b" => Ok(Self::Blake2b),
            _ => Err(Error::Input),
        }
    }
    fn len(self) -> usize {
        match self {
            Self::Blake2s => 32,
            Self::Blake2b => 64,
        }
    }
    fn block_len(self) -> usize {
        2 * self.len()
    }
    fn hash(self, parts: &[&[u8]]) -> [u8; 64] {
        match self {
            Self::Blake2s => {
                let mut out = [0; 64];
                out[..32].copy_from_slice(&blake2s::hash(parts));
                out
            }
            Self::Blake2b => blake2b::hash(parts),
        }
    }
    fn hmac(self, key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
        let mut block = [0u8; 128];
        let mut hashed_key = [0u8; 64];
        let key = if key.len() > self.block_len() {
            hashed_key = self.hash(&[key]);
            &hashed_key[..self.len()]
        } else {
            key
        };
        block[..key.len()].copy_from_slice(key);
        for b in &mut block[..self.block_len()] {
            *b ^= 0x36;
        }
        // HKDF has at most three parts; no allocation or secret-bearing Vec.
        assert!(parts.len() <= 3);
        let mut inner_parts: [&[u8]; 4] = [&[]; 4];
        inner_parts[0] = &block[..self.block_len()];
        inner_parts[1..parts.len() + 1].copy_from_slice(parts);
        let mut inner = self.hash(&inner_parts[..parts.len() + 1]);
        for b in &mut block[..self.block_len()] {
            *b ^= 0x36 ^ 0x5c;
        }
        let output = self.hash(&[&block[..self.block_len()], &inner[..self.len()]]);
        wipe(&mut block);
        wipe(&mut hashed_key);
        wipe(&mut inner);
        output
    }
    fn hkdf2(self, ck: &[u8], input: &[u8]) -> ([u8; 64], [u8; 64]) {
        let mut temp = self.hmac(ck, &[input]);
        let first = self.hmac(&temp[..self.len()], &[&[1]]);
        let second = self.hmac(&temp[..self.len()], &[&first[..self.len()], &[2]]);
        wipe(&mut temp);
        (first, second)
    }
}

#[derive(Clone)]
struct Symmetric {
    hash: Hash,
    h: [u8; 64],
    ck: [u8; 64],
    key: [u8; 32],
    nonce: u64,
}
impl Symmetric {
    fn new(protocol: &str, prologue: &[u8], rs: &[u8; 32]) -> Result<Self, Error> {
        let hash = Hash::parse(protocol)?;
        let mut h = [0; 64];
        if protocol.len() <= hash.len() {
            h[..protocol.len()].copy_from_slice(protocol.as_bytes());
        } else {
            h = hash.hash(&[protocol.as_bytes()]);
        }
        let mut state = Self {
            hash,
            ck: h,
            h,
            key: [0; 32],
            nonce: 0,
        };
        state.mix_hash(prologue);
        state.mix_hash(rs);
        Ok(state)
    }
    fn mix_hash(&mut self, bytes: &[u8]) {
        self.h = self.hash.hash(&[&self.h[..self.hash.len()], bytes]);
    }
    fn mix_key(&mut self, shared: &[u8; 32]) {
        let (ck, mut key) = self.hash.hkdf2(&self.ck[..self.hash.len()], shared);
        wipe(&mut self.ck);
        self.ck = ck;
        wipe(&mut self.key);
        self.key.copy_from_slice(&key[..32]);
        wipe(&mut key);
        self.nonce = 0;
    }
    fn encrypt_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        validate_nonce(self.nonce)?;
        let n = aead::seal(
            &self.key,
            self.nonce,
            &self.h[..self.hash.len()],
            plaintext,
            out,
        )?;
        self.nonce += 1;
        self.mix_hash(&out[..n]);
        Ok(n)
    }
    fn decrypt_hash(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        validate_nonce(self.nonce)?;
        let n = aead::open(
            &self.key,
            self.nonce,
            &self.h[..self.hash.len()],
            ciphertext,
            out,
        )?;
        self.nonce += 1;
        self.mix_hash(ciphertext);
        Ok(n)
    }
    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let (mut a, mut b) = self.hash.hkdf2(&self.ck[..self.hash.len()], &[]);
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        first.copy_from_slice(&a[..32]);
        second.copy_from_slice(&b[..32]);
        wipe(&mut a);
        wipe(&mut b);
        (first, second)
    }
}
impl Drop for Symmetric {
    fn drop(&mut self) {
        wipe(&mut self.h);
        wipe(&mut self.ck);
        wipe(&mut self.key);
        self.nonce = 0;
    }
}

/// An IK handshake with caller-supplied static and ephemeral private bytes.
/// Private bytes are retained exactly as supplied (as in Snow); X25519 clamps
/// only when multiplying. Never reuse an ephemeral secret for a new handshake.
#[derive(Clone)]
pub struct HandshakeState {
    symmetric: Symmetric,
    s: [u8; 32],
    e: [u8; 32],
    rs: [u8; 32],
    re: [u8; 32],
    initiator: bool,
    step: u8,
    remote_static_known: bool,
}
impl core::fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeState").finish_non_exhaustive()
    }
}
impl Drop for HandshakeState {
    fn drop(&mut self) {
        wipe(&mut self.s);
        wipe(&mut self.e);
        wipe(&mut self.rs);
        wipe(&mut self.re);
    }
}
impl HandshakeState {
    pub fn initiator(
        protocol: &str,
        prologue: &[u8],
        local_private: &[u8],
        remote_public: &[u8],
        ephemeral: [u8; 32],
    ) -> Result<Self, Error> {
        let s: [u8; 32] = local_private.try_into().map_err(|_| Error::Input)?;
        let rs: [u8; 32] = remote_public.try_into().map_err(|_| Error::Input)?;
        Ok(Self {
            symmetric: Symmetric::new(protocol, prologue, &rs)?,
            s,
            e: ephemeral,
            rs,
            re: [0; 32],
            initiator: true,
            step: 0,
            remote_static_known: true,
        })
    }
    pub fn responder(
        protocol: &str,
        prologue: &[u8],
        local_private: &[u8],
        ephemeral: [u8; 32],
    ) -> Result<Self, Error> {
        let s: [u8; 32] = local_private.try_into().map_err(|_| Error::Input)?;
        Ok(Self {
            symmetric: Symmetric::new(protocol, prologue, &public_key(&s))?,
            s,
            e: ephemeral,
            rs: [0; 32],
            re: [0; 32],
            initiator: false,
            step: 0,
            remote_static_known: false,
        })
    }
    fn mix_dh(&mut self, mut local: [u8; 32], remote: [u8; 32]) {
        // Match the locked Snow resolver: Montgomery multiplication accepts all
        // encoded u-coordinates, including those giving an all-zero DH result.
        let mut dh = x25519::x25519(&local, &remote);
        wipe(&mut local);
        self.symmetric.mix_key(&dh);
        wipe(&mut dh);
    }
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.step >= 2 {
            return Err(Error::State(StateProblem::HandshakeAlreadyFinished));
        }
        if self.initiator != (self.step == 0) {
            return Err(Error::State(StateProblem::NotTurnToWrite));
        }
        let overhead = if self.step == 0 { 96 } else { 48 };
        let size = payload.len().checked_add(overhead).ok_or(Error::Input)?;
        if size > 65535 || out.len() < size {
            return Err(Error::Input);
        }
        // Work on a checkpoint so errors never commit a partial transcript.
        let mut next = self.clone();
        let ep = public_key(&next.e);
        out[..32].copy_from_slice(&ep);
        next.symmetric.mix_hash(&ep);
        let offset;
        if next.step == 0 {
            next.mix_dh(next.e, next.rs); // es
            next.symmetric
                .encrypt_hash(&public_key(&next.s), &mut out[32..80])?;
            next.mix_dh(next.s, next.rs); // ss
            offset = 80;
        } else {
            next.mix_dh(next.e, next.re); // ee
            next.mix_dh(next.e, next.rs); // se
            offset = 32;
        }
        next.symmetric
            .encrypt_hash(payload, &mut out[offset..size])?;
        next.step += 1;
        *self = next;
        Ok(size)
    }
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        if message.len() > 65535 {
            return Err(Error::Input);
        }
        if self.step >= 2 {
            return Err(Error::State(StateProblem::HandshakeAlreadyFinished));
        }
        if self.initiator == (self.step == 0) {
            return Err(Error::State(StateProblem::NotTurnToRead));
        }
        // The E and S tokens are structural inputs; a missing final AEAD tag
        // is a decryption failure, matching Snow's token parser.
        let token_len = if self.step == 0 { 80 } else { 32 };
        if message.len() < token_len {
            return Err(Error::Input);
        }
        let mut next = self.clone();
        next.re.copy_from_slice(&message[..32]);
        next.symmetric.mix_hash(&next.re);
        if next.step == 0 {
            next.mix_dh(next.s, next.re); // es
            next.symmetric
                .decrypt_hash(&message[32..80], &mut next.rs)?;
            next.remote_static_known = true;
            next.mix_dh(next.s, next.rs); // ss
        } else {
            next.mix_dh(next.e, next.re); // ee
            next.mix_dh(next.s, next.re); // se
        }
        let n = next
            .symmetric
            .decrypt_hash(&message[token_len..], payload)?;
        next.step += 1;
        *self = next;
        Ok(n)
    }
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        if self.remote_static_known {
            Some(&self.rs)
        } else {
            None
        }
    }
    pub fn get_handshake_hash(&self) -> &[u8] {
        &self.symmetric.h[..self.symmetric.hash.len()]
    }
    pub fn is_handshake_finished(&self) -> bool {
        self.step == 2
    }
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
    pub fn into_stateless_transport_mode(self) -> Result<StatelessTransportState, Error> {
        if !self.is_handshake_finished() {
            return Err(Error::State(StateProblem::HandshakeNotFinished));
        }
        let (initiator_key, responder_key) = self.symmetric.split();
        Ok(StatelessTransportState {
            initiator_key,
            responder_key,
            remote_static: self.rs,
            initiator: self.initiator,
        })
    }
}

/// Explicit-nonce transport. Nonce uniqueness and epoch/replay policy remain
/// STP's responsibility, exactly as with Snow's stateless transport API.
#[derive(Clone)]
pub struct StatelessTransportState {
    initiator_key: [u8; 32],
    responder_key: [u8; 32],
    remote_static: [u8; 32],
    initiator: bool,
}
impl core::fmt::Debug for StatelessTransportState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatelessTransportState").finish()
    }
}
impl Drop for StatelessTransportState {
    fn drop(&mut self) {
        wipe(&mut self.initiator_key);
        wipe(&mut self.responder_key);
        wipe(&mut self.remote_static);
    }
}
fn validate_nonce(nonce: u64) -> Result<(), Error> {
    if nonce == u64::MAX {
        Err(Error::State(StateProblem::Exhausted))
    } else {
        Ok(())
    }
}
impl StatelessTransportState {
    pub fn write_message_with_additional_data(
        &self,
        nonce: u64,
        ad: &[u8],
        plaintext: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        let len = plaintext.len().checked_add(16).ok_or(Error::Input)?;
        if len > 65535 || message.len() < len {
            return Err(Error::Input);
        }
        validate_nonce(nonce)?;
        let key = if self.initiator {
            &self.initiator_key
        } else {
            &self.responder_key
        };
        aead::seal(key, nonce, ad, plaintext, message)
    }
    pub fn read_message_with_additional_data(
        &self,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        if ciphertext.len() > 65535 {
            return Err(Error::Input);
        }
        if ciphertext.len() < 16 || message.len() < ciphertext.len() - 16 {
            return Err(Error::Decrypt);
        }
        validate_nonce(nonce)?;
        let key = if self.initiator {
            &self.responder_key
        } else {
            &self.initiator_key
        };
        aead::open(key, nonce, ad, ciphertext, message)
    }
    pub fn write_message(
        &self,
        nonce: u64,
        plaintext: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        self.write_message_with_additional_data(nonce, &[], plaintext, message)
    }
    pub fn read_message(
        &self,
        nonce: u64,
        ciphertext: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        self.read_message_with_additional_data(nonce, &[], ciphertext, message)
    }
    pub fn rekey_outgoing(&mut self) {
        if self.initiator {
            aead::rekey(&mut self.initiator_key);
        } else {
            aead::rekey(&mut self.responder_key);
        }
    }
    pub fn rekey_incoming(&mut self) {
        if self.initiator {
            aead::rekey(&mut self.responder_key);
        } else {
            aead::rekey(&mut self.initiator_key);
        }
    }
    pub fn rekey_manually(&mut self, initiator: Option<&[u8; 32]>, responder: Option<&[u8; 32]>) {
        if let Some(key) = initiator {
            self.rekey_initiator_manually(key);
        }
        if let Some(key) = responder {
            self.rekey_responder_manually(key);
        }
    }
    pub fn rekey_initiator_manually(&mut self, key: &[u8; 32]) {
        wipe(&mut self.initiator_key);
        self.initiator_key.copy_from_slice(key);
    }
    pub fn rekey_responder_manually(&mut self, key: &[u8; 32]) {
        wipe(&mut self.responder_key);
        self.responder_key.copy_from_slice(key);
    }
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        Some(&self.remote_static)
    }
}
