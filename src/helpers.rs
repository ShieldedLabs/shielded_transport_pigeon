pub trait SliceWrite     { fn write_to(&self, buf: &mut [u8]) -> usize; }
impl SliceWrite for u128 { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0..16].copy_from_slice(&self.to_le_bytes()); 16 } }
impl SliceWrite for i128 { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0..16].copy_from_slice(&self.to_le_bytes()); 16 } }
impl SliceWrite for u64  { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0.. 8].copy_from_slice(&self.to_le_bytes());  8 } }
impl SliceWrite for i64  { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0.. 8].copy_from_slice(&self.to_le_bytes());  8 } }
impl SliceWrite for u32  { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0.. 4].copy_from_slice(&self.to_le_bytes());  4 } }
impl SliceWrite for i32  { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0.. 4].copy_from_slice(&self.to_le_bytes());  4 } }
impl SliceWrite for u16  { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0.. 2].copy_from_slice(&self.to_le_bytes());  2 } }
impl SliceWrite for i16  { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0.. 2].copy_from_slice(&self.to_le_bytes());  2 } }
impl SliceWrite for u8   { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0] = *self as u8;                                   1 } }
impl SliceWrite for i8   { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0] = *self as u8;                                   1 } }
impl SliceWrite for [u8] { fn write_to(&self, buf: &mut [u8]) -> usize { buf[0..self.len()].copy_from_slice(self);      self.len() } }
pub trait SliceRead: Sized { fn read_from(buf: &mut &[u8]) -> Option<Self>; }
impl SliceRead for u128    { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() < 16 { return None; } let (b, rest) = buf.split_at(16); *buf = rest; Some(u128::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for i128    { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() < 16 { return None; } let (b, rest) = buf.split_at(16); *buf = rest; Some(i128::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for u64     { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  8 { return None; } let (b, rest) = buf.split_at( 8); *buf = rest; Some( u64::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for i64     { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  8 { return None; } let (b, rest) = buf.split_at( 8); *buf = rest; Some( i64::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for u32     { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  4 { return None; } let (b, rest) = buf.split_at( 4); *buf = rest; Some( u32::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for i32     { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  4 { return None; } let (b, rest) = buf.split_at( 4); *buf = rest; Some( i32::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for u16     { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  2 { return None; } let (b, rest) = buf.split_at( 2); *buf = rest; Some( u16::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for i16     { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  2 { return None; } let (b, rest) = buf.split_at( 2); *buf = rest; Some( i16::from_le_bytes(b.try_into().unwrap())) } }
impl SliceRead for u8      { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  1 { return None; } let v = buf[0];        *buf = &buf[1..]; Some(v)       } }
impl SliceRead for i8      { fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() <  1 { return None; } let v = buf[0] as i8;  *buf = &buf[1..]; Some(v)       } }
impl<const N: usize> SliceRead for [u8; N] {
    fn read_from(buf: &mut &[u8]) -> Option<Self> { if buf.len() < N { return None; } let (b, rest) = buf.split_at(N); *buf = rest; Some(b.try_into().unwrap()) }
}
#[inline] pub fn store_u64(buf: &mut [u8], value: u64) {
    debug_assert!(buf.len() == 8);
    buf[..8].copy_from_slice(&value.to_le_bytes()); }
#[inline] pub fn load_u64(buf: &[u8]) -> u64 { debug_assert!(buf.len() == 8); u64::from_le_bytes(buf[..8].try_into().unwrap()) }
#[inline] pub fn store_u48(buf: &mut [u8], value: u64) {
    debug_assert!(buf.len() == 6);
    buf.copy_from_slice(&value.to_le_bytes()[..6]); }
#[inline] pub fn load_u48(buf: &[u8]) -> u64 {
    debug_assert!(buf.len() == 6); let mut tmp = [0u8; 8]; tmp[..6].copy_from_slice(buf);
    u64::from_le_bytes(tmp) }
#[inline] pub fn store_u32(buf: &mut [u8], value: u32) {
    debug_assert!(buf.len() == 4);
    buf.copy_from_slice(&value.to_le_bytes()[..4]); }
#[inline] pub fn load_u32(buf: &[u8]) -> u32 {
    debug_assert!(buf.len() == 4); let mut tmp = [0u8; 4]; tmp[..4].copy_from_slice(buf);
    u32::from_le_bytes(tmp) }
#[inline] pub fn store_u24(buf: &mut [u8], value: u32) {
    debug_assert!(buf.len() == 3);
    buf.copy_from_slice(&value.to_le_bytes()[..3]); }
#[inline] pub fn load_u24(buf: &[u8]) -> u32 {
    debug_assert!(buf.len() == 3); let mut tmp = [0u8; 4]; tmp[..3].copy_from_slice(buf);
    u32::from_le_bytes(tmp) }
#[inline] pub fn store_u16(buf: &mut [u8], value: u16) {
    debug_assert!(buf.len() == 2);
    buf.copy_from_slice(&value.to_le_bytes()[..2]); }
#[inline] pub fn load_u16(buf: &[u8]) -> u16 {
    debug_assert!(buf.len() == 2); let mut tmp = [0u8; 2]; tmp[..2].copy_from_slice(buf);
    u16::from_le_bytes(tmp) }
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)] pub struct BytesPerSecond(pub u64);
impl BytesPerSecond {
    const KIB: u64 = 1024; const MIB: u64 = 1024 * 1024; const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    pub fn best_unit(bps: u64) -> (u64, &'static str) {
        if bps >= Self::TIB { (Self::TIB, "TiB/s") } else if bps >= Self::GIB {
            (Self::GIB, "GiB/s") } else if bps >= Self::MIB { (Self::MIB, "MiB/s") } else if bps >= Self::KIB {
            (Self::KIB, "KiB/s") } else { (1, "B/s") } }
    pub fn format_value(value: u64, unit: u64) -> (u64, u64) {
        let scaled = (value.saturating_mul(100) + unit / 2) / unit;
        (scaled / 100, scaled % 100) } }
impl std::fmt::Display for BytesPerSecond {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bps = self.0; let (unit, suffix) = Self::best_unit(bps);
        if unit == 1 { return write!(f, "{} {}", bps, suffix); }
        let (whole, frac) = Self::format_value(bps, unit);
        if frac == 0 { write!(f, "{} {}", whole, suffix) } else if whole >= 10 {
            let one_decimal = (bps.saturating_mul(10) + unit / 2) / unit;
            write!(f, "{}.{:01} {}", one_decimal / 10, one_decimal % 10, suffix)
        } else { write!(f, "{}.{:02} {}", whole, frac, suffix) } } }
impl std::fmt::Debug for BytesPerSecond {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BytesPerSecond").field(&format_args!("{}", self)).field(&self.0).finish() } }
pub use snow as noise; struct OsRandom;
impl noise::types::Random for OsRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), noise::Error> {
        crate::platform::fill_random(dest).map_err(|_| noise::Error::Rng) } }
struct OsRandomResolver;
impl noise::resolvers::CryptoResolver for OsRandomResolver {
    fn resolve_rng(&self) -> Option<Box<dyn noise::types::Random>> { Some(Box::new(OsRandom)) }
    fn resolve_dh(&self, _: &noise::params::DHChoice) -> Option<Box<dyn noise::types::Dh>> { None }
    fn resolve_hash(&self, _: &noise::params::HashChoice) -> Option<Box<dyn noise::types::Hash>> { None }
    fn resolve_cipher(&self, _: &noise::params::CipherChoice) -> Option<Box<dyn noise::types::Cipher>> { None } }
fn noise_builder(protocol: &str) -> Result<noise::Builder<'_>, noise::Error> {
    let resolver = noise::resolvers::FallbackResolver::new(
        Box::new(OsRandomResolver), Box::new(noise::resolvers::DefaultResolver), );
    Ok(noise::Builder::with_resolver(protocol.parse()?, Box::new(resolver))) }
pub(crate) fn crypto_random() -> Result<[u8; 32], noise::Error> {
    let mut bytes = [0u8; 32]; crate::platform::fill_random(&mut bytes).map_err(|_| noise::Error::Rng)?;
    Ok(bytes) }
#[doc(hidden)]
pub fn noise_initiator(protocol: &str, prologue: &[u8], private: &[u8], remote: &[u8]) -> Result<noise::HandshakeState, noise::Error> {
    noise_builder(protocol)?.prologue(prologue)?.local_private_key(private)?.remote_public_key(remote)?.build_initiator() }
pub(crate) fn noise_responder(protocol: &str, prologue: &[u8], private: &[u8]) -> Result<noise::HandshakeState, noise::Error> {
    noise_builder(protocol)?.prologue(prologue)?.local_private_key(private)?.build_responder() }
