use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc7748_x25519_public_and_shared() {
    let a: [u8; 32] = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .try_into()
        .unwrap();
    let b: [u8; 32] = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        .try_into()
        .unwrap();
    let ap = x25519::public_key(&a);
    let bp = x25519::public_key(&b);
    assert_eq!(
        ap.as_slice(),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        bp.as_slice(),
        hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let shared = x25519::x25519(&a, &bp);
    assert_eq!(
        shared.as_slice(),
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    assert_eq!(shared, x25519::x25519(&b, &ap));
}

#[test]
fn rfc8439_chacha_block() {
    let key = core::array::from_fn(|i| i as u8);
    let block = chacha20::block(&key, 0x0900000000000001, 0x4a000000);
    assert_eq!(
        block.as_slice(),
        hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        )
    );
}

#[test]
fn rfc8439_poly1305() {
    let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        .try_into()
        .unwrap();
    let mut mac = poly1305::State::new(&key);
    for part in b"Cryptographic Forum Research Group".chunks(16) {
        let mut block = [0u8; 16];
        block[..part.len()].copy_from_slice(part);
        let partial = part.len() < 16;
        if partial {
            block[part.len()] = 1;
        }
        mac.compute_block(&block, partial);
    }
    assert_eq!(
        mac.finalize_mut().as_slice(),
        hex("a8061dc1305136c6c22b8baf0c0127a9")
    );
}

#[test]
fn rfc7693_blake2() {
    assert_eq!(
        blake2s::hash(&[b"abc"]).as_slice(),
        hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    );
    assert_eq!(
        blake2b::hash(&[b"a", b"bc"]).as_slice(),
        hex(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        )
    );
}

fn pair(protocol: &str) -> (noise::HandshakeState, noise::HandshakeState) {
    let a = [1u8; 32];
    let b = [2u8; 32];
    (
        noise::HandshakeState::initiator(
            protocol,
            b"STP header",
            &a,
            &noise::public_key(&b),
            [3; 32],
        )
        .unwrap(),
        noise::HandshakeState::responder(protocol, b"STP header", &b, [4; 32]).unwrap(),
    )
}

#[test]
fn noise_handshake_transport_rekey_tamper_and_retry() {
    for protocol in [
        "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        "Noise_IK_25519_ChaChaPoly_BLAKE2b",
    ] {
        let (mut a, mut b) = pair(protocol);
        let mut wire = [0u8; 1024];
        let mut out = [0u8; 1024];
        assert!(!a.is_handshake_finished());
        let n = a.write_message(b"request", &mut wire).unwrap();
        let old_hash = b.get_handshake_hash().to_vec();
        wire[n - 1] ^= 1;
        out.fill(0xa5);
        assert_eq!(
            b.read_message(&wire[..n], &mut out),
            Err(noise::Error::Decrypt)
        );
        assert_eq!(out, [0xa5; 1024]);
        assert_eq!(old_hash, b.get_handshake_hash());
        wire[n - 1] ^= 1;
        assert_eq!(b.read_message(&wire[..n], &mut out).unwrap(), 7);
        assert_eq!(&out[..7], b"request");
        assert_eq!(b.get_remote_static().unwrap(), noise::public_key(&[1; 32]));
        let n = b.write_message(b"response", &mut wire).unwrap();
        assert_eq!(a.read_message(&wire[..n], &mut out).unwrap(), 8);
        assert_eq!(a.get_handshake_hash(), b.get_handshake_hash());
        assert!(a.is_handshake_finished() && b.is_handshake_finished());
        let mut a = a.into_stateless_transport_mode().unwrap();
        let mut b = b.into_stateless_transport_mode().unwrap();
        let old_b = b.clone();
        for epoch in 0..4 {
            let n = a
                .write_message_with_additional_data(77, b"AD", b"packet", &mut wire)
                .unwrap();
            assert_eq!(
                b.read_message_with_additional_data(77, b"AD", &wire[..n], &mut out)
                    .unwrap(),
                6
            );
            for i in 0..n {
                wire[i] ^= 1;
                out.fill(0xa5);
                assert_eq!(
                    b.read_message_with_additional_data(77, b"AD", &wire[..n], &mut out),
                    Err(noise::Error::Decrypt)
                );
                assert_eq!(out, [0xa5; 1024]);
                wire[i] ^= 1;
            }
            assert_eq!(
                b.read_message_with_additional_data(77, b"bad AD", &wire[..n], &mut out),
                Err(noise::Error::Decrypt)
            );
            if epoch > 0 {
                assert_eq!(
                    old_b.read_message_with_additional_data(77, b"AD", &wire[..n], &mut out),
                    Err(noise::Error::Decrypt)
                );
            }
            a.rekey_outgoing();
            b.rekey_incoming();
        }
        assert_eq!(
            a.write_message(u64::MAX, b"x", &mut wire),
            Err(noise::Error::State(noise::StateProblem::Exhausted))
        );
        a.rekey_manually(Some(&[0; 32]), Some(&[0; 32]));
        b.rekey_manually(Some(&[0; 32]), Some(&[0; 32]));
        let n = b.write_message(12, b"manual", &mut wire).unwrap();
        assert_eq!(a.read_message(12, &wire[..n], &mut out).unwrap(), 6);
    }
}

#[test]
fn aead_padding_boundaries_and_authentication_atomicity() {
    for n in [0, 1, 15, 16, 17, 63, 64, 65, 255, 1024] {
        for an in [0, 1, 15, 16, 17, 64] {
            let input = vec![0x5a; n];
            let ad = vec![0x42; an];
            let mut encrypted = vec![0u8; n + 16];
            let mut output = vec![0xa5; n];
            aead::seal(&[37; 32], 42, &ad, &input, &mut encrypted).unwrap();
            assert_eq!(
                aead::open(&[37; 32], 42, &ad, &encrypted, &mut output).unwrap(),
                n
            );
            assert_eq!(input, output);
            encrypted[n + 15] ^= 1;
            output.fill(0xa5);
            assert!(aead::open(&[37; 32], 42, &ad, &encrypted, &mut output).is_err());
            assert_eq!(output, vec![0xa5; n]);
        }
    }
}

#[test]
fn cacophony_noise_ik_published_vectors() {
    // Cacophony vectors distributed in shielded_labs_snow 0.10.0,
    // tests/vectors/cacophony.txt. Retained with Snow's license notices.
    let a = hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
    let b = hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
    let ae: [u8; 32] = hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
        .try_into()
        .unwrap();
    let be: [u8; 32] = hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")
        .try_into()
        .unwrap();
    let bp = hex("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62");
    let request = hex("4c756477696720766f6e204d69736573");
    let reply = hex("4d757272617920526f746862617264");
    let payloads = [
        "462e20412e20486179656b",
        "4361726c204d656e676572",
        "4a65616e2d426170746973746520536179",
        "457567656e2042f6686d20766f6e2042617765726b",
    ];
    for (protocol, hash, first, second, transport) in [
        (
            "Noise_IK_25519_ChaChaPoly_BLAKE2b",
            "1c8fa891cb414fedba6daa7c6f4ae0a6d98e5f9768cc9cecd27e805614943ee9c8a1b27fbfb76dc197255c8aa69f6b4285c423840b8bedf45e652ca64f797d81",
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944ba83a447b38c83e327ad936929812f624884847b7831e95e197b2f797088efdd2f88f1db7e1fb0e99c64419097af91cee64e470f4b6fcd9298ce0b56fe20f86e13bf70439c538e3602a7127af71a29cc",
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088439f069b267a06b3de3ecb1043bcb098e9af91d9c64748d998c7b47890871571",
            [
                "cd54383060e7a28434cca27fb1cc524cfbabeb18181589df219d07",
                "a856d3bf0246bfc476c655009cd1ed677b8dcc5b349ae8ef2a05f2",
                "49063084b2c51f098337cb8a13739ac848f907e67cfb2cc8a8b60586467aa02fc7",
                "8b9709d23b47e4639df7678d7a21741eba4ef1e9c60383001c7435549c20f9d56f30e935d3",
            ],
        ),
        (
            "Noise_IK_25519_ChaChaPoly_BLAKE2s",
            "48f3cb8bc9319da4ba1e9933991b1c4ed4034f1f126a76d3a1fbcfd7f94248d4",
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440b03ddc7aac5123d06a1b23b71670e32e76c28239a7ca4ac8f784de7e44c1adbfc6e83fef7352a58d9d56157400c0a737b1d171ce368229c7b752ac25b8faf4eca690f6d896f543be02c996ab2b86b76",
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d9b5a8927f0ac9655ef76833bc7e5561f42e691ac8404efd6fbd6308b6a27c",
            [
                "2c256ed08fcd08c2980f954ee4beaccb61c9581340f5dd2fd1cf3b",
                "d6033f70eee20945c7c9dba304e397ee3b284ff5e00fd9efb095d3",
                "a9c068ca5d8babf72560652d8e851adbfac35c8a66e810d560863173e96adf4cfe",
                "2a09d8f459e5927e40fdd2eddc99bdafb04e13a26f145cb5cfe9e6ba34c94331ebc17d5156",
            ],
        ),
    ] {
        let mut a = noise::HandshakeState::initiator(protocol, b"John Galt", &a, &bp, ae).unwrap();
        let mut b = noise::HandshakeState::responder(protocol, b"John Galt", &b, be).unwrap();
        let mut wire = [0u8; 1024];
        let mut out = [0u8; 1024];
        let n = a.write_message(&request, &mut wire).unwrap();
        assert_eq!(&wire[..n], hex(first));
        assert_eq!(b.read_message(&wire[..n], &mut out).unwrap(), request.len());
        let n = b.write_message(&reply, &mut wire).unwrap();
        assert_eq!(&wire[..n], hex(second));
        assert_eq!(a.read_message(&wire[..n], &mut out).unwrap(), reply.len());
        assert_eq!(a.get_handshake_hash(), hex(hash));
        assert_eq!(b.get_handshake_hash(), hex(hash));
        let a = a.into_stateless_transport_mode().unwrap();
        let b = b.into_stateless_transport_mode().unwrap();
        for i in 0..4 {
            let (sender, receiver) = if i % 2 == 0 { (&a, &b) } else { (&b, &a) };
            let p = hex(payloads[i]);
            let n = sender.write_message((i / 2) as u64, &p, &mut wire).unwrap();
            assert_eq!(&wire[..n], hex(transport[i]));
            assert_eq!(
                receiver
                    .read_message((i / 2) as u64, &wire[..n], &mut out)
                    .unwrap(),
                p.len()
            );
            assert_eq!(&out[..p.len()], p);
        }
    }
}
