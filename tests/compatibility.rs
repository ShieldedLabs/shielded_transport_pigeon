//! Public compatibility fixtures captured from pre-port STP commit 1e00403.
//! All seeds and resulting keys below are deliberately public test data.
use shielded_transport_pigeon::stp::*;

#[test]
fn seeded_identity_bytes_and_address_encoding_match_pre_port_release() {
    let fixtures = [
        ([0u8; 32], "drjgraDxPZBAXWrlU4a9KL3SGbigje0aqDbvzIt3Dcc", "vAHVXcoXGuokLhota-KKeXXEZAczHNhHgWcThgUSKGM"),
        ([1u8; 32], "Aj83IDokdsQlZqYcxVw8qHXbtMxBwN63ifjnv4gYNjg", "1Tuf6h3U1XDb44GAdnwjZFbKZjPxA_GqBjfnthPSUnQ"),
        ([255u8; 32], "9riYQS9KsGGUMWfB4j76orqY40Wgk_CwbaE7_9vUssc", "nua0GVd5aAuNa-k_khnM2v-25xXLNqFTyyjA0RWISRE"),
        (std::array::from_fn(|i| i as u8), "Of0rfdnFGWqNvQN3uNxKSYo12G-83mrMssx9TNjqJJI", "IkEEKIIuzYnsZFQCIVvK3GtaW-89cxDoE20hYQZU5xc"),
    ];
    for magic in [CONNECT_MAGIC1_PLAIN_TEXT, CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s,
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b] {
        for (seed, private, public) in &fixtures {
            let key = new_keypair_from_connect_magic1_with_seed(magic, *seed).unwrap();
            assert_eq!(b64(&key.private), *private);
            assert_eq!(b64(&key.public), *public);
            assert_eq!(key.magic1, magic);
            let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, 6000, &key);
            let coded = format!("{address:?}");
            assert_eq!(STPAddress::parse(&coded), Some(address));
            assert!(!coded.contains('='));
        }
    }
}
