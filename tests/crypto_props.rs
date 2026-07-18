//! Phase 1 gate: round-trip encrypt/decrypt property tests.

use proptest::prelude::*;
use sshvault::crypto;
use zeroize::Zeroizing;

fn key_strategy() -> impl Strategy<Value = crypto::Secret32> {
    any::<[u8; 32]>().prop_map(Zeroizing::new)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// seal → open is the identity for any payload/AAD under any key.
    #[test]
    fn seal_open_round_trip(key in key_strategy(), payload in proptest::collection::vec(any::<u8>(), 0..4096), aad in proptest::collection::vec(any::<u8>(), 0..64)) {
        let blob = crypto::seal(&key, &payload, &aad);
        let opened = crypto::open(&key, &blob, &aad).expect("round trip must succeed");
        prop_assert_eq!(opened.as_slice(), payload.as_slice());
    }

    /// Any single-bit corruption anywhere in the blob must fail decryption.
    #[test]
    fn any_bitflip_fails(key in key_strategy(), payload in proptest::collection::vec(any::<u8>(), 1..512), byte_idx: prop::sample::Index, bit in 0u8..8) {
        let mut blob = crypto::seal(&key, &payload, b"aad");
        let idx = byte_idx.index(blob.len());
        blob[idx] ^= 1 << bit;
        prop_assert!(crypto::open(&key, &blob, b"aad").is_err());
    }

    /// AAD is binding: opening under any different AAD fails.
    #[test]
    fn aad_is_binding(key in key_strategy(), payload in proptest::collection::vec(any::<u8>(), 0..512), aad1 in proptest::collection::vec(any::<u8>(), 0..32), aad2 in proptest::collection::vec(any::<u8>(), 0..32)) {
        prop_assume!(aad1 != aad2);
        let blob = crypto::seal(&key, &payload, &aad1);
        prop_assert!(crypto::open(&key, &blob, &aad2).is_err());
    }

    /// Wrapping the vault key for a device round-trips, and never unwraps for a
    /// different device id.
    #[test]
    fn vault_key_wrap_round_trip(vk in key_strategy(), device_id in proptest::collection::vec(any::<u8>(), 1..32)) {
        let dev = crypto::new_device_keys();
        let dev_pub = x25519_dalek::PublicKey::from(&dev.x25519);
        let wrapped = crypto::wrap_vault_key(vk.as_ref(), &dev_pub, &device_id);
        let unwrapped = crypto::unwrap_vault_key(&dev.x25519, &wrapped, &device_id).expect("unwrap");
        prop_assert_eq!(unwrapped.as_slice(), vk.as_ref());

        let mut other_id = device_id.clone();
        other_id[0] ^= 1;
        prop_assert!(crypto::unwrap_vault_key(&dev.x25519, &wrapped, &other_id).is_err());
    }
}
