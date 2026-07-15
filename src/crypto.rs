//! Crypto layer. Standard constructions only — see `docs/crypto-design.md`.
//!
//! Key hierarchy:
//! - BIP39 mnemonic → seed → HKDF → vault key (VK) + recovery Ed25519 keypair
//! - passphrase → Argon2id → KEK (encrypts the local keyring at rest)
//! - per-device X25519 (receives wrapped VK) + Ed25519 (signs relay requests)
//!
//! All secret material is zeroized on drop. Errors never carry key bytes.

use bip39::Mnemonic;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// 24-byte XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Argon2id parameters: RFC 9106 second recommended set (64 MiB, t=3, p=1).
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 1;

/// A 32-byte secret that is zeroized on drop.
pub type Secret32 = Zeroizing<[u8; 32]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Deliberately opaque: wrong key, wrong AAD, or tampered ciphertext.
    #[error("decryption failed: wrong passphrase or corrupted data")]
    Decrypt,
    #[error("invalid recovery phrase")]
    BadPhrase,
    #[error("key derivation failed")]
    Kdf,
    #[error("malformed ciphertext")]
    Malformed,
}

/// Keys deterministically derived from the recovery phrase.
pub struct PhraseKeys {
    /// Vault key: encrypts every record.
    pub vault_key: Secret32,
    /// Recovery Ed25519 keypair: proves vault ownership to the relay for recovery.
    pub recovery_signing: SigningKey,
}

/// Generate a fresh 24-word recovery phrase and its derived keys.
pub fn new_phrase() -> (String, PhraseKeys) {
    let mut entropy = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(entropy.as_mut());
    let mnemonic = Mnemonic::from_entropy(entropy.as_ref()).expect("32 bytes is valid entropy");
    let phrase = mnemonic.to_string();
    let keys = keys_from_phrase(&phrase).expect("just-generated phrase is valid");
    (phrase, keys)
}

/// Re-derive the vault key and recovery keypair from a recovery phrase.
pub fn keys_from_phrase(phrase: &str) -> Result<PhraseKeys, CryptoError> {
    let mnemonic = Mnemonic::parse_normalized(phrase.trim()).map_err(|_| CryptoError::BadPhrase)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let hk = Hkdf::<Sha256>::new(None, seed.as_ref());
    let mut vk = Zeroizing::new([0u8; 32]);
    hk.expand(b"sshvault/v1/vault-key", vk.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    let mut rk = Zeroizing::new([0u8; 32]);
    hk.expand(b"sshvault/v1/recovery-auth", rk.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(PhraseKeys {
        vault_key: vk,
        recovery_signing: SigningKey::from_bytes(&rk),
    })
}

/// Derive the keyring-encryption key (KEK) from a passphrase with Argon2id.
///
/// Parameters are taken as arguments (not constants) so stored vaults can carry
/// their own params and we can raise defaults later without breaking old vaults.
pub fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<Secret32, CryptoError> {
    let params = argon2::Params::new(m_kib, t, p, Some(32)).map_err(|_| CryptoError::Kdf)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// Encrypt `plaintext` under `key` with a fresh random nonce.
/// Output layout: `nonce(24) || ciphertext+tag`.
pub fn seal(key: &Secret32, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a `seal`-produced blob. Fails opaquely on any mismatch.
pub fn open(key: &Secret32, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Malformed);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Wrap the vault key for a recipient device: ephemeral-static X25519 +
/// HKDF-SHA256 + XChaCha20-Poly1305 (sealed-box construction, see
/// crypto-design.md). Output layout: `eph_pub(32) || nonce(24) || ciphertext+tag`.
pub fn wrap_vault_key(
    vault_key: &Secret32,
    recipient_pub: &x25519_dalek::PublicKey,
    recipient_device_id: &[u8],
) -> Vec<u8> {
    let eph = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let shared = eph.diffie_hellman(recipient_pub);
    let wrap_key = wrap_key_from_shared(
        shared.as_bytes(),
        eph_pub.as_bytes(),
        recipient_pub.as_bytes(),
    );
    let sealed = seal(&wrap_key, vault_key.as_ref(), recipient_device_id);
    let mut out = Vec::with_capacity(32 + sealed.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&sealed);
    out
}

/// Unwrap a vault key wrapped for this device by `wrap_vault_key`.
pub fn unwrap_vault_key(
    device_secret: &x25519_dalek::StaticSecret,
    blob: &[u8],
    device_id: &[u8],
) -> Result<Secret32, CryptoError> {
    if blob.len() < 32 + NONCE_LEN + 16 {
        return Err(CryptoError::Malformed);
    }
    let eph_pub_bytes: [u8; 32] = blob[..32].try_into().expect("length checked");
    let eph_pub = x25519_dalek::PublicKey::from(eph_pub_bytes);
    let my_pub = x25519_dalek::PublicKey::from(device_secret);
    let shared = device_secret.diffie_hellman(&eph_pub);
    let wrap_key = wrap_key_from_shared(shared.as_bytes(), eph_pub.as_bytes(), my_pub.as_bytes());
    let pt = open(&wrap_key, &blob[32..], device_id)?;
    let bytes: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed)?;
    Ok(Zeroizing::new(bytes))
}

/// HKDF both public keys into the wrap key so a wrapped blob is bound to exactly
/// one (ephemeral, recipient) pair and cannot be replayed across devices.
fn wrap_key_from_shared(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Secret32 {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(21 + 64);
    info.extend_from_slice(b"sshvault/v1/vk-wrap");
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recipient_pub);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut())
        .expect("32 bytes is a valid HKDF length");
    out
}

/// Freshly generated per-device secrets. Never leave the machine.
pub struct DeviceKeys {
    pub x25519: x25519_dalek::StaticSecret,
    pub ed25519: SigningKey,
}

/// Generate a new device keypair set.
pub fn new_device_keys() -> DeviceKeys {
    DeviceKeys {
        x25519: x25519_dalek::StaticSecret::random_from_rng(OsRng),
        ed25519: SigningKey::generate(&mut OsRng),
    }
}

/// Fill `buf` with cryptographically secure random bytes (salts, ids).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Secret32 {
        Zeroizing::new(random_bytes::<32>())
    }

    #[test]
    fn seal_open_round_trip() {
        let k = key();
        let blob = seal(&k, b"hello vault", b"aad-1");
        assert_eq!(
            open(&k, &blob, b"aad-1").unwrap().as_slice(),
            b"hello vault"
        );
    }

    #[test]
    fn open_rejects_wrong_aad_key_and_tamper() {
        let k = key();
        let blob = seal(&k, b"secret", b"aad-1");
        assert!(open(&k, &blob, b"aad-2").is_err(), "wrong AAD must fail");
        assert!(
            open(&key(), &blob, b"aad-1").is_err(),
            "wrong key must fail"
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&k, &tampered, b"aad-1").is_err(), "tamper must fail");
        assert!(
            open(&k, &blob[..30], b"aad-1").is_err(),
            "truncation must fail"
        );
    }

    #[test]
    fn nonces_are_unique_per_seal() {
        let k = key();
        let a = seal(&k, b"x", b"");
        let b = seal(&k, b"x", b"");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[test]
    fn phrase_derivation_is_deterministic() {
        let (phrase, keys1) = new_phrase();
        let keys2 = keys_from_phrase(&phrase).unwrap();
        assert_eq!(keys1.vault_key.as_ref(), keys2.vault_key.as_ref());
        assert_eq!(
            keys1.recovery_signing.verifying_key(),
            keys2.recovery_signing.verifying_key()
        );
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(keys_from_phrase("not a valid phrase").is_err());
    }

    #[test]
    fn kek_is_deterministic_and_salt_sensitive() {
        // small params to keep the test fast; production params live in vault meta
        let a = derive_kek(b"pw", b"0123456789abcdef", 8, 1, 1).unwrap();
        let b = derive_kek(b"pw", b"0123456789abcdef", 8, 1, 1).unwrap();
        let c = derive_kek(b"pw", b"fedcba9876543210", 8, 1, 1).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), c.as_ref());
    }

    #[test]
    fn vault_key_wrap_round_trip() {
        let vk = key();
        let dev = new_device_keys();
        let dev_pub = x25519_dalek::PublicKey::from(&dev.x25519);
        let wrapped = wrap_vault_key(&vk, &dev_pub, b"device-1");
        let unwrapped = unwrap_vault_key(&dev.x25519, &wrapped, b"device-1").unwrap();
        assert_eq!(unwrapped.as_ref(), vk.as_ref());
        // bound to device id: replay under another id fails
        assert!(unwrap_vault_key(&dev.x25519, &wrapped, b"device-2").is_err());
        // bound to recipient: another device cannot unwrap
        let other = new_device_keys();
        assert!(unwrap_vault_key(&other.x25519, &wrapped, b"device-1").is_err());
    }
}
