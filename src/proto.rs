//! Wire protocol shared by the client (`sync`) and relay (`serve`).
//!
//! Zero-knowledge: every payload the relay stores is an opaque sealed `entry`
//! (`entry_id` + ciphertext `blob`). The relay authenticates devices by Ed25519
//! signature over the request body — it never holds a password or a vault key.
//!
//! IDs and public keys travel base64 in JSON; blobs travel base64 too (JSON has
//! no bytes). The relay treats `blob` as bytes and never inspects it.

use serde::{Deserialize, Serialize};

/// One opaque log entry as it crosses the wire / rests in the relay DB.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireEntry {
    /// 16-byte log entry id, base64.
    pub entry_id_b64: String,
    /// Sealed record bytes (`nonce||ct`), base64. Relay never decrypts this.
    pub blob_b64: String,
}

/// `POST /v1/push` body: entries this device holds that it wants the relay to store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushReq {
    pub entries: Vec<WireEntry>,
}

/// `POST /v1/push` response: current relay head after the append.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResp {
    pub head: u64,
    /// How many of the pushed entries were new (not already stored).
    pub stored: usize,
}

/// `GET /v1/pull` response: entries with `seq > since`, plus the new head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResp {
    pub entries: Vec<WireEntry>,
    pub head: u64,
}

/// `POST /v1/enroll` body: register a device's public keys for a vault. In v0.1
/// enrollment is trust-on-first-use per vault (Phase 4 adds approval + the
/// wrapped-key handshake); the relay only stores these to authenticate later
/// requests and to let existing devices discover who to wrap the vault key for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollReq {
    pub device_name: String,
    /// Ed25519 verifying key, base64 — this is the device's relay identity.
    pub ed25519_pub_b64: String,
    /// X25519 public key, base64 — recipient for a wrapped vault key.
    pub x25519_pub_b64: String,
}

/// Authenticated envelope: `body` is the JSON of one of the request types above,
/// signed by the device's Ed25519 key. `vault_id` selects the store; `device_pub`
/// selects the key to verify against (for enroll it is the newly-registered key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed {
    pub vault_id_b64: String,
    pub device_pub_b64: String,
    /// Detached Ed25519 signature over `body` bytes, base64.
    pub sig_b64: String,
    /// The inner request, serialized to a JSON string (signed verbatim).
    pub body: String,
}
