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

/// `POST /v1/enroll` body: register a device's public keys for a vault. The
/// first device to enroll a vault bootstraps it (auto-approved, and its
/// `recovery_pub` is recorded for recovery); every later device starts pending
/// until an approved device approves it and wraps the vault key for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollReq {
    pub device_name: String,
    /// Ed25519 verifying key, base64 — this is the device's relay identity.
    pub ed25519_pub_b64: String,
    /// X25519 public key, base64 — recipient for a wrapped vault key.
    pub x25519_pub_b64: String,
    /// Recovery Ed25519 public key, base64. Honored only when bootstrapping the
    /// vault (first enroll); ignored for later devices.
    pub recovery_pub_b64: String,
}

/// `POST /v1/enroll` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResp {
    /// True if this device may already sync (it bootstrapped the vault).
    pub approved: bool,
    pub head: u64,
}

/// `POST /v1/approve` body (signed by an approved device): admit `target_pub`
/// and hand it the vault key wrapped for its X25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveReq {
    /// Ed25519 pub (base64) of the device being approved.
    pub target_pub_b64: String,
    /// Vault key wrapped for the target (base64). The relay stores it opaquely.
    pub wrapped_key_b64: String,
}

/// `POST /v1/revoke` body (signed by an approved device).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeReq {
    /// Ed25519 pub (base64) of the device to revoke.
    pub target_pub_b64: String,
}

/// One device as seen by `GET /v1/devices`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub ed25519_pub_b64: String,
    pub x25519_pub_b64: String,
    pub approved: bool,
    pub revoked: bool,
}

/// `GET /v1/devices` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicesResp {
    pub devices: Vec<DeviceInfo>,
}

/// `GET /v1/wrapped` response: a pending device polls for its wrapped vault key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedResp {
    pub approved: bool,
    /// The vault key wrapped for this device (base64), once an approver set it.
    pub wrapped_key_b64: Option<String>,
}

/// `POST /v1/recover` body: prove ownership of the recovery key to re-admit a
/// fresh device with only the recovery phrase. Not a [`Signed`] envelope — the
/// device isn't enrolled yet; it authenticates with `sig` over its new Ed25519
/// public key, made by the recovery key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverReq {
    pub recovery_pub_b64: String,
    pub device_name: String,
    pub ed25519_pub_b64: String,
    pub x25519_pub_b64: String,
    /// Recovery-key signature over the new device's Ed25519 public key bytes.
    pub sig_b64: String,
}

/// `POST /v1/recover` response: which vault the recovery key unlocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverResp {
    pub vault_id_b64: String,
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
