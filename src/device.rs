//! Device lifecycle client: enroll a new device, approve/revoke from an existing
//! one, and recover a vault from its phrase on a fresh machine.
//!
//! The vault key never crosses the wire in the clear. Approval wraps it for the
//! new device's X25519 key (see [`crate::crypto::wrap_vault_key`]); recovery
//! re-derives it locally from the recovery phrase, so no wrapping is needed.

use crate::crypto;
use crate::proto::{
    ApproveReq, DeviceInfo, DevicesResp, RecoverReq, RecoverResp, RevokeReq, WrappedResp,
};
use crate::sync::{self, SyncError, B64};
use crate::vault::{self, Vault, VaultError};
use base64::Engine;
use ed25519_dalek::Signer;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A short, human-verifiable fingerprint of a device's Ed25519 public key.
/// Displayed by the joining device and used by the approver to name the target,
/// so the two humans can confirm they're approving the same device out-of-band.
pub fn short_code(ed25519_pub_b64: &str) -> String {
    let bytes = B64.decode(ed25519_pub_b64).unwrap_or_default();
    let mut out = String::with_capacity(11);
    // 8 hex chars grouped 4-4: enough to be unique per vault, short enough to read aloud
    for (i, b) in bytes.iter().take(4).enumerate() {
        if i == 2 {
            out.push('-');
        }
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Provision a brand-new device that joins vault `vault_id`, register it with the
/// relay, and block until an existing device approves it and its wrapped vault
/// key arrives — then install that key. Returns the opened, ready vault.
///
/// `poll` is called between relay polls with this device's short code so the CLI
/// can tell the user what to approve; return value is ignored.
pub async fn enroll_and_wait(
    dir: &Path,
    device_name: &str,
    passphrase: &str,
    vault_id: Uuid,
    relay: &str,
    mut on_pending: impl FnMut(&str),
) -> Result<Vault, EnrollError> {
    // Provisional vault: real vault_id, but a throwaway vault key until approval
    // hands us the real one. recovery_pub is unknown to a joining device (only
    // the bootstrapper set it), so pass zeros — the relay ignores it here.
    let provisional = Zeroizing::new(crypto::random_bytes::<32>());
    let mut v = Vault::create(
        dir,
        device_name,
        passphrase,
        vault_id,
        &provisional,
        &[0u8; 32],
    )?;
    v.set_relay_url(relay)?;

    let approved = sync::enroll(&v, relay).await?;
    if approved {
        return Ok(v); // bootstrapper: nothing to wait for
    }
    let code = short_code(&v.meta.ed25519_pub_b64);
    on_pending(&code);

    // Poll for the wrapped key. ponytail: fixed 2s poll; WS push is a v0.2 nicety.
    let client = reqwest::Client::new();
    loop {
        if let Some(wrapped_b64) = poll_wrapped(&client, &v, relay).await? {
            let wrapped = B64
                .decode(&wrapped_b64)
                .map_err(|_| sync::bad("wrapped_key"))?;
            let vk = crypto::unwrap_vault_key(&v.x25519_secret(), &wrapped, &v.ed25519_pub())
                .map_err(VaultError::from)?;
            v.set_vault_key(&vk, passphrase)?;
            return Ok(v);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// One poll for this device's wrapped key. `Ok(Some(_))` once approved.
async fn poll_wrapped(
    client: &reqwest::Client,
    v: &Vault,
    relay: &str,
) -> Result<Option<String>, SyncError> {
    let url = signed_get_url(v, relay, "wrapped");
    let resp: WrappedResp = sync::parse(client.get(url).send().await?).await?;
    Ok(if resp.approved {
        resp.wrapped_key_b64
    } else {
        None
    })
}

/// List every device the relay knows for this vault (approver's view).
pub async fn list_devices(v: &Vault, relay: &str) -> Result<Vec<DeviceInfo>, SyncError> {
    let client = reqwest::Client::new();
    let url = signed_get_url(v, relay, "devices");
    let resp: DevicesResp = sync::parse(client.get(url).send().await?).await?;
    Ok(resp.devices)
}

/// Approve a pending device identified by its short code: fetch its X25519 key,
/// wrap our vault key for it, and hand the wrapped blob to the relay.
pub async fn approve(v: &Vault, relay: &str, code: &str) -> Result<String, EnrollError> {
    let target = find_by_code(v, relay, code).await?;
    let x_pub_bytes: [u8; 32] = B64
        .decode(&target.x25519_pub_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| sync::bad("x25519_pub"))?;
    let x_pub = x25519_dalek::PublicKey::from(x_pub_bytes);
    // The wrapped key is bound (via AAD) to the target's Ed25519 public key —
    // its stable relay identity, which both approver and joiner already know.
    let target_ed: [u8; 32] = B64
        .decode(&target.ed25519_pub_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| sync::bad("ed25519_pub"))?;
    let vk = v.vault_key();
    let wrapped = crypto::wrap_vault_key(&vk, &x_pub, &target_ed);
    let req = ApproveReq {
        target_pub_b64: target.ed25519_pub_b64.clone(),
        wrapped_key_b64: B64.encode(&wrapped),
    };
    let client = reqwest::Client::new();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("approve serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/approve"), &signed).await?;
    Ok(target.name)
}

/// Revoke a device by short code. After this it cannot sync or re-enroll.
pub async fn revoke(v: &Vault, relay: &str, code: &str) -> Result<String, EnrollError> {
    let target = find_by_code(v, relay, code).await?;
    let req = RevokeReq {
        target_pub_b64: target.ed25519_pub_b64.clone(),
    };
    let client = reqwest::Client::new();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("revoke serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/revoke"), &signed).await?;
    Ok(target.name)
}

/// Recover a vault on a fresh machine from its recovery phrase. Re-derives the
/// vault key locally, proves phrase ownership to the relay to get the vault id,
/// and writes a ready-to-sync vault at `dir`.
pub async fn recover(
    dir: &Path,
    device_name: &str,
    passphrase: &str,
    phrase: &str,
    relay: &str,
) -> Result<Vault, EnrollError> {
    let keys = crypto::keys_from_phrase(phrase).map_err(VaultError::from)?;
    let recovery_pub = keys.recovery_signing.verifying_key().to_bytes();
    let device = crypto::new_device_keys();
    let ed_pub = device.ed25519.verifying_key().to_bytes();
    // recovery key signs the new device key → proves we hold the phrase
    let sig = keys.recovery_signing.sign(&ed_pub);
    let x_pub = x25519_dalek::PublicKey::from(&device.x25519);
    let req = RecoverReq {
        recovery_pub_b64: B64.encode(recovery_pub),
        device_name: device_name.to_string(),
        ed25519_pub_b64: B64.encode(ed_pub),
        x25519_pub_b64: B64.encode(x_pub.as_bytes()),
        sig_b64: B64.encode(sig.to_bytes()),
    };
    let client = reqwest::Client::new();
    let http = client
        .post(format!("{relay}/v1/recover"))
        .json(&req)
        .send()
        .await
        .map_err(SyncError::from)?;
    let resp: RecoverResp = sync::parse(http).await?;
    let vault_id = uuid_from_b64(&resp.vault_id_b64)?;
    let mut v = Vault::create_with_keys(
        dir,
        device_name,
        passphrase,
        vault_id,
        &keys.vault_key,
        &recovery_pub,
        device,
    )?;
    v.set_relay_url(relay)?;
    Ok(v)
}

// ---- helpers ----------------------------------------------------------------

async fn find_by_code(v: &Vault, relay: &str, code: &str) -> Result<DeviceInfo, EnrollError> {
    let code = code.to_lowercase();
    let mut matches: Vec<DeviceInfo> = list_devices(v, relay)
        .await?
        .into_iter()
        .filter(|d| short_code(&d.ed25519_pub_b64) == code)
        .collect();
    match matches.len() {
        0 => Err(EnrollError::NoSuchDevice(code)),
        1 => Ok(matches.remove(0)),
        _ => Err(EnrollError::AmbiguousCode(code)),
    }
}

/// Build a signed GET URL for `action` (`"devices"`, `"wrapped"`): the device
/// signs the string `"<action>:<vault_b64>"`, matching the relay's `SignedQuery`.
fn signed_get_url(v: &Vault, relay: &str, action: &str) -> String {
    let vault_b64 = B64.encode(v.vault_id().as_bytes());
    let device_b64 = B64.encode(v.ed25519_pub());
    let body = format!("{action}:{vault_b64}");
    let sig = B64.encode(v.signing_key().sign(body.as_bytes()).to_bytes());
    format!(
        "{relay}/v1/{action}?vault={}&device={}&sig={}",
        sync::urlencode(&vault_b64),
        sync::urlencode(&device_b64),
        sync::urlencode(&sig),
    )
}

/// Recover the vault id from its base64 (16 raw bytes, as the relay sends it).
fn uuid_from_b64(b64: &str) -> Result<Uuid, EnrollError> {
    let bytes: [u8; 16] = B64
        .decode(b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| sync::bad("vault_id"))?;
    Ok(Uuid::from_bytes(bytes))
}

/// Default vault directory (re-exported for the CLI).
pub fn default_dir() -> std::path::PathBuf {
    vault::default_dir()
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("no pending device with code {0} — check `sshvault device list`")]
    NoSuchDevice(String),
    #[error("code {0} matches more than one device")]
    AmbiguousCode(String),
}
