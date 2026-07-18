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
use crate::record::Kind;
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
    let client = sync::http_client();
    loop {
        if let Some(wrapped_b64) = poll_wrapped(&client, &v, relay).await? {
            let wrapped = B64
                .decode(&wrapped_b64)
                .map_err(|_| sync::bad("wrapped_key"))?;
            let key_list = crypto::unwrap_vault_key(&v.x25519_secret(), &wrapped, &v.ed25519_pub())
                .map_err(VaultError::from)?;
            v.set_vault_key(&key_list)?;
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
    let client = sync::http_client();
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
    // Wrap the whole epoch key-list so the joiner can read entries from every
    // epoch, not just the current one.
    let key_list = v.vault_key_list();
    let wrapped = crypto::wrap_vault_key(&key_list, &x_pub, &target_ed);
    let req = ApproveReq {
        target_pub_b64: target.ed25519_pub_b64.clone(),
        wrapped_key_b64: B64.encode(&wrapped),
    };
    let client = sync::http_client();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("approve serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/approve"), &signed).await?;
    Ok(target.name)
}

/// Revoke a device by short code. After this it cannot sync or re-enroll. This
/// is access-control only — it does NOT rotate the vault key, so the revoked
/// device still holds the key and can read anything it already pulled. For
/// forward secrecy use [`revoke_and_rotate`].
pub async fn revoke(v: &Vault, relay: &str, code: &str) -> Result<String, EnrollError> {
    let target = find_by_code(v, relay, code).await?;
    let req = RevokeReq {
        target_pub_b64: target.ed25519_pub_b64.clone(),
    };
    let client = sync::http_client();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("revoke serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/revoke"), &signed).await?;
    Ok(target.name)
}

/// Revoke a device AND rotate the vault key so the revoked device cannot read
/// data written after this point (forward secrecy). Requires the recovery phrase
/// — the new epoch key is derived from the seed, which only the phrase holder
/// has. Steps: revoke the target, mint the next epoch locally, re-wrap the new
/// epoch key-list for every *remaining* non-revoked device, and hand the relay
/// the bump + the per-device wrapped lists in one signed call.
///
/// Cannot recover plaintext the revoked device already pulled (see
/// threat-model.md); it closes the going-forward gap only.
pub async fn revoke_and_rotate(
    v: &mut Vault,
    relay: &str,
    code: &str,
    phrase: &str,
) -> Result<String, EnrollError> {
    let target = find_by_code(v, relay, code).await?;
    // 1. Revoke first, so the target is already gone from the device list we
    //    re-wrap for even if it races an enroll.
    let name = revoke(v, relay, code).await?;

    // 2. Mint the next epoch locally (phrase-gated) and seal future writes under it.
    let epoch = v.rotate(phrase)?;
    let key_list = v.vault_key_list();

    // 3. Re-wrap the new key-list for every remaining approved/pending device
    //    except the one we just revoked.
    let devices = list_devices(v, relay).await?;
    let mut wrapped = Vec::new();
    for d in &devices {
        if d.revoked || d.ed25519_pub_b64 == target.ed25519_pub_b64 {
            continue;
        }
        let x_pub_bytes: [u8; 32] = B64
            .decode(&d.x25519_pub_b64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| sync::bad("x25519_pub"))?;
        let ed: [u8; 32] = B64
            .decode(&d.ed25519_pub_b64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| sync::bad("ed25519_pub"))?;
        let x_pub = x25519_dalek::PublicKey::from(x_pub_bytes);
        wrapped.push(crate::proto::WrappedFor {
            device_pub_b64: d.ed25519_pub_b64.clone(),
            wrapped_key_b64: B64.encode(crypto::wrap_vault_key(&key_list, &x_pub, &ed)),
        });
    }

    // 4. Hand the relay the epoch bump + re-wrapped lists in one signed call.
    let req = crate::proto::RotateReq { epoch, wrapped };
    let client = sync::http_client();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("rotate serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/rotate"), &signed).await?;
    Ok(name)
}

// ---- shares -----------------------------------------------------------------

/// Wrap `key_list` for each named device (by short code), returning the
/// `WrappedFor` blobs. Errors if a code matches no or many devices.
async fn wrap_for_codes(
    v: &Vault,
    relay: &str,
    key_list: &[u8],
    codes: &[String],
) -> Result<Vec<crate::proto::WrappedFor>, EnrollError> {
    let mut out = Vec::new();
    for code in codes {
        let d = find_by_code(v, relay, code).await?;
        let x_pub_bytes: [u8; 32] = B64
            .decode(&d.x25519_pub_b64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| sync::bad("x25519_pub"))?;
        let ed: [u8; 32] = B64
            .decode(&d.ed25519_pub_b64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| sync::bad("ed25519_pub"))?;
        let x_pub = x25519_dalek::PublicKey::from(x_pub_bytes);
        out.push(crate::proto::WrappedFor {
            device_pub_b64: d.ed25519_pub_b64.clone(),
            wrapped_key_b64: B64.encode(crypto::wrap_vault_key(key_list, &x_pub, &ed)),
        });
    }
    Ok(out)
}

/// Create a new share locally and grant it to `member_codes` (plus this device,
/// so every device you own can read it). `name` is recorded in the default share
/// so all members can address the share by name. Returns the new share id.
pub async fn create_share(
    v: &mut Vault,
    relay: &str,
    name: &str,
    member_codes: &[String],
) -> Result<Uuid, EnrollError> {
    if v.resolve_share(name).is_some() {
        return Err(EnrollError::Vault(VaultError::Duplicate {
            kind: "share",
            name: name.into(),
        }));
    }
    let share = v.create_share()?;
    // Record name→id in the default share so it syncs to every member.
    v.add(
        Kind::ShareName,
        "name",
        name,
        &crate::record::ShareName {
            name: name.into(),
            share_id_b64: B64.encode(share.as_bytes()),
        },
    )?;
    let key_list = v.share_key_list_for(share);
    // Grant to the named members AND to this device (self), so its own future
    // syncs on other machines re-learn the share via /v1/shares.
    let mut wrapped = wrap_for_codes(v, relay, &key_list, member_codes).await?;
    let self_code = short_code(&v.meta.ed25519_pub_b64);
    wrapped.extend(wrap_for_codes(v, relay, &key_list, std::slice::from_ref(&self_code)).await?);
    let req = crate::proto::ShareGrantReq {
        share_id_b64: B64.encode(share.as_bytes()),
        epoch: v.share_epoch_for(share),
        wrapped,
    };
    let client = sync::http_client();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("grant serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/share/grant"), &signed).await?;
    Ok(share)
}

/// Add members to an existing share you hold: wrap the current key-list for each
/// and grant.
pub async fn share_add(
    v: &Vault,
    relay: &str,
    share: Uuid,
    member_codes: &[String],
) -> Result<(), EnrollError> {
    if !v.has_share(share) {
        return Err(EnrollError::Vault(VaultError::Corrupt(
            "you are not a member of this share".into(),
        )));
    }
    let key_list = v.share_key_list_for(share);
    let wrapped = wrap_for_codes(v, relay, &key_list, member_codes).await?;
    let req = crate::proto::ShareGrantReq {
        share_id_b64: B64.encode(share.as_bytes()),
        epoch: v.share_epoch_for(share),
        wrapped,
    };
    let client = sync::http_client();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("grant serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/share/grant"), &signed).await?;
    Ok(())
}

/// Remove a member from a share and rotate its key so the removed device can't
/// read data written afterward. Named-share rotation uses a fresh RANDOM key
/// (members lack the recovery seed), unlike the phrase-gated default share.
pub async fn share_remove(
    v: &mut Vault,
    relay: &str,
    share: Uuid,
    member_code: &str,
) -> Result<String, EnrollError> {
    if !v.has_share(share) {
        return Err(EnrollError::Vault(VaultError::Corrupt(
            "you are not a member of this share".into(),
        )));
    }
    let target = find_by_code(v, relay, member_code).await?;

    // Mint the new random epoch locally, then re-wrap for every remaining member.
    let epoch = v.rotate_share(share)?;
    let key_list = v.share_key_list_for(share);

    // Who are the remaining members? Ask the relay for current membership.
    let members = share_members(v, relay, share).await?;
    let mut wrapped = Vec::new();
    for ed_b64 in &members {
        if *ed_b64 == target.ed25519_pub_b64 {
            continue; // the one being removed
        }
        // Look the device up to get its X25519 key.
        let code = short_code(ed_b64);
        wrapped.extend(wrap_for_codes(v, relay, &key_list, std::slice::from_ref(&code)).await?);
    }
    let req = crate::proto::ShareRotateReq {
        share_id_b64: B64.encode(share.as_bytes()),
        epoch,
        wrapped,
        remove: vec![target.ed25519_pub_b64.clone()],
    };
    let client = sync::http_client();
    let signed = sync::sign(v, serde_json::to_string(&req).expect("share rotate serializes"));
    let _: crate::proto::PushResp =
        sync::post(&client, format!("{relay}/v1/share/rotate"), &signed).await?;
    Ok(target.name)
}

/// The Ed25519 pubs (base64) to re-wrap a rotated share for. Rotation UPDATEs
/// only existing members on the relay, so re-wrapping for every approved device
/// is safe — a wrap for a non-member updates zero rows. We therefore don't need
/// the exact member set here.
/// ponytail: re-wrap for all approved devices; tighten to exact membership only
/// if a per-share member-list endpoint is ever added.
async fn share_members(v: &Vault, relay: &str, _share: Uuid) -> Result<Vec<String>, EnrollError> {
    let devices = list_devices(v, relay).await?;
    Ok(devices
        .into_iter()
        .filter(|d| d.approved && !d.revoked)
        .map(|d| d.ed25519_pub_b64)
        .collect())
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
    let client = sync::http_client();
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
/// signs a fresh timestamp bound to the string `"<action>:<vault_b64>"`, matching
/// the relay's `SignedQuery`. The `ts` travels as a query param so the relay can
/// reconstruct the exact signed message and bound replay.
fn signed_get_url(v: &Vault, relay: &str, action: &str) -> String {
    let ts = crate::proto::now_unix();
    let vault_b64 = B64.encode(v.vault_id().as_bytes());
    let device_b64 = B64.encode(v.ed25519_pub());
    let body = format!("{action}:{vault_b64}");
    let sig = B64.encode(
        v.signing_key()
            .sign(crate::proto::signing_message(ts, &body).as_bytes())
            .to_bytes(),
    );
    format!(
        "{relay}/v1/{action}?vault={}&device={}&sig={}&ts={ts}",
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
