//! Client side of sync: enroll with a relay, push local entries, pull remote
//! ones. All requests are Ed25519-signed by the device key; the relay verifies
//! against the enrolled public key. The vault key never leaves the machine —
//! only sealed blobs cross the wire.

use crate::proto::{
    now_unix, signing_message, EnrollReq, EnrollResp, PullResp, PushReq, PushResp, Signed,
    WireEntry,
};
use crate::vault::{Vault, VaultError};
use base64::Engine;
use ed25519_dalek::Signer;
use std::collections::HashSet;

type B64 = base64::engine::general_purpose::GeneralPurpose;
pub(crate) const B64: B64 = base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("no relay configured — run `sshvault sync --relay <url>` once to set it")]
    NoRelay,
    #[error("relay request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("relay rejected the request ({status}): {body}")]
    Rejected { status: u16, body: String },
    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// Sign `body` with the device key and wrap it in a [`Signed`] envelope. The
/// signature covers a fresh timestamp bound to the body so the relay can bound
/// replay of the captured envelope.
pub(crate) fn sign(v: &Vault, body: String) -> Signed {
    let ts = now_unix();
    let sig = v.signing_key().sign(signing_message(ts, &body).as_bytes());
    Signed {
        vault_id_b64: B64.encode(v.vault_id().as_bytes()),
        device_pub_b64: B64.encode(v.ed25519_pub()),
        sig_b64: B64.encode(sig.to_bytes()),
        ts,
        body,
    }
}

pub(crate) async fn post<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: String,
    signed: &Signed,
) -> Result<T, SyncError> {
    let resp = client.post(url).json(signed).send().await?;
    parse(resp).await
}

pub(crate) async fn parse<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, SyncError> {
    let status = resp.status();
    if !status.is_success() {
        return Err(SyncError::Rejected {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        });
    }
    Ok(resp.json().await?)
}

/// Register this device with the relay. Returns whether it is already approved
/// (true only for the device that bootstrapped the vault).
pub async fn enroll(v: &Vault, relay: &str) -> Result<bool, SyncError> {
    let client = reqwest::Client::new();
    let req = EnrollReq {
        device_name: v.meta.device_name.clone(),
        ed25519_pub_b64: B64.encode(v.ed25519_pub()),
        x25519_pub_b64: v.meta.x25519_pub_b64.clone(),
        recovery_pub_b64: v.meta.recovery_pub_b64.clone(),
    };
    let signed = sign(v, serde_json::to_string(&req).expect("enroll serializes"));
    let resp: EnrollResp = post(&client, format!("{relay}/v1/enroll"), &signed).await?;
    Ok(resp.approved)
}

/// One full sync round: push everything the relay lacks, then pull everything we
/// lack and merge it. Returns `(pushed, pulled)` entry counts.
pub async fn sync_once(v: &mut Vault) -> Result<(usize, usize), SyncError> {
    let relay = v.relay_url().ok_or(SyncError::NoRelay)?.to_string();
    let client = reqwest::Client::new();

    // Push: send all local entries; the relay ignores ones it already has.
    let local = v.raw_entries()?;
    let entries: Vec<WireEntry> = local
        .iter()
        .map(|(id, blob)| WireEntry {
            entry_id_b64: B64.encode(id),
            blob_b64: B64.encode(blob),
        })
        .collect();
    let body = serde_json::to_string(&PushReq { entries }).expect("push serializes");
    let pushed: PushResp = post(&client, format!("{relay}/v1/push"), &sign(v, body)).await?;

    // Pull: everything past our cursor. Signed like the POST envelope — a fresh
    // timestamp bound to the body — so a captured pull URL can't be replayed
    // outside the relay's skew window.
    let since = v.sync_cursor();
    let ts = now_unix();
    let vault_b64 = B64.encode(v.vault_id().as_bytes());
    let device_b64 = B64.encode(v.ed25519_pub());
    let sig = B64.encode(
        v.signing_key()
            .sign(signing_message(ts, &format!("pull:{since}")).as_bytes())
            .to_bytes(),
    );
    let url = format!(
        "{relay}/v1/pull?vault={}&device={}&sig={}&since={since}&ts={ts}",
        urlencode(&vault_b64),
        urlencode(&device_b64),
        urlencode(&sig),
    );
    let resp: PullResp = parse(client.get(url).send().await?).await?;

    // Apply entries we don't already have locally.
    let have: HashSet<[u8; 16]> = local.iter().map(|(id, _)| *id).collect();
    let mut pulled = 0usize;
    for e in &resp.entries {
        let id: [u8; 16] = decode16(&e.entry_id_b64)?;
        if have.contains(&id) {
            continue;
        }
        let blob = B64.decode(&e.blob_b64).map_err(|_| bad("blob"))?;
        v.apply_remote_entry(&id, &blob)?;
        pulled += 1;
    }
    v.set_sync_cursor(resp.head)?;
    Ok((pushed.stored, pulled))
}

fn decode16(b64: &str) -> Result<[u8; 16], SyncError> {
    B64.decode(b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("entry_id"))
}

pub(crate) fn bad(what: &str) -> SyncError {
    SyncError::Vault(VaultError::Corrupt(format!("relay sent malformed {what}")))
}

/// Minimal percent-encoding for base64 in a query string (`+ / =`).
pub(crate) fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}
