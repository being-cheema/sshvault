//! Client side of sync: enroll with a relay, push local entries, pull remote
//! ones. All requests are Ed25519-signed by the device key; the relay verifies
//! against the enrolled public key. The vault key never leaves the machine —
//! only sealed blobs cross the wire.

use crate::proto::{
    now_unix, signing_message, EnrollReq, EnrollResp, PullResp, PushReq, PushResp, Signed,
    WireEntry, WrappedResp,
};
use crate::vault::{Vault, VaultError};
use base64::Engine;
use ed25519_dalek::Signer;
use std::collections::HashSet;

type B64 = base64::engine::general_purpose::GeneralPurpose;
pub(crate) const B64: B64 = base64::engine::general_purpose::STANDARD;

/// Shared HTTP client with bounded timeouts. Without these a relay that accepts
/// the TCP connection but never responds (black-holed by a firewall, or hung)
/// would wedge a sync round — and the `syncd` daemon — indefinitely.
pub(crate) fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client builds from static config")
}

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
    let client = http_client();
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

/// One full sync round: heal a missed rotation, push everything the relay lacks,
/// then pull everything we lack and merge it. Returns `(pushed, pulled)` counts.
pub async fn sync_once(v: &mut Vault) -> Result<(usize, usize), SyncError> {
    let relay = v.relay_url().ok_or(SyncError::NoRelay)?.to_string();
    let client = http_client();

    // Heal first: if the vault rotated while we were away, our key-list is stale
    // Heal first: pull any share keys we're missing (new grants, rotations) so
    // freshly-authorized entries decrypt this round; also heals default-share
    // rotation. Returns whether membership changed (→ rewind cursor to re-pull).
    let membership_changed = heal_shares(&client, v, &relay).await?;

    // Push: send all local entries (tagged with their share) — the relay ignores
    // ones it already has and routes each by share for membership filtering.
    let local = v.raw_entries_tagged()?;
    let entries: Vec<WireEntry> = local
        .iter()
        .map(|(id, blob, share)| WireEntry {
            entry_id_b64: B64.encode(id),
            blob_b64: B64.encode(blob),
            share_id_b64: B64.encode(share.as_bytes()),
        })
        .collect();
    let body = serde_json::to_string(&PushReq { entries }).expect("push serializes");
    let pushed: PushResp = post(&client, format!("{relay}/v1/push"), &sign(v, body)).await?;

    // Pull: everything past our cursor. Signed like the POST envelope — a fresh
    // timestamp bound to the body — so a captured pull URL can't be replayed
    // outside the relay's skew window. A membership change rewinds the cursor to
    // 0 so entries we skipped as a non-member get re-fetched now that we're in.
    if membership_changed {
        v.reset_sync_cursor()?;
    }
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
    let have: HashSet<[u8; 16]> = local.iter().map(|(id, _, _)| *id).collect();
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

/// If the relay's epoch is ahead of ours, a rotation happened while this device
/// was away and its key-list is stale. Fetch the re-wrapped list from the signed
/// `/v1/wrapped` endpoint and absorb it so subsequent pulls of new-epoch entries
/// decrypt. A no-op when already current (the common case), costing one GET.
/// Heal any key material this device is missing before it pulls: the default
/// share's rotated epoch (via `/v1/wrapped`) and every named share it now belongs
/// to (via `/v1/shares`). Returns `true` if the device *gained* a share it didn't
/// hold before — the caller rewinds the pull cursor so previously-filtered
/// entries get re-fetched. A no-op in the common already-current case.
async fn heal_shares(
    client: &reqwest::Client,
    v: &mut Vault,
    relay: &str,
) -> Result<bool, SyncError> {
    let mut gained = false;

    // Default share: rotation appends epochs; fetch our re-wrapped list if stale.
    let resp: WrappedResp = signed_get(client, v, relay, "wrapped").await?;
    if resp.epoch > v.epoch() {
        if let Some(wrapped_b64) = resp.wrapped_key_b64 {
            let list = unwrap_for(v, &wrapped_b64)?;
            v.absorb_vault_key_list(&list)?;
        }
    }

    // Named shares: any share we have a membership row for. New membership (a
    // grant) means we must re-pull entries we previously skipped.
    let resp: crate::proto::SharesResp = signed_get(client, v, relay, "shares").await?;
    for m in &resp.shares {
        let share = match B64
            .decode(&m.share_id_b64)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        {
            Some(b) => uuid::Uuid::from_bytes(b),
            None => continue,
        };
        if share.is_nil() {
            continue; // default share handled above
        }
        let had = v.has_share(share);
        // Absorb if we lack the share entirely, or it rotated past what we hold.
        if !had || m.epoch > v.share_epoch_for(share) {
            let list = unwrap_for(v, &m.wrapped_key_b64)?;
            v.absorb_share_key(share, &list)?;
            if !had {
                gained = true;
            }
        }
    }
    Ok(gained)
}

/// Unwrap a base64 wrapped key-list addressed to this device.
fn unwrap_for(v: &Vault, wrapped_b64: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, SyncError> {
    let wrapped = B64.decode(wrapped_b64).map_err(|_| bad("wrapped_key"))?;
    crate::crypto::unwrap_vault_key(&v.x25519_secret(), &wrapped, &v.ed25519_pub())
        .map_err(|e| SyncError::Vault(VaultError::from(e)))
}

/// Issue a signed GET to `/v1/<action>` (body `"<action>:<vault_b64>"`) and parse
/// the JSON response — the shared shape behind `/v1/wrapped` and `/v1/shares`.
async fn signed_get<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    v: &Vault,
    relay: &str,
    action: &str,
) -> Result<T, SyncError> {
    let ts = now_unix();
    let vault_b64 = B64.encode(v.vault_id().as_bytes());
    let device_b64 = B64.encode(v.ed25519_pub());
    let body = format!("{action}:{vault_b64}");
    let sig = B64.encode(
        v.signing_key()
            .sign(signing_message(ts, &body).as_bytes())
            .to_bytes(),
    );
    let url = format!(
        "{relay}/v1/{action}?vault={}&device={}&sig={}&ts={ts}",
        urlencode(&vault_b64),
        urlencode(&device_b64),
        urlencode(&sig),
    );
    parse(client.get(url).send().await?).await
}

/// How often the daemon runs a round even without a relay notification. This is
/// what pushes entries that *other* local sshvault processes appended (the relay
/// only announces remote pushes) and heals any missed WS notification.
const SYNCD_POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// Resolve the fallback poll interval. Normally [`SYNCD_POLL`], but overridable
/// via `SSHVAULT_SYNCD_POLL_SECS` — an advanced operational knob that also lets
/// the daemon test push the fallback far out, so that any convergence it
/// observes can only have come from a WS notification, not the tick.
fn syncd_poll() -> std::time::Duration {
    std::env::var("SSHVAULT_SYNCD_POLL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(SYNCD_POLL)
}

/// A WebSocket must stay up at least this long to count as a healthy connection
/// and reset the reconnect backoff. Shorter-lived connections keep the backoff
/// climbing so a flapping relay is retried with increasing delay, not hammered.
const HEALTHY_CONN: std::time::Duration = std::time::Duration::from_secs(30);

/// Run sync continuously (`sshvault syncd`): an immediate round, then a round
/// whenever the relay announces a new head over its `/v1/ws` WebSocket, with the
/// [`syncd_poll`] tick as fallback and capped-exponential reconnect backoff.
/// `on_round` fires after every successful round with `(vault, pushed, pulled)`.
///
/// Transient failures (relay unreachable, 5xx) are retried forever; fatal ones
/// (local storage errors, or the relay actively refusing us — e.g. this device
/// was revoked) return. Runs until the caller drops/aborts the future.
pub async fn syncd(
    v: &mut Vault,
    mut on_round: impl FnMut(&Vault, usize, usize),
) -> Result<(), SyncError> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let relay = v.relay_url().ok_or(SyncError::NoRelay)?.to_string();
    // http(s):// → ws(s)://; the notify endpoint is unauthenticated by design
    // (it leaks only "something changed") — the pull that follows is signed.
    let ws_url = format!(
        "{}/v1/ws?vault={}",
        relay.replacen("http", "ws", 1),
        urlencode(&B64.encode(v.vault_id().as_bytes())),
    );

    let mut backoff_secs = 1u64;
    loop {
        round(v, &mut on_round).await?;
        let connected_at = tokio::time::Instant::now();
        let mut ws = match tokio_tungstenite::connect_async(ws_url.as_str()).await {
            Ok((ws, _)) => ws,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }
        };
        let mut tick = tokio::time::interval(syncd_poll());
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // interval yields immediately once; skip that
        loop {
            tokio::select! {
                msg = ws.next() => match msg {
                    // the relay broadcasts its new head; skip echoes of our own push
                    Some(Ok(Message::Text(head))) => {
                        let stale = match head.as_str().trim().parse::<u64>() {
                            Ok(h) => h > v.sync_cursor(),
                            Err(_) => true, // unrecognized message — resync defensively
                        };
                        if stale {
                            round(v, &mut on_round).await?;
                        }
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {} // ping/pong — tungstenite answers pings itself
                },
                _ = tick.tick() => round(v, &mut on_round).await?,
            }
        }
        // Socket dropped — reconnect, resyncing in case a notify was missed.
        // Only clear the backoff if this connection actually held for a while;
        // a relay that accepts the handshake then immediately drops us (crash
        // loop, or refusing this vault at the WS layer) must not reset us into a
        // tight reconnect spin — it should keep climbing toward the 60s cap.
        if connected_at.elapsed() >= HEALTHY_CONN {
            backoff_secs = 1;
        } else {
            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(60);
        }
    }
}

/// One daemon round: reload local state from disk (another sshvault process may
/// have appended), then push/pull. Transient errors are swallowed — the daemon
/// loop retries; fatal ones bubble.
async fn round(
    v: &mut Vault,
    on_round: &mut impl FnMut(&Vault, usize, usize),
) -> Result<(), SyncError> {
    v.reload()?;
    match sync_once(v).await {
        Ok((pushed, pulled)) => {
            on_round(v, pushed, pulled);
            Ok(())
        }
        Err(e) if transient(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Worth retrying (relay down / server error) vs. fatal (local storage broke,
/// or the relay actively refused us — bad auth, revoked device).
fn transient(e: &SyncError) -> bool {
    match e {
        SyncError::Http(_) => true,
        SyncError::Rejected { status, .. } => *status >= 500,
        SyncError::NoRelay | SyncError::Vault(_) => false,
    }
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
