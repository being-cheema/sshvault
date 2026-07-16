//! Replay-window gate: the relay binds a timestamp into every device signature
//! and rejects requests whose `ts` falls outside ±`MAX_SKEW_SECS`. This proves
//! the control documented in `docs/crypto-design.md` ("Relay request auth") is
//! actually enforced, not just asserted.

use base64::Engine;
use ed25519_dalek::Signer;
use sshvault::proto::{now_unix, signing_message, PushReq, Signed, WireEntry, MAX_SKEW_SECS};
use sshvault::vault::Vault;
use tempfile::TempDir;

mod common;
use common::start_relay;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Hand-build a signed `/v1/push` envelope for `v` at timestamp `ts`, correctly
/// signed over `signing_message(ts, body)` — so the ONLY thing a rejection can be
/// testing is the freshness window, not a broken signature.
fn signed_push_at(v: &Vault, ts: i64) -> Signed {
    let body = serde_json::to_string(&PushReq {
        entries: Vec::<WireEntry>::new(),
    })
    .unwrap();
    let sig = v.signing_key().sign(signing_message(ts, &body).as_bytes());
    Signed {
        vault_id_b64: B64.encode(v.vault_id().as_bytes()),
        device_pub_b64: B64.encode(v.ed25519_pub()),
        sig_b64: B64.encode(sig.to_bytes()),
        ts,
        body,
    }
}

async fn post_push(client: &reqwest::Client, relay: &str, signed: &Signed) -> reqwest::StatusCode {
    client
        .post(format!("{relay}/v1/push"))
        .json(signed)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn stale_timestamp_is_rejected_but_fresh_is_accepted() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;
    let client = reqwest::Client::new();

    // Bootstrap + enroll so the device is approved and may push.
    let (mut v, _phrase) = Vault::init(&tmp.path().join("dev0"), "dev0", "pw").unwrap();
    v.set_relay_url(&relay).unwrap();
    assert!(sshvault::sync::enroll(&v, &relay).await.unwrap());

    // Control: a fresh, correctly-signed push is accepted.
    let fresh = signed_push_at(&v, now_unix());
    assert_eq!(
        post_push(&client, &relay, &fresh).await,
        reqwest::StatusCode::OK,
        "a fresh signed request must be accepted"
    );

    // A signature captured and replayed after the window closes is rejected —
    // even though the signature itself is perfectly valid for its (stale) ts.
    let stale = signed_push_at(&v, now_unix() - (MAX_SKEW_SECS + 60));
    assert_eq!(
        post_push(&client, &relay, &stale).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "a request older than the skew window must be rejected"
    );

    // A far-future timestamp (clock-skew forgery attempt) is rejected too.
    let future = signed_push_at(&v, now_unix() + (MAX_SKEW_SECS + 60));
    assert_eq!(
        post_push(&client, &relay, &future).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "a request too far in the future must be rejected"
    );

    // Tamper check: keep a fresh ts but sign a DIFFERENT ts — the bound-timestamp
    // signature must fail, proving ts is inside the signed message (not just a
    // side channel the relay range-checks and then ignores).
    let mut forged = signed_push_at(&v, now_unix() - 1000);
    forged.ts = now_unix(); // fresh ts, but signature covers the old one
    assert_eq!(
        post_push(&client, &relay, &forged).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "moving ts without re-signing must fail signature verification"
    );
}
