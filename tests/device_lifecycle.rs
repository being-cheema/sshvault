//! Phase 4 gate: device lifecycle end to end.
//! - a joining device with NO vault key gets it via the approve→wrap→unwrap
//!   handshake and can then sync;
//! - a revoked device's next sync is rejected;
//! - recovery from the 24-word phrase restores the full vault on a fresh machine.

use sshvault::record::Kind;
use sshvault::sync::SyncError;
use sshvault::vault::Vault;
use std::time::Duration;
use tempfile::TempDir;

mod common;
use common::{drain, host, hosts_sorted, start_relay};

/// Poll the relay (as `approver`) until a pending device shows up, approve it,
/// and return its short code.
async fn approve_first_pending(approver: &Vault, relay: &str) -> String {
    for _ in 0..100 {
        let devices = sshvault::device::list_devices(approver, relay)
            .await
            .unwrap();
        if let Some(p) = devices.iter().find(|d| !d.approved && !d.revoked) {
            let code = sshvault::device::short_code(&p.ed25519_pub_b64);
            sshvault::device::approve(approver, relay, &code)
                .await
                .unwrap();
            return code;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no pending device appeared");
}

#[tokio::test]
async fn enroll_handshake_then_revoke() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;

    // dev0 bootstraps the vault and seeds a host.
    let (mut v0, _phrase) = Vault::init(&tmp.path().join("dev0"), "dev0", "pw").unwrap();
    v0.set_relay_url(&relay).unwrap();
    assert!(
        sshvault::sync::enroll(&v0, &relay).await.unwrap(),
        "bootstrapper is auto-approved"
    );
    v0.add(
        Kind::Host,
        "alias",
        "web",
        &host("web", "web.example.com", 22),
    )
    .unwrap();
    drain(&mut v0).await;

    // dev1 joins with NO vault key: enroll_and_wait blocks until approved and the
    // wrapped key arrives. Run it concurrently with dev0's approval.
    let vault_id = v0.vault_id();
    let dir1 = tmp.path().join("dev1");
    let relay1 = relay.clone();
    let joining = tokio::spawn(async move {
        sshvault::device::enroll_and_wait(&dir1, "dev1", "pw", vault_id, &relay1, |_| {})
            .await
            .unwrap()
    });
    let code1 = approve_first_pending(&v0, &relay).await;
    let mut v1 = joining.await.unwrap();

    // The handshake delivered the real vault key: dev1 can decrypt dev0's data.
    drain(&mut v1).await;
    let hosts = hosts_sorted(&v1);
    assert_eq!(hosts.len(), 1, "dev1 pulled the seeded host");
    assert_eq!(hosts[0].hostname.as_deref(), Some("web.example.com"));

    // dev1 makes and pushes a change; dev0 sees it (proves two-way sync works).
    v1.add(Kind::Host, "alias", "db", &host("db", "db.internal", 5432))
        .unwrap();
    drain(&mut v1).await;
    drain(&mut v0).await;
    assert_eq!(hosts_sorted(&v0).len(), 2, "dev0 received dev1's host");

    // Revoke dev1. Its very next sync must be rejected by the relay.
    sshvault::device::revoke(&v0, &relay, &code1).await.unwrap();
    let err = sshvault::sync::sync_once(&mut v1).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Rejected { status: 403, .. }),
        "revoked device sync must be forbidden, got {err:?}"
    );

    // And it cannot re-enroll its way back in.
    let err = sshvault::sync::enroll(&v1, &relay).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Rejected { status: 403, .. }),
        "revoked device re-enroll must be forbidden, got {err:?}"
    );
}

#[tokio::test]
async fn recover_from_phrase_restores_vault() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;

    // Bootstrap a vault with real data and keep its recovery phrase.
    let (mut v0, phrase) = Vault::init(&tmp.path().join("dev0"), "dev0", "pw").unwrap();
    v0.set_relay_url(&relay).unwrap();
    sshvault::sync::enroll(&v0, &relay).await.unwrap();
    v0.add(
        Kind::Host,
        "alias",
        "web",
        &host("web", "web.example.com", 22),
    )
    .unwrap();
    v0.add(Kind::Host, "alias", "db", &host("db", "db.internal", 5432))
        .unwrap();
    drain(&mut v0).await;

    // Fresh machine: only the phrase + relay URL. No prior device, no vault key.
    let dir_r = tmp.path().join("recovered");
    let mut vr = sshvault::device::recover(&dir_r, "recovered", "pw2", phrase.trim(), &relay)
        .await
        .unwrap();
    assert_eq!(vr.vault_id(), v0.vault_id(), "recovered the same vault");
    drain(&mut vr).await;

    let recovered = hosts_sorted(&vr);
    let original = hosts_sorted(&v0);
    assert_eq!(recovered, original, "recovery restored the full vault");
    assert_eq!(recovered.len(), 2);
}

#[tokio::test]
async fn recover_rejects_wrong_phrase() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;

    let (mut v0, _phrase) = Vault::init(&tmp.path().join("dev0"), "dev0", "pw").unwrap();
    v0.set_relay_url(&relay).unwrap();
    sshvault::sync::enroll(&v0, &relay).await.unwrap();

    // A different, valid phrase must not unlock this vault.
    let (wrong_phrase, _) = sshvault::crypto::new_phrase();
    let result = sshvault::device::recover(
        &tmp.path().join("nope"),
        "attacker",
        "pw",
        &wrong_phrase,
        &relay,
    )
    .await;
    // Vault isn't Debug, so inspect the error arm directly instead of unwrap_err.
    let err = match result {
        Ok(_) => panic!("recovery with an unknown phrase must not succeed"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err,
            sshvault::device::EnrollError::Sync(SyncError::Rejected { status: 404, .. })
        ),
        "unknown recovery phrase must be rejected, got {err:?}"
    );
}
