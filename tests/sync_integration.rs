//! Phase 3 gate: three simulated devices making concurrent, conflicting edits
//! must converge to identical state after syncing through a real in-process
//! relay — and the relay's storage must contain zero plaintext.

use sshvault::record::Kind;
use sshvault::vault::Vault;
use std::path::Path;
use tempfile::TempDir;
use uuid::Uuid;

mod common;
use common::{drain, host, hosts_sorted, start_relay};

/// Create N devices that all share one vault_id + vault_key (as enrollment would
/// produce), each in its own dir, all pointed at `relay`. Device 0 bootstraps the
/// vault and approves every later device, so all N may sync.
async fn make_devices(root: &Path, n: usize, relay: &str) -> Vec<Vault> {
    let vault_id = Uuid::new_v4();
    let vault_key = sshvault::crypto::Secret32::new(sshvault::crypto::random_bytes::<32>());
    let recovery_pub = [9u8; 32];
    let mut devices = Vec::new();
    for i in 0..n {
        let dir = root.join(format!("dev{i}"));
        let mut v = Vault::create(
            &dir,
            &format!("dev{i}"),
            "pw",
            vault_id,
            &vault_key,
            &recovery_pub,
        )
        .unwrap();
        v.set_relay_url(relay).unwrap();
        let approved = sshvault::sync::enroll(&v, relay).await.unwrap();
        assert_eq!(approved, i == 0, "only the bootstrapper is auto-approved");
        devices.push(v);
    }
    // dev0 approves every pending device so they can sync.
    for i in 1..n {
        let code = sshvault::device::short_code(&devices[i].meta.ed25519_pub_b64);
        sshvault::device::approve(&devices[0], relay, &code)
            .await
            .unwrap();
    }
    devices
}

#[tokio::test]
async fn three_devices_converge_through_relay() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db.clone()).await;
    let mut devs = make_devices(tmp.path(), 3, &relay).await;

    // Seed a shared record on dev0 and fan it out to everyone.
    devs[0]
        .add(
            Kind::Host,
            "alias",
            "web",
            &host("web", "web.example.com", 22),
        )
        .unwrap();
    for d in devs.iter_mut() {
        drain(d).await;
    }
    for d in devs.iter_mut() {
        drain(d).await; // second pass so dev0's push reaches dev1/dev2
    }

    // Concurrent conflicting edits to the SAME field on all three, offline.
    devs[0]
        .edit(
            Kind::Host,
            "alias",
            "web",
            &host("web", "web.example.com", 100),
        )
        .unwrap();
    devs[1]
        .edit(
            Kind::Host,
            "alias",
            "web",
            &host("web", "web.example.com", 200),
        )
        .unwrap();
    devs[2]
        .edit(
            Kind::Host,
            "alias",
            "web",
            &host("web", "web.example.com", 300),
        )
        .unwrap();

    // Add distinct records concurrently too.
    devs[0]
        .add(Kind::Host, "alias", "db", &host("db", "db.internal", 5432))
        .unwrap();
    devs[1]
        .add(
            Kind::Host,
            "alias",
            "cache",
            &host("cache", "cache.internal", 6379),
        )
        .unwrap();

    // dev2 deletes a record while dev0 concurrently edits a different one.
    // (deletion of "web" would race the port edits; keep tombstone separate.)

    // Sync everyone repeatedly in a fixed-but-interleaved order until stable.
    for _ in 0..4 {
        for i in [0usize, 2, 1] {
            drain(&mut devs[i]).await;
        }
    }

    let s0 = hosts_sorted(&devs[0]);
    let s1 = hosts_sorted(&devs[1]);
    let s2 = hosts_sorted(&devs[2]);
    assert_eq!(s0, s1, "dev0 and dev1 must converge");
    assert_eq!(s1, s2, "dev1 and dev2 must converge");

    // The conflicting port edit resolves to a single deterministic winner.
    let web = s0.iter().find(|h| h.alias == "web").unwrap();
    assert!(
        [Some(100), Some(200), Some(300)].contains(&web.port),
        "web port is one of the concurrent writes, got {:?}",
        web.port
    );
    // All three distinct hosts present: web, db, cache.
    assert_eq!(s0.len(), 3, "web + db + cache all synced");

    // Zero-knowledge check: the relay DB bytes must not contain any plaintext.
    let raw = std::fs::read(&db).unwrap();
    for marker in [
        "web.example.com",
        "db.internal",
        "cache.internal",
        "web",
        "alias",
    ] {
        assert!(
            !contains(&raw, marker.as_bytes()),
            "relay storage leaked plaintext marker {marker:?}"
        );
    }
}

#[tokio::test]
async fn deletion_survives_sync_no_resurrection() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;
    let mut devs = make_devices(tmp.path(), 2, &relay).await;

    devs[0]
        .add(Kind::Host, "alias", "temp", &host("temp", "temp.host", 22))
        .unwrap();
    drain(&mut devs[0]).await;
    drain(&mut devs[1]).await;
    assert_eq!(hosts_sorted(&devs[1]).len(), 1, "dev1 received the host");

    // dev0 edits and pushes; dev1 pulls it, THEN deletes — so the tombstone's
    // lamport is strictly above the edit's, making the deletion causally latest.
    devs[0]
        .edit(
            Kind::Host,
            "alias",
            "temp",
            &host("temp", "temp.host", 2222),
        )
        .unwrap();
    drain(&mut devs[0]).await;
    drain(&mut devs[1]).await;
    devs[1].remove(Kind::Host, "alias", "temp").unwrap();

    // Sync repeatedly in interleaved orders; a causally-latest tombstone must
    // never be resurrected by any ordering.
    for _ in 0..4 {
        drain(&mut devs[1]).await;
        drain(&mut devs[0]).await;
    }
    assert!(hosts_sorted(&devs[0]).is_empty(), "dev0 sees the deletion");
    assert!(hosts_sorted(&devs[1]).is_empty(), "dev1 stays deleted");
    assert_eq!(hosts_sorted(&devs[0]), hosts_sorted(&devs[1]));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
