//! Team-vault gate: named shares compartmentalize records. A share's entries
//! reach only its members — the relay filters non-members out of pull AND their
//! device key can't open the ciphertext. Removing a member rotates the share so
//! the removed device is blind to data written afterward. Default-share records
//! still reach everyone (backward compatibility).

use sshvault::record::{Host, Kind};
use tempfile::TempDir;

mod common;
use common::{drain, host, make_devices, start_relay};

fn hosts(v: &sshvault::vault::Vault) -> Vec<Host> {
    let mut h: Vec<Host> = v
        .list::<Host>(Kind::Host)
        .into_iter()
        .map(|(_, h)| h)
        .collect();
    h.sort_by(|a, b| a.alias.cmp(&b.alias));
    h
}

fn code(v: &sshvault::vault::Vault) -> String {
    sshvault::device::short_code(&v.meta.ed25519_pub_b64)
}

#[tokio::test]
async fn shares_compartmentalize_and_rotate_on_removal() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db.clone()).await;
    // dev0 (creator), dev1 (member), dev2 (outsider).
    let mut devs = make_devices(tmp.path(), 3, &relay).await;

    // A default-share host reaches everyone (backward-compat baseline).
    devs[0]
        .add(
            Kind::Host,
            "alias",
            "public",
            &host("public", "public.example", 22),
        )
        .unwrap();

    // dev0 creates a share with dev1 and puts a secret host in it.
    let dev1_code = code(&devs[1]);
    let share = sshvault::device::create_share(&mut devs[0], &relay, "ops", &[dev1_code])
        .await
        .unwrap();
    devs[0]
        .add_in(
            Kind::Host,
            "alias",
            "secret",
            &host("secret", "secret.internal", 22),
            share,
        )
        .unwrap();

    // Converge everyone (several interleaved rounds so grants + entries settle).
    for _ in 0..3 {
        for d in devs.iter_mut() {
            drain(d).await;
        }
    }

    // Everyone sees the public host.
    for d in &devs {
        assert!(
            hosts(d).iter().any(|h| h.alias == "public"),
            "default-share host reaches all devices"
        );
    }
    // dev0 and dev1 (members) see the secret; dev2 (outsider) does not.
    assert!(
        hosts(&devs[0]).iter().any(|h| h.alias == "secret"),
        "creator sees secret"
    );
    assert!(devs[1].has_share(share), "dev1 became a member");
    assert!(
        hosts(&devs[1]).iter().any(|h| h.alias == "secret"),
        "member dev1 reads the share"
    );
    assert!(!devs[2].has_share(share), "dev2 is not a member");
    assert!(
        !hosts(&devs[2]).iter().any(|h| h.alias == "secret"),
        "outsider dev2 cannot see the share host"
    );

    // Relay stores no plaintext.
    let raw = std::fs::read(&db).unwrap();
    for marker in ["secret.internal", "public.example", "secret", "public"] {
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "relay leaked plaintext marker {marker:?}"
        );
    }

    // Remove dev1 from the share + rotate. dev0 writes a NEW share host after.
    let dev1_code = code(&devs[1]);
    sshvault::device::share_remove(&mut devs[0], &relay, share, &dev1_code)
        .await
        .unwrap();
    devs[0]
        .add_in(
            Kind::Host,
            "alias",
            "secret2",
            &host("secret2", "postrotate.internal", 22),
            share,
        )
        .unwrap();
    for _ in 0..3 {
        for d in devs.iter_mut() {
            drain(d).await;
        }
    }

    // dev0 still reads both share hosts.
    let h0 = hosts(&devs[0]);
    assert!(
        h0.iter().any(|h| h.alias == "secret"),
        "creator keeps old share host"
    );
    assert!(
        h0.iter().any(|h| h.alias == "secret2"),
        "creator reads post-rotation host"
    );

    // dev1 was removed: it must NOT gain the post-rotation host. (It may still
    // hold the pre-rotation secret it already pulled — rotation is forward-only.)
    assert!(
        !hosts(&devs[1]).iter().any(|h| h.alias == "secret2"),
        "removed member cannot read data written after its removal"
    );
    // dev2 was never a member: still blind to everything in the share.
    assert!(!hosts(&devs[2]).iter().any(|h| h.alias == "secret2"));
    assert!(!hosts(&devs[2]).iter().any(|h| h.alias == "secret"));
}
