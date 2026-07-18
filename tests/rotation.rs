//! v0.2 gate: `device revoke --rotate` must give forward secrecy. After a
//! rotation, a remaining device reads new-epoch data (self-healing its key-list
//! over sync), while the revoked device is cut off AND the key material it still
//! holds cannot decrypt anything written under the new epoch.

use sshvault::crypto;
use sshvault::record::Kind;
use sshvault::vault::Vault;
use base64::Engine;
use ed25519_dalek::Signer;
use uuid::Uuid;
use tempfile::TempDir;

mod common;
use common::{drain, host, hosts_sorted, start_relay};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Bootstrap dev0 from a real recovery phrase, then create `extra` sibling
/// devices that share its epoch-0 vault key + vault id, enroll and approve them.
/// Returns (devices, phrase). Mirrors `make_devices` but keeps the phrase so the
/// vault can be rotated (rotation derives new epochs from the phrase seed).
async fn phrase_devices(root: &std::path::Path, extra: usize, relay: &str) -> (Vec<Vault>, String) {
    let keys = crypto::new_phrase();
    let phrase = keys.0;
    let pk = crypto::keys_from_phrase(&phrase).unwrap();
    let recovery_pub = pk.recovery_signing.verifying_key().to_bytes();
    let vault_id = Uuid::new_v4();

    let mut devices = Vec::new();
    // Epoch-0 key IS the phrase-derived key, so rotation stays self-consistent.
    let vk = pk.vault_key;
    for i in 0..=extra {
        let dir = root.join(format!("dev{i}"));
        let mut v =
            Vault::create(&dir, &format!("dev{i}"), "pw", vault_id, &vk, &recovery_pub).unwrap();
        v.set_relay_url(relay).unwrap();
        let approved = sshvault::sync::enroll(&v, relay).await.unwrap();
        assert_eq!(approved, i == 0, "only the bootstrapper is auto-approved");
        devices.push(v);
    }
    for i in 1..=extra {
        let code = sshvault::device::short_code(&devices[i].meta.ed25519_pub_b64);
        sshvault::device::approve(&devices[0], relay, &code)
            .await
            .unwrap();
    }
    (devices, phrase)
}

#[tokio::test]
async fn revoke_rotate_gives_forward_secrecy() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;
    // dev0 (holder), dev1 (stays), dev2 (to be revoked).
    let (mut devs, phrase) = phrase_devices(tmp.path(), 2, &relay).await;

    // Seed a pre-rotation record and converge everyone.
    devs[0]
        .add(Kind::Host, "alias", "web", &host("web", "web.example.com", 22))
        .unwrap();
    for _ in 0..2 {
        for d in devs.iter_mut() {
            drain(d).await;
        }
    }
    for d in &devs {
        assert_eq!(hosts_sorted(d).len(), 1, "everyone has the pre-rotation host");
    }
    assert_eq!(devs[0].epoch(), 0, "no rotation yet");

    // dev0 revokes dev2 AND rotates. dev2's code first.
    let dev2_code = sshvault::device::short_code(&devs[2].meta.ed25519_pub_b64);
    sshvault::device::revoke_and_rotate(&mut devs[0], &relay, &dev2_code, &phrase)
        .await
        .unwrap();
    assert_eq!(devs[0].epoch(), 1, "dev0 advanced to epoch 1");

    // dev0 writes a NEW record under the new epoch and pushes it.
    devs[0]
        .add(Kind::Host, "alias", "secret", &host("secret", "post.rotation", 22))
        .unwrap();
    drain(&mut devs[0]).await;

    // dev1 (remaining) syncs: heal_epoch pulls its re-wrapped key-list, so it
    // both advances its epoch and can decrypt the new-epoch record.
    drain(&mut devs[1]).await;
    assert_eq!(devs[1].epoch(), 1, "dev1 self-healed to the new epoch");
    assert!(
        hosts_sorted(&devs[1]).iter().any(|h| h.alias == "secret"),
        "dev1 reads the post-rotation record"
    );

    // dev2 (revoked) is cut off at the relay — every sync now errors.
    let cut_off = sshvault::sync::sync_once(&mut devs[2]).await.is_err();
    assert!(cut_off, "revoked device can no longer sync");

    // Forward-secrecy core: the key material dev2 still holds is epoch 0 only.
    // Re-encrypt the post-rotation plaintext under the epoch-0 key and confirm
    // dev2's key cannot be what protects new writes — i.e. the new record's blob
    // on the relay does NOT open under epoch-0's key.
    let e0 = crypto::vault_key_at_epoch(&phrase, 0).unwrap();
    let e1 = crypto::vault_key_at_epoch(&phrase, 1).unwrap();
    assert_ne!(e0.as_ref(), e1.as_ref(), "epochs differ");

    // Pull the raw blobs dev0 pushed and prove the newest one opens under e1, not e0.
    let raw = devs[0].raw_entries().unwrap();
    let (id, blob) = raw.last().unwrap();
    assert!(
        crypto::open(&e0, blob, id).is_err(),
        "post-rotation entry must NOT decrypt under the revoked device's epoch-0 key"
    );
    assert!(
        crypto::open(&e1, blob, id).is_ok(),
        "post-rotation entry decrypts under the new epoch key"
    );
}

/// The seen-signature cache must make `/v1/rotate` non-replayable: a captured,
/// still-fresh rotate envelope replayed verbatim is rejected as a duplicate,
/// even though its signature and timestamp are perfectly valid. This is the
/// precondition the team-vault (non-idempotent) endpoints will depend on.
#[tokio::test]
async fn rotate_signature_cannot_be_replayed() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;
    let (mut devs, phrase) = phrase_devices(tmp.path(), 1, &relay).await;

    // Build a real rotate call by hand so we can capture and resend its envelope.
    let epoch = devs[0].rotate(&phrase).unwrap();
    let key_list = devs[0].vault_key_list();
    // Re-wrap for dev1 (the only remaining device besides dev0).
    let d1_x: [u8; 32] = B64
        .decode(&devs[1].meta.x25519_pub_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let d1_ed: [u8; 32] = B64
        .decode(&devs[1].meta.ed25519_pub_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let d0_x: [u8; 32] = B64
        .decode(&devs[0].meta.x25519_pub_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let d0_ed: [u8; 32] = B64
        .decode(&devs[0].meta.ed25519_pub_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let wrapped = vec![
        sshvault::proto::WrappedFor {
            device_pub_b64: devs[0].meta.ed25519_pub_b64.clone(),
            wrapped_key_b64: B64.encode(crypto::wrap_vault_key(
                &key_list,
                &x25519_dalek::PublicKey::from(d0_x),
                &d0_ed,
            )),
        },
        sshvault::proto::WrappedFor {
            device_pub_b64: devs[1].meta.ed25519_pub_b64.clone(),
            wrapped_key_b64: B64.encode(crypto::wrap_vault_key(
                &key_list,
                &x25519_dalek::PublicKey::from(d1_x),
                &d1_ed,
            )),
        },
    ];
    let body = serde_json::to_string(&sshvault::proto::RotateReq { epoch, wrapped }).unwrap();
    let ts = sshvault::proto::now_unix();
    let sig = devs[0]
        .signing_key()
        .sign(sshvault::proto::signing_message(ts, &body).as_bytes());
    let signed = sshvault::proto::Signed {
        vault_id_b64: B64.encode(devs[0].vault_id().as_bytes()),
        device_pub_b64: B64.encode(devs[0].ed25519_pub()),
        sig_b64: B64.encode(sig.to_bytes()),
        ts,
        body,
    };

    let client = reqwest::Client::new();
    let first = client
        .post(format!("{relay}/v1/rotate"))
        .json(&signed)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(first, reqwest::StatusCode::OK, "first rotate accepted");

    // Replay the exact same envelope: fresh ts, valid sig — but seen before.
    let replay = client
        .post(format!("{relay}/v1/rotate"))
        .json(&signed)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        replay,
        reqwest::StatusCode::CONFLICT,
        "a replayed rotate signature must be rejected by the seen-sig cache"
    );
}
