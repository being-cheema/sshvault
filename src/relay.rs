//! The relay: a zero-knowledge, append-only blob store per vault.
//!
//! The relay authenticates devices by Ed25519 signature and stores opaque
//! sealed entries. It has no vault key and no decryption path — a full server
//! compromise leaks only blob sizes, timestamps, and which device pushed what.
//!
//! Storage (SQLite via sqlx):
//! - `vaults(vault_id, recovery_pub)`                             — bootstrap + recovery
//! - `devices(vault_id, ed25519_pub, x25519_pub, name, approved, revoked, wrapped_key)`
//! - `entries(vault_id, seq, entry_id, blob)`                     — the opaque log
//!
//! `seq` is a per-relay monotonic cursor; clients pull everything with
//! `seq > their_cursor`. Convergence is the client's merge engine's job.
//!
//! Device lifecycle: the first device to enroll a vault bootstraps it and is
//! auto-approved; later devices are pending until an approved device approves
//! them (handing over the vault key wrapped for their X25519 key). Only
//! approved, non-revoked devices may push/pull. Revocation is sticky — a
//! revoked device cannot re-enroll its way back in.

use crate::proto::{
    now_unix, signing_message, ApproveReq, DeviceInfo, DevicesResp, EnrollReq, EnrollResp,
    PullResp, PushReq, PushResp, RecoverReq, RecoverResp, RevokeReq, RotateReq, ShareGrantReq,
    ShareMembership, ShareRotateReq, SharesResp, Signed, WireEntry, WrappedResp, MAX_SKEW_SECS,
};
use axum::{
    extract::{ws::WebSocketUpgrade, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;

type B64 = base64::engine::general_purpose::GeneralPurpose;
const B64: B64 = base64::engine::general_purpose::STANDARD;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    /// vault_id_b64 → broadcaster of the new head, for WS change notifications.
    notify:
        std::sync::Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::broadcast::Sender<u64>>>>,
}

/// Run the relay on `addr`, storing everything in the SQLite file at `db_path`.
pub async fn serve(addr: &str, db_path: &str) -> anyhow::Result<()> {
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true);
    let db = SqlitePoolOptions::new().connect_with(opts).await?;
    migrate(&db).await?;
    let state = AppState {
        db,
        notify: Default::default(),
    };
    let app = Router::new()
        .route("/v1/enroll", post(enroll))
        .route("/v1/approve", post(approve))
        .route("/v1/revoke", post(revoke))
        .route("/v1/rotate", post(rotate))
        .route("/v1/share/grant", post(share_grant))
        .route("/v1/share/rotate", post(share_rotate))
        .route("/v1/shares", get(shares))
        .route("/v1/devices", get(devices))
        .route("/v1/wrapped", get(wrapped))
        .route("/v1/recover", post(recover))
        .route("/v1/push", post(push))
        .route("/v1/pull", get(pull))
        .route("/v1/ws", get(ws))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("sshvault relay listening on {addr}, db {db_path}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn migrate(db: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS vaults (
            vault_id      TEXT PRIMARY KEY,
            recovery_pub  BLOB NOT NULL,
            epoch         INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(db)
    .await?;
    // Older relays predate the epoch column; add it if missing (ignore if not).
    let _ = sqlx::query("ALTER TABLE vaults ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0")
        .execute(db)
        .await;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS devices (
            vault_id     TEXT NOT NULL,
            ed25519_pub  BLOB NOT NULL,
            x25519_pub   BLOB NOT NULL,
            name         TEXT NOT NULL,
            approved     INTEGER NOT NULL DEFAULT 0,
            revoked      INTEGER NOT NULL DEFAULT 0,
            wrapped_key  BLOB,
            PRIMARY KEY (vault_id, ed25519_pub)
        )",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS entries (
            vault_id  TEXT NOT NULL,
            seq       INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id  BLOB NOT NULL,
            blob      BLOB NOT NULL,
            share_id  BLOB NOT NULL DEFAULT x'00000000000000000000000000000000',
            UNIQUE (vault_id, entry_id)
        )",
    )
    .execute(db)
    .await?;
    // Older relays predate share_id; add it (nil default = the default share).
    let _ = sqlx::query(
        "ALTER TABLE entries ADD COLUMN share_id BLOB NOT NULL \
         DEFAULT x'00000000000000000000000000000000'",
    )
    .execute(db)
    .await;
    // Per-share epoch counter (named shares only; the default share's epoch lives
    // in vaults.epoch). Absence of a row means epoch 0.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS shares (
            vault_id  TEXT NOT NULL,
            share_id  BLOB NOT NULL,
            epoch     INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (vault_id, share_id)
        )",
    )
    .execute(db)
    .await?;
    // Share membership + each member's wrapped key-list. A device may pull a
    // share's entries iff it has a row here (or the share is nil).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS share_members (
            vault_id     TEXT NOT NULL,
            share_id     BLOB NOT NULL,
            ed25519_pub  BLOB NOT NULL,
            wrapped_key  BLOB NOT NULL,
            PRIMARY KEY (vault_id, share_id, ed25519_pub)
        )",
    )
    .execute(db)
    .await?;
    // Replay cache for non-idempotent authenticated endpoints (rotate; future
    // team-vault mutations). Keyed on the raw 64-byte signature; rows expire
    // after the skew window. Persisted so a relay restart doesn't reopen the
    // replay window. ponytail: lazy GC on insert, add a timer only if it grows.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS seen_sigs (
            sig         BLOB PRIMARY KEY,
            expires_at  INTEGER NOT NULL
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Record a signature as seen, returning `false` if it was already present (a
/// replay). Opportunistically evicts expired rows. Only called on the
/// non-idempotent endpoints — idempotent ones don't need it (see crypto-design).
async fn mark_seen(db: &SqlitePool, sig_b64: &str) -> Result<bool, (StatusCode, String)> {
    let sig = B64
        .decode(sig_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "sig".to_string()))?;
    let now = now_unix();
    sqlx::query("DELETE FROM seen_sigs WHERE expires_at < ?")
        .bind(now)
        .execute(db)
        .await
        .map_err(db_err)?;
    let inserted = sqlx::query("INSERT OR IGNORE INTO seen_sigs (sig, expires_at) VALUES (?, ?)")
        .bind(sig)
        .bind(now + MAX_SKEW_SECS)
        .execute(db)
        .await
        .map_err(db_err)?
        .rows_affected()
        > 0;
    Ok(inserted)
}

// ---- auth -------------------------------------------------------------------

/// Verify the Ed25519 signature over `signing_message(ts, body)` and check the
/// timestamp is within [`MAX_SKEW_SECS`] of relay time. Returns the decoded
/// 16-byte vault id (base64) and the device's public key. Does NOT check
/// enrollment. Binding `ts` into the signed message bounds replay of any
/// captured envelope to the skew window.
fn verify(signed: &Signed) -> Result<(String, VerifyingKey), (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let unauth = |m: &str| (StatusCode::UNAUTHORIZED, m.to_string());
    // Reject stale or far-future timestamps before touching the signature.
    if (now_unix() - signed.ts).abs() > MAX_SKEW_SECS {
        return Err(unauth("request timestamp outside acceptance window"));
    }
    let pub_bytes: [u8; 32] = B64
        .decode(&signed.device_pub_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("device_pub"))?;
    let key =
        VerifyingKey::from_bytes(&pub_bytes).map_err(|_| bad("device_pub not a valid key"))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&signed.sig_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("sig"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = signing_message(signed.ts, &signed.body);
    key.verify(msg.as_bytes(), &sig)
        .map_err(|_| unauth("signature does not verify"))?;
    Ok((signed.vault_id_b64.clone(), key))
}

/// A device may sync only if it is enrolled, approved, and not revoked.
async fn can_sync(db: &SqlitePool, vault: &str, pubk: &VerifyingKey) -> bool {
    device_row(db, vault, pubk)
        .await
        .map(|(approved, revoked, _)| approved && !revoked)
        .unwrap_or(false)
}

/// Fetch `(approved, revoked, x25519_pub)` for a device, if it exists.
async fn device_row(
    db: &SqlitePool,
    vault: &str,
    pubk: &VerifyingKey,
) -> Option<(bool, bool, Vec<u8>)> {
    sqlx::query(
        "SELECT approved, revoked, x25519_pub FROM devices WHERE vault_id = ? AND ed25519_pub = ?",
    )
    .bind(vault)
    .bind(pubk.as_bytes().as_slice())
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|row| {
        (
            row.get::<i64, _>("approved") != 0,
            row.get::<i64, _>("revoked") != 0,
            row.get::<Vec<u8>, _>("x25519_pub"),
        )
    })
}

fn json_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, (StatusCode, String)> {
    serde_json::from_str(body).map_err(|e| (StatusCode::BAD_REQUEST, format!("bad body: {e}")))
}

// ---- handlers ---------------------------------------------------------------

/// Register a device for a vault. The signature proves the caller holds the
/// private key for the pubkey it is registering. The first device to enroll a
/// vault bootstraps it (auto-approved, recovery key recorded); later devices
/// enroll as pending. Revocation is sticky: a revoked device stays out.
async fn enroll(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<EnrollResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    let req: EnrollReq = json_body(&signed.body)?;
    // the signing key must be the key being enrolled — no enrolling on behalf of others
    if req.ed25519_pub_b64 != signed.device_pub_b64 {
        return Err((StatusCode::BAD_REQUEST, "enroll must be self-signed".into()));
    }
    // a device that was revoked cannot re-enroll its way back in
    if let Some((_, revoked, _)) = device_row(&st.db, &vault, &key).await {
        if revoked {
            return Err((StatusCode::FORBIDDEN, "device is revoked".into()));
        }
    }
    let x_pub = B64
        .decode(&req.x25519_pub_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "x25519_pub".to_string()))?;

    // First device for this vault bootstraps it and is auto-approved.
    let bootstrap =
        sqlx::query("INSERT OR IGNORE INTO vaults (vault_id, recovery_pub) VALUES (?, ?)")
            .bind(&vault)
            .bind(
                B64.decode(&req.recovery_pub_b64)
                    .map_err(|_| (StatusCode::BAD_REQUEST, "recovery_pub".to_string()))?,
            )
            .execute(&st.db)
            .await
            .map_err(db_err)?
            .rows_affected()
            > 0;
    let approved = if bootstrap { 1 } else { 0 };

    sqlx::query(
        "INSERT INTO devices (vault_id, ed25519_pub, x25519_pub, name, approved, revoked)
         VALUES (?, ?, ?, ?, ?, 0)
         ON CONFLICT (vault_id, ed25519_pub)
         DO UPDATE SET name = excluded.name, x25519_pub = excluded.x25519_pub",
    )
    .bind(&vault)
    .bind(key.as_bytes().as_slice())
    .bind(x_pub)
    .bind(&req.device_name)
    .bind(approved)
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(EnrollResp {
        approved: approved == 1,
        head,
    }))
}

/// Approve a pending device and store the vault key wrapped for it. Signed by an
/// already-approved device; the relay never sees the unwrapped key.
async fn approve(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "approver not approved".into()));
    }
    let req: ApproveReq = json_body(&signed.body)?;
    let target = B64
        .decode(&req.target_pub_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "target_pub".to_string()))?;
    let wrapped = B64
        .decode(&req.wrapped_key_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "wrapped_key".to_string()))?;
    let res = sqlx::query(
        "UPDATE devices SET approved = 1, wrapped_key = ?
         WHERE vault_id = ? AND ed25519_pub = ? AND revoked = 0",
    )
    .bind(wrapped)
    .bind(&vault)
    .bind(&target)
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "no such pending device".into()));
    }
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(PushResp { head, stored: 0 }))
}

/// Revoke a device: it can no longer sync and cannot re-enroll. Signed by an
/// approved device. Clearing its wrapped key removes the ciphertext copy.
async fn revoke(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "revoker not approved".into()));
    }
    let req: RevokeReq = json_body(&signed.body)?;
    let target = B64
        .decode(&req.target_pub_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "target_pub".to_string()))?;
    let res = sqlx::query(
        "UPDATE devices SET revoked = 1, approved = 0, wrapped_key = NULL
         WHERE vault_id = ? AND ed25519_pub = ?",
    )
    .bind(&vault)
    .bind(&target)
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "no such device".into()));
    }
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(PushResp { head, stored: 0 }))
}

/// Rotate the vault key. Signed by an approved device (which proved it holds the
/// recovery phrase locally by minting the new epoch key). Bumps the vault epoch
/// and stores the re-wrapped key-list for every remaining device. The revoked
/// device is simply not among the `wrapped` recipients, so it never receives the
/// new key — that is the whole point of rotation.
///
/// Non-idempotent (it advances an epoch counter), so it is the first endpoint
/// gated by the seen-signature cache. The epoch bump is also guarded
/// (`WHERE epoch = ? - 1`) so a within-window duplicate that slips the cache
/// still can't double-advance.
async fn rotate(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "rotator not approved".into()));
    }
    if !mark_seen(&st.db, &signed.sig_b64).await? {
        return Err((StatusCode::CONFLICT, "replayed request".into()));
    }
    let req: RotateReq = json_body(&signed.body)?;
    // Advance the epoch, but only from exactly the previous one — rejects stale
    // or double rotations even if the signature cache is ever bypassed.
    let bumped = sqlx::query("UPDATE vaults SET epoch = ? WHERE vault_id = ? AND epoch = ?")
        .bind(req.epoch as i64)
        .bind(&vault)
        .bind(req.epoch as i64 - 1)
        .execute(&st.db)
        .await
        .map_err(db_err)?
        .rows_affected()
        > 0;
    if !bumped {
        return Err((StatusCode::CONFLICT, "epoch already advanced".into()));
    }
    // Store each remaining device's re-wrapped key-list. A revoked device is not
    // in this list, and we guard on revoked = 0 so a racing revoke still wins.
    for w in &req.wrapped {
        let target = B64
            .decode(&w.device_pub_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "device_pub".to_string()))?;
        let wrapped = B64
            .decode(&w.wrapped_key_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "wrapped_key".to_string()))?;
        sqlx::query(
            "UPDATE devices SET wrapped_key = ?
             WHERE vault_id = ? AND ed25519_pub = ? AND revoked = 0",
        )
        .bind(wrapped)
        .bind(&vault)
        .bind(&target)
        .execute(&st.db)
        .await
        .map_err(db_err)?;
    }
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(PushResp { head, stored: 0 }))
}

fn decode_share(b64: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    B64.decode(b64)
        .ok()
        .filter(|b| b.len() == 16)
        .ok_or((StatusCode::BAD_REQUEST, "share_id".to_string()))
}

/// Grant one or more devices membership in a share by storing each a wrapped
/// key-list. Signed by any approved device (the "any member manages" model). The
/// relay stores membership + opaque wrapped blobs and enforces no policy: a
/// caller who doesn't actually hold the share key can only store a wrap the
/// target can't open, which grants nothing. Idempotent (upsert), so replay-safe
/// without the seen-sig cache.
async fn share_grant(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "granter not approved".into()));
    }
    let req: ShareGrantReq = json_body(&signed.body)?;
    let share = decode_share(&req.share_id_b64)?;
    // Record the share's epoch (idempotent; a stale epoch can't lower it).
    sqlx::query(
        "INSERT INTO shares (vault_id, share_id, epoch) VALUES (?, ?, ?)
         ON CONFLICT (vault_id, share_id) DO UPDATE SET epoch = MAX(epoch, excluded.epoch)",
    )
    .bind(&vault)
    .bind(&share)
    .bind(req.epoch as i64)
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    for w in &req.wrapped {
        let target = B64
            .decode(&w.device_pub_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "device_pub".to_string()))?;
        let wrapped = B64
            .decode(&w.wrapped_key_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "wrapped_key".to_string()))?;
        sqlx::query(
            "INSERT INTO share_members (vault_id, share_id, ed25519_pub, wrapped_key)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (vault_id, share_id, ed25519_pub)
             DO UPDATE SET wrapped_key = excluded.wrapped_key",
        )
        .bind(&vault)
        .bind(&share)
        .bind(&target)
        .bind(wrapped)
        .execute(&st.db)
        .await
        .map_err(db_err)?;
    }
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(PushResp { head, stored: 0 }))
}

/// Rotate a share on member removal: bump its epoch, re-wrap for remaining
/// members, and drop the removed ones. Same seen-sig gating + guarded bump as
/// `/v1/rotate` (it advances a counter, so it's non-idempotent).
async fn share_rotate(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "rotator not approved".into()));
    }
    if !mark_seen(&st.db, &signed.sig_b64).await? {
        return Err((StatusCode::CONFLICT, "replayed request".into()));
    }
    let req: ShareRotateReq = json_body(&signed.body)?;
    let share = decode_share(&req.share_id_b64)?;
    // Guarded bump: only from exactly the previous epoch. A share seen for the
    // first time here (epoch 1 with no prior row) is inserted at epoch 1.
    let bumped = sqlx::query(
        "UPDATE shares SET epoch = ? WHERE vault_id = ? AND share_id = ? AND epoch = ?",
    )
    .bind(req.epoch as i64)
    .bind(&vault)
    .bind(&share)
    .bind(req.epoch as i64 - 1)
    .execute(&st.db)
    .await
    .map_err(db_err)?
    .rows_affected()
        > 0;
    if !bumped {
        // Allow first-ever rotation of a share the relay never saw an epoch for.
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO shares (vault_id, share_id, epoch) VALUES (?, ?, ?)",
        )
        .bind(&vault)
        .bind(&share)
        .bind(req.epoch as i64)
        .execute(&st.db)
        .await
        .map_err(db_err)?
        .rows_affected()
            > 0;
        if !inserted {
            return Err((StatusCode::CONFLICT, "epoch already advanced".into()));
        }
    }
    // Drop removed members first, then re-wrap for the remaining ones.
    for pub_b64 in &req.remove {
        let target = B64
            .decode(pub_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "remove pub".to_string()))?;
        sqlx::query("DELETE FROM share_members WHERE vault_id = ? AND share_id = ? AND ed25519_pub = ?")
            .bind(&vault)
            .bind(&share)
            .bind(&target)
            .execute(&st.db)
            .await
            .map_err(db_err)?;
    }
    for w in &req.wrapped {
        let target = B64
            .decode(&w.device_pub_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "device_pub".to_string()))?;
        let wrapped = B64
            .decode(&w.wrapped_key_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "wrapped_key".to_string()))?;
        // UPDATE only — rotation re-keys EXISTING members. A wrap for a device
        // that isn't a member updates zero rows (harmless), so the rotating
        // device can safely re-wrap for every approved device without needing to
        // know the exact membership set. Adding members is `share_grant`'s job.
        sqlx::query(
            "UPDATE share_members SET wrapped_key = ?
             WHERE vault_id = ? AND share_id = ? AND ed25519_pub = ?",
        )
        .bind(wrapped)
        .bind(&vault)
        .bind(&share)
        .bind(&target)
        .execute(&st.db)
        .await
        .map_err(db_err)?;
    }
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(PushResp { head, stored: 0 }))
}

/// Return every share this device belongs to, with its wrapped key-list and the
/// share's current epoch. Feeds bootstrap and offline self-heal (mirrors
/// `/v1/wrapped` for named shares). Signed GET, any approved device.
async fn shares(
    State(st): State<AppState>,
    Query(q): Query<SignedQuery>,
) -> Result<Json<SharesResp>, (StatusCode, String)> {
    let signed = q.into_signed("shares");
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "device not approved".into()));
    }
    let rows = sqlx::query(
        "SELECT m.share_id AS share_id, m.wrapped_key AS wrapped_key,
                COALESCE(s.epoch, 0) AS epoch
         FROM share_members m
         LEFT JOIN shares s ON s.vault_id = m.vault_id AND s.share_id = m.share_id
         WHERE m.vault_id = ? AND m.ed25519_pub = ?",
    )
    .bind(&vault)
    .bind(key.as_bytes().as_slice())
    .fetch_all(&st.db)
    .await
    .map_err(db_err)?;
    let shares = rows
        .into_iter()
        .map(|row| ShareMembership {
            share_id_b64: B64.encode(row.get::<Vec<u8>, _>("share_id")),
            epoch: row.get::<i64, _>("epoch") as u32,
            wrapped_key_b64: B64.encode(row.get::<Vec<u8>, _>("wrapped_key")),
        })
        .collect();
    Ok(Json(SharesResp { shares }))
}
async fn devices(
    State(st): State<AppState>,
    Query(q): Query<SignedQuery>,
) -> Result<Json<DevicesResp>, (StatusCode, String)> {
    let signed = q.into_signed("devices");
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((StatusCode::FORBIDDEN, "device not approved".into()));
    }
    let rows = sqlx::query(
        "SELECT name, ed25519_pub, x25519_pub, approved, revoked FROM devices WHERE vault_id = ?",
    )
    .bind(&vault)
    .fetch_all(&st.db)
    .await
    .map_err(db_err)?;
    let devices = rows
        .into_iter()
        .map(|row| DeviceInfo {
            name: row.get::<String, _>("name"),
            ed25519_pub_b64: B64.encode(row.get::<Vec<u8>, _>("ed25519_pub")),
            x25519_pub_b64: B64.encode(row.get::<Vec<u8>, _>("x25519_pub")),
            approved: row.get::<i64, _>("approved") != 0,
            revoked: row.get::<i64, _>("revoked") != 0,
        })
        .collect();
    Ok(Json(DevicesResp { devices }))
}

/// A pending device polls here for its wrapped vault key (signed GET).
async fn wrapped(
    State(st): State<AppState>,
    Query(q): Query<SignedQuery>,
) -> Result<Json<WrappedResp>, (StatusCode, String)> {
    let signed = q.into_signed("wrapped");
    let (vault, key) = verify(&signed)?;
    let row = sqlx::query(
        "SELECT approved, revoked, wrapped_key FROM devices WHERE vault_id = ? AND ed25519_pub = ?",
    )
    .bind(&vault)
    .bind(key.as_bytes().as_slice())
    .fetch_optional(&st.db)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "device not enrolled".to_string()))?;
    if row.get::<i64, _>("revoked") != 0 {
        return Err((StatusCode::FORBIDDEN, "device is revoked".into()));
    }
    let epoch = sqlx::query("SELECT epoch FROM vaults WHERE vault_id = ?")
        .bind(&vault)
        .fetch_optional(&st.db)
        .await
        .map_err(db_err)?
        .map(|r| r.get::<i64, _>("epoch") as u32)
        .unwrap_or(0);
    Ok(Json(WrappedResp {
        approved: row.get::<i64, _>("approved") != 0,
        wrapped_key_b64: row
            .get::<Option<Vec<u8>>, _>("wrapped_key")
            .map(|b| B64.encode(b)),
        epoch,
    }))
}

/// Recover on a fresh machine using only the recovery phrase. The caller proves
/// it holds the recovery private key by signing its new device's Ed25519 public
/// key; the relay looks up the vault by recovery public key and admits the new
/// device as approved. The wrapped-key handshake is unnecessary — the recovery
/// phrase re-derives the vault key locally.
async fn recover(
    State(st): State<AppState>,
    Json(req): Json<RecoverReq>,
) -> Result<Json<RecoverResp>, (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let recovery_pub: [u8; 32] = B64
        .decode(&req.recovery_pub_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("recovery_pub"))?;
    let ed_pub_bytes: [u8; 32] = B64
        .decode(&req.ed25519_pub_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("ed25519_pub"))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&req.sig_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("sig"))?;
    // the recovery key must sign the new device key — proves phrase ownership
    let rkey = VerifyingKey::from_bytes(&recovery_pub).map_err(|_| bad("recovery_pub"))?;
    rkey.verify(&ed_pub_bytes, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "recovery signature invalid".into(),
            )
        })?;

    // find the vault this recovery key bootstrapped
    let vrow = sqlx::query("SELECT vault_id FROM vaults WHERE recovery_pub = ?")
        .bind(recovery_pub.as_slice())
        .fetch_optional(&st.db)
        .await
        .map_err(db_err)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no vault for this phrase".to_string(),
        ))?;
    let vault: String = vrow.get::<String, _>("vault_id");
    let x_pub = B64
        .decode(&req.x25519_pub_b64)
        .map_err(|_| bad("x25519_pub"))?;
    sqlx::query(
        "INSERT INTO devices (vault_id, ed25519_pub, x25519_pub, name, approved, revoked)
         VALUES (?, ?, ?, ?, 1, 0)
         ON CONFLICT (vault_id, ed25519_pub)
         DO UPDATE SET approved = 1, revoked = 0, x25519_pub = excluded.x25519_pub",
    )
    .bind(&vault)
    .bind(ed_pub_bytes.as_slice())
    .bind(x_pub)
    .bind(&req.device_name)
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    Ok(Json(RecoverResp {
        vault_id_b64: vault,
    }))
}

async fn push(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((
            StatusCode::FORBIDDEN,
            "device not enrolled or revoked".into(),
        ));
    }
    let req: PushReq = json_body(&signed.body)?;
    let mut stored = 0usize;
    for e in &req.entries {
        let entry_id = B64
            .decode(&e.entry_id_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "entry_id".to_string()))?;
        let blob = B64
            .decode(&e.blob_b64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "blob".to_string()))?;
        // share_id is cleartext routing metadata; empty/absent means the default
        // (nil) share, so old clients that never send it keep working.
        let share_id = if e.share_id_b64.is_empty() {
            vec![0u8; 16]
        } else {
            B64.decode(&e.share_id_b64)
                .ok()
                .filter(|b| b.len() == 16)
                .ok_or((StatusCode::BAD_REQUEST, "share_id".to_string()))?
        };
        let res = sqlx::query(
            "INSERT OR IGNORE INTO entries (vault_id, entry_id, blob, share_id) VALUES (?, ?, ?, ?)",
        )
        .bind(&vault)
        .bind(entry_id)
        .bind(blob)
        .bind(share_id)
        .execute(&st.db)
        .await
        .map_err(db_err)?;
        stored += res.rows_affected() as usize;
    }
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    if stored > 0 {
        notify(&st, &vault, head).await;
    }
    Ok(Json(PushResp { head, stored }))
}

#[derive(Deserialize)]
struct PullQuery {
    /// base64 vault id
    vault: String,
    /// base64 device pub
    device: String,
    /// base64 signature over `signing_message(ts, "pull:<since>")`
    sig: String,
    since: u64,
    /// unix seconds the request was signed at
    ts: i64,
}

/// A signed GET whose body is `"<action>:<vault_b64>"` — used for endpoints that
/// carry no request body of their own (devices, wrapped). The `ts` is bound into
/// the signature exactly as in the POST envelope.
#[derive(Deserialize)]
struct SignedQuery {
    vault: String,
    device: String,
    sig: String,
    ts: i64,
}

impl SignedQuery {
    fn into_signed(self, action: &str) -> Signed {
        let body = format!("{action}:{}", self.vault);
        Signed {
            vault_id_b64: self.vault,
            device_pub_b64: self.device,
            sig_b64: self.sig,
            ts: self.ts,
            body,
        }
    }
}

/// Pull is a GET, so we sign the string `pull:<since>` instead of a JSON body.
async fn pull(
    State(st): State<AppState>,
    Query(q): Query<PullQuery>,
) -> Result<Json<PullResp>, (StatusCode, String)> {
    let signed = Signed {
        vault_id_b64: q.vault.clone(),
        device_pub_b64: q.device.clone(),
        sig_b64: q.sig.clone(),
        ts: q.ts,
        body: format!("pull:{}", q.since),
    };
    let (vault, key) = verify(&signed)?;
    if !can_sync(&st.db, &vault, &key).await {
        return Err((
            StatusCode::FORBIDDEN,
            "device not enrolled or revoked".into(),
        ));
    }
    // Membership filter: a device may pull an entry iff it's in the default
    // (nil) share OR has a share_members row for that entry's share. The relay
    // enforces this as routing, never as a decryption gate — non-members simply
    // aren't handed the ciphertext.
    let rows = sqlx::query(
        "SELECT seq, entry_id, blob, share_id FROM entries
         WHERE vault_id = ? AND seq > ?
           AND (share_id = x'00000000000000000000000000000000'
                OR EXISTS (SELECT 1 FROM share_members m
                           WHERE m.vault_id = entries.vault_id
                             AND m.share_id = entries.share_id
                             AND m.ed25519_pub = ?))
         ORDER BY seq",
    )
    .bind(&vault)
    .bind(q.since as i64)
    .bind(key.as_bytes().as_slice())
    .fetch_all(&st.db)
    .await
    .map_err(db_err)?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        entries.push(WireEntry {
            entry_id_b64: B64.encode(row.get::<Vec<u8>, _>("entry_id")),
            blob_b64: B64.encode(row.get::<Vec<u8>, _>("blob")),
            share_id_b64: B64.encode(row.get::<Vec<u8>, _>("share_id")),
        });
    }
    // Advance the cursor past ALL entries, including ones filtered out above —
    // otherwise a trailing non-member entry would stall the cursor and be
    // re-pulled forever. A device newly granted a share resets its cursor to
    // re-fetch what it skipped (see sync::heal_shares).
    let head = head(&st.db, &vault).await.map_err(db_err)?.max(q.since);
    Ok(Json(PullResp { entries, head }))
}

#[derive(Deserialize)]
struct WsQuery {
    vault: String,
}

/// Subscribe to change notifications for a vault; each message is the new head
/// sequence. Unauthenticated: it leaks only "something changed" (a timestamp the
/// relay already sees), never contents. Clients still pull with auth.
async fn ws(
    State(st): State<AppState>,
    Query(q): Query<WsQuery>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    let mut rx = {
        let mut map = st.notify.lock().await;
        map.entry(q.vault.clone())
            .or_insert_with(|| tokio::sync::broadcast::channel(64).0)
            .subscribe()
    };
    upgrade.on_upgrade(move |mut socket| async move {
        use axum::extract::ws::Message;
        while let Ok(head) = rx.recv().await {
            if socket
                .send(Message::Text(head.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

// ---- helpers ----------------------------------------------------------------

async fn head(db: &SqlitePool, vault: &str) -> Result<u64, sqlx::Error> {
    let row = sqlx::query("SELECT COALESCE(MAX(seq), 0) AS h FROM entries WHERE vault_id = ?")
        .bind(vault)
        .fetch_one(db)
        .await?;
    Ok(row.get::<i64, _>("h") as u64)
}

async fn notify(st: &AppState, vault: &str, head: u64) {
    let map = st.notify.lock().await;
    if let Some(tx) = map.get(vault) {
        let _ = tx.send(head); // no subscribers is fine
    }
}

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!("db error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "relay storage error".into(),
    )
}
