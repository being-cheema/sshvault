//! The relay: a zero-knowledge, append-only blob store per vault.
//!
//! The relay authenticates devices by Ed25519 signature and stores opaque
//! sealed entries. It has no vault key and no decryption path — a full server
//! compromise leaks only blob sizes, timestamps, and which device pushed what.
//!
//! Storage (SQLite via sqlx):
//! - `devices(vault_id, ed25519_pub, x25519_pub, name, revoked)`  — who may sync
//! - `entries(vault_id, seq, entry_id, blob)`                      — the opaque log
//!
//! `seq` is a per-relay monotonic cursor; clients pull everything with
//! `seq > their_cursor`. Convergence is the client's merge engine's job.

use crate::proto::{EnrollReq, PullResp, PushReq, PushResp, Signed, WireEntry};
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
        "CREATE TABLE IF NOT EXISTS devices (
            vault_id     TEXT NOT NULL,
            ed25519_pub  BLOB NOT NULL,
            x25519_pub   BLOB NOT NULL,
            name         TEXT NOT NULL,
            revoked      INTEGER NOT NULL DEFAULT 0,
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
            UNIQUE (vault_id, entry_id)
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

// ---- auth -------------------------------------------------------------------

/// Verify the Ed25519 signature over `body` and return the decoded 16-byte
/// vault id and the device's public key bytes. Does NOT check enrollment.
fn verify(signed: &Signed) -> Result<(String, VerifyingKey), (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let unauth = |m: &str| (StatusCode::UNAUTHORIZED, m.to_string());
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
    key.verify(signed.body.as_bytes(), &sig)
        .map_err(|_| unauth("signature does not verify"))?;
    Ok((signed.vault_id_b64.clone(), key))
}

async fn is_enrolled(db: &SqlitePool, vault: &str, pubk: &VerifyingKey) -> bool {
    sqlx::query("SELECT revoked FROM devices WHERE vault_id = ? AND ed25519_pub = ?")
        .bind(vault)
        .bind(pubk.as_bytes().as_slice())
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|row| row.get::<i64, _>("revoked") == 0)
        .unwrap_or(false)
}

fn json_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, (StatusCode, String)> {
    serde_json::from_str(body).map_err(|e| (StatusCode::BAD_REQUEST, format!("bad body: {e}")))
}

// ---- handlers ---------------------------------------------------------------

/// Register a device for a vault (TOFU in v0.1). The signature proves the caller
/// holds the private key for the pubkey it is registering.
async fn enroll(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    let req: EnrollReq = json_body(&signed.body)?;
    // the signing key must be the key being enrolled — no enrolling on behalf of others
    if req.ed25519_pub_b64 != signed.device_pub_b64 {
        return Err((StatusCode::BAD_REQUEST, "enroll must be self-signed".into()));
    }
    let x_pub = B64
        .decode(&req.x25519_pub_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "x25519_pub".to_string()))?;
    sqlx::query(
        "INSERT INTO devices (vault_id, ed25519_pub, x25519_pub, name, revoked)
         VALUES (?, ?, ?, ?, 0)
         ON CONFLICT (vault_id, ed25519_pub) DO UPDATE SET revoked = 0, name = excluded.name",
    )
    .bind(&vault)
    .bind(key.as_bytes().as_slice())
    .bind(x_pub)
    .bind(&req.device_name)
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    let head = head(&st.db, &vault).await.map_err(db_err)?;
    Ok(Json(PushResp { head, stored: 0 }))
}

async fn push(
    State(st): State<AppState>,
    Json(signed): Json<Signed>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (vault, key) = verify(&signed)?;
    if !is_enrolled(&st.db, &vault, &key).await {
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
        let res = sqlx::query(
            "INSERT OR IGNORE INTO entries (vault_id, entry_id, blob) VALUES (?, ?, ?)",
        )
        .bind(&vault)
        .bind(entry_id)
        .bind(blob)
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
    /// base64 signature over the string "pull:<since>"
    sig: String,
    since: u64,
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
        body: format!("pull:{}", q.since),
    };
    let (vault, key) = verify(&signed)?;
    if !is_enrolled(&st.db, &vault, &key).await {
        return Err((
            StatusCode::FORBIDDEN,
            "device not enrolled or revoked".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT seq, entry_id, blob FROM entries
         WHERE vault_id = ? AND seq > ? ORDER BY seq",
    )
    .bind(&vault)
    .bind(q.since as i64)
    .fetch_all(&st.db)
    .await
    .map_err(db_err)?;
    let mut head = q.since;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        head = row.get::<i64, _>("seq") as u64;
        entries.push(WireEntry {
            entry_id_b64: B64.encode(row.get::<Vec<u8>, _>("entry_id")),
            blob_b64: B64.encode(row.get::<Vec<u8>, _>("blob")),
        });
    }
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
