//! Local encrypted vault storage.
//!
//! Layout under the vault directory (`$SSHVAULT_DIR` or `<data_dir>/sshvault`):
//! - `meta.json`    — plaintext metadata: ids, KDF params, public keys, lamport counter
//! - `keyring.enc`  — vault key + device secrets, encrypted under the passphrase KEK
//! - `log.bin`      — append-only frames: `u32 len || entry_id(16) || sealed record`
//!
//! Every mutation appends an immutable encrypted snapshot; state is rebuilt by
//! folding [`crate::merge::merge_all`] over the decrypted log.

use crate::crypto::{self, CryptoError, Secret32};
use crate::merge;
use crate::record::{fields_from_payload, Clock, Field, Kind, Record};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault already exists at {0} — `sshvault init` refuses to overwrite it")]
    AlreadyExists(PathBuf),
    #[error("no vault found at {0} — run `sshvault init` first")]
    NotFound(PathBuf),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("vault storage error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupted vault data: {0}")]
    Corrupt(String),
    #[error("{kind} '{name}' already exists — use `edit`, or `rm` it first")]
    Duplicate { kind: &'static str, name: String },
    #[error("{kind} '{name}' not found")]
    NoSuchRecord { kind: &'static str, name: String },
    #[error("refusing to store private key material: {0} looks like a private key (v0.1 syncs key metadata only)")]
    PrivateKeyMaterial(String),
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

/// Argon2id parameters + salt, stored per-vault so they can be raised later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub salt_b64: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Plaintext vault metadata (`meta.json`). Contains no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub vault_id: Uuid,
    pub device_id: Uuid,
    pub device_name: String,
    pub kdf: KdfParams,
    /// Device public keys, base64.
    pub x25519_pub_b64: String,
    pub ed25519_pub_b64: String,
    /// Recovery Ed25519 public key, base64 (registered with the relay).
    pub recovery_pub_b64: String,
    /// This device's lamport counter (last used value).
    pub lamport: u64,
    /// Relay endpoint + sync cursor (Phase 3).
    #[serde(default)]
    pub relay_url: Option<String>,
    #[serde(default)]
    pub sync_cursor: u64,
}

/// Decrypted secret keys. Zeroized on drop.
#[derive(Serialize, Deserialize, Zeroize, zeroize::ZeroizeOnDrop)]
struct Keyring {
    /// Per-share epoch key-lists. Every record is sealed under its share's
    /// newest-epoch key; a device holds a `ShareKeys` only for shares it belongs
    /// to. The default share (nil id) is always present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    shares: Vec<ShareKeys>,
    /// Legacy epoch list for the default share (rotation-era vaults, pre-shares).
    /// Drained into `shares[nil]` by [`Keyring::normalize`], then never written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vault_keys: Vec<[u8; 32]>,
    /// Legacy single vault key (pre-rotation vaults). Drained on load too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_key: Option<[u8; 32]>,
    x25519_secret: [u8; 32],
    ed25519_secret: [u8; 32],
}

/// One share's epoch key-list, keyed by raw 16-byte share id (nil = default).
/// Raw bytes rather than `Uuid` so the whole keyring stays `Zeroize`-derivable.
#[derive(Serialize, Deserialize, Zeroize, zeroize::ZeroizeOnDrop)]
struct ShareKeys {
    id: [u8; 16],
    keys: Vec<[u8; 32]>,
}

impl Keyring {
    /// Fold legacy default-share keys (single key, or a bare epoch list) into the
    /// per-share map under the nil share id. Idempotent.
    fn normalize(&mut self) {
        let mut legacy = std::mem::take(&mut self.vault_keys);
        if let Some(k) = self.vault_key.take() {
            if legacy.is_empty() {
                legacy.push(k);
            }
        }
        if !legacy.is_empty() && !self.shares.iter().any(|s| s.id == NIL) {
            self.shares.push(ShareKeys {
                id: NIL,
                keys: legacy,
            });
        }
    }

    fn share(&self, id: &[u8; 16]) -> Option<&ShareKeys> {
        self.shares.iter().find(|s| &s.id == id)
    }

    fn share_mut(&mut self, id: &[u8; 16]) -> Option<&mut ShareKeys> {
        self.shares.iter_mut().find(|s| &s.id == id)
    }

    /// The current (newest-epoch) key for a share, if this device holds it.
    fn current_for(&self, id: &[u8; 16]) -> Option<[u8; 32]> {
        self.share(id).and_then(|s| s.keys.last().copied())
    }

    /// The default-share current key. Always present in an open vault.
    fn current(&self) -> [u8; 32] {
        self.current_for(&NIL)
            .expect("keyring always holds the default share key")
    }
}

/// Nil share id (the default share every member holds).
const NIL: [u8; 16] = [0u8; 16];

/// An open (unlocked) vault.
pub struct Vault {
    pub dir: PathBuf,
    pub meta: Meta,
    keyring: Keyring,
    /// The passphrase-derived KEK, cached so keyring rewrites (rotation, offline
    /// self-heal in `syncd`) don't need the passphrase re-supplied. No new
    /// exposure: the vault already holds the decrypted keys in memory.
    kek: Secret32,
    /// Merged current state per record id (includes tombstones).
    state: HashMap<Uuid, Record>,
}

/// Resolve the vault directory: `$SSHVAULT_DIR` override or `<data_dir>/sshvault`.
pub fn default_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SSHVAULT_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sshvault")
}

const META: &str = "meta.json";
const KEYRING: &str = "keyring.enc";
const LOG: &str = "log.bin";
const LOCK: &str = ".lock";

/// A raw log frame: 16-byte entry id + its sealed blob.
pub type RawEntry = ([u8; 16], Vec<u8>);

/// A raw frame plus the share id its plaintext belongs to (nil if unreadable
/// here). Feeds share-routed push.
pub type TaggedEntry = ([u8; 16], Vec<u8>, Uuid);

impl Vault {
    /// Create a new vault. Returns the vault and the 24-word recovery phrase —
    /// the only time it is ever available.
    pub fn init(
        dir: &Path,
        device_name: &str,
        passphrase: &str,
    ) -> Result<(Vault, String), VaultError> {
        let (phrase, phrase_keys) = crypto::new_phrase();
        let recovery_pub = phrase_keys.recovery_signing.verifying_key().to_bytes();
        let vault = Self::create(
            dir,
            device_name,
            passphrase,
            Uuid::new_v4(),
            &phrase_keys.vault_key,
            &recovery_pub,
        )?;
        Ok((vault, phrase))
    }

    /// Create a vault directory for a device joining an existing vault: it shares
    /// the `vault_id` and `vault_key` (obtained via enrollment or recovery) but
    /// gets its own fresh device keypair and an empty log to sync into.
    pub fn create(
        dir: &Path,
        device_name: &str,
        passphrase: &str,
        vault_id: Uuid,
        vault_key: &Secret32,
        recovery_pub: &[u8; 32],
    ) -> Result<Vault, VaultError> {
        Self::create_with_keys(
            dir,
            device_name,
            passphrase,
            vault_id,
            vault_key,
            recovery_pub,
            crypto::new_device_keys(),
        )
    }

    /// Like [`Vault::create`] but with caller-supplied device keys — used by
    /// recovery, where the device's Ed25519 key must be known (to prove phrase
    /// ownership to the relay) before the vault_id is learned.
    pub fn create_with_keys(
        dir: &Path,
        device_name: &str,
        passphrase: &str,
        vault_id: Uuid,
        vault_key: &Secret32,
        recovery_pub: &[u8; 32],
        device: crypto::DeviceKeys,
    ) -> Result<Vault, VaultError> {
        if dir.join(META).exists() {
            return Err(VaultError::AlreadyExists(dir.to_path_buf()));
        }
        fs::create_dir_all(dir)?;
        restrict_permissions(dir)?;

        let kdf = KdfParams {
            salt_b64: b64(&crypto::random_bytes::<16>()),
            m_kib: crypto::ARGON2_M_KIB,
            t: crypto::ARGON2_T,
            p: crypto::ARGON2_P,
        };
        let meta = Meta {
            vault_id,
            device_id: Uuid::new_v4(),
            device_name: device_name.to_string(),
            kdf,
            x25519_pub_b64: b64(x25519_dalek::PublicKey::from(&device.x25519).as_bytes()),
            ed25519_pub_b64: b64(device.ed25519.verifying_key().as_bytes()),
            recovery_pub_b64: b64(recovery_pub),
            lamport: 0,
            relay_url: None,
            sync_cursor: 0,
        };
        let keyring = Keyring {
            shares: vec![ShareKeys {
                id: NIL,
                keys: vec![**vault_key],
            }],
            vault_keys: Vec::new(),
            vault_key: None,
            x25519_secret: device.x25519.to_bytes(),
            ed25519_secret: device.ed25519.to_bytes(),
        };
        let kek = derive_kek(&meta, passphrase)?;
        let vault = Vault {
            dir: dir.to_path_buf(),
            meta,
            keyring,
            kek,
            state: HashMap::new(),
        };
        vault.write_keyring()?;
        vault.write_meta()?;
        fs::File::create(dir.join(LOG))?;
        restrict_permissions(&dir.join(LOG))?;
        Ok(vault)
    }

    /// Unlock an existing vault with the passphrase and replay its log.
    pub fn open(dir: &Path, passphrase: &str) -> Result<Vault, VaultError> {
        let meta_path = dir.join(META);
        if !meta_path.exists() {
            return Err(VaultError::NotFound(dir.to_path_buf()));
        }
        let meta: Meta = serde_json::from_str(&fs::read_to_string(&meta_path)?)
            .map_err(|e| VaultError::Corrupt(format!("meta.json: {e}")))?;
        let kek = derive_kek(&meta, passphrase)?;
        let sealed = fs::read(dir.join(KEYRING))?;
        let plain = crypto::open(&kek, &sealed, meta.vault_id.as_bytes())?;
        let mut keyring: Keyring = rmp_serde::from_slice(&plain)
            .map_err(|e| VaultError::Corrupt(format!("keyring: {e}")))?;
        keyring.normalize();
        let mut vault = Vault {
            dir: dir.to_path_buf(),
            meta,
            keyring,
            kek,
            state: HashMap::new(),
        };
        vault.replay_log()?;
        Ok(vault)
    }

    /// Re-read metadata and replay the log from disk, picking up appends and
    /// lamport/cursor changes made by other sshvault processes on this machine
    /// (the sync daemon calls this before every round). The keyring never
    /// changes while a vault stays open, so it is not re-read.
    pub fn reload(&mut self) -> Result<(), VaultError> {
        self.meta = serde_json::from_str(&fs::read_to_string(self.dir.join(META))?)
            .map_err(|e| VaultError::Corrupt(format!("meta.json: {e}")))?;
        self.replay_log()
    }

    /// The current (newest-epoch) default-share key, for sync-layer encryption.
    pub fn vault_key(&self) -> Secret32 {
        Zeroizing::new(self.keyring.current())
    }

    /// Current default-share rotation epoch (0 if it never rotated).
    pub fn epoch(&self) -> u32 {
        self.share_epoch(&NIL)
    }

    /// Current epoch of `share` (number of keys − 1); 0 if this device doesn't
    /// hold the share (it has no epochs to speak of locally).
    fn share_epoch(&self, id: &[u8; 16]) -> u32 {
        self.keyring
            .share(id)
            .map(|s| (s.keys.len() - 1) as u32)
            .unwrap_or(0)
    }

    /// The default-share epoch key-list as raw bytes (`epoch0 || epoch1 || …`).
    pub fn vault_key_list(&self) -> Zeroizing<Vec<u8>> {
        self.share_key_list(&NIL)
    }

    /// A share's epoch key-list as raw bytes, for wrapping to a member device.
    /// Empty if this device does not hold the share.
    fn share_key_list(&self, id: &[u8; 16]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        if let Some(s) = self.keyring.share(id) {
            out.reserve(32 * s.keys.len());
            for k in &s.keys {
                out.extend_from_slice(k);
            }
        }
        out
    }

    /// This device's Ed25519 signing key (for relay request auth).
    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.keyring.ed25519_secret)
    }

    /// This device's X25519 static secret (receives wrapped vault keys).
    pub fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.keyring.x25519_secret)
    }

    /// Install the real vault key-list on a device that joined with a provisional
    /// key (enrollment / recovery). `list` is the concatenated epoch keys
    /// (`epoch0 || epoch1 || …`) as produced by [`Vault::vault_key_list`]. Safe
    /// only while the log is empty — nothing has been sealed under the old key yet
    /// — which is the case before a device is approved and first syncs.
    pub fn set_vault_key(&mut self, list: &[u8]) -> Result<(), VaultError> {
        if !self.raw_entries()?.is_empty() {
            return Err(VaultError::Corrupt(
                "refusing to swap vault key on a non-empty log".into(),
            ));
        }
        self.set_share_keys(NIL, split_key_list(list)?);
        self.keyring.vault_keys = Vec::new();
        self.keyring.vault_key = None;
        self.write_keyring()?;
        self.state.clear();
        Ok(())
    }

    /// Replace the epoch key-list on an already-syncing device (offline self-heal
    /// after a rotation it missed). Unlike [`Vault::set_vault_key`] this keeps the
    /// log: the new list is a superset of the old (rotation only appends epochs),
    /// so every existing entry still decrypts and state is unchanged.
    pub fn absorb_vault_key_list(&mut self, list: &[u8]) -> Result<(), VaultError> {
        self.absorb_share_key(Uuid::nil(), list)
    }

    /// Rotate the default vault key: derive the next epoch's key from the recovery
    /// phrase, append it, and persist. Phrase-gated by construction — the new key
    /// comes from the seed, which only the phrase holder can produce.
    pub fn rotate(&mut self, phrase: &str) -> Result<u32, VaultError> {
        let next = self.epoch() + 1;
        let key = crypto::vault_key_at_epoch(phrase, next)?;
        self.push_share_key(NIL, *key);
        self.write_keyring()?;
        Ok(next)
    }

    // ---- shares ------------------------------------------------------------

    /// True if this device holds `share` (nil is always held).
    pub fn has_share(&self, share: Uuid) -> bool {
        self.keyring.share(&share.into_bytes()).is_some()
    }

    /// The share ids this device currently holds (includes nil).
    pub fn held_shares(&self) -> Vec<Uuid> {
        self.keyring
            .shares
            .iter()
            .map(|s| Uuid::from_bytes(s.id))
            .collect()
    }

    /// Resolve a share's human name to its id via the `ShareName` records in the
    /// default share. `None` if no such name is known here.
    pub fn resolve_share(&self, name: &str) -> Option<Uuid> {
        self.find(Kind::ShareName, "name", name).and_then(|r| {
            r.payload::<crate::record::ShareName>()
                .ok()
                .and_then(|sn| b64_decode(&sn.share_id_b64))
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                .map(Uuid::from_bytes)
        })
    }

    /// All known (name, id) share mappings, for `share list`.
    pub fn share_names(&self) -> Vec<(String, Uuid)> {
        self.list::<crate::record::ShareName>(Kind::ShareName)
            .into_iter()
            .filter_map(|(_, sn)| {
                b64_decode(&sn.share_id_b64)
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                    .map(|b| (sn.name, Uuid::from_bytes(b)))
            })
            .collect()
    }

    /// The current epoch key-list of `share`, for wrapping to a member. Empty if
    /// this device doesn't hold it.
    pub fn share_key_list_for(&self, share: Uuid) -> Zeroizing<Vec<u8>> {
        self.share_key_list(&share.into_bytes())
    }

    /// This share's current epoch.
    pub fn share_epoch_for(&self, share: Uuid) -> u32 {
        self.share_epoch(&share.into_bytes())
    }

    /// Create a new share with a fresh random epoch-0 key. Named-share keys are
    /// random (not phrase-derived): any member must be able to rotate on removal
    /// without the seed, so they cannot be re-derived from the phrase — recovery
    /// restores the default share only. Returns the new share id.
    pub fn create_share(&mut self) -> Result<Uuid, VaultError> {
        let id = Uuid::new_v4();
        self.push_share_key(id.into_bytes(), crypto::random_bytes::<32>());
        self.write_keyring()?;
        Ok(id)
    }

    /// Rotate a named share: mint a fresh RANDOM next-epoch key (members lack the
    /// seed, so unlike the default share this is not phrase-derived). New writes
    /// to the share seal under it; the removed member's held key can't open them.
    pub fn rotate_share(&mut self, share: Uuid) -> Result<u32, VaultError> {
        let id = share.into_bytes();
        if self.keyring.share(&id).is_none() {
            return Err(VaultError::Corrupt("not a member of this share".into()));
        }
        self.push_share_key(id, crypto::random_bytes::<32>());
        self.write_keyring()?;
        Ok(self.share_epoch(&id))
    }

    /// Install/replace a share's key-list from a wrapped grant or self-heal. Only
    /// grows: a shorter list (stale) is ignored, so a late grant can't roll back.
    pub fn absorb_share_key(&mut self, share: Uuid, list: &[u8]) -> Result<(), VaultError> {
        let keys = split_key_list(list)?;
        let id = share.into_bytes();
        if let Some(existing) = self.keyring.share(&id) {
            if keys.len() <= existing.keys.len() {
                return Ok(()); // nothing newer
            }
        }
        self.set_share_keys(id, keys);
        self.write_keyring()
    }

    /// Append `key` as a share's next epoch, creating the share if absent.
    fn push_share_key(&mut self, id: [u8; 16], key: [u8; 32]) {
        if let Some(s) = self.keyring.share_mut(&id) {
            s.keys.push(key);
        } else {
            self.keyring.shares.push(ShareKeys {
                id,
                keys: vec![key],
            });
        }
    }

    /// Replace a share's whole key-list (create if absent).
    fn set_share_keys(&mut self, id: [u8; 16], keys: Vec<[u8; 32]>) {
        if let Some(s) = self.keyring.share_mut(&id) {
            s.keys = keys;
        } else {
            self.keyring.shares.push(ShareKeys { id, keys });
        }
    }

    // ---- CRUD --------------------------------------------------------------

    /// All live records of the payload type `T` under `kind`, with their ids.
    pub fn list<T: DeserializeOwned>(&self, kind: Kind) -> Vec<(Uuid, T)> {
        let mut out: Vec<(Uuid, T)> = self
            .state
            .values()
            .filter(|r| merge::live(r) && r.kind == kind)
            .filter_map(|r| r.payload().ok().map(|p| (r.id, p)))
            .collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }

    /// Find a live record of `kind` whose `name_field` equals `name`.
    pub fn find(&self, kind: Kind, name_field: &str, name: &str) -> Option<&Record> {
        self.state.values().find(|r| {
            merge::live(r)
                && r.kind == kind
                && r.fields.get(name_field).map(|f| f.value == name) == Some(true)
        })
    }

    /// Insert a new record into the default share. `name` is the unique human key
    /// (alias for hosts, name otherwise); duplicates are rejected.
    pub fn add<T: Serialize>(
        &mut self,
        kind: Kind,
        name_field: &'static str,
        name: &str,
        payload: &T,
    ) -> Result<Uuid, VaultError> {
        self.add_in(kind, name_field, name, payload, Uuid::nil())
    }

    /// Insert a new record into `share`. Errors if this device doesn't hold the
    /// share (can't seal under a key it lacks).
    pub fn add_in<T: Serialize>(
        &mut self,
        kind: Kind,
        name_field: &'static str,
        name: &str,
        payload: &T,
        share: Uuid,
    ) -> Result<Uuid, VaultError> {
        validate_payload(kind, payload)?;
        if !self.has_share(share) {
            return Err(VaultError::Corrupt(
                "cannot add to a share this device is not a member of".into(),
            ));
        }
        if self.find(kind, name_field, name).is_some() {
            return Err(VaultError::Duplicate {
                kind: kind_str(kind),
                name: name.into(),
            });
        }
        let clock = self.next_clock()?;
        let record = Record {
            id: Uuid::new_v4(),
            kind,
            fields: fields_from_payload(payload, clock),
            deleted_at: None,
            clock,
            device_id: self.meta.device_id,
            modified_at: now(),
            share_id: share,
        };
        self.append(&record)?;
        Ok(record.id)
    }

    /// Update an existing record: only fields whose value actually changed get
    /// the new clock (this is what makes merge field-level).
    pub fn edit<T: Serialize>(
        &mut self,
        kind: Kind,
        name_field: &'static str,
        name: &str,
        payload: &T,
    ) -> Result<(), VaultError> {
        validate_payload(kind, payload)?;
        let old = self
            .find(kind, name_field, name)
            .ok_or_else(|| VaultError::NoSuchRecord {
                kind: kind_str(kind),
                name: name.into(),
            })?
            .clone();
        let clock = self.next_clock()?;
        let mut fields: BTreeMap<String, Field> = fields_from_payload(payload, clock);
        for (k, f) in fields.iter_mut() {
            if let Some(prev) = old.fields.get(k) {
                if prev.value == f.value {
                    f.clock = prev.clock; // unchanged → keep old clock
                }
            }
        }
        let record = Record {
            id: old.id,
            kind,
            fields,
            deleted_at: old.deleted_at,
            clock,
            device_id: self.meta.device_id,
            modified_at: now(),
            share_id: old.share_id,
        };
        self.append(&record)?;
        Ok(())
    }

    /// Delete a record by name: appends a tombstone.
    pub fn remove(&mut self, kind: Kind, name_field: &str, name: &str) -> Result<(), VaultError> {
        let old = self
            .find(kind, name_field, name)
            .ok_or_else(|| VaultError::NoSuchRecord {
                kind: kind_str(kind),
                name: name.into(),
            })?;
        let id = old.id;
        let share_id = old.share_id;
        let clock = self.next_clock()?;
        let tomb = Record {
            id,
            kind: Kind::Tombstone,
            fields: BTreeMap::new(),
            deleted_at: Some(clock),
            clock,
            device_id: self.meta.device_id,
            modified_at: now(),
            share_id,
        };
        self.append(&tomb)
    }

    // ---- log ---------------------------------------------------------------

    /// Seal a record under its share's current key and append it to the log;
    /// merge it into in-memory state.
    fn append(&mut self, record: &Record) -> Result<(), VaultError> {
        let entry_id = Uuid::new_v4();
        let plain = Zeroizing::new(
            rmp_serde::to_vec_named(record).map_err(|e| VaultError::Corrupt(e.to_string()))?,
        );
        let key = Zeroizing::new(
            self.keyring
                .current_for(&record.share_id.into_bytes())
                .ok_or_else(|| VaultError::Corrupt("sealing under a share not held".into()))?,
        );
        let blob = crypto::seal(&key, &plain, entry_id.as_bytes());
        self.write_frame(entry_id.as_bytes(), &blob)?;
        self.state
            .entry(record.id)
            .and_modify(|cur| *cur = merge::merge(cur, record))
            .or_insert_with(|| record.clone());
        Ok(())
    }

    /// Append one raw frame (`u32 len || entry_id(16) || blob`) to the log,
    /// under the exclusive lock so a concurrent reader never sees a torn frame.
    fn write_frame(&self, entry_id: &[u8; 16], blob: &[u8]) -> Result<(), VaultError> {
        let _lock = self.lock(true)?;
        self.write_frame_inner(entry_id, blob)
    }

    /// Append one raw frame; caller already holds the exclusive lock.
    fn write_frame_inner(&self, entry_id: &[u8; 16], blob: &[u8]) -> Result<(), VaultError> {
        let mut frame = Vec::with_capacity(4 + 16 + blob.len());
        frame.extend_from_slice(&((16 + blob.len()) as u32).to_le_bytes());
        frame.extend_from_slice(entry_id);
        frame.extend_from_slice(blob);
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join(LOG))?;
        f.write_all(&frame)?;
        f.sync_all()?;
        Ok(())
    }

    /// Decrypt and fold the whole log into state. Entries this device can't open
    /// (a share it isn't a member of) are skipped, not fatal.
    /// ponytail: full replay on open; add snapshot/compaction past ~10k entries
    fn replay_log(&mut self) -> Result<(), VaultError> {
        let frames = {
            let _lock = self.lock(false)?;
            let mut data = Vec::new();
            fs::File::open(self.dir.join(LOG))?.read_to_end(&mut data)?;
            parse_frames(&data)?
        };
        let mut records = Vec::with_capacity(frames.len());
        for (id, blob) in &frames {
            if let Some(rec) = self.open_entry(id, blob)? {
                records.push(rec);
            }
        }
        self.state = merge::merge_all(&records);
        Ok(())
    }

    /// Decrypt one log entry by trying every key this device holds — each share,
    /// newest epoch first. An entry was sealed under exactly one key and AEAD
    /// authentication makes the match unambiguous. Returns `Ok(None)` if no held
    /// key opens it (an entry for a share this device is not a member of), which
    /// is a legitimate skip, not corruption. `Err` only on a decrypt that opened
    /// but produced unparseable plaintext.
    fn open_entry(&self, entry_id: &[u8; 16], blob: &[u8]) -> Result<Option<Record>, VaultError> {
        for share in &self.keyring.shares {
            for k in share.keys.iter().rev() {
                let key = Zeroizing::new(*k);
                if let Ok(plain) = crypto::open(&key, blob, entry_id) {
                    let rec = rmp_serde::from_slice(&plain)
                        .map_err(|e| VaultError::Corrupt(format!("log entry: {e}")))?;
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }

    // ---- sync surface (Phase 3) --------------------------------------------

    pub fn vault_id(&self) -> Uuid {
        self.meta.vault_id
    }
    pub fn device_id(&self) -> Uuid {
        self.meta.device_id
    }
    /// This device's Ed25519 public key (relay identity / auth).
    pub fn ed25519_pub(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }
    pub fn relay_url(&self) -> Option<&str> {
        self.meta.relay_url.as_deref()
    }
    pub fn set_relay_url(&mut self, url: &str) -> Result<(), VaultError> {
        let _lock = self.lock(true)?;
        self.absorb_disk_meta();
        self.meta.relay_url = Some(url.to_string());
        self.write_meta()
    }
    /// Highest relay sequence number this device has pulled.
    pub fn sync_cursor(&self) -> u64 {
        self.meta.sync_cursor
    }
    pub fn set_sync_cursor(&mut self, cursor: u64) -> Result<(), VaultError> {
        let _lock = self.lock(true)?;
        self.absorb_disk_meta();
        // The cursor only ever advances; never let a stale caller move it back.
        self.meta.sync_cursor = self.meta.sync_cursor.max(cursor);
        self.write_meta()
    }

    /// Rewind the pull cursor to 0 so the next pull re-fetches from the start.
    /// Used after a share grant: entries the relay filtered out while we were a
    /// non-member were never stored locally, so we must re-pull them. Dedup by
    /// entry_id makes the re-pull idempotent. This is the one legitimate cursor
    /// regression (membership grew), so it bypasses the monotonic guard.
    pub fn reset_sync_cursor(&mut self) -> Result<(), VaultError> {
        let _lock = self.lock(true)?;
        self.absorb_disk_meta();
        self.meta.sync_cursor = 0;
        self.write_meta()
    }

    /// Raw log frames `(entry_id, sealed_blob)` — no decryption. Feeds push.
    pub fn raw_entries(&self) -> Result<Vec<RawEntry>, VaultError> {
        let _lock = self.lock(false)?;
        let mut data = Vec::new();
        fs::File::open(self.dir.join(LOG))?.read_to_end(&mut data)?;
        parse_frames(&data)
    }

    /// Raw frames tagged with each entry's share id, for share-routed push. For a
    /// frame this device can open, the real share id is read from the plaintext;
    /// for a retained foreign-share frame it can't open, the id is unknown so nil
    /// is reported — harmless, because such a frame already exists on the relay
    /// (a member pushed it) and the re-push is an `INSERT OR IGNORE` no-op.
    pub fn raw_entries_tagged(&self) -> Result<Vec<TaggedEntry>, VaultError> {
        let frames = self.raw_entries()?;
        let mut out = Vec::with_capacity(frames.len());
        for (id, blob) in frames {
            let share = self
                .open_entry(&id, &blob)?
                .map(|r| r.share_id)
                .unwrap_or_else(Uuid::nil);
            out.push((id, blob, share));
        }
        Ok(out)
    }

    /// Apply a sealed entry pulled from the relay: decrypt (proves it belongs to
    /// this vault), append to the log, merge into state, and advance the local
    /// lamport past the incoming clock so future local writes stay causally after
    /// what we've observed. Caller must skip entry_ids already present locally.
    pub fn apply_remote_entry(
        &mut self,
        entry_id: &[u8; 16],
        blob: &[u8],
    ) -> Result<(), VaultError> {
        let opened = self.open_entry(entry_id, blob)?;
        let _lock = self.lock(true)?;
        self.absorb_disk_meta();
        // Persist the frame regardless: if this is a share we're not (yet) a
        // member of, we retain the ciphertext so a later grant + replay picks it
        // up. We just can't merge it into state or read its clock now.
        self.write_frame_inner(entry_id, blob)?;
        if let Some(rec) = opened {
            let incoming = rec.clock.lamport;
            self.state
                .entry(rec.id)
                .and_modify(|cur| *cur = merge::merge(cur, &rec))
                .or_insert(rec);
            if incoming > self.meta.lamport {
                self.meta.lamport = incoming;
            }
        }
        self.write_meta()?;
        Ok(())
    }

    // ---- export / import ---------------------------------------------------

    /// Plaintext JSON export — the user owns their data.
    pub fn export_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "hosts": self.list::<crate::record::Host>(Kind::Host).into_iter().map(|(_, p)| p).collect::<Vec<_>>(),
            "snippets": self.list::<crate::record::Snippet>(Kind::Snippet).into_iter().map(|(_, p)| p).collect::<Vec<_>>(),
            "forwards": self.list::<crate::record::PortForward>(Kind::PortForward).into_iter().map(|(_, p)| p).collect::<Vec<_>>(),
            "keys": self.list::<crate::record::KeyMeta>(Kind::KeyMeta).into_iter().map(|(_, p)| p).collect::<Vec<_>>(),
        })
    }

    /// Import a JSON export. Existing names are skipped (no overwrite); returns
    /// (imported, skipped) counts.
    pub fn import_json(&mut self, json: &serde_json::Value) -> Result<(usize, usize), VaultError> {
        let mut imported = 0usize;
        let mut skipped = 0usize;
        macro_rules! import_kind {
            ($key:literal, $ty:ty, $kind:expr, $name_field:literal, $name:ident) => {
                for item in json
                    .get($key)
                    .and_then(|v| v.as_array())
                    .unwrap_or(&Vec::new())
                {
                    let payload: $ty = serde_json::from_value(item.clone())
                        .map_err(|e| VaultError::Corrupt(format!("import {}: {e}", $key)))?;
                    match self.add($kind, $name_field, &payload.$name.clone(), &payload) {
                        Ok(_) => imported += 1,
                        Err(VaultError::Duplicate { .. }) => skipped += 1,
                        Err(e) => return Err(e),
                    }
                }
            };
        }
        import_kind!("hosts", crate::record::Host, Kind::Host, "alias", alias);
        import_kind!(
            "snippets",
            crate::record::Snippet,
            Kind::Snippet,
            "name",
            name
        );
        import_kind!(
            "forwards",
            crate::record::PortForward,
            Kind::PortForward,
            "name",
            name
        );
        import_kind!("keys", crate::record::KeyMeta, Kind::KeyMeta, "name", name);
        Ok((imported, skipped))
    }

    // ---- internals ----------------------------------------------------------

    /// Advisory inter-process lock on the vault directory (blocking; released
    /// when the returned handle drops). `syncd` made concurrent vault access by
    /// multiple sshvault processes the normal case, so every meta.json write
    /// and every log.bin read/append synchronizes here: exclusive for writers,
    /// shared for readers (a reader must never observe a half-written frame).
    fn lock(&self, exclusive: bool) -> Result<fs::File, VaultError> {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(LOCK))?;
        if exclusive {
            f.lock()?;
        } else {
            f.lock_shared()?;
        }
        Ok(f)
    }

    /// Fold the strictly-increasing counters from the on-disk meta into ours.
    /// A stale in-memory copy (a daemon round spans network awaits; a CLI open
    /// spans the Argon2 KDF) must never roll back another process's lamport or
    /// cursor — reused clocks break merge convergence permanently. Callers must
    /// hold the exclusive lock.
    fn absorb_disk_meta(&mut self) {
        if let Ok(s) = fs::read_to_string(self.dir.join(META)) {
            if let Ok(disk) = serde_json::from_str::<Meta>(&s) {
                self.meta.lamport = self.meta.lamport.max(disk.lamport);
                self.meta.sync_cursor = self.meta.sync_cursor.max(disk.sync_cursor);
            }
        }
    }

    /// Next lamport clock for a local mutation; persisted before use so a crash
    /// can't reuse a clock value.
    fn next_clock(&mut self) -> Result<Clock, VaultError> {
        let _lock = self.lock(true)?;
        self.absorb_disk_meta();
        self.meta.lamport += 1;
        self.write_meta()?;
        Ok(Clock {
            lamport: self.meta.lamport,
            device: self.meta.device_id,
        })
    }

    fn write_meta(&self) -> Result<(), VaultError> {
        atomic_write(
            &self.dir.join(META),
            serde_json::to_string_pretty(&self.meta)
                .expect("meta serializes")
                .as_bytes(),
        )
    }

    fn write_keyring(&self) -> Result<(), VaultError> {
        let plain =
            Zeroizing::new(rmp_serde::to_vec_named(&self.keyring).expect("keyring serializes"));
        let sealed = crypto::seal(&self.kek, &plain, self.meta.vault_id.as_bytes());
        atomic_write(&self.dir.join(KEYRING), &sealed)
    }
}

fn derive_kek(meta: &Meta, passphrase: &str) -> Result<Secret32, VaultError> {
    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &meta.kdf.salt_b64,
    )
    .map_err(|e| VaultError::Corrupt(format!("kdf salt: {e}")))?;
    Ok(crypto::derive_kek(
        passphrase.as_bytes(),
        &salt,
        meta.kdf.m_kib,
        meta.kdf.t,
        meta.kdf.p,
    )?)
}

/// Reject anything that smells like private key material (non-negotiable v0.1
/// invariant: private keys never enter the vault). Checks every string field.
fn validate_payload<T: Serialize>(kind: Kind, payload: &T) -> Result<(), VaultError> {
    let value = serde_json::to_value(payload).expect("payloads are plain structs");
    let mut stack = vec![&value];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::String(s) => {
                if s.contains("PRIVATE KEY") {
                    return Err(VaultError::PrivateKeyMaterial(format!(
                        "a {} field",
                        kind_str(kind)
                    )));
                }
                // ssh_config injection guard: field values become config tokens
                if s.contains('\n') || s.contains('\r') {
                    return Err(VaultError::InvalidField {
                        field: "value",
                        reason: "newlines are not allowed".into(),
                    });
                }
                // quotes can't be escaped inside ssh_config quoted tokens;
                // snippets never reach ssh_config so they may contain anything
                if kind != Kind::Snippet && s.contains('"') {
                    return Err(VaultError::InvalidField {
                        field: "value",
                        reason: "double quotes are not allowed".into(),
                    });
                }
            }
            serde_json::Value::Array(a) => stack.extend(a),
            serde_json::Value::Object(o) => stack.extend(o.values()),
            _ => {}
        }
    }
    Ok(())
}

/// Split raw log bytes into `(entry_id, sealed_blob)` frames without decrypting.
fn parse_frames(data: &[u8]) -> Result<Vec<RawEntry>, VaultError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if len < 16 || off + len > data.len() {
            return Err(VaultError::Corrupt("truncated log frame".into()));
        }
        let id: [u8; 16] = data[off..off + 16].try_into().unwrap();
        let blob = data[off + 16..off + len].to_vec();
        out.push((id, blob));
        off += len;
    }
    if off != data.len() {
        return Err(VaultError::Corrupt("trailing bytes in log".into()));
    }
    Ok(out)
}

/// Split a concatenated epoch key-list (`epoch0 || epoch1 || …`) into 32-byte
/// keys. Rejects a length that is not a positive multiple of 32.
fn split_key_list(list: &[u8]) -> Result<Vec<[u8; 32]>, VaultError> {
    if list.is_empty() || !list.len().is_multiple_of(32) {
        return Err(VaultError::Corrupt("malformed vault key list".into()));
    }
    Ok(list
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect())
}

fn kind_str(kind: Kind) -> &'static str {
    match kind {
        Kind::Host => "host",
        Kind::Snippet => "snippet",
        Kind::PortForward => "port-forward",
        Kind::KeyMeta => "key",
        Kind::ShareName => "share",
        Kind::Tombstone => "record",
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).ok()
}

/// Write via temp file + rename so a crash never leaves a half-written file.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    restrict_permissions(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// chmod 700 for dirs / 600 for files — vault data is secret-adjacent.
fn restrict_permissions(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Host, KeyMeta, Snippet};
    use tempfile::TempDir;

    fn test_vault() -> (TempDir, Vault) {
        // fast KDF for tests: init with defaults would take ~0.5 s per test
        let tmp = TempDir::new().unwrap();
        let (mut vault, _phrase) = Vault::init(tmp.path(), "test-device", "pw").unwrap();
        vault.meta.kdf = KdfParams {
            salt_b64: vault.meta.kdf.salt_b64.clone(),
            m_kib: 8,
            t: 1,
            p: 1,
        };
        // kdf params just changed; refresh the cached KEK to match before rewrite
        vault.kek = derive_kek(&vault.meta, "pw").unwrap();
        vault.write_keyring().unwrap();
        vault.write_meta().unwrap();
        (tmp, vault)
    }

    fn host(alias: &str) -> Host {
        Host {
            alias: alias.into(),
            hostname: Some(format!("{alias}.example.com")),
            ..Default::default()
        }
    }

    #[test]
    fn init_refuses_to_overwrite() {
        let (tmp, _v) = test_vault();
        assert!(matches!(
            Vault::init(tmp.path(), "x", "pw"),
            Err(VaultError::AlreadyExists(_))
        ));
    }

    #[test]
    fn crud_persists_across_reopen() {
        let (tmp, mut v) = test_vault();
        v.add(Kind::Host, "alias", "web", &host("web")).unwrap();
        v.add(
            Kind::Snippet,
            "name",
            "logs",
            &Snippet {
                name: "logs".into(),
                command: "tail -f /var/log/syslog".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut edited = host("web");
        edited.port = Some(2222);
        v.edit(Kind::Host, "alias", "web", &edited).unwrap();
        v.remove(Kind::Snippet, "name", "logs").unwrap();
        drop(v);

        let v = Vault::open(tmp.path(), "pw").unwrap();
        let hosts = v.list::<Host>(Kind::Host);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].1.port, Some(2222));
        assert!(
            v.list::<Snippet>(Kind::Snippet).is_empty(),
            "removed snippet stays gone"
        );
    }

    #[test]
    fn wrong_passphrase_fails_opaquely() {
        let (tmp, v) = test_vault();
        drop(v);
        assert!(matches!(
            Vault::open(tmp.path(), "wrong"),
            Err(VaultError::Crypto(CryptoError::Decrypt))
        ));
    }

    #[test]
    fn duplicate_and_missing_names_are_rejected() {
        let (_tmp, mut v) = test_vault();
        v.add(Kind::Host, "alias", "web", &host("web")).unwrap();
        assert!(matches!(
            v.add(Kind::Host, "alias", "web", &host("web")),
            Err(VaultError::Duplicate { .. })
        ));
        assert!(matches!(
            v.remove(Kind::Host, "alias", "nope"),
            Err(VaultError::NoSuchRecord { .. })
        ));
    }

    #[test]
    fn private_key_material_is_rejected() {
        let (_tmp, mut v) = test_vault();
        let bad = KeyMeta {
            name: "oops".into(),
            public_key: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
            ..Default::default()
        };
        assert!(matches!(
            v.add(Kind::KeyMeta, "name", "oops", &bad),
            Err(VaultError::PrivateKeyMaterial(_))
        ));
    }

    #[test]
    fn newlines_in_fields_are_rejected() {
        let (_tmp, mut v) = test_vault();
        let mut h = host("evil");
        h.hostname = Some("x\nProxyCommand curl attacker".into());
        assert!(matches!(
            v.add(Kind::Host, "alias", "evil", &h),
            Err(VaultError::InvalidField { .. })
        ));
    }

    #[test]
    fn export_import_round_trip() {
        let (_tmp, mut v) = test_vault();
        v.add(Kind::Host, "alias", "web", &host("web")).unwrap();
        let json = v.export_json();

        let tmp2 = TempDir::new().unwrap();
        let (mut v2, _) = Vault::init(tmp2.path(), "d2", "pw2").unwrap();
        let (imported, skipped) = v2.import_json(&json).unwrap();
        assert_eq!((imported, skipped), (1, 0));
        assert_eq!(v2.list::<Host>(Kind::Host)[0].1.alias, "web");
        // re-import skips duplicates
        assert_eq!(v2.import_json(&json).unwrap(), (0, 1));
    }

    #[test]
    fn field_level_clocks_only_bump_changed_fields() {
        let (_tmp, mut v) = test_vault();
        v.add(Kind::Host, "alias", "web", &host("web")).unwrap();
        let mut edited = host("web");
        edited.user = Some("deploy".into());
        v.edit(Kind::Host, "alias", "web", &edited).unwrap();
        let rec = v.find(Kind::Host, "alias", "web").unwrap();
        let alias_clock = rec.fields["alias"].clock;
        let user_clock = rec.fields["user"].clock;
        assert!(
            user_clock > alias_clock,
            "only the changed field gets the new clock"
        );
    }

    #[test]
    fn stale_handle_never_rolls_back_the_lamport() {
        // Model two sshvault processes sharing a vault dir: a long-lived handle
        // (e.g. syncd, whose in-memory meta predates the KDF-slow CLI open) must
        // never overwrite meta.json with a lamport behind what another process
        // has since committed. The lock + absorb_disk_meta path is what prevents
        // clock reuse and the permanent cross-device divergence it causes.
        let (tmp, mut stale) = test_vault();

        // A second handle onto the same dir advances the lamport several times.
        let mut fresh = Vault::open(tmp.path(), "pw").unwrap();
        for i in 0..5 {
            fresh
                .add(
                    Kind::Host,
                    "alias",
                    &format!("h{i}"),
                    &host(&format!("h{i}")),
                )
                .unwrap();
        }
        let advanced = fresh.meta.lamport;
        assert!(advanced >= 5);

        // The stale handle still thinks the lamport is 0. Its next write must
        // fold in the on-disk value, not clobber it back to ~1.
        let clock = stale.next_clock().unwrap();
        assert!(
            clock.lamport > advanced,
            "stale writer bumped past the committed lamport ({} > {advanced})",
            clock.lamport
        );

        // And the persisted meta reflects the higher value, so a subsequent
        // open by either process sees a monotonic clock.
        let on_disk = Vault::open(tmp.path(), "pw").unwrap();
        assert!(on_disk.meta.lamport >= clock.lamport);
    }

    #[test]
    fn sync_cursor_never_regresses() {
        let (tmp, mut a) = test_vault();
        let mut b = Vault::open(tmp.path(), "pw").unwrap();
        a.set_sync_cursor(10).unwrap();
        // b is stale (cursor 0); advancing it to 5 must not roll disk back.
        b.set_sync_cursor(5).unwrap();
        let disk = Vault::open(tmp.path(), "pw").unwrap();
        assert_eq!(disk.meta.sync_cursor, 10, "cursor only advances");
    }
}
