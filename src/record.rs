//! Vault data model: encrypted record snapshots with per-field clocks.
//!
//! Every mutation appends one immutable [`Record`] snapshot to the log. Merge
//! (see [`crate::merge`]) folds snapshots into current state per record id.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Lamport clock with device-id tiebreak. Total order; ties impossible across
/// distinct operations (a device increments its counter on every mutation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Clock {
    pub lamport: u64,
    pub device: Uuid,
}

/// Record types. `Tombstone` marks deletion of any record id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    Tombstone, // ordered first so any live kind wins a (never-legit) kind conflict
    Host,
    Snippet,
    PortForward,
    KeyMeta,
    /// Private key material. The ONE kind permitted to carry a `PRIVATE KEY`
    /// blob into the vault (opt-in only; see `vault::validate_payload`). Still
    /// sealed under the share/vault key like every record, so the relay never
    /// sees plaintext. Never rendered to ssh_config.
    PrivateKey,
    /// Maps a share's human name to its id, so every default-share member can
    /// address a share by name. Names aren't secret (membership is), so this
    /// lives in the default share. Never rendered to ssh_config.
    ShareName,
}

/// One field of a record with the clock of its last write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub value: serde_json::Value,
    pub clock: Clock,
}

/// An immutable record snapshot. This is what gets MessagePack-encoded and
/// encrypted into a log entry (the relay never sees any of these fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub kind: Kind,
    /// Field name → value + last-writer clock.
    pub fields: BTreeMap<String, Field>,
    /// Deletion marker: set by tombstone entries, max-merged.
    pub deleted_at: Option<Clock>,
    /// Clock of the write that produced this snapshot.
    pub clock: Clock,
    /// Authoring device.
    pub device_id: Uuid,
    /// Unix seconds; informational only — never used for merge decisions.
    pub modified_at: u64,
    /// Which share (compartment) this record lives in. Nil = the default share
    /// every member holds. A record is sealed under its share's key; a device
    /// not in the share cannot decrypt it. Defaults to nil so pre-share records
    /// and single-user vaults need no migration.
    #[serde(default)]
    pub share_id: Uuid,
}

impl Record {
    /// A record is deleted iff its tombstone clock beats every field clock
    /// (i.e. the deletion is causally-later under lamport ordering).
    pub fn is_deleted(&self) -> bool {
        match self.deleted_at {
            None => false,
            Some(d) => self.fields.values().all(|f| f.clock < d),
        }
    }

    /// Extract the typed payload from the field map.
    pub fn payload<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        let map: serde_json::Map<String, serde_json::Value> = self
            .fields
            .iter()
            .map(|(k, f)| (k.clone(), f.value.clone()))
            .collect();
        serde_json::from_value(serde_json::Value::Object(map))
    }
}

/// Convert a typed payload into a field map, stamping every field with `clock`.
pub fn fields_from_payload<T: Serialize>(payload: &T, clock: Clock) -> BTreeMap<String, Field> {
    let serde_json::Value::Object(map) =
        serde_json::to_value(payload).expect("payloads are plain structs")
    else {
        unreachable!("payloads serialize to JSON objects")
    };
    map.into_iter()
        .map(|(k, value)| (k, Field { value, clock }))
        .collect()
}

// ---- typed payloads -------------------------------------------------------

/// An SSH host entry (maps to a `Host` block in ssh_config).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub alias: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `ProxyJump` target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_host: Option<String>,
    /// Reference to a key by name (see [`KeyMeta`]), rendered as `IdentityFile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// A reusable shell command template.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snippet {
    pub name: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Port-forward flavor, mirroring ssh's -L / -R / -D.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

/// A named port-forward definition attached to a host alias.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortForward {
    pub name: String,
    pub kind: ForwardKind,
    /// ssh forward spec, e.g. `8080:localhost:80` (or `1080` for dynamic).
    pub spec: String,
    /// Host alias this forward belongs to.
    pub host: String,
}

/// SSH key *metadata* — never private key material (enforced in `vault`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyMeta {
    pub name: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Host aliases that use this key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// Private key material — the one payload allowed to carry a PEM `PRIVATE KEY`
/// blob. Stored only via the explicit `key add-private` command and sealed like
/// any record. No `Debug` derive on `key_pem` is a concern only if logged; we
/// never log this struct. `public_key` is the optional matching `.pub`.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub name: String,
    pub key_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Maps a share's human name to its 16-byte id (base64). Lives in the default
/// share so every member can resolve a share name to its id locally.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShareName {
    pub name: String,
    pub share_id_b64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(n: u64) -> Clock {
        Clock {
            lamport: n,
            device: Uuid::nil(),
        }
    }

    #[test]
    fn payload_round_trips_through_fields() {
        let host = Host {
            alias: "web".into(),
            hostname: Some("web.example.com".into()),
            port: Some(2222),
            user: Some("deploy".into()),
            jump_host: None,
            identity_file: None,
            tags: vec!["prod".into()],
        };
        let fields = fields_from_payload(&host, clock(1));
        let rec = Record {
            id: Uuid::new_v4(),
            kind: Kind::Host,
            fields,
            deleted_at: None,
            clock: clock(1),
            device_id: Uuid::nil(),
            modified_at: 0,
            share_id: Uuid::nil(),
        };
        assert_eq!(rec.payload::<Host>().unwrap(), host);
    }

    #[test]
    fn deletion_requires_tombstone_beating_all_fields() {
        let mut rec = Record {
            id: Uuid::new_v4(),
            kind: Kind::Snippet,
            fields: fields_from_payload(
                &Snippet {
                    name: "x".into(),
                    command: "ls".into(),
                    ..Default::default()
                },
                clock(5),
            ),
            deleted_at: Some(clock(4)),
            clock: clock(5),
            device_id: Uuid::nil(),
            modified_at: 0,
            share_id: Uuid::nil(),
        };
        assert!(!rec.is_deleted(), "older tombstone loses to newer edit");
        rec.deleted_at = Some(clock(6));
        assert!(rec.is_deleted(), "newer tombstone wins");
    }

    #[test]
    fn msgpack_round_trip() {
        let rec = Record {
            id: Uuid::new_v4(),
            kind: Kind::PortForward,
            fields: fields_from_payload(
                &PortForward {
                    name: "db".into(),
                    kind: ForwardKind::Local,
                    spec: "5432:localhost:5432".into(),
                    host: "web".into(),
                },
                clock(9),
            ),
            deleted_at: None,
            clock: clock(9),
            device_id: Uuid::new_v4(),
            modified_at: 1234,
            share_id: Uuid::nil(),
        };
        let bytes = rmp_serde::to_vec_named(&rec).unwrap();
        let back: Record = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back, rec);
    }
}
