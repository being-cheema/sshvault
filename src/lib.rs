//! sshvault — end-to-end-encrypted sync for SSH workflows.
//!
//! See `docs/architecture.md` for the design. Modules:
//! - [`crypto`] — key hierarchy and encryption primitives (audited crates only)
//! - [`record`] — the vault data model (encrypted record snapshots)
//! - [`merge`] — field-level last-writer-wins merge
//! - [`vault`] — local encrypted append-only storage + CRUD
//! - [`sshconfig`] — OpenSSH config generation (`sshvault apply`)
//! - [`proto`] — wire protocol shared by client and relay
//! - [`relay`] — the zero-knowledge sync server (`sshvault serve`)
//! - [`sync`] — client sync: enroll, push, pull (`sshvault sync`)
//! - [`device`] — device lifecycle: enroll, approve, revoke, recover

pub mod crypto;
pub mod device;
pub mod merge;
pub mod proto;
pub mod record;
pub mod relay;
pub mod sshconfig;
pub mod sync;
pub mod vault;
