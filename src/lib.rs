//! sshvault — end-to-end-encrypted sync for SSH workflows.
//!
//! See `docs/architecture.md` for the design. Modules:
//! - [`crypto`] — key hierarchy and encryption primitives (audited crates only)
//! - [`record`] — the vault data model (encrypted record snapshots)
//! - [`merge`] — field-level last-writer-wins merge
//! - [`vault`] — local encrypted append-only storage + CRUD
//! - [`sshconfig`] — OpenSSH config generation (`sshvault apply`)

pub mod crypto;
pub mod merge;
pub mod record;
pub mod sshconfig;
pub mod vault;
