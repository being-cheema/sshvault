# sshvault architecture

Status: living document. Decisions recorded here override memory; deviations from the
original brief are in [Deviations](#deviations).

## Overview

sshvault is a single Rust binary that acts as both client CLI and relay server
(`sshvault serve`). A **vault** is an append-only log of encrypted records synced
through a zero-knowledge relay. All encryption/decryption happens client-side.

```
┌──────────┐  push/pull entries   ┌───────────┐   ┌──────────┐
│ device A │◄────────────────────►│   relay   │◄─►│ device B │
│ (laptop) │   {entry_id, blob}   │ axum+sqlite│  │ (desktop)│
└──────────┘      WebSocket       └───────────┘   └──────────┘
     │              notify              │
     ▼                                  ▼
~/.ssh/sshvault.conf         stores ciphertext only
```

## Crate layout

Single crate, lib + bin (`src/main.rs` is CLI dispatch only):

| module | contents | phase |
|---|---|---|
| `crypto` | key hierarchy, AEAD, Argon2id, recovery phrase, X25519 wrap, Ed25519 auth | 1 |
| `record` | `Record`, `Clock`, field maps, typed payloads (Host/Snippet/PortForward/KeyMeta) | 1 |
| `merge` | field-level LWW merge, tombstones | 2 |
| `vault` | local storage: meta file, keyring, append-only entry log, CRUD ops | 1 |
| `sshconfig` | `apply`: generate sshvault.conf, ensure `Include` | 1 |
| `relay` | axum server, SQLite storage, signed-request auth, WS notify | 3 |
| `sync` | client push/pull, syncd | 3 |
| `enroll` | device enrollment / approval / revocation / recovery | 4 |

## Data model

Every mutation appends an immutable **entry** to the log. An entry is one encrypted
`Record` snapshot:

```text
Record (plaintext, MessagePack):
  id:          Uuid            — stable record identity
  kind:        Host | Snippet | PortForward | KeyMeta | Tombstone
  fields:      BTreeMap<String, Field { value: msgpack Value, clock: Clock }>
  clock:       Clock           — record-level (max of field clocks; the clock for Tombstone)
  device_id:   Uuid            — author device
  modified_at: u64             — unix seconds, informational only (never used for merge)

Clock = (lamport: u64, device_id: Uuid)   — totally ordered, ties impossible
```

Typed payloads (`Host`, `Snippet`, …) are serde structs converted to/from the generic
field map, so **one** merge implementation covers all record types.

Wire/storage envelope (what the relay and the local log see):

```text
Entry { entry_id: Uuid, blob: nonce(24B) || XChaCha20-Poly1305(record, aad=entry_id) }
```

The relay never sees record ids, kinds, clocks, or field names — only `entry_id`
(random) and an opaque blob. See crypto-design.md for the AAD rationale.

## Merge (Phase 2)

Last-writer-wins **per field**, ordered by `(lamport, device_id)`:

- merged state of a record id = per-field max-clock value over all entries seen
- tombstone carries a record-level clock; the record is deleted iff
  `tombstone.clock > every field clock` — i.e. the deletion is (approximately)
  causally later. A concurrent edit with a higher clock survives, per spec.
- Merge is a pure fold over a *set* of entries: commutative, associative, idempotent
  (proptest-verified, 10k+ cases). Replays and reorderings are no-ops by construction.
- Deleted record ids are never reused; re-adding creates a fresh uuid.

Lamport clock: one counter per device, persisted in vault meta; incremented on every
local mutation; bumped to `max(local, observed)+1` when merging pulled entries.

## Local storage

`~/.local/share/sshvault/` (dirs crate; `$SSHVAULT_DIR` overrides for tests):

- `meta.json` — plaintext: vault id, device id, argon2 params + salt, device public
  keys, wrapped vault key, relay URL, lamport counter, sync cursor
- `keyring.enc` — vault key + device secret keys, encrypted under passphrase-derived KEK
- `log.bin` — append-only length-prefixed entry frames, same envelope as the wire

State is rebuilt by folding merge over decrypted log entries at startup.
<!-- ponytail: full log replay on open; add compaction/snapshot when logs exceed ~10k entries -->

## Sync protocol (Phase 3)

JSON over HTTP; every authenticated request is Ed25519-signed by the device. The
signature covers a timestamp bound into the signed message
(`signing_message(ts, body)` = `"<ts>\n<body>"`); the relay rejects any request
whose `ts` is outside a ±300 s window. POSTs carry a `Signed` JSON envelope
(`{vault_id, device_pub, ts, sig, body}`); the signed GETs carry the same fields
as query params. See `crypto-design.md` §"Relay request auth".

- `POST /v1/enroll` — register a device for a vault (first device bootstraps it)
- `POST /v1/push` — push `[{entry_id, blob}]`; relay dedupes on entry_id, assigns
  monotonic `seq`
- `GET /v1/pull?since=<seq>` — pull entries past the cursor; client persists cursor
- `GET /v1/ws` — WebSocket; relay broadcasts new `seq` (client then pulls)
- device lifecycle (Phase 4): `POST /v1/approve` · `POST /v1/revoke` ·
  `POST /v1/recover` · `GET /v1/devices` · `GET /v1/wrapped`

Server tables: `vaults`, `devices` (pubkeys, status, wrapped vault key), `entries`
(vault_id, seq, entry_id, blob). No plaintext columns; Phase 3 gate greps blobs.

Offline-first: all CLI ops touch only the local log; `sync` reconciles when reachable.
`sshvault syncd` follows the relay live: it subscribes to `/v1/ws` and runs a
push/pull round on every head announcement, with a 30 s fallback poll (that's what
pushes appends made by other local sshvault processes; overridable via
`SSHVAULT_SYNCD_POLL_SECS`), capped-exponential reconnect backoff that only resets
once a connection has held ≥30 s (so a flapping relay isn't hammered), and a
`Vault::reload` before each round. Concurrent sshvault processes on one machine are
safe: every meta.json write and log.bin read/append takes an advisory file lock
(`.lock`, exclusive for writers / shared for readers) and re-folds the on-disk
lamport + sync cursor before persisting, so a stale handle can never roll a counter
back and reuse a clock.

## Device lifecycle (Phase 4)

- **Enroll**: new device generates X25519+Ed25519 keypairs, uploads pending request,
  prints short verification code = first 6 words of a hash of its pubkeys.
- **Approve**: existing device fetches pending request, user compares code out-of-band,
  approver wraps vault key to the new device's X25519 key (ephemeral-static ECDH,
  see crypto-design.md) and uploads it. Server marks device active.
- **Revoke**: server marks device revoked → auth rejected on next sync; wrapped key
  deleted. v0.1 does **not** rotate the vault key (revoked device already knew it);
  honest note in threat-model.md.
- **Recover**: BIP39 phrase → vault key + recovery Ed25519 keypair; server stored the
  recovery public key at vault creation; a fresh device signs its enrollment with the
  recovery key and is auto-approved.

## CLI

clap derive. Surface per brief: `init`, `host|snippet|fwd add/edit/rm/list`,
`snippet run`, `apply`, `sync`, `syncd`, `device enroll|approve|list|revoke`,
`serve`, `export`, `import`. Errors: `thiserror` in lib modules, `anyhow` + context in
the CLI layer.

## Deviations

| brief said | doing instead | why |
|---|---|---|
| `sodiumoxide` deprecated → RustCrypto or age | RustCrypto + dalek crates | age adds envelope format we don't need; we need record-level AAD + raw X25519/Ed25519 anyway |
| WebSocket push | WebSocket (axum `ws` + tokio-tungstenite client) | as specified — deviation retracted once crates were fetchable |
| MessagePack or CBOR | MessagePack (`rmp-serde`) | as specified |
| dev-environment note | crates.io is firewalled in the working sandbox | user runs `cargo fetch`; all builds/tests run `--offline`; `cargo audit -n` against local advisory-db clone |

## Verification gates

Each phase ends with its gate from the brief; additionally every gate runs:
`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --offline`,
`cargo audit -n --db ~/.cargo/advisory-db`. CI (GitHub Actions) repeats all four
plus `cargo audit` with a fresh DB.
