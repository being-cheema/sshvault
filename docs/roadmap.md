# sshvault roadmap (v0.2+)

Status: sketch, not commitment. v0.1 is done (see `architecture.md`). Everything
below preserves two invariants: **zero-knowledge relay** (the server never gains a
decryption path) and **no custom cryptography** (`crypto-design.md`, rule zero).

## v0.2 (next)

### Optional encrypted private-key sync

v0.1 rejects private key material outright (`vault.rs`: "refusing to store private
key material… v0.1 syncs key metadata only"); `crypto-design.md` already reserves
the extension point: "an opt-in encrypted private-key record type using the same
envelope." Approach: a new record kind, **opt-in per key** via an explicit flag
(`sshvault key add --sync-private`), each key wrapped separately under VK with the
same XChaCha20-Poly1305 + AAD envelope — the relay still sees only entry_id + blob,
so zero-knowledge is untouched. Hard part: the pull side — materializing the key to
disk with 0600 perms (or straight into ssh-agent) without ever logging or lingering
in temp files, and making the opt-in impossible to trip accidentally (the v0.1
rejection stays the default for `KeyMeta`).

### Windows support

The core is already close: std `File::lock` (MSRV 1.89) and the `dirs` crate are
cross-platform, and sqlite is bundled. What's actually missing: the two
`cfg(unix)` 0600 permission sites (`sshconfig.rs`, `vault.rs`) need a Windows ACL
equivalent, `apply` must be validated against Win32-OpenSSH (`ssh -G` gate), and CI
needs a `windows-latest` leg next to ubuntu. Hard part: permission semantics —
"private file" on NTFS is an ACL story, not a mode-bits story, and getting it wrong
silently is worse than not shipping.

### Team / multi-user vaults — DONE

Shipped as named **shares**. A share is a subset of records under its own key-list
(the default share, held by every device, is the nil share). Keys are wrapped per
member device via `wrap_vault_key`; the relay routes ciphertext per share and filters
pull by membership, learning only the share *shape* (never names or contents — see
`threat-model.md` "Share shape"). Membership removal rotates the share with a fresh
random key (`share remove`), reusing the VK-rotation mechanism + seen-sig cache. Named
shares use random keys (not phrase-derived), so recovery-from-phrase restores the
default share only; named shares are re-granted by a remaining member. No server-side
ACL: "any member manages", access = holding the key. See `crypto-design.md` §"Shares".
CLI: `sshvault share create|add|remove|list` and `host add --share <name>`.
ponytail: `--share` wired on `host add` only so far; snippet/forward/key add and
moving an existing record between shares are additive follow-ups.

### Mobile

The crate is already lib + bin, so the path is bindings (uniffi or similar) over
the existing vault/sync/crypto core — no protocol changes. Scope honestly:
read/copy hosts and snippets, run `sync`, and act as a `device approve` approver
(the out-of-band short-code check is exactly a phone-shaped job). Hard part:
key storage — the Argon2id passphrase KEK should be replaced or supplemented by
the platform keystore/secure enclave; and there is no background `syncd` on
mobile, so sync is foreground-only. `apply` is meaningless on a phone; not ported.

## Hardening / infrastructure

- **Vault key rotation on revoke. — DONE.** `revoke --rotate` mints a new
  phrase-derived VK epoch, re-wraps the new key-list for every *remaining* device
  via `wrap_vault_key`, and seals new writes under it; offline devices self-heal
  their key-list over `/v1/wrapped`. Old entries stay readable via retained epoch
  keys (trial-decrypt on replay), so history is *not* re-encrypted — rotation
  closes the going-forward gap only and never claims to recover plaintext a revoked
  device already pulled. See `crypto-design.md` §"Vault key epochs".
- **Seen-signature cache. — DONE** (shipped with rotation, which needs it).
  Persisted `seen_sigs` table gates the non-idempotent `/v1/rotate`; team-vault
  mutations will reuse it.
- **Log compaction / snapshots.** `vault.rs:428`: "ponytail: full replay on open;
  add snapshot/compaction past ~10k entries" (echoed in `architecture.md`).
  Design: periodically write the merged state as a snapshot entry set, truncate
  the log behind it. Hard part: proving the snapshot fold is byte-equivalent to
  the full replay (extend the existing merge proptests) and never dropping a
  tombstone another device still needs.
- **WS push for enrollment approval.** `device.rs:71`: "ponytail: fixed 2s poll;
  WS push is a v0.2 nicety." The enrolling device should learn of approval over
  the existing `/v1/ws` channel instead of polling `/v1/wrapped` every 2 s.
- **Seen-signature cache on the relay. — DONE** (see the rotation entry above).
- **Native TLS option for `serve`. — DONE.** `serve --tls-cert --tls-key` makes
  the relay terminate HTTPS itself (rustls/aws-lc-rs); without them it serves plain
  HTTP for a reverse proxy to front. See `self-hosting.md` §TLS. You bring the cert;
  the relay does not obtain or renew certificates.
- **Traffic-analysis padding.** `threat-model.md` concedes the relay sees blob
  sizes and timing. Bucketed padding of entry blobs is cheap and shrinks that
  channel; it will never fully close it, and the doc will keep saying so.

## Explicit non-goals

- **A terminal emulator or GUI client.** sshvault stays a CLI that feeds your
  existing `ssh` via the generated config. It will not open shells for you.
- **Replacing ssh or ssh-agent.** We generate config and (v0.2+) optionally move
  keys; the OpenSSH tools stay in charge of transport and auth.
- **Any server-side decryption feature.** No "web vault view," no relay-side
  search. If a feature needs the relay to read plaintext, the feature is wrong.
