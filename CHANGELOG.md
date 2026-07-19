# Changelog

All notable changes to sshvault are documented here. Versions follow
[semantic versioning](https://semver.org); pre-1.0, minor versions may carry
new features and the occasional breaking change (called out explicitly).

## [0.2.0] — 2026-07-19

### Added
- **Native TLS for the relay.** `sshvault serve --tls-cert <pem> --tls-key <pem>`
  terminates HTTPS directly (rustls); without the flags the relay serves plain
  HTTP for a reverse proxy to front, as before. See `docs/self-hosting.md`.
- **Key management CLI.** `sshvault key add/edit/rm/list` manages public-key
  metadata (`KeyMeta`); `add`/`edit` read a `.pub` file and compute the OpenSSH
  `SHA256:` fingerprint (verified against `ssh-keygen -lf`).
- **Opt-in encrypted private-key sync.** `sshvault key add-private <name>
  --private <path>` stores a PEM private key sealed end-to-end like every record
  (same XChaCha20-Poly1305 + AAD envelope — the relay stays zero-knowledge);
  `sshvault key install <name>` materializes it to disk at mode 0600 (set at file
  creation, never a world-readable window), refusing to overwrite without
  `--force`. Private keys are still rejected by default for every other record
  kind — this is a narrow, explicit opt-in.
- **Log compaction.** Vaults past ~10k log entries now open fast via a KEK-sealed
  snapshot sidecar. The append-only log, its entry ids, and sync cursors are
  byte-identical after compaction (it is a local read optimization, not a log
  rewrite), and tombstones are never dropped.

### Security
- Fixed a path-injection found in adversarial review of private-key sync: a
  synced `PrivateKey` record with a crafted `name` (`config`, `../x`, or an
  absolute path) could have made `key install` overwrite an arbitrary file with
  attacker-controlled contents. The install destination derived from a record
  name is now constrained to a single plain filename under `~/.ssh`.

### Notes
- `cargo audit` clean. `rustls-pemfile` (transitive via `axum-server`) carries an
  "unmaintained" advisory (RUSTSEC-2025-0134) — informational, no vulnerability.

## [0.1.0] — 2026-07-18

Initial release: end-to-end-encrypted sync for SSH hosts, config, snippets, and
port-forwards; zero-knowledge relay; offline-first field-level LWW merge;
multi-device enrollment with forward-secret revocation (`revoke --rotate`) and
team shares; recovery from a 24-word phrase.
