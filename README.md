# sshvault

End-to-end-encrypted sync for your SSH workflow: hosts, config, snippets, and
port-forwards — one binary that is both the client CLI and the relay server.

- **E2EE, zero-knowledge relay.** Every record is XChaCha20-Poly1305 ciphertext
  before it leaves your machine; the relay stores opaque blobs and device public
  keys, nothing password-shaped, no decryption path.
- **Offline-first.** All commands work against the local encrypted log; `sync`
  reconciles whenever a relay is reachable. Conflicts resolve with field-level
  last-writer-wins (property-tested: commutative, associative, idempotent).
- **Your `~/.ssh/config` stays yours.** `sshvault apply` writes a managed
  `sshvault.conf` and adds a single `Include` line — it never edits your config.
- **Private keys never enter the vault.** v0.1 syncs key *metadata* only and
  actively rejects anything that looks like private key material.

See [docs/architecture.md](docs/architecture.md),
[docs/crypto-design.md](docs/crypto-design.md), and
[docs/threat-model.md](docs/threat-model.md) for the design.

## Quickstart

```sh
sshvault init                        # prints a 24-word recovery phrase — store it offline
sshvault host add web --hostname web.example.com --user deploy
sshvault snippet add logs 'journalctl -fu app' --description "tail app logs"
sshvault fwd add pg 5432:localhost:5432 --host web
sshvault apply                       # writes ~/.ssh/sshvault.conf + Include
ssh web                              # just works
sshvault snippet run logs
```

## Sync across machines

```sh
# somewhere reachable (or localhost to try it):
sshvault serve --addr 0.0.0.0:8787 --db relay.db

# first machine
sshvault sync --relay https://relay.example.com   # enrolls + syncs; URL is remembered
sshvault syncd --apply                            # optional: follow changes live

# second machine
sshvault device enroll --vault <vault-id> --relay https://relay.example.com
# it prints a short code; on the first machine:
sshvault device approve <code>
```

`device list` shows enrolled devices; `device revoke <code>` locks one out
(read the revocation semantics in the threat model — the vault key is not
rotated in v0.1).

Lost every device? `sshvault recover --relay <url>` + your recovery phrase
restores the vault on a fresh machine.

## Export / import

`sshvault export` prints your data as plaintext JSON (you own your data);
`sshvault import file.json` merges it back, skipping duplicates.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test          # unit + property tests (10k cases/law) + integration gates
cargo audit
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
