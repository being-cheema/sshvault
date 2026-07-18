# sshvault

[![crates.io](https://img.shields.io/crates/v/sshvault.svg)](https://crates.io/crates/sshvault)
[![CI](https://github.com/being-cheema/sshvault/actions/workflows/ci.yml/badge.svg)](https://github.com/being-cheema/sshvault/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/sshvault.svg)](#license)

**End-to-end-encrypted sync for your SSH workflow** — hosts, `~/.ssh/config`
entries, snippets, and port-forwards, kept in sync across all your machines. One
small binary that is both the client CLI and the self-hostable relay server.

Think **1Password for your SSH setup**: you keep using `ssh` exactly as you do
today, but your host aliases, jump-hosts, snippets, and forwards follow you from
laptop to laptop — encrypted so the sync server never sees them in the clear.

### Is this for me?

- ✅ You live in the terminal and want your `ssh` config to sync across machines
  **without trusting a cloud provider** with it.
- ✅ You want a shared, encrypted set of hosts/snippets for a **team** (see shares).
- ✅ You want to **self-host** the sync relay, or trust that even a hosted one is
  zero-knowledge.
- ❌ You want a **GUI terminal, tabs, SFTP, or a mobile shell** — that's Termius /
  iTerm / your terminal emulator. sshvault is a config-and-secrets layer *under*
  `ssh`, not a terminal client. It never opens shells for you ([non-goals](docs/roadmap.md#explicit-non-goals)).

## Highlights

- **E2EE, zero-knowledge relay.** Every record is XChaCha20-Poly1305 ciphertext
  before it leaves your machine; the relay stores opaque blobs and device public
  keys, nothing password-shaped, no decryption path.
- **Offline-first.** All commands work against the local encrypted log; `sync`
  reconciles whenever a relay is reachable. Conflicts resolve with field-level
  last-writer-wins (property-tested: commutative, associative, idempotent).
- **Your `~/.ssh/config` stays yours.** `sshvault apply` writes a managed
  `sshvault.conf` and adds a single `Include` line — it never edits your config.
- **Multi-device with real revocation.** Enroll devices with an out-of-band short
  code; `device revoke --rotate` mints a new vault-key epoch for forward secrecy.
- **Team shares.** Named compartments visible only to their members; removing a
  member rotates the share key.
- **Private keys stay put.** Syncs key *metadata* only and actively rejects
  anything that looks like private key material.

See [docs/architecture.md](docs/architecture.md),
[docs/crypto-design.md](docs/crypto-design.md), and
[docs/threat-model.md](docs/threat-model.md) for the design.

## Install

**From crates.io** (needs a [Rust toolchain](https://rustup.rs), 1.89+):

```sh
cargo install sshvault
```

**Prebuilt binaries** — grab the archive for your platform from the
[latest release](https://github.com/being-cheema/sshvault/releases/latest),
unpack, and put `sshvault` on your `PATH`.

**From source:**

```sh
git clone https://github.com/being-cheema/sshvault
cd sshvault && cargo install --path .
```

**Docker** (handy for running the relay):

```sh
docker compose up -d          # builds + starts the relay on :8787, data in a named volume
```

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

Or watch it end-to-end: [`scripts/demo.sh`](scripts/demo.sh) runs the whole
quickstart — including two-device sync — against a local relay in a temp dir.

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

`device list` shows enrolled devices; `device revoke <code>` locks one out.
Add `--rotate` to also mint a new vault-key epoch so the revoked device cannot
read anything written afterward (forward secrecy — needs your recovery phrase).
See the revocation semantics in the [threat model](docs/threat-model.md).

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
