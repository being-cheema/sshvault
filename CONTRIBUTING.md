# Contributing

sshvault is a small single-maintainer project. PRs and issues are welcome; there
is no process beyond what's below.

## Dev setup

Stable Rust >= 1.89 (`rust-version` in Cargo.toml). No other system deps —
SQLite is compiled in via sqlx.

Before pushing, run the same four gates CI enforces
([.github/workflows/ci.yml](.github/workflows/ci.yml)):

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo audit          # cargo install cargo-audit
```

Note: the integration tests (`tests/sync_integration.rs`, `tests/syncd.rs`,
`tests/device_lifecycle.rs`, `tests/relay_replay.rs`) bind localhost sockets —
they grab a free port on 127.0.0.1 and run a real relay in-process. They need no
network access beyond loopback, but will fail in environments that forbid
binding sockets.

## Conventions

Read a module before patching it; the code is the reference. The rules it
follows:

- **Errors**: library modules (`crypto`, `vault`, `device`, ...) define typed
  errors with `thiserror`. The CLI (`main.rs`) and relay use `anyhow`; the CLI
  adds `.context()`/`.with_context()` so failures name the thing that failed.
- **No panics reachable from user input.** `unwrap()`/`expect()` are fine in
  tests and for internal invariants (e.g. slice-to-array conversions after an
  explicit bounds check), never on a path a malformed file, flag, or wire
  message can reach.
- **Docs**: every public fn in `crypto` and `merge` carries a doc comment.
  Keep that true for anything you add.
- **Key material** lives in `Zeroizing`/zeroize-derived types and is wiped on
  drop. Don't copy secrets into plain `Vec<u8>`/`[u8; 32]`.
- **No `unsafe`.** There is currently none in `src/`; a change that introduces
  it needs a very good reason and will probably be rejected.

## The catastrophic-bug zones: crypto and merge

A bug in `src/crypto.rs` can silently weaken every vault; a bug in
`src/merge.rs` can silently lose or resurrect records on sync. Changes to
either get extra scrutiny and **must** come with tests.

Property tests live in `tests/crypto_props.rs` and `tests/merge_props.rs`.
The merge is a semilattice join, and the proptest laws encode that:
**commutative**, **associative**, **idempotent**, and **no-resurrection**
(a tombstoned entry never comes back under any replay order). Any merge change
must keep all four passing at the configured case counts — if your change needs
a law relaxed, that's a design discussion, not a test edit.

## Security issues

Report vulnerabilities privately via
[GitHub security advisories](https://github.com/being-cheema/sshvault/security/advisories/new),
not as public issues. See [docs/threat-model.md](docs/threat-model.md) for what
sshvault does and does not defend against.

## License

By contributing you agree that your contributions are dual-licensed under
[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), like the rest of the
project, without any additional terms or conditions.
