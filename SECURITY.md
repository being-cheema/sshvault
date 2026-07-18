# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

sshvault handles cryptographic material and syncs your SSH configuration, so a
flaw can have real consequences. If you find one, report it privately:

- Use GitHub's [private vulnerability reporting](https://github.com/being-cheema/sshvault/security/advisories/new)
  (Security → Report a vulnerability), **or**
- email the maintainer at the address on the GitHub profile
  [@being-cheema](https://github.com/being-cheema).

Please include:

- a description of the issue and the impact you think it has,
- steps to reproduce (a proof-of-concept is ideal),
- affected version / commit, and platform.

You can expect an acknowledgement within a few days. We'll work with you on a
fix and a coordinated disclosure, and credit you in the release notes unless you
prefer to stay anonymous.

## Scope

sshvault's security rests on two invariants (see
[`docs/threat-model.md`](docs/threat-model.md) and
[`docs/crypto-design.md`](docs/crypto-design.md)):

1. **Zero-knowledge relay.** The server stores only ciphertext and non-secret
   routing metadata (device public keys, the recovery *public* key, opaque
   blobs, sizes, timestamps). Any path by which the relay could obtain plaintext,
   a vault key, a passphrase, or private key material is a critical bug.
2. **Standard cryptography only.** XChaCha20-Poly1305, X25519, Ed25519, HKDF-SHA256,
   Argon2id — from audited RustCrypto / dalek crates. No custom constructions.

Findings that break either invariant, or that fall under the documented threat
model, are in scope. The threat model is explicit about what sshvault does *not*
defend against (e.g. a compromised endpoint, or plaintext a revoked device
already pulled) — those are documented limitations, not vulnerabilities.

## Supported versions

sshvault is pre-1.0; security fixes land on the latest release. Until 1.0, only
the most recent published version is supported.
