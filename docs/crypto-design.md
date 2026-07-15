# sshvault crypto design

Rule zero: **no custom cryptography.** Every construction below is a standard
composition of primitives from audited RustCrypto / dalek crates. This document
justifies each choice and pins the exact parameters.

## Crate choices

| purpose | crate | why this one |
|---|---|---|
| record AEAD | `chacha20poly1305` (XChaCha20-Poly1305) | RustCrypto, NCC-audited lineage; 192-bit nonce makes random-nonce-per-record safe (collision probability negligible at any realistic record count) |
| passphrase KDF | `argon2` (Argon2id) | RFC 9106 winner; id variant resists both side-channel and GPU attacks |
| key agreement | `x25519-dalek` (static + ephemeral) | de-facto standard X25519; `static_secrets` + `zeroize` features |
| signatures | `ed25519-dalek` | de-facto standard Ed25519 for device request auth |
| KDF (non-passphrase) | `hkdf` + `sha2` | standard HKDF-SHA256 for deriving subkeys from high-entropy input |
| recovery phrase | `bip39` | standard 24-word/256-bit mnemonic, English wordlist |
| zeroization | `zeroize` | all secret key material zeroized on drop |
| constant-time eq | `subtle` | verification-code and MAC-adjacent comparisons |

**Committed: raw RustCrypto, not `age`/rage.** `age` is *whole-file* envelope
encryption — one recipient-stanza header, then a single encrypted stream. Our unit
of sync is the *individual record*: each entry is sealed independently so devices can
push/pull/merge one record at a time (Phase 2/3). Wrapping every record as its own
`age` file would mean an X25519 recipient stanza per record (huge overhead) and still
leaves us needing raw X25519/Ed25519 for enrollment and request auth. So `age` would
be a second envelope format bolted on top of the same primitives we already use
directly — more surface, more bytes, no gain. The record format is therefore raw
`chacha20poly1305` + `x25519-dalek`, full stop. This decision is final for v0.1.

## Key hierarchy

```
BIP39 mnemonic (24 words, 256-bit entropy)         generated once at `init`
        │  PBKDF2-HMAC-SHA512 (standard BIP39 to_seed, empty passphrase)
        ▼
      seed (64B)
        ├── HKDF-SHA256(seed, info="sshvault/v1/vault-key")     → vault key VK (32B)
        └── HKDF-SHA256(seed, info="sshvault/v1/recovery-auth") → Ed25519 recovery keypair
```

- **VK** encrypts every record. Same VK for the life of the vault (v0.1; rotation is
  the v0.2 extension point).
- **Recovery keypair**: public half registered with the relay at vault creation; a
  fresh machine holding the phrase can re-derive it, sign an enrollment request, and
  be auto-approved (`sshvault recover`). The relay never sees the seed or VK.
- **Device keys** (generated per device, never derived from the phrase, never leave
  the machine): X25519 static keypair (receives wrapped VK) + Ed25519 keypair
  (signs relay requests).

## Decision: the recovery phrase directly derives the vault key

Two designs were possible for phrase-based recovery:

1. **Direct derivation** — the phrase *is* the root of the key hierarchy. VK is
   re-derived locally from the phrase every time (`keys_from_phrase`, above). The
   relay stores nothing that could unwrap the vault.
2. **Wrapped-blob** — the relay stores a copy of VK wrapped for a recovery key; a
   recovering device fetches that blob and unwraps it.

**We chose direct derivation.** Rationale:

- **Zero-knowledge stays clean.** With a wrapped blob the relay holds ciphertext of
  VK — still zero-knowledge in principle, but it's one more piece of key-shaped data
  on the server whose security rests on the wrap. Direct derivation means there is
  *no VK-derived material on the relay at all*, so there is simply nothing there to
  attack. Fewer secrets on the server is strictly better.
- **No extra construction to get right.** The wrapped-blob path needs its own
  wrap/rotate/re-store lifecycle (every VK rotation must re-wrap the recovery blob
  too). Direct derivation reuses the HKDF hierarchy we already have.
- **The phrase is high-entropy** (256-bit BIP39), so re-derivation is safe without a
  slow KDF — see the note below.

**What the relay *does* store for recovery, and why it's still zero-knowledge:** the
`vaults` table keeps the recovery Ed25519 **public** key (`recovery_pub`) so a
recovering device can prove phrase ownership (sign a challenge → relay maps the
signature to the right `vault_id`). A public key reveals nothing about VK or the seed;
it is exactly the kind of non-secret metadata a zero-knowledge relay is allowed to
hold. The relay never stores the seed, VK, or any wrapped copy of VK.

> **KDF note (as-built).** The recovery phrase feeds **HKDF-SHA256**, not Argon2id.
> Argon2id exists to stretch *low-entropy* human passphrases; the 24-word phrase
> already carries 256 bits of entropy, so a memory-hard KDF would add latency for no
> security gain. Argon2id is used only on the separate passphrase→KEK path (at-rest
> keyring encryption), where the input genuinely is low-entropy.

## At-rest protection (local keyring)

`keyring.enc` holds `{VK, device X25519 secret, device Ed25519 secret}` and is
encrypted with a KEK derived from the user passphrase:

- **Argon2id**, m = 64 MiB, t = 3, p = 1, salt = 16 B random, output = 32 B
  (RFC 9106 second recommended parameter set; ~0.5 s on a laptop).
  Params + salt stored in `meta.json` so they can be raised later without breaking
  old vaults.
- KEK encrypts the keyring with XChaCha20-Poly1305, random 24 B nonce,
  AAD = vault_id.

## Record encryption

For each log entry (an immutable record snapshot):

```
nonce   = 24 random bytes (OsRng)
blob    = nonce || XChaCha20-Poly1305_VK(nonce, msgpack(record), aad = entry_id)
wire    = { entry_id: random uuid, blob }
```

**AAD rationale.** The brief asks that AAD bind "record uuid + type" against
swap/replay. Record id and type live *inside* the authenticated plaintext (the relay
must not see them — zero-knowledge principle overrides). Binding `entry_id` as AAD
plus authenticating id/type as plaintext gives the same guarantees:

- *Swap*: presenting blob X under entry_id Y fails AEAD verification (AAD mismatch).
- *Tamper*: any bit-flip in id/type/fields fails the Poly1305 tag.
- *Replay*: entries are immutable and merge is idempotent/order-independent
  (Phase 2 property tests), so replaying or reordering entries is a no-op.
- What the relay *can* do is withhold entries (availability attack) — unavoidable for
  any sync server; documented in threat-model.md.

Nonce uniqueness: 192-bit random nonces; no counters, no state to corrupt. Collision
probability after 2^40 records ≈ 2^-113 — not a realistic concern (and the reason
XChaCha over ChaCha/AES-GCM with 96-bit nonces).

## Vault-key wrapping (device enrollment)

Ephemeral-static X25519 + HKDF + AEAD (the standard sealed-box/ECIES composition,
same shape as libsodium `crypto_box_seal`):

```
eph            = X25519 ephemeral keypair (approver side)
shared         = X25519(eph_secret, recipient_static_public)
wrap_key       = HKDF-SHA256(shared, info = "sshvault/v1/vk-wrap" || eph_pub || recipient_pub)
wrapped        = eph_pub || nonce || XChaCha20-Poly1305_wrap_key(VK, aad = recipient_device_id)
```

Recipient unwraps with `X25519(device_secret, eph_pub)`. Binding both public keys in
the HKDF info and the recipient device id in the AAD prevents cross-device replay of
wrapped keys.

## Relay request auth

Every mutating/reading relay call carries:

```
X-Device-Id: uuid
X-Timestamp: unix seconds        (rejected outside ±300 s)
X-Signature: base64(Ed25519(method || "\n" || path || "\n" || sha256(body) || "\n" || timestamp))
```

The relay stores only device public keys — nothing password-shaped. Signature
verification is constant-time inside ed25519-dalek. Replaying a captured request
within the window can only re-execute idempotent operations (push of immutable
entries, reads); revoke is idempotent too.
<!-- ponytail: no per-request nonce cache; add one if any non-idempotent endpoint appears -->

## Zeroization

`VK`, KEK, X25519/Ed25519 secrets, BIP39 seed, and passphrase buffers are wrapped in
zeroize-on-drop types (`zeroize::Zeroizing` / `ZeroizeOnDrop`). Secrets never appear
in `Debug` impls, logs, or error messages (enforced by clippy + Phase 5 self-review
checklist: nonce reuse, key material in logs/errors, non-constant-time comparisons).

## What private keys never do (v0.1)

SSH **private key material is never read, stored, or transmitted**. `KeyMeta` records
hold name, public key, fingerprint, and host associations only. Enforced in code (no
API reads private key files) and by test: the vault store rejects a `KeyMeta` payload
containing a PEM/OPENSSH private-key header. Extension point for v0.2: an opt-in
encrypted private-key record type using the same envelope.
