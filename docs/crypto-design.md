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

- **VK** encrypts every record. Epoch 0 is the original key; `revoke --rotate` mints
  later epochs (see §"Vault key epochs").
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
wrapped keys. The wrapped payload is the vault key (enrollment) or, after any rotation,
the whole epoch key-list (see below) — the wrap construction is payload-length-agnostic.

## Vault key epochs (rotation)

`revoke --rotate` gives forward secrecy by rotating VK. VK is not a single key but an
**epoch-indexed list**; the newest epoch encrypts new writes, older epochs stay in the
list so pre-rotation entries still decrypt.

```
VK_0 = HKDF-SHA256(seed, info = "sshvault/v1/vault-key")        // == the original key
VK_n = HKDF-SHA256(seed, info = "sshvault/v1/vault-key/{n}")    // n ≥ 1, minted on rotate
```

- **Epoch 0 is byte-identical to the pre-rotation derivation.** A vault that never
  rotates is exactly an epoch-0 vault; no migration, no format change.
- **Rotation is phrase-gated.** `VK_n` is derived from the BIP39 seed, so only the
  recovery-phrase holder can mint a new epoch. This is why `revoke --rotate` prompts for
  the phrase. It keeps the relay VK-free (direct-derivation property, above) across
  rotations: recovery from the phrase alone still reaches *every* epoch.
- **No epoch tag on the wire or on disk.** A log entry carries no epoch marker; the
  reader trial-decrypts newest-epoch-first until the AEAD tag verifies (unambiguous at
  2^-128). So `WireEntry`, the relay `entries` table, and the on-disk log frame are all
  unchanged by rotation — the cost is at most (#epochs) trial-opens per entry on replay.
- **AAD is still just `entry_id`.** The key *is* the epoch selector; adding the epoch to
  the AAD would buy nothing (an attacker without a key cannot forge ciphertext under any
  epoch), so the record AEAD is unchanged.
- **Re-wrapping.** On rotate, the rotating device wraps the new epoch key-list (via the
  `wrap_vault_key` path above) for every *remaining* device and hands the relay the epoch
  bump + per-device wrapped blobs in one signed `/v1/rotate` call. Offline devices
  self-heal: each sync round first fetches its wrapped list from the signed
  `/v1/wrapped` endpoint and absorbs it if the relay epoch is ahead, before pulling
  new-epoch entries. History is never re-encrypted (see threat-model.md for why).

## Shares (compartments)

A **share** is a subset of records under its own key-list, readable only by its member
devices. Every record carries a `share_id` (nil = the default share, held by all
approved devices). Shares reuse the epoch machinery above verbatim — a share is just
another keyed container that can rotate:

- **The vault holds a per-share key-list**, keyed by 16-byte share id. Sealing a record
  uses its share's newest-epoch key; on replay a device trial-decrypts across *every*
  share key it holds (newest epoch first). An entry in a share the device isn't a member
  of simply doesn't open and is skipped — retained as ciphertext so a later grant + replay
  can read it, but never merged into state meanwhile.
- **Default share = phrase-derived; named shares = random.** The default share's keys are
  `VK_n` above (phrase-derived, so it's fully phrase-recoverable). A **named** share's keys
  are random 32-byte keys, *not* derived from the seed. This is forced, not chosen: any
  member must be able to rotate a named share when a member is removed, and members don't
  hold the recovery seed. The consequence is that phrase-only recovery restores the default
  share alone; named shares are re-granted by a remaining member (threat-model.md).
- **Granting** wraps the share's key-list for each new member via the same `wrap_vault_key`
  path (`POST /v1/share/grant`); the relay stores membership + opaque wrapped blobs and
  enforces no policy — holding the key *is* the authorization ("any member manages"). A
  caller who doesn't actually hold the share key can only store a wrap the target can't
  open, which grants nothing.
- **Removal rotates.** `share remove` mints a fresh random next-epoch key, re-wraps it for
  every *remaining* member, and drops the removed member's membership row
  (`POST /v1/share/rotate`, seen-sig gated + guarded epoch bump exactly like `/v1/rotate`).
  Forward-only: the removed device keeps whatever it already pulled.
- **The relay filters pull by membership** (an entry reaches a device iff its share is nil
  or the device has a membership row) as a routing optimization; the key, not the filter,
  is the security boundary. This is the one new metadata surface shares add — see
  threat-model.md "Share shape".

## Relay request auth

Every relay call that names a vault is Ed25519-signed by the calling device. The
signature is transported in a JSON envelope (`proto::Signed`) for POSTs, and as
query parameters for the two signed GETs (`/v1/pull`, `/v1/devices`, `/v1/wrapped`):

```
Signed {
  vault_id_b64          // which vault
  device_pub_b64        // the device verifying key
  ts                    // unix seconds when signed
  sig_b64               // Ed25519( signing_message(ts, body) )
  body                  // the request JSON (POST) or "<action>:<vault_b64>" / "pull:<since>" (GET)
}

signing_message(ts, body) = "<ts>\n<body>"      // ts is INSIDE the signed bytes
```

The relay (`relay::verify`) recomputes `signing_message(ts, body)`, checks the
signature against `device_pub`, and rejects any request whose `ts` is more than
`MAX_SKEW_SECS` (±300 s) from relay time. Because `ts` is bound *inside* the
signed message, an attacker cannot slide a captured signature forward by editing
the `ts` field — that invalidates the signature. A captured, still-valid envelope
is therefore replayable only within the ±300 s window.

The relay stores only device public keys — nothing password-shaped. Signature
verification is constant-time inside ed25519-dalek. Within the 300 s window a
replay can still re-execute the endpoint, so replay-safety rests on every
authenticated endpoint being **idempotent**: push inserts immutable entries
(`INSERT OR IGNORE` on a unique `entry_id`), pull and the signed GETs are reads,
approve is a guarded idempotent UPDATE (`WHERE revoked = 0`, so a replay can't
resurrect a revoked device), and revoke is a sticky idempotent UPDATE. No
authenticated endpoint has a non-idempotent side effect, so a within-window
replay is a no-op beyond what the original request already did.

`/v1/recover` is deliberately exempt from the `Signed` envelope: the recovering
device isn't enrolled yet, so it authenticates by signing its *freshly generated*
Ed25519 device key with the recovery key. Replaying that request only re-admits
the same device key its author already controls — no timestamp is needed to make
it safe.

**Seen-signature cache.** `/v1/rotate` is the first (and, until team vaults, only)
authenticated endpoint with a *non-idempotent* side effect — it advances an epoch
counter. The ±300 s window alone would let a captured rotate envelope be replayed once
more inside the window, so the relay keeps a persisted `seen_sigs(sig, expires_at)`
table (SQLite, so it survives restarts — a restart must not reopen the window) keyed on
the raw 64-byte signature, entries expiring after `MAX_SKEW_SECS`. `/v1/rotate` inserts
its signature and rejects a duplicate with 409. The epoch bump is *also* guarded
(`UPDATE … WHERE epoch = n-1`) so even a cache bypass can't double-advance. Idempotent
endpoints (push/pull/approve/revoke/reads) are not gated — they don't need it.

## Device short code (out-of-band verification)

`sshvault device approve/revoke <code>` identifies a target device by a **32-bit**
short code — the first 4 bytes of its Ed25519 public key, rendered as `aabb-ccdd`.
This is a human-readable handle for the approve/revoke UX, **not** a cryptographic
authenticator: the approver still wraps the vault key for the target's full
X25519/Ed25519 keys, and a code collision surfaces as an explicit "ambiguous code"
error (`EnrollError::AmbiguousCode`), never a silent wrong-device approval. Treat
the short code as a convenience label with collision *detection*, not a 128-bit
identity. See `threat-model.md` for the trust decision this sits inside.

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
