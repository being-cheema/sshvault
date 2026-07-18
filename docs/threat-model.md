# sshvault threat model

What sshvault protects, what it does not, and the exact boundary between them. The
guiding property is **zero-knowledge relay**: the server stores only ciphertext and
non-secret routing metadata, and there is no server-side decryption path, ever.

## What is protected

- **Full server compromise.** An attacker who owns the relay — database, disk, process
  memory — learns only: opaque per-vault entry blobs, their sizes, their arrival
  timestamps, device public keys, and the recovery *public* key. No plaintext record,
  no vault key, no passphrase, no private key. See `crypto-design.md` for why the
  stored `recovery_pub` is non-secret.
- **Network attacker (passive or active).** All record contents are XChaCha20-Poly1305
  ciphertext before they reach the wire; the relay only ever relays ciphertext. Every
  authenticated call is Ed25519-signed over a timestamp bound into the signed message
  (`signing_message(ts, body)`), and the relay rejects any request whose timestamp is
  outside a ±300 s window. A MITM therefore cannot forge a request, and a captured
  signature is replayable only inside that window — and then only onto idempotent
  operations (immutable-entry push, reads, guarded approve/revoke), so a replay changes
  nothing. See `crypto-design.md` §"Relay request auth" for the exact envelope and the
  idempotency argument.
- **Stolen ciphertext at rest.** A dumped relay database or a stolen blob backup is
  inert without a device key or the recovery phrase. The local keyring is itself
  encrypted with an Argon2id-derived KEK, so a stolen laptop file (without the
  passphrase) is likewise inert.
- **Record swap / tamper / replay.** AEAD with `entry_id` as AAD plus id/type inside
  the authenticated plaintext defeats swapping one record's blob under another's id;
  any bit-flip fails the Poly1305 tag; immutable entries + idempotent merge make replay
  a no-op.

## What is NOT protected (be honest)

- **A compromised endpoint.** If an attacker controls a machine while its vault is
  unlocked, they have the plaintext and the vault key. No sync tool can fix a
  compromised endpoint; sshvault does not try to.
- **A malicious enrolled device.** Any device approved into a share holds that share's
  key and can read and write every record in it. Enrollment approval is the trust
  decision. Named **shares** compartmentalize *within* a vault — a device only holds the
  keys for shares it was granted, so a record in a share you're not a member of is opaque
  to you (the relay also won't hand you its ciphertext; see "Share metadata" below). But
  within a share there is no finer ACL: a member reads and writes all of it. The default
  share (records added with no `--share`) is held by every approved device, exactly as
  before shares existed. The approver identifies the joining device by a 32-bit short
  code (see below), so the approver must confirm that code out-of-band with the person
  operating the joining device — approving the wrong device hands it the vault key.
- **The recovery phrase.** Anyone who obtains the 24-word phrase can re-derive the vault
  key on a fresh machine and recover the entire vault. The phrase is a bearer secret;
  its protection is the user's responsibility.
- **Traffic analysis.** The relay sees blob sizes and timing. It can infer *that* a
  vault is active and roughly how much data changed, though not *what* changed.
- **Share shape (compartmentalization metadata).** With named shares the relay learns
  the *structure* of the split, because it routes ciphertext by membership: how many
  shares exist, which devices belong to which share, each share's entry count and epoch,
  and the share id stamped on every entry (cleartext routing metadata, like `entry_id`).
  It never learns share *names* (those live encrypted in the default share) or any record
  contents or keys. This is the honest cost of server-side membership filtering; the
  alternative — shipping every device every share's ciphertext — would hide the shape but
  waste bandwidth and still leak sizes. A share holder reading its data is never gated by
  the relay's view; membership filtering is a routing optimization, not the security
  boundary (the key is).
- **Named-share recovery.** The recovery phrase restores the **default share** only.
  Named-share keys are random (not phrase-derived — see `crypto-design.md`), so a device
  recovered from the phrase alone rejoins named shares only when a remaining member
  re-grants them. This is deliberate: a team share is not yours to unilaterally recover.
- **Availability.** A malicious or failed relay can withhold entries or refuse service.
  This is unavoidable for any sync server; sshvault stays offline-first so a missing
  relay never blocks local use, but it cannot force a hostile relay to deliver data.

## Device short code (the approval handle)

Approve/revoke name a device by a **32-bit** short code — the first 4 bytes of its
Ed25519 public key. It is a convenience handle for the human approving a join, not a
cryptographic identity:

- **It is not the authenticator.** Approval wraps the vault key for the target's *full*
  X25519 public key (bound to its full Ed25519 key via AAD); the 32-bit code only picks
  which enrolled device that is. A device cannot forge a short code into someone else's
  key material — at worst two devices share a code.
- **Collisions are detected, not silently resolved.** If two devices share a code, the
  approve/revoke call fails with `AmbiguousCode` rather than acting on the wrong one. So
  the residual risk is confusion/denial (retry needed), not a silent wrong-device grant.
- **Still verify out-of-band.** The code exists so two humans can confirm "the device I'm
  approving is the device you're joining with." Approving a device you can't vouch for
  hands it the whole vault (see "A malicious enrolled device" above).

## Device revocation semantics (read this carefully)

Revoking a device (`sshvault device revoke`) sets a sticky `revoked` flag on the relay.
Its concrete, honest effect:

- **Future sync is cut off.** The relay refuses every subsequent push, pull, and even
  re-enrollment from that device (HTTP 403). A revoked device cannot rejoin without a
  fresh approval, and the flag is sticky so it cannot revoke-then-re-enroll its way
  back in.
- **It does NOT un-know what the device already synced.** Revocation is access control
  at the relay, not retroactive secrecy. Any record the device pulled and decrypted
  before revocation is already plaintext in its possession; sshvault cannot reach into
  another machine and erase it. Assume a revoked device retained everything it ever saw.
- **It does NOT rotate the vault key by default.** Because every enrolled device
  shares one long-lived vault key, a plain `revoke` leaves the revoked device still
  *holding* that key. Any vault ciphertext it copied before revocation — including
  blobs it could pull from a relay it still has network access to snapshot — remains
  decryptable by it. Use `revoke --rotate` (below) to close this going-forward.

## Vault key rotation (`device revoke --rotate`)

`revoke --rotate` adds forward secrecy on top of revocation. It requires the recovery
phrase, because the new key is derived from the phrase seed (see `crypto-design.md`
§"Vault key epochs"). Its effect:

- **A new key epoch is minted.** The vault key becomes epoch-indexed: `revoke --rotate`
  derives `VK_{n+1} = HKDF(seed, epoch n+1)`, appends it to the key-list, and seals all
  subsequent writes under it. Old entries stay readable via the retained older keys, so
  no re-encryption of history is needed (and none is performed — see below).
- **The new key is re-wrapped for every *remaining* device, never the revoked one.**
  The rotating device wraps the new key-list (via the existing X25519 `wrap_vault_key`
  path) for each non-revoked device and hands the relay the epoch bump plus the
  per-device wrapped blobs in one signed call. A device that was offline during the
  rotation self-heals on its next sync: it fetches its re-wrapped key-list from the
  signed `/v1/wrapped` endpoint before pulling new-epoch entries, so being offline
  during a rotation is *not* a re-enrollment — no grace period, no manual step.
- **After rotation, records written under the new key are opaque to the revoked
  device.** This closes the going-forward gap.
- **It still does NOT recover already-synced plaintext.** Rotation is forward-only:
  anything the revoked device pulled and decrypted before revocation is already in its
  possession, and sshvault cannot reach into another machine to erase it. History is
  deliberately *not* re-encrypted under the new key — doing so would only deny the
  revoked device future pulls of old data it either already copied or never had, at the
  cost of rewriting the whole log. Assume a revoked device retained everything it saw.

**Forward protection requires key rotation.** To actually stop a revoked device from
reading data going forward, the vault key must be rotated: generate a new VK, encrypt
from-now-on records under it, and re-wrap the new VK for every *remaining* device via
the X25519 wrap path — never for the revoked one. This is what `revoke --rotate` does.
After rotation, records written under the new key are opaque to the revoked device. It
closes the going-forward gap but still cannot recover the already-synced plaintext above.

**Status:** plain `revoke` is access-control only (the flag + 403s). `revoke --rotate`
adds forward secrecy via phrase-derived key epochs and per-device re-wrapping. Neither
recovers plaintext a revoked device already pulled — for that, rotate the phrase and
re-init the vault.
