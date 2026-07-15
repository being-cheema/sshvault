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
  mutating/reading call is Ed25519-signed with a timestamp, so a MITM cannot forge or
  usefully replay requests (replays land only on idempotent operations, within a ±300 s
  window).
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
- **A malicious enrolled device.** Any approved device holds the vault key and can read
  and write every record. Enrollment approval is the trust decision; there is no
  intra-vault compartmentalization in v0.1 (team/multi-user vaults are out of scope).
- **The recovery phrase.** Anyone who obtains the 24-word phrase can re-derive the vault
  key on a fresh machine and recover the entire vault. The phrase is a bearer secret;
  its protection is the user's responsibility.
- **Traffic analysis.** The relay sees blob sizes and timing. It can infer *that* a
  vault is active and roughly how much data changed, though not *what* changed.
- **Availability.** A malicious or failed relay can withhold entries or refuse service.
  This is unavoidable for any sync server; sshvault stays offline-first so a missing
  relay never blocks local use, but it cannot force a hostile relay to deliver data.

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
- **It does NOT rotate the vault key in v0.1.** Because every enrolled device shares one
  long-lived vault key, a revoked device still *holds* that key. Any vault ciphertext it
  copied before revocation — including blobs it could pull from a relay it still has
  network access to snapshot — remains decryptable by it forever. The relay refusing new
  requests does not change what the held key can open.

**Forward protection requires key rotation.** To actually stop a revoked device from
reading data going forward, the vault key must be rotated: generate a new VK, re-encrypt
(or from-now-on encrypt) records under it, and re-wrap the new VK for every *remaining*
device via the existing X25519 wrap path — never for the revoked one. After rotation,
records written under the new key are opaque to the revoked device. This closes the
going-forward gap but still cannot recover the already-synced plaintext above.

**v0.1 status:** revocation is access-control only (the flag + 403s). VK rotation and
re-wrapping is the planned v0.2 mechanism (the wrap primitive it needs,
`wrap_vault_key`, already exists — see `crypto-design.md`). Until then, treat revocation
as "this device can no longer *sync*," not "this device can no longer *read what it
already has*." Users who need the stronger guarantee today should rotate the phrase and
re-init the vault.
