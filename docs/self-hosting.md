# Self-hosting the relay

The relay is the `sshvault` binary itself (`sshvault serve`) — no separate server
build, no external database. It is a zero-knowledge blob store: run it anywhere you
can point a domain at, and read [threat-model.md](threat-model.md) for exactly what
a compromised relay does and does not get.

## Run it

```sh
sshvault serve --addr 0.0.0.0:8787 --db /var/lib/sshvault/relay.db
```

Defaults: `--addr 127.0.0.1:8787`, `--db sshvault-relay.db` (in the current
directory). The SQLite schema is created on first start; there is nothing to
provision. `GET /healthz` returns `ok` for liveness checks.

### Docker

A `Dockerfile` and `docker-compose.yml` at the repo root run the same command
(`sshvault serve --addr 0.0.0.0:8787 --db /data/relay.db`) with the database on a
`/data` volume:

```sh
docker compose up -d
```

The volume is the only state — see [Persistence & backup](#persistence--backup).

## What the relay stores

Three SQLite tables (`src/relay.rs`):

- `vaults` — vault id and the recovery *public* key (non-secret; see
  crypto-design.md).
- `devices` — per-device Ed25519/X25519 public keys, a human-readable name,
  approved/revoked flags, and the vault key wrapped (encrypted) for that device.
- `entries` — the opaque log: random entry ids, ciphertext blobs, and a monotonic
  `seq` cursor.

No plaintext records, no vault key, no passphrases, no decryption path. A full
relay compromise leaks blob sizes, timing, device public keys, and device names —
nothing else. See [threat-model.md](threat-model.md).

## TLS: put it behind a reverse proxy

The relay serves **plain HTTP** — it does not terminate TLS. E2EE means an on-path
attacker never sees record contents and cannot forge requests (every call is
Ed25519-signed with a ±300 s replay window), but plaintext HTTP still exposes
metadata the threat model already concedes to the relay — vault ids, device public
keys and names, blob sizes, timing — to *everyone on the path*, and an active MITM
can drop or withhold traffic at will. Terminate TLS in front:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

That single Caddyfile block gets automatic certificates and — important — proxies
the WebSocket upgrade on `/v1/ws` without extra config. `syncd` derives
`wss://…/v1/ws` from your `https://` relay URL, so if the proxy doesn't pass
WebSocket upgrades, live notifications silently degrade to the fallback poll. With
nginx you must forward the `Upgrade`/`Connection` headers on `/v1/ws` yourself.

Keep the relay bound to `127.0.0.1` when a proxy fronts it.

## Persistence & backup

All state is the one SQLite file given by `--db`. Back it up by stopping the relay
and copying the file, or live via `sqlite3 relay.db ".backup /path/backup.db"`.
The file is ciphertext and public keys only — a stolen backup is inert (see
threat-model.md), so backups can live anywhere.

What losing the file actually means:

- **Entries are recoverable.** Every client keeps the full encrypted log locally
  and pushes all of it on each sync; the relay dedupes on entry id. Any enrolled
  device repopulates the log.
- **Enrollment state is gone.** The `devices` and `vaults` tables are the relay's
  memory of who is approved. After a wipe every device gets 403 until it
  re-enrolls (`sshvault sync --relay <url>`); the first one to do so re-bootstraps
  the vault and must re-approve the rest (`device approve`). The recovery public
  key is re-recorded at re-bootstrap from the client's local metadata, so
  `sshvault recover` keeps working.
- **Sync cursors go stale.** `seq` restarts at 1 in a fresh database while clients
  still hold cursors pointing at the old head, so their pulls return nothing until
  the new head passes the old cursor. Harmless if all devices were already
  converged (each holds everything); devices that had diverged may not see each
  other's newer entries until then.

Restoring a backup avoids all of that. Prefer restore over re-bootstrap.

## Pointing clients at it

```sh
sshvault sync --relay https://relay.example.com   # enrolls + syncs; URL remembered
sshvault sync                                     # thereafter
sshvault syncd --apply                            # follow changes live
```

The URL is persisted in the vault metadata after first use. `device enroll` and
`recover` take `--relay` explicitly. `syncd` subscribes to `/v1/ws` and runs a
sync round on each change notification, with a 30 s fallback poll
(`SSHVAULT_SYNCD_POLL_SECS` overrides it).

## Resource expectations

Small. One binary, SQLite compiled in (no runtime sqlite dependency), a few tens
of MB of RSS. Work per request is one Ed25519 verify plus SQLite I/O; blobs are
SSH config records, i.e. bytes not megabytes. A vault syncing a few machines is
idle almost all the time. The smallest VPS you can rent — or a Raspberry Pi — is
plenty.

Honest limits (v0.1): the relay is multi-tenant and open — anyone who can reach it
can enroll a new vault and store blobs; there are no quotas or rate limits, and the
entry log is append-only with no compaction. Don't expose a relay URL you wouldn't
share.
