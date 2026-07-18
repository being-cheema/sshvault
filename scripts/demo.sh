#!/usr/bin/env bash
# demo.sh — the 60-second sshvault quickstart, end to end, against localhost.
#
# What it does: init a vault → add a host, snippet, and port-forward → apply to
# a throwaway .ssh dir → start a local relay → sync → enroll a second "machine"
# (a second SSHVAULT_DIR) → approve it → watch it converge.
#
# Everything lives in a mktemp dir; nothing touches ~/.ssh, your real vault, or
# any network beyond 127.0.0.1. The relay and its SQLite db are killed/removed
# on exit.
#
# Fully non-interactive: the CLI reads $SSHVAULT_PASSPHRASE before ever
# prompting (see passphrase()/prompt_new_passphrase() in src/main.rs), and
# `device enroll` prints its short approval code then polls the relay — so we
# capture the code from its output and approve it from machine A. No tty needed.
#
# Needs: bash, curl, and a built sshvault binary (builds one via cargo if
# target/release/sshvault is missing). Override the port with
# SSHVAULT_DEMO_PORT, pacing with DEMO_PAUSE (seconds between steps).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SSHVAULT_BIN:-$ROOT/target/release/sshvault}"
if [[ ! -x "$BIN" ]]; then
    echo "no binary at $BIN — building (cargo build --release)..."
    cargo build --release --manifest-path "$ROOT/Cargo.toml"
fi

PORT="${SSHVAULT_DEMO_PORT:-8787}"
RELAY="http://127.0.0.1:$PORT"
PAUSE="${DEMO_PAUSE:-1}"
PASS="demo-passphrase" # throwaway vault, throwaway passphrase

TMP="$(mktemp -d)"
A="$TMP/machine-a"
B="$TMP/machine-b"
SSH_DIR="$TMP/ssh" # stands in for ~/.ssh

RELAY_PID=""
ENROLL_PID=""
cleanup() {
    [[ -n "$ENROLL_PID" ]] && kill "$ENROLL_PID" 2>/dev/null || true
    [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

# ---- pretty-printed runners (echo each command, short pause after) -----------

say() {
    printf '\n\033[1;34m# %s\033[0m\n' "$*"
    sleep "$PAUSE"
}
run_a() {
    printf '\n\033[1;32m[machine-a]$ sshvault %s\033[0m\n' "$*"
    SSHVAULT_DIR="$A" SSHVAULT_PASSPHRASE="$PASS" "$BIN" "$@"
    sleep "$PAUSE"
}
run_b() {
    printf '\n\033[1;33m[machine-b]$ sshvault %s\033[0m\n' "$*"
    SSHVAULT_DIR="$B" SSHVAULT_PASSPHRASE="$PASS" "$BIN" "$@"
    sleep "$PAUSE"
}
# same as run_a/run_b but capture stdout instead of showing it
quiet_a() { SSHVAULT_DIR="$A" SSHVAULT_PASSPHRASE="$PASS" "$BIN" "$@"; }
quiet_b() { SSHVAULT_DIR="$B" SSHVAULT_PASSPHRASE="$PASS" "$BIN" "$@"; }

# ---- machine A: build a vault ------------------------------------------------

say "create a vault (passphrase supplied via \$SSHVAULT_PASSPHRASE)"
run_a init --device-name machine-a

say "add a host, a snippet, and a port-forward"
run_a host add web --hostname web.example.com --user deploy
run_a snippet add logs 'journalctl -fu app' --description "tail app logs"
run_a fwd add pg 5432:localhost:5432 --host web
run_a host list

say "apply: write the managed ssh config (demo uses a temp dir, not ~/.ssh)"
run_a apply --ssh-dir "$SSH_DIR"
printf '\n\033[1;32m[machine-a]$ cat %s/sshvault.conf\033[0m\n' "$SSH_DIR"
cat "$SSH_DIR/sshvault.conf"
sleep "$PAUSE"

# ---- relay -------------------------------------------------------------------

say "start a zero-knowledge relay on 127.0.0.1:$PORT (E2EE — it stores only opaque blobs)"
"$BIN" serve --addr "127.0.0.1:$PORT" --db "$TMP/relay.db" >"$TMP/relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 50); do
    curl -fsS "$RELAY/healthz" >/dev/null 2>&1 && break
    sleep 0.2
done
curl -fsS "$RELAY/healthz" >/dev/null 2>&1 || {
    echo "relay failed to start (is port $PORT free? set SSHVAULT_DEMO_PORT):"
    cat "$TMP/relay.log"
    exit 1
}
echo "relay up (pid $RELAY_PID)"

say "enroll machine A and push (first device is auto-approved; URL is remembered)"
run_a sync --relay "$RELAY"
run_a device list

# ---- machine B: second device joins and converges -----------------------------
# `device enroll` blocks polling the relay until an enrolled device approves it,
# printing "(code for THIS device: xxxx-xxxx)" first — so we background it,
# scrape the code from its output, and approve from machine A.

VAULT_ID="$(quiet_a device list | awk '/^vault:/ {print $2}')"

say "machine B joins the vault (background — it waits for approval)"
printf '\033[1;33m[machine-b]$ sshvault device enroll --vault %s --relay %s\033[0m\n' "$VAULT_ID" "$RELAY"
quiet_b device enroll --vault "$VAULT_ID" --relay "$RELAY" --device-name machine-b \
    >"$TMP/enroll.log" 2>&1 &
ENROLL_PID=$!

CODE=""
for _ in $(seq 1 100); do
    CODE="$(sed -n 's/.*code for THIS device: \([0-9a-f-]*\).*/\1/p' "$TMP/enroll.log" | head -n1)"
    [[ -n "$CODE" ]] && break
    sleep 0.2
done
[[ -n "$CODE" ]] || {
    echo "enroll never printed a short code:"
    cat "$TMP/enroll.log"
    exit 1
}
echo "machine B is pending with code: $CODE"
sleep "$PAUSE"

say "approve it from machine A (this wraps the vault key for machine B's X25519 key)"
run_a device approve "$CODE"

wait "$ENROLL_PID" # enroll polls every 2s; returns once the wrapped key lands
ENROLL_PID=""
cat "$TMP/enroll.log"
sleep "$PAUSE"

say "machine B syncs and has everything"
run_b sync
run_b host list
run_b snippet list
run_a device list

say "done — two devices, one E2EE vault, relay never saw plaintext"
