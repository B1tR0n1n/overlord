#!/usr/bin/env bash
# OVERLORD adversarial suite — escape attempts against the jail.
# Every attack that lands becomes a fix and stays here as a regression test.
# Requires the kernel backend (jail); self-skips otherwise.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
export OVERLORD_HOME="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$OVERLORD_HOME" "$WORK"' EXIT

OVERLORD="python3 $HERE/overlord.py"
if command -v overlord > /dev/null && cmp -s /usr/local/lib/overlord/overlord.py "$HERE/overlord.py"; then
    OVERLORD="overlord"
fi
if ! $OVERLORD doctor 2>/dev/null | grep -q 'kernel backend.*: available'; then
    echo "SKIP: red team needs the kernel backend"
    exit 0
fi
echo "red team vs: $OVERLORD"

TARGET="$WORK/target"
FAILED=0
hold() {
    local msg="$1"
    echo "  HELD:     $msg"
    return 0
}
breach() {
    local msg="$1"
    echo "  BREACH:   $msg"
    FAILED=1
    return 0
}

reset_target() {
    rm -rf "$TARGET"
    mkdir -p "$TARGET"
    echo secret > "$TARGET/data.txt"
    return 0
}

# attack runner: executes CMD inside a jailed session, echoes its stdout, rolls back
attack() {
    local cmd="$1"
    local out sid
    reset_target
    out=$($OVERLORD run --jail -t "$TARGET" -- bash -c "$cmd" 2>/dev/null)
    sid=$(grep -oP 'session \K\S+' <<< "$out" | head -1)
    [[ -n "$sid" ]] && $OVERLORD rollback "$sid" > /dev/null 2>&1
    echo "$out"
    return 0
}

# --- A1: symlink escape — absolute symlink out of the target
reset_target
CANARY="$HOME/.overlord-redteam-canary-$$"
rm -f "$CANARY"
ln -s "$HOME" "$TARGET/evil"
OUT=$($OVERLORD run --jail -t "$TARGET" -- bash -c \
  "echo pwned > evil/.overlord-redteam-canary-$$ 2>/dev/null && echo WROTE || echo DENIED" 2>/dev/null)
SID=$(grep -oP 'session \K\S+' <<< "$OUT" | head -1); [[ -n "$SID" ]] && $OVERLORD rollback "$SID" > /dev/null
if [[ -e "$CANARY" ]]; then breach "A1 symlink escape reached real \$HOME"; rm -f "$CANARY"
else hold "A1 symlink escape (absolute link resolves inside jail)"; fi

# --- A2: dotdot traversal — climb out of the target
OUT=$(attack 'echo pwned > ../../escape.txt 2>/dev/null; echo x > /escape.txt 2>/dev/null; echo done')
if [[ -e "$WORK/escape.txt" ]] || [[ -e /escape.txt ]]; then breach "A2 traversal reached real fs"
else hold "A2 dotdot traversal (lands in throwaway tmpfs root)"; fi

# --- A3: session-record tampering — the engine's own books must be out of reach
OUT=$(attack 'ls /.overlord/manifest.json 2>/dev/null && echo BOOKS-VISIBLE || echo BOOKS-SEALED')
if grep -q BOOKS-VISIBLE <<< "$OUT"; then breach "A3 session records (manifest/meta) reachable from inside the jail"
else hold "A3 session records sealed"; fi

# --- A4: host sysctl write — the write may land in the jail's private UTS
# namespace (it does when overlord itself runs as root); what must never
# happen is the host's own hostname changing
HOST_BEFORE="$(cat /proc/sys/kernel/hostname)"
OUT=$(attack 'echo owned > /proc/sys/kernel/hostname 2>/dev/null && echo WROTE || echo DENIED')
if [[ "$(cat /proc/sys/kernel/hostname)" != "$HOST_BEFORE" ]]; then breach "A4 host sysctl reached host (hostname changed)"
elif grep -q WROTE <<< "$OUT"; then hold "A4 host sysctls (write contained to private uts namespace)"
else hold "A4 host sysctls read-only"; fi

# --- A5: device node forgery
OUT=$(attack 'mknod /dev/sda-clone b 8 0 2>/dev/null && echo MADE || echo DENIED')
if grep -q MADE <<< "$OUT"; then breach "A5 block device node created in jail"
else hold "A5 device node forgery denied"; fi

# --- A6: host process visibility / signaling
HOSTPID=$$
OUT=$(attack "kill -0 $HOSTPID 2>/dev/null && echo SEEN || echo BLIND; ls /proc | grep -cE '^[0-9]+\$'")
if grep -q SEEN <<< "$OUT"; then breach "A6 host process visible/signalable from jail"
else hold "A6 host processes invisible (private pidns)"; fi

# --- A7: read reach — the vault must not exist
OUT=$(attack 'cat /mnt/vault/CLAUDE.md 2>/dev/null && echo READ || echo NOENT; ls /home 2>/dev/null && echo HOME || echo NOHOME')
if grep -qE 'READ|^HOME$' <<< "$OUT"; then breach "A7 real filesystem readable from jail"
else hold "A7 /mnt and /home do not exist"; fi

# --- A8: upperdir direct access — overlay internals must be unreachable
OUT=$(attack 'U=$(grep -oP "upperdir=\K[^,]+" /proc/mounts | head -1); [ -n "$U" ] && ls "$U" 2>/dev/null && echo UPPER-OPEN || echo UPPER-SEALED')
if grep -q UPPER-OPEN <<< "$OUT"; then breach "A8 overlay upperdir reachable (session forgeable)"
else hold "A8 overlay internals unreachable"; fi

# --- A9: inherited fd leak — no fd may point at the real fs
OUT=$(attack 'for f in /proc/self/fd/*; do readlink "$f"; done 2>/dev/null | grep -E "/(home|mnt|overlord)" && echo FD-LEAK || echo FD-CLEAN')
if grep -q FD-LEAK <<< "$OUT"; then breach "A9 leaked file descriptor into jail"
else hold "A9 no fd leaks"; fi

# --- A11: environment inheritance — the operator's shell exports provider
# keys and OVERLORD_HOME; a sandboxed command must see none of them
OUT=$(ANTHROPIC_API_KEY=sk-ant-REDTEAM-MARKER OPENAI_API_KEY=sk-REDTEAM-MARKER OVERLORD_HOME="${OVERLORD_HOME:-$HOME/.overlord}" \
      attack 'env | grep -qE "MARKER|OVERLORD_HOME" && echo LEAKED || echo CLEAN; cat /proc/1/environ 2>/dev/null | tr "\0" "\n" | grep -q MARKER && echo LEAKED1 || echo CLEAN1')
if grep -qE 'LEAKED' <<< "$OUT"; then breach "A11 host environment (API keys) readable from jail"
else hold "A11 environment scrubbed: no keys, no OVERLORD_HOME"; fi

# --- A12: the system tree is bound from the host and must be read-only —
# a write into /etc, /usr or /opt from the jail is a write to the machine
OUT=$(attack 'W=0; for p in /etc/ovl-a12 /usr/ovl-a12 /opt/ovl-a12 /usr/bin/python3; do echo x >> "$p" 2>/dev/null && W=1; done; ls /etc/ovl-a12 /usr/ovl-a12 /opt/ovl-a12 2>/dev/null; [ "$W" = 1 ] && echo WROTE || echo READONLY')
if grep -q WROTE <<< "$OUT" || [[ -e /etc/ovl-a12 || -e /usr/ovl-a12 || -e /opt/ovl-a12 ]]; then
    rm -f /etc/ovl-a12 /usr/ovl-a12 /opt/ovl-a12 2>/dev/null
    breach "A12 host system tree writable from jail"
else hold "A12 /etc /usr /opt read-only in the jail"; fi

# --- A10: in-jail mount games must not persist or reach out
OUT=$(attack 'mkdir -p /mnt 2>/dev/null; mount -t tmpfs t /mnt 2>/dev/null; mount --bind / /mnt 2>/dev/null; ls /mnt/vault 2>/dev/null && echo REACHED || echo CONTAINED')
if grep -q REACHED <<< "$OUT"; then breach "A10 mount tricks reached real fs"
else hold "A10 mount games contained to jail"; fi

echo
if [[ "$FAILED" -eq 0 ]]; then
    echo "PASS: jail held against all attacks"
else
    echo "FAIL: breaches found — fix before release"
    exit 1
fi
