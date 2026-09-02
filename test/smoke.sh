#!/usr/bin/env bash
# OVERLORD e2e suite: run/diff/rollback/commit, conflict detection, provenance,
# shell, syscall trace (when strace present), containment (when kernel backend
# is available). Exercises whichever backends the host supports.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
export OVERLORD_HOME="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$OVERLORD_HOME" "$WORK"' EXIT

OVERLORD="python3 $HERE/overlord.py"
# The AppArmor userns grant attaches to the installed ELF launcher, not to a
# bare python3 invocation — use the installed binary when it matches the repo.
if command -v overlord > /dev/null && cmp -s /usr/local/lib/overlord/overlord.py "$HERE/overlord.py"; then
    OVERLORD="overlord"
fi
echo "under test: $OVERLORD"
TARGET="$WORK/target"

reset_target() {
    rm -rf "$TARGET"
    mkdir -p "$TARGET/sub"
    echo original > "$TARGET/keep.txt"
    echo original > "$TARGET/edit.txt"
    echo original > "$TARGET/doomed.txt"
    echo original > "$TARGET/sub/nested.txt"
}

fail() { echo "FAIL: $1" >&2; exit 1; }
pass() { echo "  ok: $1"; }
sid_of() { grep -oP 'session \K\S+' <<< "$1" | head -1; }

reset_target

# --- 1. transactional run: mutations must NOT hit the target
OUT=$($OVERLORD run -t "$TARGET" -- bash -c \
  'echo changed > edit.txt; rm doomed.txt; echo new > created.txt; echo n2 > sub/also.txt')
SID=$(sid_of "$OUT"); [ -n "$SID" ] || fail "no session id"
grep -q original "$TARGET/edit.txt"  || fail "target mutated before commit (edit)"
[ -f "$TARGET/doomed.txt" ]          || fail "target mutated before commit (delete)"
[ ! -f "$TARGET/created.txt" ]       || fail "target mutated before commit (create)"
pass "isolation"

# --- 2. diff completeness
DIFF=$($OVERLORD diff "$SID")
grep -q 'modified.*edit.txt'  <<< "$DIFF" || fail "diff missed modify"
grep -q 'deleted.*doomed.txt' <<< "$DIFF" || fail "diff missed delete"
grep -q 'added.*created.txt'  <<< "$DIFF" || fail "diff missed add"
grep -q 'sub/also.txt'        <<< "$DIFF" || fail "diff missed nested add"
pass "diff"

# --- 3. provenance: before/after hashes recorded
LOG=$($OVERLORD log "$SID")
grep -qP 'modified\s+edit.txt\s+[0-9a-f]{12} -> [0-9a-f]{12}' <<< "$LOG" || fail "provenance missing modify hashes"
grep -qP 'deleted\s+doomed.txt\s+[0-9a-f]{12} -> -'           <<< "$LOG" || fail "provenance missing delete before-hash"
pass "provenance"

# --- 4. rollback leaves target byte-identical
$OVERLORD rollback "$SID" > /dev/null
grep -q original "$TARGET/edit.txt" && [ -f "$TARGET/doomed.txt" ] && [ ! -f "$TARGET/created.txt" ] \
  || fail "rollback not clean"
pass "rollback"

# --- 5. commit applies exactly the recorded changes
OUT=$($OVERLORD run -t "$TARGET" -- bash -c 'echo changed > edit.txt; rm doomed.txt; echo new > created.txt')
SID=$(sid_of "$OUT")
$OVERLORD commit "$SID" > /dev/null
grep -q changed "$TARGET/edit.txt"        || fail "commit missed modify"
[ ! -f "$TARGET/doomed.txt" ]             || fail "commit missed delete"
grep -q new "$TARGET/created.txt"         || fail "commit missed create"
grep -q original "$TARGET/keep.txt"       || fail "commit damaged untouched file"
grep -q original "$TARGET/sub/nested.txt" || fail "commit damaged nested file"
pass "commit"

# --- 6. committed session refuses rollback
$OVERLORD rollback "$SID" 2>/dev/null && fail "rollback allowed after commit" || true
pass "commit finality"

# --- 7. conflict detection: external drift refuses commit; --force overrides
reset_target
OUT=$($OVERLORD run -t "$TARGET" -- bash -c 'echo session-edit > edit.txt')
SID=$(sid_of "$OUT")
sleep 0.01; echo external-edit > "$TARGET/edit.txt"   # drift after snapshot
$OVERLORD commit "$SID" 2>/dev/null && fail "commit ignored external drift" || true
grep -q external-edit "$TARGET/edit.txt" || fail "refused commit still mutated target"
$OVERLORD commit --force "$SID" > /dev/null || fail "--force commit failed"
grep -q session-edit "$TARGET/edit.txt"  || fail "--force did not apply"
pass "conflict detection"

# --- 8. conflict detection: externally created file blocks session's add
reset_target
OUT=$($OVERLORD run -t "$TARGET" -- bash -c 'echo mine > race.txt')
SID=$(sid_of "$OUT")
echo theirs > "$TARGET/race.txt"
$OVERLORD commit "$SID" 2>/dev/null && fail "commit clobbered externally created file" || true
$OVERLORD rollback "$SID" > /dev/null
pass "conflict on create"

# --- 9. shell (non-interactive stdin drive)
reset_target
OUT=$(echo 'echo fromshell > shellfile.txt' | $OVERLORD shell -t "$TARGET" 2>/dev/null) || true
SID=$(sid_of "$OUT"); [ -n "$SID" ] || fail "shell produced no session"
$OVERLORD diff "$SID" | grep -q 'added.*shellfile.txt' || fail "shell session missed write"
[ ! -f "$TARGET/shellfile.txt" ] || fail "shell wrote through to target"
$OVERLORD rollback "$SID" > /dev/null
pass "shell"

# --- 10. syscall trace (only when strace is installed)
if command -v strace > /dev/null; then
    reset_target
    OUT=$($OVERLORD run --trace -t "$TARGET" -- bash -c 'echo traced > t.txt')
    SID=$(sid_of "$OUT")
    [ -s "$OVERLORD_HOME/sessions/$SID/syscalls.jsonl" ] || fail "trace produced no syscall log"
    grep -q '"write": true' "$OVERLORD_HOME/sessions/$SID/syscalls.jsonl" || fail "trace missed write syscalls"
    $OVERLORD rollback "$SID" > /dev/null
    pass "syscall trace"
else
    echo "  skip: syscall trace (strace not installed)"
fi

# --- 11. absolute-path containment (kernel backend only)
if $OVERLORD doctor 2>/dev/null | grep -q 'kernel backend.*: available'; then
    reset_target
    OUT=$($OVERLORD run --backend kernel -t "$TARGET" -- bash -c "echo abs > $TARGET/abs.txt")
    SID=$(sid_of "$OUT")
    [ ! -f "$TARGET/abs.txt" ] || fail "kernel backend leaked absolute-path write"
    $OVERLORD diff "$SID" | grep -q 'added.*abs.txt' || fail "kernel backend lost absolute-path write"
    $OVERLORD rollback "$SID" > /dev/null
    pass "absolute-path containment (kernel)"
else
    echo "  skip: containment test (kernel backend unavailable)"
fi

# --- 12. cleanup survives mode-000 dirs (kernel overlayfs creates work/work as 000)
reset_target
OUT=$($OVERLORD run -t "$TARGET" -- true)
SID=$(sid_of "$OUT")
mkdir -p "$OVERLORD_HOME/sessions/$SID/work/work"
chmod 000 "$OVERLORD_HOME/sessions/$SID/work/work"
$OVERLORD rollback "$SID" > /dev/null || fail "rollback died on mode-000 work dir"
[ ! -d "$OVERLORD_HOME/sessions/$SID" ] || fail "session dir survived rollback"
pass "mode-000 cleanup"

# --- 13. timeout grant kills the process group
reset_target
if OUT=$($OVERLORD run --timeout 1 -t "$TARGET" -- sleep 30 2>/dev/null); then
    fail "timeout did not produce nonzero exit"
fi
SID=$($OVERLORD sessions | grep timed-out | tail -1 | cut -d' ' -f1)
[ -n "$SID" ] || fail "timed-out session not recorded"
$OVERLORD rollback "$SID" > /dev/null
pass "timeout grant"

# --- 14. manifest file drives grants
reset_target
echo '{"timeout": 1}' > "$WORK/cap.json"
if $OVERLORD run --manifest "$WORK/cap.json" -t "$TARGET" -- sleep 30 > /dev/null 2>&1; then
    fail "manifest timeout not enforced"
fi
$OVERLORD rollback "$($OVERLORD sessions | grep timed-out | tail -1 | cut -d' ' -f1)" > /dev/null
pass "capability manifest"

# --- 15. arbitration: pending session blocks new runs; --stack overrides
reset_target
OUT=$($OVERLORD run -t "$TARGET" -- bash -c 'echo a > a.txt'); SIDA=$(sid_of "$OUT")
if $OVERLORD run -t "$TARGET" -- true > /dev/null 2>&1; then
    fail "second run allowed with pending session"
fi
OUT=$($OVERLORD run --stack -t "$TARGET" -- true); SIDB=$(sid_of "$OUT")
$OVERLORD rollback "$SIDA" > /dev/null; $OVERLORD rollback "$SIDB" > /dev/null
pass "arbitration"

# --- 16. three-way merge: non-overlapping drift merges; overlapping refuses
reset_target
printf 'l1\nl2\nl3\n' > "$TARGET/merge.txt"
OUT=$($OVERLORD run --merge-base -t "$TARGET" -- bash -c "sed -i 's/l1/session1/' merge.txt")
SID=$(sid_of "$OUT")
sleep 0.01; sed -i 's/l3/external3/' "$TARGET/merge.txt"
$OVERLORD commit "$SID" 2>/dev/null && fail "drift committed without merge" || true
$OVERLORD commit --merge "$SID" > /dev/null || fail "clean three-way merge refused"
grep -q session1 "$TARGET/merge.txt" && grep -q external3 "$TARGET/merge.txt" \
  || fail "merge lost an edit"
# overlapping edit must refuse even with --merge
printf 'x1\nx2\n' > "$TARGET/clash.txt"
OUT=$($OVERLORD run --merge-base -t "$TARGET" -- bash -c "sed -i 's/x1/session/' clash.txt")
SID=$(sid_of "$OUT")
sleep 0.01; sed -i 's/x1/external/' "$TARGET/clash.txt"
$OVERLORD commit --merge "$SID" 2>/dev/null && fail "overlapping edit merged silently" || true
$OVERLORD rollback "$SID" > /dev/null
pass "three-way merge"

KERNEL_OK=false
if $OVERLORD doctor 2>/dev/null | grep -q 'kernel backend.*: available'; then KERNEL_OK=true; fi

# --- 17. jail grant: rest of the filesystem does not exist (kernel only)
if $KERNEL_OK; then
    reset_target
    OUT=$($OVERLORD run --jail -t "$TARGET" -- bash -c \
      '[ ! -d /home ] && [ ! -d /mnt ] && echo sealed > verdict.txt; ls /usr > /dev/null && echo tools >> verdict.txt')
    SID=$(sid_of "$OUT")
    $OVERLORD diff "$SID" | grep -q 'added.*verdict.txt' || fail "jail session lost its write"
    $OVERLORD commit "$SID" > /dev/null
    grep -q sealed "$TARGET/verdict.txt" || fail "jail did not seal the filesystem"
    grep -q tools "$TARGET/verdict.txt"  || fail "jail broke system dir access"
    pass "jail grant"
else
    echo "  skip: jail grant (kernel backend unavailable)"
fi

# --- 18. net:none grant: even loopback to host services is unreachable (kernel only)
if $KERNEL_OK; then
    reset_target
    python3 -m http.server 8377 --bind 127.0.0.1 --directory "$TARGET" > /dev/null 2>&1 &
    HTTP_PID=$!
    sleep 0.7
    OUT=$($OVERLORD run -t "$TARGET" -- bash -c \
      'if (echo > /dev/tcp/127.0.0.1/8377) 2>/dev/null; then echo open > net.txt; else echo closed > net.txt; fi')
    SID=$(sid_of "$OUT")
    grep -q '"after' "$OVERLORD_HOME/sessions/$SID/provenance.jsonl" || true
    $OVERLORD commit "$SID" > /dev/null
    grep -q open "$TARGET/net.txt" || fail "host-net control failed (server unreachable?)"
    OUT=$($OVERLORD run --net none -t "$TARGET" -- bash -c \
      'if (echo > /dev/tcp/127.0.0.1/8377) 2>/dev/null; then echo open > net.txt; else echo closed > net.txt; fi')
    SID=$(sid_of "$OUT")
    $OVERLORD commit --force "$SID" > /dev/null
    kill "$HTTP_PID" 2>/dev/null || true
    grep -q closed "$TARGET/net.txt" || fail "net:none did not isolate the network"
    pass "net:none grant"
else
    echo "  skip: net:none grant (kernel backend unavailable)"
fi

# --- 19. jail + strace combo: trace lands, records stay sealed (kernel only)
if $KERNEL_OK && command -v strace > /dev/null; then
    reset_target
    OUT=$($OVERLORD run --jail --trace -t "$TARGET" -- bash -c \
      'echo t > t.txt; ls /.overlord/manifest.json 2>/dev/null && echo BOOKS || echo SEALED')
    SID=$(sid_of "$OUT")
    [ -s "$OVERLORD_HOME/sessions/$SID/syscalls.jsonl" ] || fail "jail+trace produced no syscall log"
    grep -q BOOKS <<< "$OUT" && fail "session records visible in jail+trace mode" || true
    $OVERLORD rollback "$SID" > /dev/null
    pass "jail + trace (records sealed)"
else
    echo "  skip: jail+trace combo"
fi

echo "PASS: all smoke assertions"
