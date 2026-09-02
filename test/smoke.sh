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
if unshare --map-root-user --mount true 2>/dev/null; then
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

echo "PASS: all smoke assertions"
