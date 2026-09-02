#!/usr/bin/env bash
# OVERLORD e2e smoke test: run → diff → rollback → run → commit.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
export OVERLORD_HOME="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$OVERLORD_HOME" "$WORK"' EXIT

OVERLORD="python3 $HERE/overlord.py"
TARGET="$WORK/target"
mkdir -p "$TARGET/sub"
echo original > "$TARGET/keep.txt"
echo original > "$TARGET/edit.txt"
echo original > "$TARGET/doomed.txt"
echo original > "$TARGET/sub/nested.txt"

fail() { echo "FAIL: $1" >&2; exit 1; }

# --- 1. transactional run: mutations must NOT hit the target
OUT=$($OVERLORD run -t "$TARGET" -- bash -c \
  'echo changed > edit.txt; rm doomed.txt; echo new > created.txt; echo n2 > sub/also.txt')
SID=$(echo "$OUT" | grep -oP 'session \K\S+')
[ -n "$SID" ] || fail "no session id in output"

grep -q original "$TARGET/edit.txt"        || fail "target mutated before commit (edit)"
[ -f "$TARGET/doomed.txt" ]                || fail "target mutated before commit (delete)"
[ ! -f "$TARGET/created.txt" ]             || fail "target mutated before commit (create)"

# --- 2. diff sees all four changes
DIFF=$($OVERLORD diff "$SID")
echo "$DIFF" | grep -q 'modified.*edit.txt'   || fail "diff missed modify"
echo "$DIFF" | grep -q 'deleted.*doomed.txt'  || fail "diff missed delete"
echo "$DIFF" | grep -q 'added.*created.txt'   || fail "diff missed add"
echo "$DIFF" | grep -q 'sub/also.txt'         || fail "diff missed nested add"

# --- 3. rollback leaves target byte-identical
$OVERLORD rollback "$SID" > /dev/null
grep -q original "$TARGET/edit.txt" && [ -f "$TARGET/doomed.txt" ] && [ ! -f "$TARGET/created.txt" ] \
  || fail "rollback did not leave target untouched"

# --- 4. commit applies exactly the recorded changes
OUT=$($OVERLORD run -t "$TARGET" -- bash -c \
  'echo changed > edit.txt; rm doomed.txt; echo new > created.txt')
SID=$(echo "$OUT" | grep -oP 'session \K\S+')
$OVERLORD commit "$SID" > /dev/null

grep -q changed "$TARGET/edit.txt"   || fail "commit did not apply modify"
[ ! -f "$TARGET/doomed.txt" ]        || fail "commit did not apply delete"
grep -q new "$TARGET/created.txt"    || fail "commit did not apply create"
grep -q original "$TARGET/keep.txt"  || fail "commit damaged untouched file"
grep -q original "$TARGET/sub/nested.txt" || fail "commit damaged untouched nested file"

# --- 5. committed session refuses rollback
$OVERLORD rollback "$SID" 2>/dev/null && fail "rollback allowed on committed session" || true

echo "PASS: all smoke assertions"
