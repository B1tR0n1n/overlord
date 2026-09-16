#!/usr/bin/env bash
# Run every suite; one line per suite, logs under $OVERLORD_TEST_LOGS
# (default: a temp dir), nonzero exit if any failed. A suite that self-skips
# (no kernel backend, no playwright) counts as a pass and says SKIP.
set -u
cd "$(dirname "$0")/.."
LOGS="${OVERLORD_TEST_LOGS:-$(mktemp -d)}"
mkdir -p "$LOGS"
fails=0
run() {                                   # run <name> <command...>
    local name="$1"; shift
    if "$@" > "$LOGS/$name.log" 2>&1; then
        if grep -q '^SKIP' "$LOGS/$name.log"; then echo "SKIP $name  ($(grep -m1 '^SKIP' "$LOGS/$name.log" | cut -c7-80))"
        else echo "PASS $name"; fi
    else
        echo "FAIL $name  (see $LOGS/$name.log)"; fails=$((fails + 1))
    fi
}
run smoke   bash test/smoke.sh
run redteam bash test/redteam.sh
for t in test/*_test.py; do
    run "$(basename "$t" .py)" python3 "$t"
done
echo "logs: $LOGS"
echo "failures: $fails"
exit $((fails > 0))
