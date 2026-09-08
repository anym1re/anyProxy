#!/usr/bin/env bash
# Proves each convention check fires on a violation and stays quiet on the
# equivalent code written correctly. A check nobody has seen fail is not a
# check.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
checker="${here}/check-conventions.sh"
failures=0

echo "convention checks"

if good_output=$(bash "$checker" "${here}/fixtures/good" 2>&1); then
    echo "  ok    correct code passes"
else
    echo "  FAIL  correct code was flagged:"
    printf '%s\n' "$good_output" | sed 's/^/        /'
    failures=$((failures + 1))
fi

bad_output=$(bash "$checker" "${here}/fixtures/bad" 2>&1)
for id in user-facing-literal secret-exposed timestamp-string-op sql-concatenation \
          handler-without-actor feed-on-the-rest-listener; do
    if printf '%s\n' "$bad_output" | grep -q "^${id}"; then
        echo "  ok    ${id} fires"
    else
        echo "  FAIL  ${id} did not fire"
        failures=$((failures + 1))
    fi
done

if [ "$failures" -ne 0 ]; then
    echo "${failures} check(s) not proven" >&2
    exit 1
fi
echo "all checks proven"
