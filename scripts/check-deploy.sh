#!/usr/bin/env bash
# Checks what deployment promises: the units are confined, and a binary
# without a signature of ours is refused.
#
# Each refusal is proved against a fixture rather than asserted, so a check
# that stopped working would be noticed here rather than at an installation.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

report() {
    echo "  $1"
    failures=$((failures + 1))
}

# ── the units are confined ───────────────────────────────────────────────

if command -v systemd-analyze >/dev/null 2>&1; then
    for unit in "${root}"/deploy/*.service; do
        name="$(basename "${unit}")"
        # An offline reading, so nothing has to be installed to be measured.
        exposure="$(systemd-analyze security --offline=true "${unit}" 2>/dev/null \
            | sed -n 's/.*Overall exposure level for .*: \([0-9.]*\).*/\1/p')"
        if [ -z "${exposure}" ]; then
            report "${name}: systemd-analyze said nothing about it"
            continue
        fi
        # Below four is systemd's own boundary between OK and medium.
        if awk "BEGIN { exit !(${exposure} >= 4.0) }"; then
            report "${name}: exposure ${exposure}, worse than medium"
        else
            echo "  ${name}: exposure ${exposure}"
        fi
    done
else
    echo "  systemd-analyze is absent; the units were not measured"
fi

# ── an unsigned binary is refused ────────────────────────────────────────

verify="${root}/scripts/verify-release.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

printf 'not really a binary' > "${work}/artefact"
printf 'not really a signature' > "${work}/artefact.bundle"
: > "${work}/empty.bundle"

expect_refusal() {
    local what="$1"
    shift
    if "${verify}" "$@" >/dev/null 2>&1; then
        report "the verifier accepted ${what}"
    else
        echo "  refused: ${what}"
    fi
}

expect_refusal "a file with no signature beside it" "${work}/artefact" "${work}/absent.bundle"
expect_refusal "a file with an empty signature" "${work}/artefact" "${work}/empty.bundle"
expect_refusal "a signature that is not ours" "${work}/artefact" "${work}/artefact.bundle"
expect_refusal "a file that is not there" "${work}/absent" "${work}/artefact.bundle"

if ! command -v cosign >/dev/null 2>&1; then
    echo "  cosign is absent, and the verifier refuses rather than waving it through"
fi

# ── the installer will not run as somebody who cannot install ────────────

if grep -q 'id -u.*= 0' "${root}/scripts/install-node.sh"; then
    echo "  the installer requires root"
else
    report "the installer does not check that it can install"
fi

if grep -q 'verify-release.sh' "${root}/scripts/install-node.sh"; then
    echo "  the installer verifies before it installs"
else
    report "the installer installs without verifying"
fi

if [ "${failures}" -gt 0 ]; then
    echo "deployment check failed: ${failures}"
    exit 1
fi
echo "deployment check passed"
