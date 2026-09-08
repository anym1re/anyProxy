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

# The panel installer carries the same two guards and one of its own: it will
# not run where a node is, the mirror of decision 0049.
panel="${root}/scripts/install-panel.sh"
if grep -q 'id -u.*= 0' "${panel}"; then
    echo "  the panel installer requires root"
else
    report "the panel installer does not check that it can install"
fi
if grep -q 'verify-release.sh' "${panel}"; then
    echo "  the panel installer verifies before it installs"
else
    report "the panel installer installs without verifying"
fi
if grep -q 'runs a node' "${panel}"; then
    echo "  the panel installer refuses a node's machine"
else
    report "the panel installer would install beside a node"
fi

# The site installer carries the same guards, and refuses both other
# machines: the panel's and a node's (0096).
site="${root}/scripts/install-site.sh"
if grep -q 'id -u.*= 0' "${site}"; then
    echo "  the site installer requires root"
else
    report "the site installer does not check that it can install"
fi
if grep -q 'verify-release.sh' "${site}"; then
    echo "  the site installer verifies before it installs"
else
    report "the site installer installs without verifying"
fi
if grep -q 'runs the panel or a node' "${site}"; then
    echo "  the site installer refuses the panel's and a node's machine"
else
    report "the site installer would install beside the panel or a node"
fi
if grep -q 'access_log off' "${site}"; then
    echo "  the site's front keeps no access log"
else
    report "the site's front would log who looked"
fi

# ── the node is told how it reaches its panel ────────────────────────────
#
# Each of these is run for real rather than read out of the file. The checks
# happen before the installer asks for root, so they can be proved by anyone.

installer="${root}/scripts/install-node.sh"

refuses() {
    local what="$1"
    shift
    local said
    # Not a terminal, so an absent choice is refused rather than asked for.
    said="$("${installer}" "$@" < /dev/null 2>&1)" && {
        report "the installer accepted ${what}"
        return
    }
    echo "  refused: ${what}"
}

common=(--panel "panel.invalid:8443" --code "code" --fingerprint "ff")

refuses "no way of reaching the panel" "${common[@]}"
refuses "a way of reaching the panel that does not exist" "${common[@]}" --reach carrier-pigeon
refuses "an onion route to something that is not an onion address"     "${common[@]}" --reach onion
refuses "an onion route with nothing answering"     --panel "nowhere.onion:8443" --code "code" --fingerprint "ff"     --reach onion --through "127.0.0.1:1"

if [ "${failures}" -gt 0 ]; then
    echo "deployment check failed: ${failures}"
    exit 1
fi
echo "deployment check passed"
