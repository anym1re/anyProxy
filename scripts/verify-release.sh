#!/usr/bin/env bash
# Says whether a downloaded file is one this project published.
#
#     scripts/verify-release.sh <file> <bundle>
#
# Exits zero only when the signature is present, valid, and was made by this
# repository's release workflow on a tag. Anything else — a missing bundle, a
# missing verifier, a signature from somewhere else — is a refusal.
#
# The verifier is not optional. A machine without cosign cannot tell a release
# from a file somebody left on a mirror, and installing anyway would make the
# check decorative.

set -euo pipefail

repository="${ANYPROXY_REPOSITORY:-anym1re/anyProxy}"
issuer="https://token.actions.githubusercontent.com"
identity="^https://github.com/${repository}/\\.github/workflows/release\\.yml@refs/tags/"

usage() {
    echo "usage: $0 <file> <bundle>" >&2
    exit 2
}

[ $# -eq 2 ] || usage
file="$1"
bundle="$2"

refuse() {
    echo "refusing $file: $1" >&2
    exit 1
}

command -v cosign >/dev/null 2>&1 || refuse "cosign is not installed, so the signature cannot be checked"
[ -f "${file}" ]   || refuse "no such file"
[ -f "${bundle}" ] || refuse "no signature beside it"
[ -s "${bundle}" ] || refuse "the signature is empty"

if ! cosign verify-blob \
        --bundle "${bundle}" \
        --certificate-oidc-issuer "${issuer}" \
        --certificate-identity-regexp "${identity}" \
        "${file}" >/dev/null 2>&1; then
    refuse "the signature does not belong to a release of ${repository}"
fi

echo "${file}: signed by ${repository}"
