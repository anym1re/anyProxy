#!/usr/bin/env bash
# Puts the pinned engine in place and refuses anything else.
#
#     scripts/fetch-telemt.sh [directory]
#
# Prints the path of the binary, so a caller can do:
#
#     export ANYPROXY_TELEMT="$(scripts/fetch-telemt.sh)"

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="${root}/deploy/telemt.pin"
into="${1:-${root}/target/engine}"

case "$(uname -m)" in
    x86_64)          target=x86_64-linux-musl ;;
    aarch64 | arm64) target=aarch64-linux-musl ;;
    *)               echo "no engine is published for $(uname -m)" >&2; exit 1 ;;
esac

setting() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "${pin}" | head -1
}

version="$(setting version)"
digest="$(setting "${target}")"
if [ -z "${version}" ] || [ -z "${digest}" ]; then
    echo "the pin names no ${target} for this project" >&2
    exit 1
fi

archive="telemt-${target}.tar.gz"
mkdir -p "${into}"

if [ ! -x "${into}/telemt" ] || [ "$("${into}/telemt" --version 2>/dev/null | awk '{print $2}')" != "${version}" ]; then
    url="https://github.com/telemt/telemt/releases/download/${version}/${archive}"
    curl -fsSL -o "${into}/${archive}" "${url}"

    seen="$(sha256sum "${into}/${archive}" | cut -d' ' -f1)"
    if [ "${seen}" != "${digest}" ]; then
        # The archive is not the one the pin names. It is removed rather than
        # left where a later run might use it.
        rm -f "${into}/${archive}"
        echo "digest mismatch for ${archive}" >&2
        echo "  pinned ${digest}" >&2
        echo "  got    ${seen}" >&2
        exit 1
    fi

    tar xzf "${into}/${archive}" -C "${into}"
fi

echo "${into}/telemt"
