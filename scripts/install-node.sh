#!/usr/bin/env bash
# Turns a fresh machine into a node.
#
#     scripts/install-node.sh --panel <host:port> --code <code> \
#                             --fingerprint <hex> [--version <tag>]
#
# The code and the fingerprint come from `anyproxy node add`, which prints them
# once. Everything the node runs is checked before it runs: our own binary
# against the release signature, the engine against the digest in the pin.

set -euo pipefail

repository="${ANYPROXY_REPOSITORY:-anym1re/anyProxy}"
prefix="${ANYPROXY_PREFIX:-/usr/local/bin}"
state="${ANYPROXY_STATE:-/var/lib/anyproxy}"
service_user="anyproxy"

panel=""
code=""
fingerprint=""
version=""

while [ $# -gt 0 ]; do
    case "$1" in
        --panel)       panel="$2";       shift 2 ;;
        --code)        code="$2";        shift 2 ;;
        --fingerprint) fingerprint="$2"; shift 2 ;;
        --version)     version="$2";     shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for required in panel code fingerprint; do
    if [ -z "${!required}" ]; then
        echo "missing --${required}" >&2
        exit 2
    fi
done

[ "$(id -u)" = 0 ] || { echo "run this as root; the agent itself will not be" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -m)" in
    x86_64)          target=x86_64-linux-musl ;;
    aarch64 | arm64) target=aarch64-linux-musl ;;
    *) echo "no release is published for $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "${version}" ]; then
    version="$(curl -fsSL "https://api.github.com/repos/${repository}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "${version}" ] || { echo "could not learn the latest release" >&2; exit 1; }
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

binary="anyproxy-agent-${target}"
base="https://github.com/${repository}/releases/download/${version}"
echo "fetching ${binary} ${version}"
curl -fsSL -o "${work}/${binary}" "${base}/${binary}"
curl -fsSL -o "${work}/${binary}.bundle" "${base}/${binary}.bundle"

# Before anything is installed, and before anything is run.
"${here}/verify-release.sh" "${work}/${binary}" "${work}/${binary}.bundle"

# The engine, pinned by digest rather than by tag.
engine="$("${here}/fetch-telemt.sh" "${work}/engine")"

id -u "${service_user}" >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin "${service_user}"

install -o root -g root -m 0755 "${work}/${binary}" "${prefix}/anyproxy-agent"
install -o root -g root -m 0755 "${engine}" "${prefix}/telemt"

install -d -o "${service_user}" -g "${service_user}" -m 0700 "${state}"
install -d -o root -g root -m 0755 /etc/anyproxy

cat > /etc/anyproxy/agent.env <<ENV
ANYPROXY_PANEL=${panel}
ANYPROXY_AGENT_DIR=${state}
ENV
chmod 0600 /etc/anyproxy/agent.env

install -o root -g root -m 0644 "${here}/../deploy/anyproxy-agent.service" \
    /etc/systemd/system/anyproxy-agent.service
systemctl daemon-reload

echo "enrolling with ${panel}"
runuser -u "${service_user}" -- env \
    ANYPROXY_AGENT_DIR="${state}" \
    "${prefix}/anyproxy-agent" enroll \
        --panel "${panel}" --code "${code}" --fingerprint "${fingerprint}"

systemctl enable --now anyproxy-agent.service
echo "the node is enrolled and running"
