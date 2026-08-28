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
reach=""
domain=""
email=""
agreed=""
through="${ANYPROXY_THROUGH:-127.0.0.1:9050}"

while [ $# -gt 0 ]; do
    case "$1" in
        --panel)       panel="$2";       shift 2 ;;
        --code)        code="$2";        shift 2 ;;
        --fingerprint) fingerprint="$2"; shift 2 ;;
        --version)     version="$2";     shift 2 ;;
        --reach)       reach="$2";       shift 2 ;;
        --through)     through="$2";     shift 2 ;;
        --domain)      domain="$2";      shift 2 ;;
        --email)       email="$2";       shift 2 ;;
        --agree-tos)   agreed=yes;       shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for required in panel code fingerprint; do
    if [ -z "${!required}" ]; then
        echo "missing --${required}" >&2
        exit 2
    fi
done

panel_host="${panel%:*}"

# ── the panel's machine is not a node ────────────────────────────────────

# A node carries client traffic; the panel holds every client, every access and
# every secret. Putting one on the other's machine means the address clients
# connect to is the address the whole system is kept on: whoever finds the node
# — and a node is meant to be found, that is what a link is — has found the
# panel. It also loses the separation the design rests on, where taking a node
# yields one node.
#
# Two of them would collide outright: the panel listens for its agents on 8443,
# which is also where a node serving plain MTProto binds.
#
# Refused here rather than left to the operator to remember, because the moment
# it is noticed is usually after clients are already connecting.
# Each source is read into a variable first and matched with `case`. Piping
# into `grep -q` reads better and is wrong here: `grep -q` leaves on its first
# match, the writer upstream is killed by SIGPIPE, and `set -o pipefail` turns
# that into a failed pipeline — so the test is false exactly when it has found
# something. Found on a panel host this check walked straight past.
panel_units="$(systemctl list-unit-files anyproxy-panel.service 2>/dev/null || true)"
panel_running="$(ps -eo args= 2>/dev/null || true)"
panel_ports="$(ss -ltn 2>/dev/null || true)"

panel_here=""
case "${panel_units}" in
    *anyproxy-panel*) panel_here="a systemd unit named anyproxy-panel" ;;
esac
if [ -z "${panel_here}" ] && [ -x "${prefix}/anyproxy-panel" ]; then
    panel_here="the panel binary at ${prefix}/anyproxy-panel"
fi
if [ -z "${panel_here}" ]; then
    case "${panel_running}" in
        *anyproxy-panel*) panel_here="the panel running on this machine" ;;
    esac
fi
if [ -z "${panel_here}" ]; then
    case "${panel_ports}" in
        *127.0.0.1:8080*) panel_here="something already listening on the panel's REST port" ;;
    esac
fi

if [ -n "${panel_here}" ]; then
    cat >&2 <<WHY
This machine runs the panel: ${panel_here}.

A node does not go on the panel's machine. The panel holds every client, every
access and every secret; a node is an address clients are given and are meant to
find. Putting them together means finding the node is finding the panel, and a
node serving plain MTProto would collide with the panel on 8443 besides.

Install this node on a machine of its own.
WHY
    exit 1
fi

# ── how this node reaches its panel ──────────────────────────────────────

if [ -z "${reach}" ]; then
    if [ -t 0 ]; then
        echo "The panel listens on loopback. How does this node reach it?"
        echo "  mtls       directly, over the pinned mutual TLS the channel already uses"
        echo "  wireguard  through a tunnel that is already up on this machine"
        echo "  onion      through a local Tor proxy, to an onion address"
        printf 'reach: '
        read -r reach
    else
        echo "missing --reach: say mtls, wireguard or onion" >&2
        exit 2
    fi
fi

case "${reach}" in
    mtls)
        # The channel is mutual TLS against a pinned authority whether or not
        # anything else carries it. Nothing to arrange, and nothing to check
        # beyond what enrolment will find out for itself.
        ;;
    wireguard)
        command -v wg >/dev/null 2>&1 || {
            echo "wireguard was chosen and wg is not installed" >&2
            exit 2
        }
        interfaces="$(wg show interfaces 2>/dev/null || true)"
        [ -n "${interfaces}" ] || {
            echo "wireguard was chosen and no interface is up" >&2
            exit 2
        }
        carried=""
        for interface in ${interfaces}; do
            if ip route get "${panel_host}" 2>/dev/null | grep -q "dev ${interface}"; then
                carried="${interface}"
                break
            fi
        done
        [ -n "${carried}" ] || {
            echo "no wireguard interface routes ${panel_host}" >&2
            exit 2
        }
        ;;
    onion)
        case "${panel_host}" in
            *.onion) ;;
            *) echo "onion was chosen and ${panel_host} is not an onion address" >&2; exit 2 ;;
        esac
        # The proxy has to be answering now. A node installed against a Tor
        # that is not running would enrol, fail, and retry for ever against a
        # panel it was never able to reach.
        proxy_host="${through%:*}"
        proxy_port="${through##*:}"
        (exec 3<>"/dev/tcp/${proxy_host}/${proxy_port}") 2>/dev/null || {
            echo "onion was chosen and nothing answers at ${through}" >&2
            exit 2
        }
        ;;
    *)
        echo "unknown way to reach the panel: ${reach}" >&2
        exit 2
        ;;
esac

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

# Before the agent is started: the engine takes 443 only when there is no door
# in front of it, and a door raised afterwards would find the port taken.
if [ -n "${domain}" ]; then
    front=("${here}/install-front.sh" --domain "${domain}")
    [ -n "${agreed}" ] && front+=(--agree-tos)
    [ -n "${email}" ] && front+=(--email "${email}")
    "${front[@]}"
fi

systemctl enable --now anyproxy-agent.service
echo "the node is enrolled and running"
