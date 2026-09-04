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

# ── the host is sized for a proxy, not left on desktop defaults ───────────
#
# A node's machine is small and stock: one core, half a gigabyte, no swap, a
# kernel tuned for a laptop. On that a proxy runs out of file descriptors at
# 1024, out of SYN queue at 128 and out of ephemeral ports at twenty-eight
# thousand long before the engine is busy — and the first crowd of clients
# ends in the OOM killer taking whatever it fancies. None of that is a knob an
# operator should be guessing at, so it is measured and set here, in two sizes,
# and set again on every install so a hand edit does not silently survive.
# Decision 0055.
if [ "${ANYPROXY_TUNE_HOST:-yes}" != no ]; then
    memory_kb="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
    if [ "${memory_kb}" -lt 1572864 ]; then
        # Below one and a half gigabytes: socket buffers and file tables that
        # would not fit are worse than small ones.
        nofile=65536
        socket_max=4194304
        conntrack_max=65536
    else
        nofile=262144
        socket_max=16777216
        conntrack_max=262144
    fi
    memory_high="$(( memory_kb * 7 / 10 / 1024 ))M"

    # BBR only where the module loads. The path out of the target countries to
    # Telegram's data centres drops packets, and cubic collapses on loss where
    # BBR keeps pacing. Nothing is set for it on a kernel that has not got it.
    congestion=""
    if modprobe tcp_bbr 2>/dev/null && grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
        congestion=$'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr'
    fi

    # Connection tracking is sized only when it is loaded: writing the key
    # otherwise loads the module, and a node that was not filtering packets
    # would start paying for tracking every one of them.
    conntrack=""
    if [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
        conntrack="net.netfilter.nf_conntrack_max = ${conntrack_max}"
    fi

    # Not in the list, on purpose: tcp_fastopen. It changes the handshake, and
    # a handshake that differs from the site's own is the kind of tell the
    # distinguishability model exists to avoid.
    cat > /etc/sysctl.d/60-anyproxy.conf <<SYSCTL
# Written by the anyProxy node installer. Edit a different file: this one is
# rewritten on every install.

# Queues sized for a crowd arriving at once.
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1

# Outbound connections to Telegram come and go quickly; give them ports and
# let a closed one be reused without waiting out the timer.
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Keepalives that outlive a NAT mapping and notice a dead peer in minutes.
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# Behind DPI and tunnels the path MTU is often lied about; probing finds it
# instead of stalling the connection.
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0

# Socket buffers by the memory this machine actually has.
net.core.rmem_max = ${socket_max}
net.core.wmem_max = ${socket_max}
net.ipv4.tcp_rmem = 4096 87380 ${socket_max}
net.ipv4.tcp_wmem = 4096 65536 ${socket_max}

fs.file-max = $(( nofile * 4 ))
vm.swappiness = 10
${congestion}
${conntrack}
SYSCTL
    sysctl --system >/dev/null

    # Swap on a small machine is not for running out of: it is so that a crowd
    # of clients ends in slowness rather than in the OOM killer.
    if [ "${memory_kb}" -lt 2097152 ] && [ "$(wc -l < /proc/swaps)" -le 1 ] && [ ! -e /swapfile ]; then
        if ! fallocate -l 1G /swapfile 2>/dev/null; then
            dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
        fi
        chmod 0600 /swapfile
        mkswap /swapfile >/dev/null
        swapon /swapfile
        grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

    # The unit's limits follow the size. MemoryHigh throttles the proxy before
    # the kernel has to choose a victim, and the score adjustment makes sure
    # that when it does, the victim is the proxy and not sshd.
    install -d -o root -g root -m 0755 /etc/systemd/system/anyproxy-agent.service.d
    cat > /etc/systemd/system/anyproxy-agent.service.d/host.conf <<UNIT
# Written by the anyProxy node installer for this machine's size.
[Service]
LimitNOFILE=${nofile}
MemoryHigh=${memory_high}
OOMScoreAdjust=500
UNIT
    echo "host sized: $(nproc) cpu, $(( memory_kb / 1024 )) MB, nofile ${nofile}${congestion:+, bbr}"
fi

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
