#!/usr/bin/env bash
# Turns a fresh machine into the panel.
#
#     scripts/install-panel.sh [--version <tag>]
#
# The panel holds every client, every access and every secret. It listens on
# loopback and is reached over WireGuard, an mTLS front or an onion service,
# never by being published; only the agent channel faces the nodes. This sets
# up the database, the encryption key and the service.
#
# It creates no administrator: the panel asks for one on its own screen the
# first time it is opened, and takes no commands (0062).
#
# What the panel runs is checked before it runs: the binary against the release
# signature, the same way a node checks its agent.

set -euo pipefail

repository="${ANYPROXY_REPOSITORY:-anym1re/anyProxy}"
prefix="${ANYPROXY_PREFIX:-/usr/local/bin}"
etc="/etc/anyproxy"
state="/var/lib/anyproxy-panel"
service_user="anyproxy-panel"
db_role="anyproxy"
db_name="anyproxy_live"

version=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run this as root; the panel itself will not be" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── the node's machine is not the panel ──────────────────────────────────

# The mirror of decision 0049. A node is an address handed to clients and meant
# to be found; the panel is what must not be. Together on one machine, finding
# the node finds the panel, and a node serving plain MTProto collides with the
# panel's agent channel on 8443.
#
# Each source is read into a variable and matched with `case`. Piping into
# `grep -q` reads better and is wrong under `set -o pipefail`: grep leaves on
# its first match, the writer dies of SIGPIPE, and the pipeline fails exactly
# when it found something.
node_units="$(systemctl list-unit-files anyproxy-agent.service 2>/dev/null || true)"
node_running="$(ps -eo args= 2>/dev/null || true)"
node_here=""
case "${node_units}" in *anyproxy-agent*) node_here="a systemd unit named anyproxy-agent" ;; esac
if [ -z "${node_here}" ] && [ -x "${prefix}/anyproxy-agent" ]; then
    node_here="the agent binary at ${prefix}/anyproxy-agent"
fi
if [ -z "${node_here}" ]; then
    case "${node_running}" in *anyproxy-agent*) node_here="the agent running on this machine" ;; esac
fi
if [ -n "${node_here}" ]; then
    cat >&2 <<WHY
This machine runs a node: ${node_here}.

The panel does not go on a node's machine. A node is an address clients are
given and are meant to find; the panel holds every client, every access and
every secret. Put the panel on a machine of its own.
WHY
    exit 1
fi

# ── enough memory to build nothing, but Postgres wants some ──────────────

# The panel binary is fetched, not built here, so this is only Postgres and the
# service. A little swap keeps a 1-2 GB machine from killing Postgres under a
# migration; on a machine that already has swap this does nothing.
if [ "$(free -m | awk '/^Mem:/ {print $2}')" -lt 3072 ] && [ ! -e /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "added 2G of swap"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq postgresql ca-certificates curl >/dev/null
systemctl enable --now postgresql >/dev/null 2>&1 || true

# ── the binary, checked before it is installed ───────────────────────────

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

for tool in anyproxy-panel anyproxy; do
    binary="${tool}-${target}"
    base="https://github.com/${repository}/releases/download/${version}"
    echo "fetching ${binary} ${version}"
    curl -fsSL -o "${work}/${binary}" "${base}/${binary}"
    curl -fsSL -o "${work}/${binary}.bundle" "${base}/${binary}.bundle"
    "${here}/verify-release.sh" "${work}/${binary}" "${work}/${binary}.bundle"
done

install -o root -g root -m 0755 "${work}/anyproxy-panel-${target}" "${prefix}/anyproxy-panel"
install -o root -g root -m 0755 "${work}/anyproxy-${target}" "${prefix}/anyproxy"

# ── the service account and its places ───────────────────────────────────

id -u "${service_user}" >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin "${service_user}"
install -d -o root -g root -m 0755 "${etc}"
install -d -o "${service_user}" -g "${service_user}" -m 0700 "${state}"

# The key that seals every stored credential. Thirty-two bytes, read by the
# service account alone, made once and never overwritten: rewriting it would
# strand every secret already sealed with the old one.
key_file="${etc}/panel.key"
if [ ! -f "${key_file}" ]; then
    umask 077
    head -c 32 /dev/urandom > "${key_file}"
    chown "${service_user}:${service_user}" "${key_file}"
    chmod 400 "${key_file}"
    echo "wrote a new encryption key"
else
    echo "keeping the encryption key already here"
fi

# ── the database ─────────────────────────────────────────────────────────

# The role owns its database and may create the audit role that migration 0002
# adds. CREATEROLE is granted for that reason and no other: the panel runs its
# own migrations on startup, and 0002 is one of them. Without it the first
# start fails with "permission denied to create role" — which is how a hand
# install failed until it was found.
db_password=""
if su - postgres -c "psql -tAc \"select 1 from pg_roles where rolname='${db_role}'\"" | grep -q 1; then
    echo "keeping the database role already here"
else
    db_password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
    su - postgres -c "psql -q -c \"create role ${db_role} login createrole password '${db_password}'\"" >/dev/null
    su - postgres -c "psql -q -c \"create database ${db_name} owner ${db_role}\"" >/dev/null
    echo "created the database and its role"
fi

# ── what the service reads ───────────────────────────────────────────────

# Written only when the role was just made: a re-run that kept the existing
# role has no password to write, and clobbering the file would break the
# service that is already using it.
env_file="${etc}/panel.env"
if [ -n "${db_password}" ]; then
    umask 077
    cat > "${env_file}" <<ENV
DATABASE_URL=postgres://${db_role}:${db_password}@127.0.0.1/${db_name}
ANYPROXY_KEY_FILE=${key_file}
ANYPROXY_PANEL_BIND=127.0.0.1:8080
ANYPROXY_CHANNEL_BIND=0.0.0.0:8443
ENV
    chown root:"${service_user}" "${env_file}"
    chmod 640 "${env_file}"
    echo "wrote ${env_file}"
elif [ ! -f "${env_file}" ]; then
    echo "the role was already here but ${env_file} is missing; write it by hand" >&2
    exit 1
fi

install -o root -g root -m 0644 "${here}/../deploy/anyproxy-panel.service" \
    /etc/systemd/system/anyproxy-panel.service
systemctl daemon-reload
systemctl enable --now anyproxy-panel >/dev/null 2>&1 || systemctl restart anyproxy-panel

# The migrations run on start. Wait for the REST port before going on, the way
# install-front waits for 443: a service that accepted the start signal is not
# yet a service that is serving.
waited=0
until su - postgres -c "psql -tAc \"select 1 from pg_database where datname='${db_name}'\"" \
    | grep -q 1 && ss -ltn 2>/dev/null | grep -q '127.0.0.1:8080'; do
    waited=$((waited + 1))
    if [ "${waited}" -ge 20 ]; then
        echo "the panel did not come up; its log:" >&2
        journalctl -u anyproxy-panel -n 20 --no-pager >&2 || true
        exit 1
    fi
    sleep 1
done
echo "the panel is up"

echo
echo "the panel is installed. Reach it over a tunnel; it listens on loopback."
if su - postgres -c "psql -tAc 'select count(*) from admin_user'" "${db_name}" | grep -q '^0$'; then
    echo "open it and make your account; the first one to open it becomes the owner"
fi
