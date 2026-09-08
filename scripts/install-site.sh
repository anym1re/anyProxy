#!/usr/bin/env bash
# Turns a fresh machine into the public links site.
#
#     scripts/install-site.sh --domain <name> --feed <host:port> --agree-tos \
#         [--email <address>] [--version <tag>] [--lang ru|en]
#
# The site shows the links an operator made public, to anyone, and holds
# nothing of its own: the list comes from the panel's feed over a tunnel,
# already rendered. nginx ends TLS on 443 with a certificate from Let's
# Encrypt and hands the plain request to the site on loopback.
#
# A site's machine is its own. The panel does not go here — its port would be
# on a public machine — and neither does a node: a node is one method to a
# host, and the site takes 443.
#
# What the site runs is checked before it runs: the binary against the release
# signature, the same way a node checks its agent.

set -euo pipefail

repository="${ANYPROXY_REPOSITORY:-anym1re/anyProxy}"
prefix="${ANYPROXY_PREFIX:-/usr/local/bin}"
etc="/etc/anyproxy"
service_user="anyproxy-site"

# Where the site listens and where nginx sends the plain request. Matches the
# unit and docs/spec/NETWORK.md §3.
readonly behind_front=8081

domain=""
feed=""
email=""
agreed=""
version=""
lang="ru"

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)    domain="$2";  shift 2 ;;
        --feed)      feed="$2";    shift 2 ;;
        --email)     email="$2";   shift 2 ;;
        --version)   version="$2"; shift 2 ;;
        --lang)      lang="$2";    shift 2 ;;
        --agree-tos) agreed=yes;   shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "${domain}" ] || { echo "missing --domain" >&2; exit 2; }
[ -n "${feed}" ] || { echo "missing --feed <host:port>, the panel's feed over the tunnel" >&2; exit 2; }
case "${feed}" in
    *:*) ;;
    *) echo "--feed takes host:port" >&2; exit 2 ;;
esac
case "${lang}" in
    ru | en) ;;
    *) echo "--lang is ru or en" >&2; exit 2 ;;
esac

# The certificate comes from Let's Encrypt, whose subscriber agreement is a
# thing only the person installing this can accept. Asked for plainly rather
# than assumed, and never accepted on somebody's behalf.
if [ -z "${agreed}" ]; then
    cat >&2 <<'WHY'
A certificate for this site comes from Let's Encrypt, and obtaining one means
accepting their subscriber agreement:

    https://letsencrypt.org/repository/

Pass --agree-tos to say that you accept it. Nothing is requested until you do.
WHY
    exit 2
fi

[ "$(id -u)" = 0 ] || { echo "run this as root; the site itself will not be" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── neither the panel's machine nor a node's ─────────────────────────────

# Each source is read into a variable and matched with `case`, for the reason
# install-panel.sh gives: a pipeline into `grep -q` fails under pipefail
# exactly when it found something.
units="$(systemctl list-unit-files 'anyproxy-*.service' 2>/dev/null || true)"
running="$(ps -eo args= 2>/dev/null || true)"
other=""
case "${units}" in *anyproxy-panel*) other="the systemd unit of the panel" ;; esac
if [ -z "${other}" ]; then
    case "${units}" in *anyproxy-agent*) other="the systemd unit of a node" ;; esac
fi
if [ -z "${other}" ]; then
    for binary in anyproxy-panel anyproxy-agent; do
        [ -x "${prefix}/${binary}" ] && other="the binary at ${prefix}/${binary}"
    done
fi
if [ -z "${other}" ]; then
    case "${running}" in *anyproxy-panel* | *anyproxy-agent*) other="a panel or a node running here" ;; esac
fi
if [ -n "${other}" ]; then
    cat >&2 <<WHY
This machine runs the panel or a node: ${other}.

The site does not share a machine with either. The panel holds every secret
and does not publish a port; a node serves one method on one host, and the
site takes 443. Put the site on a machine of its own.
WHY
    exit 1
fi

# A name that does not lead here cannot be certified.
resolved="$(getent hosts "${domain}" | awk '{print $1}' | head -1 || true)"
if [ -z "${resolved}" ]; then
    echo "${domain} resolves to nothing" >&2
    exit 1
fi
if ! ip -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -qx "${resolved}"; then
    echo "${domain} leads to ${resolved}, which is not an address of this machine" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq nginx certbot ca-certificates curl >/dev/null

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

binary="anyproxy-site-${target}"
base="https://github.com/${repository}/releases/download/${version}"
echo "fetching ${binary} ${version}"
curl -fsSL -o "${work}/${binary}" "${base}/${binary}"
curl -fsSL -o "${work}/${binary}.bundle" "${base}/${binary}.bundle"
"${here}/verify-release.sh" "${work}/${binary}" "${work}/${binary}.bundle"
install -o root -g root -m 0755 "${work}/${binary}" "${prefix}/anyproxy-site"

# ── the service account and what it reads ────────────────────────────────

id -u "${service_user}" >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin "${service_user}"
install -d -o root -g root -m 0755 "${etc}"

# No secret in here: the feed is reached by address over a tunnel, and the
# site has nothing to sign in with. Readable by the service alone anyway.
env_file="${etc}/site.env"
umask 077
cat > "${env_file}" <<ENV
ANYPROXY_SITE_URL=https://${domain}
ANYPROXY_SITE_FEED=http://${feed}
ANYPROXY_SITE_DEFAULT_LANG=${lang}
ANYPROXY_SITE_REFRESH=60
ENV
chown root:"${service_user}" "${env_file}"
chmod 640 "${env_file}"
umask 022

install -o root -g root -m 0644 "${here}/../deploy/anyproxy-site.service" \
    /etc/systemd/system/anyproxy-site.service
systemctl daemon-reload
systemctl enable --now anyproxy-site >/dev/null 2>&1 || systemctl restart anyproxy-site

# ── the front on 443 ─────────────────────────────────────────────────────

rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/anyproxy-links

# Port 80 answers the challenge and sends everything else to 443.
install -d -o root -g root -m 0755 /var/www/anyproxy
cat > /etc/nginx/sites-available/anyproxy-challenge <<CONF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/anyproxy;
    access_log off;

    location /.well-known/acme-challenge/ { }
    location / { return 301 https://${domain}\$request_uri; }
}
CONF
ln -sf /etc/nginx/sites-available/anyproxy-challenge /etc/nginx/sites-enabled/anyproxy-challenge
nginx -t >/dev/null
systemctl restart nginx

registration=(--agree-tos --non-interactive)
if [ -n "${email}" ]; then
    registration+=(--email "${email}")
else
    registration+=(--register-unsafely-without-email)
fi
certbot certonly --webroot -w /var/www/anyproxy -d "${domain}" "${registration[@]}" >/dev/null

install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/anyproxy-links <<'HOOK'
#!/bin/sh
systemctl reload nginx
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/anyproxy-links

# Requests per address, counted in memory and written nowhere: the site keeps
# no record of who looked, and neither does the front (0092).
if ! grep -q "anyproxy_links_zone" /etc/nginx/nginx.conf; then
    sed -i '/^http {/a\    limit_req_zone $binary_remote_addr zone=anyproxy_links_zone:10m rate=20r/s;' \
        /etc/nginx/nginx.conf
fi

# The site answers for any name it is asked by, the way every web server
# does. Security headers come from the site itself; nginx adds none and
# strips none.
cat > /etc/nginx/sites-available/anyproxy-links <<CONF
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name ${domain};

    ssl_certificate     /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;

    # Nothing about who asked for what is written down (0092).
    access_log off;
    error_log /var/log/nginx/error.log crit;

    client_max_body_size 1k;
    limit_req zone=anyproxy_links_zone burst=40 nodelay;

    location / {
        proxy_pass http://127.0.0.1:${behind_front};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_read_timeout 15s;
        proxy_send_timeout 15s;
    }
}
CONF
ln -sf /etc/nginx/sites-available/anyproxy-links /etc/nginx/sites-enabled/anyproxy-links

nginx -t >/dev/null
systemctl reload nginx
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

# Whether 443 is actually being served, asked of the port rather than of
# systemd, for the reason install-front.sh gives.
front_is_up() {
    local listening
    listening="$(ss -ltn 'sport = :443' 2>/dev/null || true)"
    case "${listening}" in
        *LISTEN*) return 0 ;;
    esac
    return 1
}

waited=0
while ! front_is_up; do
    waited=$((waited + 1))
    if [ "${waited}" -ge 10 ]; then
        echo "nginx was reloaded, but nothing is listening on 443" >&2
        ss -ltnp 'sport = :443' 2>/dev/null >&2 || true
        tail -3 /var/log/nginx/error.log 2>/dev/null >&2 || true
        exit 1
    fi
    sleep 1
    systemctl reload nginx 2>/dev/null || true
done

# Whether the site itself is up and has heard the feed. "never" here means
# the tunnel to the panel is not carrying the feed yet; the site serves an
# honest empty page until it does.
waited=0
until curl -fsS "http://127.0.0.1:8091/health" >/dev/null 2>&1; do
    waited=$((waited + 1))
    if [ "${waited}" -ge 30 ]; then
        echo "the site is up but has not heard the feed at ${feed}:" >&2
        curl -sS "http://127.0.0.1:8091/health" >&2 || true
        journalctl -u anyproxy-site -n 10 --no-pager >&2 || true
        echo "check the tunnel and ANYPROXY_FEED_BIND on the panel; the page is served empty until then" >&2
        break
    fi
    sleep 2
done

echo "the site is up at https://${domain}/"
echo "check it: scripts/check-site.sh https://${domain}"
