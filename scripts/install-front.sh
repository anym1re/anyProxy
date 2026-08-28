#!/usr/bin/env bash
# Puts the front door on 443 for a node that carries clients inside a site.
#
#     scripts/install-front.sh --domain <name> --agree-tos [--email <address>]
#
# Such a node is reached over real TLS to a name it owns, and something has to
# end that TLS. That something is here: it holds the certificate, serves the
# site, and hands the plain request to the engine.
#
# Nothing here belongs on a node of any other kind. One method to a host, so a
# node with a forged handshake ends its own TLS and keeps 443 to itself, and a
# node serving SOCKS5, HTTP or plain MTProto has no name and no certificate.

set -euo pipefail

# Where the engine listens once the panel has told it to. This matches the
# panel's own number, in docs/spec/NETWORK.md §3; a door pointing elsewhere
# would answer every client with nothing.
readonly behind_site=8444

domain=""
email=""
agreed=""

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)    domain="$2"; shift 2 ;;
        --email)     email="$2";  shift 2 ;;
        --agree-tos) agreed=yes;  shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "${domain}" ] || { echo "missing --domain" >&2; exit 2; }

# The certificate comes from Let's Encrypt, whose subscriber agreement is a
# thing only the person installing this can accept. Asked for plainly rather
# than assumed, and never accepted on somebody's behalf.
if [ -z "${agreed}" ]; then
    cat >&2 <<'WHY'
A certificate for this node comes from Let's Encrypt, and obtaining one means
accepting their subscriber agreement:

    https://letsencrypt.org/repository/

Pass --agree-tos to say that you accept it. Nothing is requested until you do.
WHY
    exit 2
fi

[ "$(id -u)" = 0 ] || { echo "run this as root" >&2; exit 1; }

# A name that does not lead here cannot be certified, and finding that out now
# is cheaper than finding it out from every client in turn.
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
apt-get install -y -qq nginx certbot >/dev/null

# Anything this script put here before is taken down first. It is written again
# below, and leaving the old one up would hold the port the new one wants —
# which is how a second run of an installer fails where the first succeeded.
#
# The stream block belongs to a door that told two carriers apart by the name
# a client asked for. One method to a host leaves nothing to tell apart, so a
# block left behind by an older install is removed rather than worked around.
rm -f /etc/nginx/sites-enabled/anyproxy-site
sed -i '/# anyproxy front door/,/^}$/d' /etc/nginx/nginx.conf
rm -f /etc/nginx/modules-enabled/60-anyproxy-front.conf

# Port 80 answers the challenge and nothing else. A node is not a web server.
install -d -o root -g root -m 0755 /var/www/anyproxy
cat > /etc/nginx/sites-available/anyproxy-challenge <<'CONF'
server {
    listen 80 default_server;
    root /var/www/anyproxy;

    # Nothing about who asked is written down. See the site block below.
    access_log off;

    location /.well-known/acme-challenge/ { }
    location / { return 404; }
}
CONF
rm -f /etc/nginx/sites-enabled/default
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

# Renewal puts a new certificate on disk; the door has to be told to read it.
install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/anyproxy-front <<'HOOK'
#!/bin/sh
systemctl reload nginx
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/anyproxy-front

if ! grep -q "anyproxy_upgrade" /etc/nginx/nginx.conf; then
    sed -i '/^http {/a\    map $http_upgrade $anyproxy_upgrade { default upgrade; "" close; }' \
        /etc/nginx/nginx.conf
fi

# The door: one name, one certificate, one thing behind it.
#
# It answers a request for any other name the same way, because it is the only
# server here and nginx serves the first one for a name it does not know. That
# is what every web server on the internet does, and refusing instead would
# make this node the one address that hangs up on an ordinary greeting.
cat > /etc/nginx/sites-available/anyproxy-site <<CONF
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name ${domain};

    ssl_certificate     /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # "nginx" and nothing after it. A version is one more thing to match a
    # node against, and no version at all is rarer than the commonest server
    # on the internet.
    server_tokens off;

    # Nothing about who asked for what is written down.
    #
    # A default access log records the request line, the time and the browser
    # of every client, which on a node is a record of who was using it and
    # when — the one record this design exists to not keep. The request line
    # also carries what the client can do, and the authorization header
    # carries a bearer credential.
    #
    # The error log is turned down for the same reason: at its usual level it
    # records the address of anyone whose request went wrong.
    access_log off;
    error_log /var/log/nginx/error.log crit;

    location / {
        proxy_pass http://127.0.0.1:${behind_site};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$anyproxy_upgrade;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }
}
CONF
ln -sf /etc/nginx/sites-available/anyproxy-site /etc/nginx/sites-enabled/anyproxy-site

nginx -t >/dev/null
systemctl reload nginx
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

# Whether 443 is actually being served, asked of the port rather than of
# systemd.
#
# `nginx -t` checks the file and `systemctl reload` returns success as soon as
# nginx accepts the signal. Neither notices that a worker could not bind: nginx
# logs `bind() ... failed (98)`, keeps the workers it already had, and exits
# zero. A door that never opened then reports itself up, and the node looks
# installed while every client reaches nothing.
#
# Seen exactly that way: the engine of the method this node served before had
# not finished letting go of 443 when the reload ran.
door_is_up() {
    local listening
    listening="$(ss -ltn 'sport = :443' 2>/dev/null || true)"
    case "${listening}" in
        *LISTEN*) return 0 ;;
    esac
    return 1
}

waited=0
while ! door_is_up; do
    waited=$((waited + 1))
    if [ "${waited}" -ge 10 ]; then
        echo "nginx was reloaded, but nothing is listening on 443" >&2
        echo "what holds the port now:" >&2
        ss -ltnp 'sport = :443' 2>/dev/null >&2 || true
        echo "what nginx said:" >&2
        tail -3 /var/log/nginx/error.log 2>/dev/null >&2 || true
        echo >&2
        echo "a node serves one method: stop the engine of the previous one" >&2
        echo "and run this again." >&2
        exit 1
    fi
    sleep 1
    systemctl reload nginx 2>/dev/null || true
done

echo "the front door is up for ${domain}"
