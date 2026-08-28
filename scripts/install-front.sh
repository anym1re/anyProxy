#!/usr/bin/env bash
# Puts the front door on 443 for a node that serves a site of its own.
#
#     scripts/install-front.sh --domain <name> --agree-tos [--email <address>]
#                              [--handshake]
#
# A node carrying clients inside web traffic is reached over real TLS, which
# something has to end. That something is here: it holds the certificate for
# the node's own name and hands the plain request to the engine.
#
# One port carries both carriers. The door sends on by the name the client
# asked for — the node's own name to the site, anything else to the forged
# handshake — so a node can serve both instead of one displacing the other.
#
# Nothing here is needed by a node that serves only the forged handshake: that
# node keeps 443 to itself and there is no door in front of it.

set -euo pipefail

# Where the engine listens once the panel has told it to. These match the
# panel's own numbers, in docs/spec/NETWORK.md §3; a door pointing elsewhere
# would answer every client with nothing.
readonly behind_site=8444
readonly behind_handshake=8445

# Where the TLS ends before the plain request goes on. Not 8443, which is where
# a panel listens for its nodes: the two collide wherever both run, and a test
# machine running both is exactly where that is found out.
readonly terminator=8446

domain=""
email=""
agreed=""
handshake=""

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)    domain="$2"; shift 2 ;;
        --email)     email="$2";  shift 2 ;;
        --agree-tos) agreed=yes;  shift ;;
        --handshake) handshake=yes; shift ;;
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
apt-get install -y -qq nginx libnginx-mod-stream certbot >/dev/null

# Anything this script put here before is taken down first. It is written again
# below, and leaving the old one up would hold a port the new one wants — which
# is how a second run of an installer fails where the first succeeded.
rm -f /etc/nginx/sites-enabled/anyproxy-site
sed -i '/# anyproxy front door/,/^}$/d' /etc/nginx/nginx.conf

# nginx takes one stream block and no more. If somebody else's is already
# there, stop: adding a second breaks the web server that machine is running,
# and a working machine broken by an installer is worse than one not installed.
if grep -qE '^\s*stream\s*\{' /etc/nginx/nginx.conf; then
    echo "this machine already has a stream block in /etc/nginx/nginx.conf" >&2
    echo "the door needs one of its own; merge them by hand and run this again" >&2
    exit 1
fi

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

# Where a name we do not serve is sent.
#
# To the forged handshake when the node serves one, because that is how its
# clients arrive: they ask for the name it borrows. Otherwise to the site,
# which answers as a web server does when the name does not match — with a
# certificate and a page. Refusing instead would make the node the one address
# on the internet that hangs up on a plain TLS greeting.
if [ -n "${handshake}" ]; then
    otherwise="127.0.0.1:${behind_handshake}"
else
    otherwise="127.0.0.1:${terminator}"
fi

# The door itself: one port, two carriers, told apart by the name asked for.
cat > /etc/nginx/modules-enabled/60-anyproxy-front.conf <<CONF
# Left empty on purpose: the stream block lives in nginx.conf, which is the
# only place nginx will read one from.
CONF
if ! grep -q "anyproxy front door" /etc/nginx/nginx.conf; then
    cat >> /etc/nginx/nginx.conf <<CONF

# anyproxy front door
stream {
    map \$ssl_preread_server_name \$anyproxy_carrier {
        ${domain}   127.0.0.1:${terminator};
        default     ${otherwise};
    }

    server {
        listen 443;
        ssl_preread on;
        proxy_pass \$anyproxy_carrier;
        proxy_timeout 300s;
        access_log off;
    }
}
CONF
fi

if ! grep -q "anyproxy_upgrade" /etc/nginx/nginx.conf; then
    sed -i '/^http {/a\    map $http_upgrade $anyproxy_upgrade { default upgrade; "" close; }' \
        /etc/nginx/nginx.conf
fi

cat > /etc/nginx/sites-available/anyproxy-site <<CONF
server {
    listen 127.0.0.1:${terminator} ssl;
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

echo "the front door is up for ${domain}"
