#!/usr/bin/env bash
# The deterministic scanners of the public links site (0094).
#
#     scripts/check-site.sh              the site in this tree, against a feed
#                                        in the same process, no network
#     scripts/check-site.sh <url>        a deployed site, over the network
#
# Without an address, this runs the scanners built into the crate: every path,
# every header, the HTML, every link. With one, the same questions are put to
# a live site with curl, so an installation can be checked from anywhere.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

report() {
    echo "  FAIL  $1"
    failures=$((failures + 1))
}

ok() {
    echo "  ok    $1"
}

if [ $# -eq 0 ]; then
    echo "site scanners, in-process"
    if (cd "${root}" && cargo test -p ap-site --locked -- --quiet); then
        echo "site scanners passed"
        exit 0
    fi
    echo "site scanners failed" >&2
    exit 1
fi

site="${1%/}"
case "${site}" in
    https://*) ;;
    *) echo "the address must begin with https://" >&2; exit 2 ;;
esac
command -v curl >/dev/null 2>&1 || { echo "curl is needed" >&2; exit 2; }

echo "site scanners against ${site}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# One request, headers and body kept apart.
fetch() {
    local method="$1" path="$2"
    shift 2
    curl -sS -o "${work}/body" -D "${work}/head" -X "${method}" "$@" \
        --max-time 15 "${site}${path}" 2>"${work}/err"
}

status() {
    sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "${work}/head"
}

header() {
    # Header names are case-insensitive; values are compared as they arrive.
    grep -i "^$1:" "${work}/head" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'
}

expect_status() {
    local path="$1" want="$2" got
    got="$(status)"
    if [ "${got}" = "${want}" ]; then
        ok "${path} answers ${want}"
    else
        report "${path} answers ${got:-nothing}, expected ${want}"
    fi
}

expect_headers() {
    local path="$1"
    local name value got
    while IFS='|' read -r name value; do
        got="$(header "${name}")"
        if [ "${got}" = "${value}" ]; then
            ok "${path}: ${name}"
        else
            report "${path}: ${name} is '${got}', expected '${value}'"
        fi
    done <<'HEADERS'
content-security-policy|default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
strict-transport-security|max-age=31536000; includeSubDomains
x-content-type-options|nosniff
referrer-policy|no-referrer
permissions-policy|camera=(), microphone=(), geolocation=(), interest-cohort=()
cross-origin-resource-policy|same-origin
HEADERS
    for absent in server x-powered-by set-cookie; do
        if [ -n "$(header "${absent}")" ]; then
            report "${path}: carries ${absent}"
        fi
    done
}

# ── every path, its status and its headers ───────────────────────────────

while IFS='|' read -r path want; do
    fetch GET "${path}" -H 'Accept-Language: de'
    expect_status "${path}" "${want}"
    expect_headers "${path}"
done <<'PATHS'
/|302
/ru|301
/ru/|200
/en/|200
/links.json|200
/sitemap.xml|200
/robots.txt|200
/llms.txt|200
/style.css|200
/icon.svg|200
/nothing-here|404
/health|404
/metrics|404
PATHS

fetch POST "/ru/"
expect_status "POST /ru/" 405
if [ "$(header allow)" = "GET, HEAD" ]; then ok "POST is refused with Allow"; else report "POST refused without Allow"; fi

fetch GET "/" -H 'Accept-Language: en'
if [ "$(header location)" = "${site}/en/" ]; then ok "/ leads English to /en/"; else report "/ led English to '$(header location)'"; fi
fetch GET "/" -H 'Accept-Language: ru'
if [ "$(header location)" = "${site}/ru/" ]; then ok "/ leads Russian to /ru/"; else report "/ led Russian to '$(header location)'"; fi

# ── the pages ─────────────────────────────────────────────────────────────

for path in /ru/ /en/; do
    fetch GET "${path}"
    page="${work}/body"
    if head -c 15 "${page}" | grep -q '^<!doctype html>'; then ok "${path}: doctype"; else report "${path}: no doctype"; fi
    if grep -qE '<html lang="(ru|en)">' "${page}"; then ok "${path}: lang"; else report "${path}: no lang"; fi
    if [ "$(grep -c '<h1>' "${page}")" = 1 ]; then ok "${path}: one h1"; else report "${path}: h1 count is $(grep -c '<h1>' "${page}")"; fi
    if [ "$(grep -c '<script' "${page}")" = 1 ] && grep -q '<script type="application/ld+json">' "${page}"; then
        ok "${path}: the only script is JSON-LD"
    else
        report "${path}: scripts other than JSON-LD"
    fi
    if grep -qE ' style="| on[a-z]+="' "${page}"; then report "${path}: inline style or handler"; else ok "${path}: no inline style or handler"; fi
    for needed in 'rel="canonical"' 'hreflang="x-default"' 'name="description"' 'property="og:url"'; do
        if grep -q "${needed}" "${page}"; then ok "${path}: ${needed}"; else report "${path}: missing ${needed}"; fi
    done
    if command -v tidy >/dev/null 2>&1; then
        if tidy -q -e "${page}" >/dev/null 2>&1; then ok "${path}: tidy finds no error"; else report "${path}: tidy reports errors"; fi
    fi

    # Every address on the page that is not a Telegram link answers 200.
    grep -oE '(href|src)="[^"]*"' "${page}" | sed 's/^[a-z]*="//; s/"$//' | sort -u \
        | while read -r address; do
            case "${address}" in
                https://t.me/*) continue ;;
                "${site}"/*) local_path="${address#"${site}"}" ;;
                /*) local_path="${address}" ;;
                *) echo "  FAIL  ${path}: foreign address ${address}"; continue ;;
            esac
            code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "${site}${local_path}" 2>/dev/null)"
            if [ "${code}" = 200 ]; then echo "  ok    ${local_path} answers"; else echo "  FAIL  ${local_path} answers ${code}"; fi
        done | tee "${work}/links"
    if grep -q FAIL "${work}/links"; then failures=$((failures + 1)); fi
done

# ── the machine copies ────────────────────────────────────────────────────

fetch GET /robots.txt
if grep -q "^Sitemap: ${site}/sitemap.xml" "${work}/body"; then ok "robots.txt names the sitemap"; else report "robots.txt does not name the sitemap"; fi
fetch GET /sitemap.xml
grep -oE '<loc>[^<]*</loc>' "${work}/body" | sed 's/<loc>//; s/<\/loc>//' | while read -r address; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "${address}" 2>/dev/null)"
    if [ "${code}" = 200 ]; then echo "  ok    sitemap: ${address}"; else echo "  FAIL  sitemap: ${address} answers ${code}"; fi
done | tee "${work}/sitemap"
if grep -q FAIL "${work}/sitemap"; then failures=$((failures + 1)); fi
fetch GET /llms.txt
if grep -q "${site}/links.json" "${work}/body"; then ok "llms.txt names the list"; else report "llms.txt does not name the list"; fi
fetch GET /links.json
if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${work}/body" 2>/dev/null \
    || grep -q '^{"links":\[' "${work}/body"; then
    ok "links.json is JSON"
else
    report "links.json is not JSON"
fi

if [ "${failures}" -ne 0 ]; then
    echo "site scanners failed: ${failures}" >&2
    exit 1
fi
echo "site scanners passed"
