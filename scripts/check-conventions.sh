#!/usr/bin/env bash
# Deterministic checks for the conventions that types cannot express.
# Usage: scripts/check-conventions.sh [root]
set -uo pipefail

root="${1:-.}"
found=0

# grep prints path:line:text, so a comment is recognised after that prefix.
# A rule that fires on prose has no value.
comment='^[^:]*:[0-9]+:[[:space:]]*(//|/\*|\*)'

# Reads matches from a command and records them. Process substitution keeps
# the loop in this shell: inside a pipeline the counter would be lost to a
# subshell and the check could never fail.
collect() {
    local id="$1"
    shift
    local hit
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        found=1
        printf '%s\t%s\n' "$id" "$hit"
    done < <("$@" 2>/dev/null | grep -vE "$comment")
}

# User-facing output comes from the message catalogue, never from a literal.
# A format string of nothing but placeholders and punctuation is fine.
user_facing_literal() {
    local path="$1"
    [ -d "$path" ] || return 0
    grep -rnE --include='*.rs' '\b(println|eprintln|print|eprint)!\("' "$path" \
        | grep -vE '!\("(\{[^}]*\}|[[:space:]:,.;|/()\[\]<>=+*-])*"'
}

# A secret leaves by exactly two roads, and no third.
#
#   ap-core        rendering a connection link, which is audited
#   ap-panel       handing the node its own accesses over the agent channel
#
# The second is not a leak: a node that does not know the secret cannot
# recognise the client it belongs to. Every other appearance is one.
secret_exposed() {
    grep -rnE --include='*.rs' '\.expose_hex\(\)' "${root}/crates"         | grep -vE '(^|/)(ap-core|ap-panel/src/channel\.rs)'
}

# Appending to a formatted timestamp is how the expiry logic died in the tool
# this project replaces. Time is parsed and printed, never edited.
timestamp_string_op() {
    [ -d "${root}/crates" ] || return 0
    # A byte literal is not a timestamp. Timestamps here are always strings,
    # so b'Z' — which turns up in character ranges like b'A'..=b'Z' — cannot be
    # the thing this rule exists to catch.
    grep -rnE --include='*.rs' '"Z"|'"'"'Z'"'"'' "${root}/crates"         | grep -vF "b'Z'"
}

# Queries are built by the query macro, not by joining strings.
sql_concatenation() {
    [ -d "${root}/crates" ] || return 0
    grep -rnE --include='*.rs' \
        '(format!|push_str|\+ ")[^\n]*(SELECT |INSERT INTO|UPDATE |DELETE FROM)' \
        "${root}/crates"
}

# Every route the panel serves reaches a handler that asks who is calling.
#
# The panel has no middleware demanding a session: each handler takes an Actor,
# and an Actor cannot be built without one. That is a convention, and a handler
# written without it would be reachable by anyone who can open the socket.
#
# Three routes are open on purpose: two say whether the process is alive, and
# the third is how a session begins. They are named here so that adding a
# fourth is a decision somebody makes rather than an omission nobody sees.
handler_without_actor() {
    local path="${root}/crates/ap-panel/src/routes.rs"
    [ -f "$path" ] || return 0

    # Open on purpose: two say whether the process is alive, one is how a
    # session begins, and five are the interface itself, its words and the
    # faces it is drawn with — a page, a catalogue and a typeface hold no
    # data (0058, 0068). Adding another should be somebody's decision rather
    # than an omission nobody sees.
    local open_on_purpose="health|ready|sign_in|setup_state|set_up|interface|interface_style|interface_script|interface_text|interface_font"
    local handler

    for handler in $(grep -oE "(get|post|delete|put|patch)\([a-z_]+\)" "$path"         | sed -E "s/^[a-z]+\(//; s/\)$//" | sort -u); do
        printf "%s" "$handler" | grep -qE "^(${open_on_purpose})$" && continue
        # The signature runs from the name to the line that closes it.
        if ! sed -n "/^async fn ${handler}(/,/^)/p" "$path" | grep -q "Actor"; then
            echo "${handler}: reachable without a session"
        fi
    done
}

# The feed the public site reads lives on a listener of its own (0091).
#
# Whoever can reach the feed must not thereby reach the sign-in or the setup
# form, so its route is built in feed.rs and served apart. A `public-links`
# route in routes.rs would put it beside them, and nothing in the type system
# would notice.
feed_on_the_rest_listener() {
    local path="${root}/crates/ap-panel/src"
    [ -d "$path" ] || return 0
    grep -rnE --include='*.rs' 'public-links' "$path" | grep -vE '(^|/)feed\.rs:'
}

collect user-facing-literal user_facing_literal "${root}/crates/ap-cli"
collect user-facing-literal user_facing_literal "${root}/crates/ap-panel"
collect secret-exposed secret_exposed
collect timestamp-string-op timestamp_string_op
collect sql-concatenation sql_concatenation
collect handler-without-actor handler_without_actor
collect feed-on-the-rest-listener feed_on_the_rest_listener

if [ "$found" -ne 0 ]; then
    echo "convention check failed" >&2
    exit 1
fi
echo "convention check passed"
