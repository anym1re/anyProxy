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

# A secret leaves only where a link is rendered, and that is audited.
secret_exposed() {
    local crate
    for crate in "${root}"/crates/*/; do
        [ -d "$crate" ] || continue
        case "$crate" in *ap-core/) continue ;; esac
        grep -rnE --include='*.rs' '\.expose_hex\(\)' "$crate"
    done
}

# Appending to a formatted timestamp is how the expiry logic died in the tool
# this project replaces. Time is parsed and printed, never edited.
timestamp_string_op() {
    [ -d "${root}/crates" ] || return 0
    grep -rnE --include='*.rs' '"Z"|'"'"'Z'"'"'' "${root}/crates"
}

# Queries are built by the query macro, not by joining strings.
sql_concatenation() {
    [ -d "${root}/crates" ] || return 0
    grep -rnE --include='*.rs' \
        '(format!|push_str|\+ ")[^\n]*(SELECT |INSERT INTO|UPDATE |DELETE FROM)' \
        "${root}/crates"
}

collect user-facing-literal user_facing_literal "${root}/crates/ap-cli"
collect user-facing-literal user_facing_literal "${root}/crates/ap-panel"
collect secret-exposed secret_exposed
collect timestamp-string-op timestamp_string_op
collect sql-concatenation sql_concatenation

if [ "$found" -ne 0 ]; then
    echo "convention check failed" >&2
    exit 1
fi
echo "convention check passed"
