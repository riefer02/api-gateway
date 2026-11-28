#!/usr/bin/env bash
#
# Enforces the two dependency rules that the module layout relies on and that
# a reviewer would otherwise have to remember. Both are greps, deliberately:
# a violation is a line in the diff, not a judgement call, and a proc-macro or
# an extra crate would be more machinery than the rule is worth.

set -euo pipefail

cd "$(dirname "$0")/.."

failed=0

check() {
    local description="$1"
    local pattern="$2"
    shift 2

    local matches
    if matches=$(grep -REn -- "$pattern" "$@" 2>/dev/null); then
        echo "architecture: $description" >&2
        echo "$matches" >&2
        failed=1
    fi
}

# `state` is the composition root. If anything it composes imports it back, the
# dependency graph gains a cycle and the module can no longer be read or tested
# without the whole application. Auth used to do this; do not reintroduce it.
check "these modules must not import state (it closes a cycle)" \
    "crate::state" \
    src/auth.rs src/proxy.rs src/net.rs src/routing.rs src/limits.rs \
    src/retry.rs src/mcp src/error.rs

# Credential and route storage each have exactly one owner: the store trait and
# the routing compiler. SQL anywhere else means a second write path that can
# drift from the first. `routing` reads the table it compiles; the store owns
# credentials; `admin` and `audit` own their own rows.
check "SQL belongs to the storage modules" \
    "sqlx::query" \
    src/routes src/proxy.rs src/auth.rs src/app.rs src/mcp

# Metric names are a contract with deploy/alerts.yml. A test checks the rules
# against the list; this stops a new literal from appearing beside it.
if matches=$(grep -REn '"gateway_[a-z0-9_]+"' src --include='*.rs' 2>/dev/null \
    | grep -v '^src/metric_names.rs:'); then
    echo "architecture: metric names belong in src/metric_names.rs" >&2
    echo "$matches" >&2
    failed=1
fi

exit "$failed"
