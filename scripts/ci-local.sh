#!/usr/bin/env bash
# Local mirror of the GitHub Actions CI surface (ci.yml + security.yml).
#
# Same five gates the workflows run, on the current checkout. Used by humans
# pre-PR (`make ci-local`). Exits non-zero on the first failing gate —
# pip-audit is advisory-only and never fails the run.

set -uo pipefail

section() { printf '\n=== [%s] %s ===\n' "$1" "$2"; }
red()     { printf '\033[31m%s\033[0m\n' "$*"; }
green()   { printf '\033[32m%s\033[0m\n' "$*"; }

FAILED=()

run_gate() {
    local id="$1"; shift
    local name="$1"; shift
    section "$id/5" "$name"
    if "$@"; then
        green "  ✓ $name"
    else
        red   "  ✗ $name"
        FAILED+=("$id $name")
    fi
}

run_gate 1 "make check (lint + test + guardrails)" make check
run_gate 2 "ruff security lint (bandit subset)" \
    uv run ruff check --select S --extend-ignore S101 .
run_gate 3 "harness guardrails (re-confirm)" \
    uv run python scripts/harness_guardrails.py
run_gate 4 "tripwire ci dogfood" uv run python -m tripwire.cli ci

section "5/5" "pip-audit (advisory — never blocks)"
if uvx pip-audit; then
    green "  ✓ pip-audit (no known vulns)"
else
    red   "  ! pip-audit reported issues (advisory; not failing)"
fi

echo
if [ "${#FAILED[@]}" -eq 0 ]; then
    green "ci-local PASS"
    exit 0
else
    red "ci-local FAIL — ${#FAILED[@]} gate(s) failed:"
    printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
