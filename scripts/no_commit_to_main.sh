#!/usr/bin/env bash
# Hard Rule #7 (AGENTS.md): never commit directly to main.
# Wired into .pre-commit-config.yaml as a `pre-commit` stage hook so it only
# fires at commit time — not on `pre-commit run --all-files` audits.
set -eu
branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
if [ "$branch" = "main" ]; then
  echo "✗ Hard Rule #7 — commit on a feature branch (feat/<id>-*, chore/, docs/, fix/), not main."
  echo "  See AGENTS.md §Hard rules."
  exit 1
fi
exit 0
