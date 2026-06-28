#!/usr/bin/env bash
# Diff-coupling enforcement: if a branch changes user-visible code
# (src/tripwire/, app/, examples/), it must also update at least one
# per-feature page in docs/features/ — the catalog is the precise
# reference (docs/features/README.md), and code change without doc
# change means consumers learn about new behaviour by surprise.
#
# Wired as a pre-push hook (sibling to no-commit-to-main).
# Escape hatch: include the literal token "[docs-skip]" in any commit
# message in the branch (for typos, formatting-only changes, etc.).
#
# Graceful no-op when docs/features/ doesn't exist on this branch
# (catalog adoption may not yet be merged).
set -eu

# Pre-push base: prefer origin/main if it exists; fall back to common
# ancestor heuristics for first-push scenarios.
if git rev-parse --verify origin/main >/dev/null 2>&1; then
  base="origin/main"
elif git rev-parse --verify main >/dev/null 2>&1; then
  base="main"
else
  echo "no main/origin/main ref — skipping diff-coverage check" >&2
  exit 0
fi

# If we are *on* main, there's nothing to check vs a base; skip.
current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
if [ "$current_branch" = "main" ]; then
  exit 0
fi

# Skip cleanly if the catalog doesn't exist yet (rule activates after
# docs/features/ lands).
if [ ! -d "docs/features" ]; then
  exit 0
fi

# Files changed in the branch (range = base..HEAD).
changed=$(git diff --name-only "$base"...HEAD 2>/dev/null || echo "")
if [ -z "$changed" ]; then
  exit 0
fi

# Behavioural paths — a change to any of these implies a consumer-visible
# difference and should be reflected in docs/features/.
behavioural=$(printf '%s\n' "$changed" | grep -E '^(src/tripwire/.*\.py|app/.*\.py|examples/.*\.py)$' || true)
features=$(printf '%s\n' "$changed" | grep -E '^docs/features/.+\.md$' | grep -v '^docs/features/README\.md$' || true)

if [ -z "$behavioural" ]; then
  exit 0  # no user-visible code change, nothing to enforce
fi
if [ -n "$features" ]; then
  exit 0  # docs/features/ touched alongside code — happy path
fi

# Escape hatch: any commit in the branch with [docs-skip] in its message
# allows the push through.
if git log "$base"..HEAD --pretty=%B | grep -qF '[docs-skip]'; then
  exit 0
fi

cat >&2 <<EOF
✗ features-diff-coverage: this branch changes user-visible code but
  doesn't update any per-feature page under docs/features/.

  Behavioural files changed (vs $base):
$(printf '    %s\n' $behavioural)

  Three ways forward:
  1. Update the relevant docs/features/<feature>.md page in the same
     commit set (the catalog is the precise reference; see
     docs/features/README.md for the per-capability index).
  2. If this PR genuinely needs no feature-catalog update (typo fix,
     internal refactor with no consumer-visible change, etc.), add
     the literal token [docs-skip] to any commit message in the
     branch.
  3. If you're pushing a WIP branch you'll polish later, add
     [docs-skip] to a temporary commit; remove it before opening
     the PR.

  See AGENTS.md §Conventions for the catalog convention.
EOF
exit 1
