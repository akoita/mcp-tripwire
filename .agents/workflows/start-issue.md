---
description: Begin an issue/epic — create a plan, branch, and the failing test/eval first.
---
# Start an issue

1. Copy `docs/plans/_TEMPLATE.md` → `docs/plans/<id>-<kebab>.md`; fill the slices + `Status:`.
2. Create the branch: `git checkout -b feat/<id>-<kebab>` (never work on `main`).
3. Write the failing test/eval FIRST (Hard Rule #5) under `tests/` (or `tests/eval/`).
4. Implement the smallest slice; keep the deterministic core stdlib-only.
5. `make check` until green, then open a PR (`feat(#id): …`).
