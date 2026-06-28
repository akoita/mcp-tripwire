---
description: Finish an issue — verify, document, and prepare the PR.
---
# Finish an issue

1. `make check` is green (lint + test + guardrails).
2. Update `docs/STATUS.md`, `CHANGELOG.md`, and the plan's `Status:` slices (no silent partials).
3. If a structural decision was made, add an ADR in `docs/adr/`.
4. Ensure no secrets/stubs leaked (`scripts/harness_guardrails.py`).
5. Open the PR; let `/code-review` (AI first-pass) run, then request human review. Never self-merge to `main`.
