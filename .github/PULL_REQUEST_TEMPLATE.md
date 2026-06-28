<!-- feat(#id): … — never target main directly from a feature branch's work without review -->
## What & why
<!-- The outcome and the problem it solves. Link the ROADMAP/epic + plan. -->

## Checklist
- [ ] `make check` is green (lint + test + guardrails)
- [ ] Tests/evals added or updated (the contract — Hard Rule #5)
- [ ] No secrets/keys; demos use canary + fake sink only (Rules #3, #4)
- [ ] Stubs self-flagged (`# STUB(Exx):`) — no silent partials (Rule #9)
- [ ] ADR added if a structural decision was made
- [ ] `docs/STATUS.md` / `CHANGELOG.md` updated
- [ ] `docs/features/` updated if any user-visible behaviour changed (catalog is the precise reference — see [docs/features/README.md](../blob/main/docs/features/README.md))
- [ ] Issue-close keywords used carefully: `Closes #N` only when ALL acceptance criteria are met; `Refs #N` for partial work

## Threat / residual risk
<!-- OWASP MCP categories touched; what remains unmitigated. -->
