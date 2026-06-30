# Submission checklist — Kaggle Freestyle

> Tick the boxes top-to-bottom right before clicking **Submit**. Each item
> either has a verifiable command (run it) or a clear human action (do it).

## Automated dry-run (verify on final `main`)

Fresh-clone reproduction on a clean machine — `git clone` + `make` cycle:

- [x] `git clone https://github.com/akoita/mcp-tripwire /tmp/tripwire-dryrun` succeeds (public repo).
- [x] `make check` → **75 passed, 46 skipped** with the default `[dev]` install, guardrails green.
- [x] `uv run --extra dev --extra agent --extra signing pytest` → **139 passed** with ADK + Ed25519 extras installed.
- [x] `make demo` → engine A/B + rug-pull + tamper proof — `Summary: poisoning blocked · rug-pull quarantined · attestation tamper-evident.`
- [x] `make demo-proxy` → bridge intercepts JSON-RPC; rug-pulled call short-circuits with `JSON-RPC error -32001`.
- [x] `make demo-proxy-sse` → HTTP/SSE bridge strips poisoned tool and quarantines rug-pull with `JSON-RPC error -32001`.
- [x] `make demo-adk` → three sections (Scanner / Red-team / Attestor); badge minted for clean tool, refused for poisoned.
- [x] `make eval` → **`9/9 attacks blocked · 0 false-positive(s) on 4 clean tool(s)` · `CI PASS.`**

If any of them regress before submission, **stop and fix** — judges can run the same commands.

## Link integrity

- [x] All inline relative links in `README.md`, `docs/writeup.md`, `docs/runbooks/deploy.md`, `docs/video-script.md`, `.agents-cli-spec.md`, `AGENTS.md`, `docs/STATUS.md` resolve to existing files (verified by walk-and-stat script).
- [x] Literal taxonomy tags (e.g. `OWASP MCP-04`) use backticks, not markdown brackets — won't render as broken refs.
- [x] Re-verify all `https://github.com/akoita/mcp-tripwire/...` URLs in writeup + runbook return 200, not 404.

## Repo state at submission

- [x] `main` branch contains every PR you intend judges to see — no unmerged work in feature branches.
- [x] Last commit on `main` is a submission-readiness merge commit, not a bot or stale auto-merge.
- [x] Backup tags `backup/pre-retro-pr` and `v0.1.0-capstone` still present in origin.
- [x] No secret material has ever been pushed: `git log --all --full-history -- '.env' '*.key' '*.pem'` returns empty.
- [x] Repo visibility is **public** (Kaggle judges can clone): `gh repo view akoita/mcp-tripwire --json isPrivate,visibility` reports `PUBLIC`.

## Open issues at submission

All remaining work is tracked in GitHub:

- **#9** — Cloud Run deploy or documented local fallback. Local Docker fallback is documented; close only when the final submission explicitly chooses that path or a live Cloud Run URL exists.
- **#11** — Record the five-minute video and add the hosted link.
- **#12** — Finalize/paste the Kaggle writeup and submit.
- **#13** — Final public dry run, link verification, and submission sanity check.
- **#49** — Refresh stale docs/status for the current v0.2 implementation state.

The README and feature catalog must reflect ground truth at the submission commit; **do not mark Cloud Run live or video complete before those artefacts exist** (Rule #6: never invent metrics, and that applies to capabilities too).

## Video link

- [ ] Recording done per [docs/video-script.md](video-script.md) (≤5:00, opens with the proof moment).
- [ ] Hosted somewhere stable (YouTube unlisted is fine, Loom works too).
- [ ] Link added to `docs/writeup.md` (replace the `_link added at submission time_` placeholder).
- [ ] Link added to the top of `README.md` if you want it above the fold.

## Cloud Run deploy (optional, but it makes the implementation-status table greener)

- [ ] `agents-cli login --interactive` succeeds.
- [ ] `agents-cli infra single-project` succeeds (provisions Cloud Run + Artifact Registry roles).
- [ ] `agents-cli deploy` succeeds; the URL returns 200 on `/healthz`.
- [ ] `/eval` over HTTPS returns `attacks_blocked: 9, passed: true` (real number, not a stub).
- [ ] `TRIPWIRE_SIGNING_KEY` is bound from Secret Manager, not a plain env value. See [docs/runbooks/deploy.md §Path B](runbooks/deploy.md#path-b--cloud-run-via-agents-cli-deploy-staged).
- [ ] Flip the README implementation-status row from `🟢 staged` to `✅ implemented` only after the URL is live.

If the deploy fights, the local Docker path (already verified) is an acceptable substitute — the runbook documents it as Path A and the README links to it.

## Writeup hygiene

- [x] `wc -w docs/writeup.md` ≤ 2,500.
- [ ] Every metric in the writeup ties back to a `make` command (Rule #6).
- [ ] No hardcoded URLs that drift if the repo moves; relative links throughout.
- [ ] Copy the rendered markdown into the Kaggle submission UI; preview it there once before submitting.

## Kaggle submission UI

- [ ] Title — short, memorable, mentions "MCP" and "trust" so it's findable in the freestyle list.
- [ ] Repo URL — `https://github.com/akoita/mcp-tripwire`.
- [ ] Video URL — from the video step above.
- [ ] Tags — `mcp`, `security`, `agents`, `adk`, `attestation`.
- [ ] **Submit at least 24 hours before the deadline.** The plan ([SPRINT-2026-06-27-to-2026-07-05.md](plans/SPRINT-2026-06-27-to-2026-07-05.md)) explicitly carves out a final-day buffer; don't burn it.

## Post-submission

- [ ] Tag the submission commit: `git tag submission/v1 && git push origin submission/v1`.
- [ ] Note any breaking issues judges flag in the Kaggle discussion thread.
- [ ] If the repo had any private dependencies (none today, but check), confirm they're public too.
