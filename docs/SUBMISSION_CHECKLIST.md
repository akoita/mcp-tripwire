# Submission checklist — Kaggle Freestyle

> Tick the boxes top-to-bottom right before clicking **Submit**. Each item
> either has a verifiable command (run it) or a clear human action (do it).

## Automated dry-run (verified on this branch)

Fresh-clone reproduction on a clean machine — `git clone` + `make` cycle:

- [x] `git clone git@github.com:akoita/mcp-tripwire /tmp/tripwire-dryrun` succeeds (depth 1).
- [x] `make check` → **41 passed, 4 skipped** (ADK/HTTP-gated tests skip cleanly), guardrails green.
- [x] `make demo` → engine A/B + rug-pull + tamper proof — `Summary: poisoning blocked · rug-pull quarantined · attestation tamper-evident.`
- [x] `make demo-proxy` → bridge intercepts JSON-RPC; rug-pulled call short-circuits with `JSON-RPC error -32001`.
- [x] `make demo-adk` → three sections (Scanner / Red-team / Attestor); badge minted for clean tool, refused for poisoned.
- [x] `make eval` → **`9/9 attacks blocked · 0 false-positive(s) on 4 clean tool(s)` · `CI PASS.`**

These ran end-to-end against this branch's commit on a clean `/tmp` clone. If any of them regress before submission, **stop and fix** — judges will run the same commands.

## Link integrity

- [x] All inline relative links in `README.md`, `docs/writeup.md`, `docs/runbooks/deploy.md`, `docs/video-script.md`, `.agents-cli-spec.md`, `AGENTS.md`, `docs/STATUS.md` resolve to existing files (verified by walk-and-stat script).
- [x] Literal taxonomy tags (e.g. `OWASP MCP-04`) use backticks, not markdown brackets — won't render as broken refs.
- [ ] After flipping the repo to public for judging: re-verify all `https://github.com/akoita/mcp-tripwire/...` URLs in writeup + runbook return 200, not 404.

## Repo state at submission

- [ ] `main` branch contains every PR you intend judges to see — no unmerged work in feature branches.
- [ ] Last commit on `main` is one of yours (`git log --oneline -1`), not a bot or stale auto-merge.
- [ ] Backup tag `backup/pre-retro-pr` still present in origin (recovery anchor for the one-time history rewind in PRs #16–#19).
- [ ] No secret material has ever been pushed: `git log --all --full-history -- '.env' '*.key' '*.pem'` returns empty.
- [ ] Repo visibility is **public** (Kaggle judges must be able to clone). The flip is one command:
      ```
      gh repo edit akoita/mcp-tripwire --visibility public --accept-visibility-change-consequences
      ```
      This also unblocks GitHub Actions (free tier for public repos), so `ci` / `security` / `ai-review` workflows will start running.

## Open issues at submission

All work fits into one of three buckets:

- **Closed:** #3 (initial), #4 (proxy bridge), #5 (proxy demo), #6 (CLI polish), #7 (drift eval), #8 (ADK wiring), #10 (README final), #11 (video script half), #12 (writeup), #14 (hygiene), #15 (docs audit), #20 (no-commit-to-main hook).
- **Open, requiring your hands:** #9 (Cloud Run push), #11 (video recording itself), #13 (this checklist).
- **Open, intentionally deferred:** the stdio MCP gateway over HTTP/SSE row in the README's implementation-status table.

The README implementation-status table reflects ground truth at this commit; **do not mark anything 🟢 staged or 🟡 planned as ✅ implemented before the deploy / recording actually happens** (Rule #6: never invent metrics, and that applies to capabilities too).

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

- [ ] `wc -w docs/writeup.md` ≤ 2,500 (currently ~1,700, plenty of headroom).
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
