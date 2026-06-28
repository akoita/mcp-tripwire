# MCP-Tripwire — Roadmap

> **Current cut:** `v0.1.0-capstone` ([tag](https://github.com/akoita/mcp-tripwire/releases/tag/v0.1.0-capstone)) — the **capstone-ready cut** of the Kaggle Freestyle entry. Tagged 2026-06-28 as a code freeze for the submission window. The Kaggle deadline is 2026-07-06 PT; submission itself, video recording, and the optional Cloud Run push are still pending human action — see [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md).
> **Now:** v0.2 planning — **Credibility & integration** — working under the deliberate-pace rule (RFC before code).
> **One-liner:** *"Can this agent keep trusting this tool during execution — and can I prove it?"*

## Capstone-ready cut — `v0.1.0-capstone` (tagged 2026-06-28)

The submission-window code freeze. What's shipped in the tag:

| Epic | What | Where |
|---|---|---|
| E1 Core | detection · engine · attestation · OWASP map · corpus runner · CLI | `src/tripwire/*.py` |
| E2 Proxy bridge (stdio) | `tools/list` rewrite · `tools/call` drift quarantine · structured stderr log | `src/tripwire/proxy.py` ([RFC-0001](rfc/RFC-0001-e2-stdio-proxy-bridge.md)) |
| E3 ADK multi-agent | Scanner / Red-team / Attestor + coordinator | `src/tripwire/agents/`, `app/agent.py` ([.agents-cli-spec.md](../.agents-cli-spec.md)) |
| E4 Proof moments | three demos: engine A/B, stdio proxy, ADK pipeline | `examples/demo*.py`, `make demo*` |
| E6 Cloud Run | HTTP gateway (`/scan` `/verify` `/eval` `/healthz`), local Docker verified, deploy runbook | `app/fast_api_app.py`, [`docs/runbooks/deploy.md`](runbooks/deploy.md) |
| E7 Submission | README final + Kaggle writeup + video script + dry-run checklist | `docs/{writeup,video-script,SUBMISSION_CHECKLIST}.md` |
| Harness | hard rules machine-enforced; pre-commit no-commit-to-main; retro-PR'd direct-to-main history | [AGENTS.md](../AGENTS.md), `scripts/harness_guardrails.py`, `scripts/no_commit_to_main.sh` |

Headline numbers at the tag: **41 tests pass**, **9/9 attacks blocked**, 0 false positives on 4 clean tools, deterministic core stdlib-only.

**Still pending human action between now and 2026-07-06** (tracked in [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md) and as open issues):
- [#11](https://github.com/akoita/mcp-tripwire/issues/11) record the 5-minute video.
- [#9](https://github.com/akoita/mcp-tripwire/issues/9) push the Cloud Run deploy via `agents-cli deploy` (optional but greens the table).
- [#13](https://github.com/akoita/mcp-tripwire/issues/13) flip repo visibility to public, paste writeup into Kaggle UI, click Submit.

A future "post-capstone" section will land here once submission is actually done.

---

## Next — v0.2 Credibility & integration

**Thesis.** Move from "capstone-ready demo" to "could be dropped into a real security pipeline today." Three pieces, **judged by one external integration**, not by better internal docs.

**Acceptance gate for the v0.2.0 tag:** an external operator path is reproducible end-to-end on a fresh clone — configure a non-fixture target MCP server, run Tripwire, get findings, verify the badge. One real consumer, not three internal tests in a trench coat.

### Ordering — SARIF first

SARIF is the fastest usefulness jump for the audience that matters (security teams already running SAST tooling). The badge alg is an internal detail of how Tripwire signs; SARIF describes findings regardless. So:

| # | Issue | What | Why this order |
|---|---|---|---|
| 1st | [#32](https://github.com/akoita/mcp-tripwire/issues/32) | **SARIF output** for `scan` + `eval` | Lands findings in GitHub Code Scanning / GitLab SAST with zero integration code. Biggest single move toward "useful" because it meets security teams where they already work. The badge field in SARIF can stay HMAC initially. |
| 2nd | [#31](https://github.com/akoita/mcp-tripwire/issues/31) | **Ed25519 signing** over HMAC | Once findings travel via SARIF, the badge metadata in those findings becomes a real-world artefact. Ed25519 turns the badge from "shared-secret HMAC" into something an arbitrary third party can verify with only the public key — the README's "portable, independently verifiable" claim, finally true. |
| 3rd | [#33](https://github.com/akoita/mcp-tripwire/issues/33) | **HTTP/SSE MCP transport** in the proxy | Broadens the deployable surface to cloud-hosted MCP servers. Necessary for the external-integration acceptance gate above, since most non-fixture MCP servers worth pointing Tripwire at use SSE. |

Each piece gets a design RFC under [`docs/rfc/`](rfc/) before code. RFCs require human review; implementation PRs cannot land until the RFC merges. This is the **deliberate-pace** ground rule for v0.2.

### Exit criteria for the v0.2.0 tag

- All three issues closed by merged PRs.
- README implementation-status table: every row 🟢 staged or 🟡 planned at v0.1 either flips to ✅ implemented or gets an explicit deferral to v0.3.
- `make eval` + `make demo*` still green from a fresh clone (regression of any v0.1 capability blocks the tag).
- **Operator-path proof:** a documented session of "fresh clone → configure a real MCP server → run Tripwire → SARIF in GH Code Scanning → badge verified with the public key by a process that didn't sign it." This is the actual judgement.

---

## After v0.2 — provisional ordering

### v0.3 — Scale & multi-upstream
One proxy fronting N MCP servers + central tool registry + per-tool policy-as-code (YAML rules an operator can edit without touching Python) + observability beyond stderr (Cloud Logging / a queryable audit store). Turns the single-host gateway into a fleet gateway. **Blocked on v0.2** — multi-upstream policy is only credible if the badges it emits are independently verifiable (#31) and its findings flow to consumers (#32).

### v1.0 — First real user
Hosted Docker image, 1-page "plug me in" doc, issue-tracker label for production bugs, feedback cadence. Find one friendly team running real MCP servers and ship Tripwire into their pipeline. Real usage drives the v1.0 → v1.x backlog more than any internal planning round.

### Permanently P2 / Won't (without a strong external pull)
- Sigstore / Rekor anchoring (interesting but premature without users asking).
- Multi-framework support beyond MCP (LangChain, Cursor, raw tools) — would dilute the wedge.
- Hosted dashboard / Tripwire-the-SaaS — explicitly the wrong shape; Tripwire is plumbing other people host.

---

## Process notes carried over from capstone

- Every commit on a feature branch, every PR closes (or refs) at least one issue.
- The `no-commit-to-main` pre-commit hook (PR #21) refuses direct commits to `main`.
- `make check` must be green before any PR.
- Hard Rule #6 — never invent metrics. Every quoted number in any artefact traces to a `make` command run.
- See [AGENTS.md](../AGENTS.md) for the full ruleset.
