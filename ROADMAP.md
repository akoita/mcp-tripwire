# MCP-Tripwire — Roadmap

> **Current cut:** `v0.1.0-capstone` ([tag](https://github.com/akoita/mcp-tripwire/releases/tag/v0.1.0-capstone)) — submission-ready state of the Kaggle Freestyle entry.
> **Now:** post-capstone, working toward **v0.2 — Credibility & integration**.
> **One-liner:** *"Can this agent keep trusting this tool during execution — and can I prove it?"*

## Done — v0.1.0-capstone (2026-07-05)

Shipped state of the project at the Kaggle submission cut:

| Epic | What | Where |
|---|---|---|
| E1 Core | detection · engine · attestation · OWASP map · corpus runner · CLI | `src/tripwire/*.py` |
| E2 Proxy bridge (stdio) | `tools/list` rewrite · `tools/call` drift quarantine · structured stderr log | `src/tripwire/proxy.py` ([RFC-0001](docs/rfc/RFC-0001-e2-stdio-proxy-bridge.md)) |
| E3 ADK multi-agent | Scanner / Red-team / Attestor + coordinator | `src/tripwire/agents/`, `app/agent.py` ([.agents-cli-spec.md](.agents-cli-spec.md)) |
| E4 Proof moments | three demos: engine A/B, stdio proxy, ADK pipeline | `examples/demo*.py`, `make demo*` |
| E6 Cloud Run | HTTP gateway (`/scan` `/verify` `/eval` `/healthz`), local Docker verified, deploy runbook | `app/fast_api_app.py`, [`docs/runbooks/deploy.md`](docs/runbooks/deploy.md) |
| E7 Submission | README final + Kaggle writeup + video script + dry-run checklist | `docs/{writeup,video-script,SUBMISSION_CHECKLIST}.md` |
| Harness | hard rules machine-enforced; pre-commit no-commit-to-main; retro-PR'd direct-to-main history | [AGENTS.md](AGENTS.md), `scripts/harness_guardrails.py`, `scripts/no_commit_to_main.sh` |

Headline numbers at the tag: **41 tests pass**, **9/9 attacks blocked**, 0 false positives on 4 clean tools, deterministic core stdlib-only.

Sprint backlog rows still requiring human action (per [SUBMISSION_CHECKLIST.md](docs/SUBMISSION_CHECKLIST.md)): record the video (#11 recording half), push `agents-cli deploy` (#9 push half), Kaggle UI submit (#13 submit half).

---

## Next — v0.2 Credibility & integration

**Thesis.** Move from "interesting demo" to "could be dropped into a real security pipeline today." Three pieces that each close a credibility gap the v0.1 README cannot defend:

| Issue | What | Why it's load-bearing |
|---|---|---|
| [#31](https://github.com/akoita/mcp-tripwire/issues/31) | **Ed25519 signing** over HMAC | HMAC needs a shared secret. Ed25519 makes the badge ecosystem genuinely portable — any verifier with the public key can audit independently, which is what the README's "third-party verifiable attestation" claim actually requires. |
| [#32](https://github.com/akoita/mcp-tripwire/issues/32) | **SARIF output** for `scan` + `eval` | Findings flow into GitHub Code Scanning / GitLab SAST / any SARIF consumer with zero integration code. Lands findings where security teams already work. |
| [#33](https://github.com/akoita/mcp-tripwire/issues/33) | **HTTP/SSE MCP transport** in the proxy | The stdio bridge only fronts subprocess-spawned upstreams. Most cloud-hosted MCP servers speak SSE — without this transport, Tripwire is single-host only. |

Each piece gets a design RFC under [`docs/rfc/`](docs/rfc/) before code. RFCs require human review; implementation PRs cannot land until the RFC merges. This is the **deliberate-pace** ground rule for v0.2.

**Ordering.** Ed25519 lands first (precondition for the other two — SARIF output and SSE-transmitted badges should both speak the new alg). SARIF and SSE can then proceed in parallel.

**Exit criteria for v0.2.0 tag:**
- All three issues closed by merged PRs.
- README implementation-status table: every row 🟢 staged or 🟡 planned at v0.1 either flips to ✅ implemented or gets an explicit deferral to v0.3.
- `make eval` + `make demo*` still green from a fresh clone (regression of any v0.1 capability blocks the tag).
- A `v0.2.0` release notes section appended below this milestone.

---

## After v0.2 — provisional ordering

### v0.3 — Scale & multi-upstream
One proxy fronting N MCP servers + central tool registry + per-tool policy-as-code (YAML rules an operator can edit without touching Python) + observability beyond stderr (Cloud Logging / a queryable audit store). Turns the demo into a fleet gateway. **Blocked on v0.2 credibility work** — multi-upstream policy is only credible if the badges it emits are independently verifiable (#31) and its findings flow to consumers (#32).

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
- See [AGENTS.md](AGENTS.md) for the full ruleset.
