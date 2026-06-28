# HTTP gateway (`/scan` · `/verify` · `/eval` · `/healthz`)

> **Status:** ✅ implemented locally · 🟢 staged on Cloud Run · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM / consumer)

The HTTP gateway is the trust loop **without** the SDK install. Anything that speaks HTTP can:

- **POST `/scan`** with a tool descriptor → get back findings grouped by OWASP MCP category.
- **POST `/verify`** with a stored badge → get back `{valid, status, reason, tool}` (status mirrors the CLI's three exit codes).
- **GET `/eval`** → run the full attack corpus, get back the live `9/9 attacks blocked` number.
- **GET `/healthz`** → liveness probe for Cloud Run / k8s.

CI jobs, downstream auditors, batch scanners, and dashboards all reach the same engine without each caller installing Tripwire.

## Audience

- **CI pipeline** (GitHub Actions, GitLab CI, Jenkins) POSTing manifests during build.
- **Centralized scanner / SOC tooling** running periodic scans across an org's MCP fleet.
- **Downstream auditor** verifying badges they received from a sibling team.
- **Dashboards** (Grafana / a future Tripwire panel) polling `/eval` for the live blocked-count gauge.

## How it works today

`app/fast_api_app.py` mounts a FastAPI app. The `tripwire` imports are deferred until *after* the fastapi guard so a missing `[agent]` extra fails fast with a clear hint, and so importing the module doesn't pull stdlib-only modules into a process that can't serve them anyway.

Verdict shapes are deliberately **shared with the CLI and the ADK Scanner**:

- `/scan` calls the same `scan_tool_descriptor()` the ADK Scanner uses; the response is identical.
- `/verify` returns the same valid / tampered / invalid taxonomy as the CLI's exit codes.
- `/eval` returns the same dict shape as `tripwire ci --json`.

Single source of truth across three surfaces — adding a field anywhere means it shows up everywhere consistently.

## Contract

```
GET  /healthz  -> {"status": "ok", "service": "mcp-tripwire"}

POST /scan     body: {"tool": {...}}
               -> {"status": "clean|findings", "findings": [...],
                   "owasp_categories": [...], "counts_by_category": {...},
                   "worst_severity": "..."}

POST /verify   body: {"badge": {...}}
               -> {"valid": bool, "status": "valid|tampered|invalid",
                   "reason": str, "tool": str|null}

GET  /eval     -> {"attacks_total": int, "attacks_blocked": int,
                   "clean_total": int, "false_positives": int,
                   "passed": bool, "rows": [...]}
```

`Content-Type: application/json` on every response today; `application/sarif+json` content-negotiation lands with [#32](https://github.com/akoita/mcp-tripwire/issues/32) per [RFC-0003 §HTTP surface](../rfc/RFC-0003-sarif-output.md#http-surface).

`TRIPWIRE_SIGNING_KEY` env var is honored at both mint and verify time (Hard Rule #3 — never hardcoded). The dev placeholder will be refused-by-default with a `TRIPWIRE_ALLOW_DEV_KEY=1` opt-in per [RFC-0002](../rfc/RFC-0002-ed25519-signing.md).

## Surfaces

| Surface | How to reach it |
|---|---|
| Local dev | `uvicorn app.fast_api_app:app --port 8080` |
| Local Docker | `docker build . && docker run -p 8080:8080 -e TRIPWIRE_SIGNING_KEY=k mcp-tripwire:dev` — verified end-to-end (see [`docs/runbooks/deploy.md` §Path A](../runbooks/deploy.md)) |
| Cloud Run | Staged. `agents-cli deploy` per [§Path B of the runbook](../runbooks/deploy.md). Requires GCP creds; tracked in [#9](https://github.com/akoita/mcp-tripwire/issues/9). |

## Verification

- Integration: [`tests/integration/test_http_endpoints.py`](../../tests/integration/test_http_endpoints.py) — 8 tests covering all four endpoints, malformed body paths, and the verify three-state outcome shape.
- Docker smoke: documented in [`docs/runbooks/deploy.md`](../runbooks/deploy.md) — curl all four endpoints from a running container.
- Schema consistency: the response dict for `/eval` is asserted to have the same keys as `tripwire ci --json` in the integration tests (round-trip check).

## Guarantees and limitations

- **Policy-only HTTP today.** This is a centralised-scanning service, *not* a transparent MCP gateway over HTTP. An MCP client wanting Tripwire in-line needs the stdio bridge ([stdio-mcp-proxy.md](stdio-mcp-proxy.md)) or, post-[#33](https://github.com/akoita/mcp-tripwire/issues/33), the SSE bridge ([http-sse-proxy-transport.md](http-sse-proxy-transport.md)). The HTTP gateway is for "POST me one descriptor, tell me your verdict," not for brokering live MCP traffic.
- **No streaming, no auth, no rate-limiting** in v0.1. Operator wraps the service behind whatever IAM their deploy target provides (Cloud Run's IAM, an API Gateway, etc.).
- **`/eval` runs the corpus on every call.** Cold-start matters for cost; `min-instances=1` on Cloud Run if request latency is a concern.
- **No persistence.** Engine state is per-process; calls are stateless. Drift detection (which is stateful) is the proxy bridge's job.

## Cross-references

- Companions: every CLI surface ([cli-scan-verify-ci.md](cli-scan-verify-ci.md)) and the ADK layer ([adk-multi-agent-layer.md](adk-multi-agent-layer.md)) share verdict shapes with this one.
- Runbook: [`docs/runbooks/deploy.md`](../runbooks/deploy.md) — local Docker (verified) and Cloud Run (staged) paths.
- Future: [sarif-output.md](sarif-output.md) — `Accept: application/sarif+json` content-negotiation per [RFC-0003](../rfc/RFC-0003-sarif-output.md).
