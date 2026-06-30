# Real-world agent demo: Playwright MCP + Google deployment

> Goal: prove Tripwire against a useful MCP server and show the Google deploy
> paths without pretending test fixtures are production.

## Why this runbook exists

The fake vulnerable MCP server is useful for deterministic security proofs, but
it is not enough to show adoption value. The real-world demo uses
[Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp), a
published MCP server that exposes browser automation tools over stdio. Tripwire
fronts that server, approves its real tool catalog, attaches badges, and then
lets a real `browser_navigate` call reach `https://example.com`.

## Local real-MCP proof

Prerequisites:

- Node.js 18+ and `npx` on PATH.
- Python/uv project setup already working (`make check` green).
- One-time Playwright browser download:

```bash
npx -y @playwright/mcp@latest install-browser chrome-for-testing
```

Run:

```bash
make demo-real-mcp
```

Expected proof:

```text
connected to Playwright ...
tools approved by Tripwire: 23
tools carrying trust badges: 23
Page URL: https://example.com/
Page Title: Example Domain
```

What this proves:

- Tripwire can front a real third-party MCP server, not only the local fixture.
- Clean, useful tool descriptors are allowed and badged.
- Real tool calls still execute when the approved descriptor has not drifted.
- The same stdio proxy path used in `make demo-proxy` works with a published MCP.

What this does **not** prove:

- It does not prove poisoning detection on Playwright MCP itself; Playwright's
  catalog is clean in the current release.
- It does not remove the need for fake/canary attack fixtures. Those fixtures
  remain the safe way to prove blocked secret exfiltration and rug-pull behavior.

## Real MCP candidates for deeper tests

| MCP server | Why it is useful | Secret requirement | Recommended test environment |
|---|---|---|---|
| Playwright MCP | Real web interaction with public pages; no business data needed. | None for public browsing; browser binary install required. | Start here. Use `https://example.com`, then a public docs page. |
| GitHub MCP | Real issues, PRs, files, and repository workflows. Excellent for security review demos. | GitHub token. | Use a disposable repo and a least-privilege token. Never use a personal high-scope token in demos. |
| Postgres MCP | Shows Tripwire in front of operational data tools. | Database credentials. | Local Docker Postgres seeded with non-sensitive data. |
| Google/Workspace MCP-style tools | Strong audience fit for GCP users. | Google OAuth/API credentials. | Separate test project, non-production docs/files, short-lived credentials. |

The rule is simple: **real environment, non-production data, least-privilege
credentials, no secrets on screen**.

## Google deployment paths

Tripwire has two related but different deploy surfaces.

### Path A — ADK coordinator on Agent Runtime

Use this when the demo goal is "a real Google-hosted agent routes to Scanner,
Red-team, and Attestor."

Dry-run verified locally:

```bash
agents-cli deploy \
  --dry-run \
  --deployment-target agent_runtime \
  --project resonate-staging-499404 \
  --region us-east1 \
  --service-name mcp-tripwire-agent \
  --no-confirm-project
```

The dry-run reports an Agent Runtime deployment with CPU/memory/concurrency
settings. A real deployment requires:

- GCP project with billing enabled.
- Authenticated `gcloud` / `agents-cli`.
- Gemini/Vertex configuration for the ADK model.
- `TRIPWIRE_SIGNING_KEY` from Secret Manager, not a literal env var.

Do **not** use `demo-only` as a deployed signing key.

### Path B — Cloud Run gateway

Use this when the demo goal is "an HTTP trust gateway exposes `/scan`,
`/verify`, `/eval`, and `/mcp/sse/*`."

Dry-run verified locally:

```bash
agents-cli deploy \
  --dry-run \
  --project resonate-staging-499404 \
  --region us-east1 \
  --no-confirm-project \
  --port 8080
```

The dry-run maps to `gcloud run deploy mcp-tripwire --source .` with the
manifest's Cloud Run settings. A real deployment should pass secrets using
`--secrets`, for example:

```bash
agents-cli deploy \
  --project "$GOOGLE_CLOUD_PROJECT" \
  --region us-east1 \
  --secrets TRIPWIRE_SIGNING_KEY=tripwire-signing-key:latest \
  --port 8080
```

Post-deploy smoke:

```bash
curl "$SERVICE_URL/healthz"
curl "$SERVICE_URL/eval"
```

Only flip README wording from "staged" to "implemented" after those live
endpoints work.

## Video path

For a judge-facing recording, use this order:

1. `make demo-real-mcp` — real useful MCP, real web action.
2. `make demo-proxy` or `make demo-proxy-sse` — canary attack and rug-pull proof.
3. `make demo-adk` — real ADK agent layer over the deterministic tools.
4. `make eval` — measured security scoreboard.

That sequence answers both concerns: "does this work on a real MCP?" and "does
it still block hostile behavior?"
