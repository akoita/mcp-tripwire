# Real-world agent demo: Playwright MCP through the proxy

> Goal: prove Tripwire against a useful, published MCP server — without
> pretending test fixtures are production.

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

  This step is required: the demo launches Playwright MCP with `--browser
  chromium` and reports a missing binary instead of auto-downloading one. The
  command prints `WARNING: It looks like you are running 'npx playwright install'
  without first installing your project's dependencies` — that warning is
  **expected and harmless** here. `npx -y` fetches `@playwright/mcp` for a single
  run, so there is no project `node_modules` to install against; the browser
  still downloads (or is confirmed already cached). `chrome-for-testing` is
  Playwright's alias for the `chromium` build the demo uses.

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

## Deployment and recording

- **Deploying Tripwire** (local Docker, Cloud Run via `agents-cli deploy`, the
  hosted SSE gateway, or the Agent Runtime target for the ADK coordinator) is
  the [deploy runbook](deploy.md)'s job — one source of truth for commands,
  env vars, and secrets handling.
- **The judge-facing recording order** is scripted beat-by-beat in
  [`docs/video-script.md`](../video-script.md); a live Gemini-driven ADK
  session has its own operator script in
  [adk-live-playground-demo.md](adk-live-playground-demo.md).
