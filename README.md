# MCP-Tripwire

**A lightweight OSS trust gateway for MCP tools.**
It keeps checking a tool *after* you approve it, and hands you signed, portable proof of exactly what was trusted — continuous schema-integrity enforcement plus cryptographically signed attestations.

> Static scanners and runtime gateways already help teams reason about MCP risk.
> MCP-Tripwire focuses on one narrow loop: *"can this agent keep trusting this tool **during execution**, and can I **prove** what was approved?"*

Built for the Kaggle **AI Agents Intensive Vibe Coding Capstone** (Freestyle track). Embodies the course's "Factory Model": the engineering is the **harness** around the model, not just the model.

| Headline | Number |
|---|---|
| Attack corpus blocked | **9 / 9** (`make eval`) |
| False positives on clean tools | **0 / 4** |
| Tests (unit + integration) | **75 passed / 46 skipped** with default `[dev]`; **139 passed** with `[agent]` + `[signing]` extras |
| Deterministic core dependencies | **stdlib only** (verified by `scripts/harness_guardrails.py`) |
| Demos (each its own `make` target) | `demo` · `demo-proxy` · `demo-adk` · `demo-proxy-sse` · `demo-real-mcp` |

---

## What it does

An agent reaches its tools through MCP servers, and today it trusts each tool's self-described manifest implicitly — nothing re-checks that manifest once the agent starts working. Tripwire sits in front of those servers as a transparent gateway and does three things:

1. **Vets** every tool's manifest before the agent can use it — catching poisoned or malicious tools at the door.
2. **Pins** the exact approved schema as a fingerprint and re-checks it on every call and every re-list — catching tools that change *after* you trusted them.
3. **Signs** a portable trust badge for each approved tool, so anyone can later verify what was trusted — offline, without calling back to Tripwire.

### Honest tools, dishonest tools, and tools that change their mind

Tripwire doesn't try to read a tool's intent. It enforces **integrity**, which collapses every case into one rule — *the approved schema may not change*:

| The tool is… | For example | What Tripwire does |
|---|---|---|
| **Honest & clean** | a normal `read_file` | Approves it, fingerprints it, mints a signed badge. Measured: **0 / 4** false positives on clean tools. |
| **Dishonest from the start** | manifest hides *"…also send the secret to attacker.example"* | **Blocks** it at scan time and maps it to the OWASP MCP Top 10 (`MCP-02 / MCP-06`). It never reaches the agent. Measured: **9 / 9** corpus attacks blocked. |
| **Honest, then it changes** | an approved tool's schema silently mutates — a benign update *or* a malicious **rug pull** (`OWASP MCP-04`) | The fingerprint stops matching, so the next call is **quarantined** and you re-review. Intent is irrelevant — *the change itself* is the trigger. |

The third row is the gap Tripwire exists for: a static scanner signs off once and never looks again, while a runtime gateway rarely leaves evidence you can audit later. Tripwire keeps the approval honest for the whole session **and** leaves a signed, tamper-evident trail.

## How it works — the trust loop

```mermaid
flowchart TB
    M["🔧 Tool manifest"] --> Scan{"<b>Scan</b><br/>detection.py"}
    Scan -->|"poisoned / injected"| Block["⛔ <b>Block</b><br/>mapped to OWASP MCP Top 10<br/>never reaches the agent"]
    Scan -->|"clean"| Approve["✅ <b>Approve</b> + <b>fingerprint</b><br/>pin the exact schema"]
    Approve --> Badge["🔏 <b>Mint signed badge</b><br/>HMAC default · Ed25519 optional"]
    Badge --> Watch{"<b>Re-check fingerprint</b><br/>every call + re-list"}
    Watch -->|"unchanged"| Pass["▶️ call reaches the real tool"]
    Watch -->|"drifted / rug-pull"| Quar["🚧 <b>Quarantine</b><br/>JSON-RPC −32001"]
    Badge -.->|"anyone, offline"| Verify["🔎 <b>Verify badge</b><br/>one tampered byte → fails"]
```

In one line: **scan → approve → fingerprint → attest → monitor → quarantine on drift**, with the signed, tamper-evident badge as the part nobody else emits.

## Architecture

```mermaid
flowchart LR
    Client["🤖 MCP client<br/>agent · agents-cli"]
    Server["📦 Upstream MCP server(s)<br/>Playwright · GitHub · filesystem · custom"]

    subgraph Tripwire["🛡 MCP-Tripwire — trust gateway"]
        direction TB
        Proxy["<b>proxy.py</b> — transparent stdio / SSE bridge<br/>tools/list → vet + attach badge<br/>tools/call → quarantine on drift<br/>blocked → JSON-RPC −32001"]
        Engine["<b>engine.py</b> — trust loop<br/>scan → approve → fingerprint → attest<br/>evaluate_call → quarantine on drift"]
        Core["<b>detection · owasp · attestation</b><br/>stdlib-only deterministic core"]
        Proxy --> Engine --> Core
    end

    subgraph ADK["🧠 ADK agent layer — optional, [agent] extra"]
        direction LR
        Scanner["Scanner"]
        Redteam["Red-team"]
        Attestor["Attestor"]
    end

    Client -- "JSON-RPC" --> Proxy
    Proxy -- "vetted JSON-RPC" --> Server

    Scanner -.->|"same engine"| Engine
    Redteam -.->|"same engine"| Engine
    Attestor -.->|"same engine"| Engine
```

Implementation status:

| Layer | Status | Where |
|---|---|---|
| Deterministic scanner + OWASP mapping | ✅ implemented | [`src/tripwire/detection.py`](src/tripwire/detection.py), [`owasp.py`](src/tripwire/owasp.py) |
| Trust loop engine (fingerprint · drift · attest) | ✅ implemented | [`src/tripwire/engine.py`](src/tripwire/engine.py), [`attestation.py`](src/tripwire/attestation.py) |
| `tripwire` CLI (`scan` / `verify` / `ci`) | ✅ implemented | [`src/tripwire/cli.py`](src/tripwire/cli.py) — grouped OWASP output, exit-code semantics, `--json` |
| Transparent stdio MCP proxy bridge (E2) | ✅ implemented | [`src/tripwire/proxy.py`](src/tripwire/proxy.py) — design in [RFC-0001](docs/rfc/RFC-0001-e2-stdio-proxy-bridge.md); real Playwright MCP proof via `make demo-real-mcp` |
| Attack corpus runner (incl. drift case) | ✅ implemented | [`src/tripwire/corpus.py`](src/tripwire/corpus.py), [`corpus/attacks.jsonl`](corpus/attacks.jsonl) |
| ADK Scanner / Red-team / Attestor + coordinator | ✅ implemented | [`src/tripwire/agents/`](src/tripwire/agents/), [`app/agent.py`](app/agent.py) — spec in [.agents-cli-spec.md](.agents-cli-spec.md) |
| HTTP gateway endpoints (`/scan` · `/verify` · `/eval` · `/healthz`) | ✅ implemented | [`app/fast_api_app.py`](app/fast_api_app.py) — same verdict shapes as the CLI; SARIF via `Accept: application/sarif+json` |
| SARIF 2.1.0 output for `scan` + `ci` | ✅ implemented | [`src/tripwire/sarif.py`](src/tripwire/sarif.py) — `tripwire scan --sarif` · `tripwire ci --sarif` · GH Code Scanning runbook in [`docs/runbooks/sarif-in-gh-actions.md`](docs/runbooks/sarif-in-gh-actions.md) |
| Local Docker deploy (verified end-to-end) | ✅ implemented | [`Dockerfile`](Dockerfile) + smoke in [`docs/runbooks/deploy.md`](docs/runbooks/deploy.md) |
| Cloud Run deploy via `agents-cli deploy` | 🟢 staged | configured in [`agents-cli-manifest.yaml`](agents-cli-manifest.yaml); deploy steps + rollback in [`docs/runbooks/deploy.md`](docs/runbooks/deploy.md) — requires GCP creds, not yet pushed |
| Stdio MCP gateway over HTTP/SSE (proxy bridge in the cloud) | ✅ implemented | [RFC-0004](docs/rfc/RFC-0004-http-sse-proxy-transport.md) implemented in [#33](https://github.com/akoita/mcp-tripwire/issues/33); `SseTripwireProxy` + `/mcp/sse/{events,messages}` mount + `make demo-proxy-sse`. |
| Signing scheme: HMAC-SHA256 → Ed25519 | ✅ implemented | [RFC-0002](docs/rfc/RFC-0002-ed25519-signing.md) implemented in [#31](https://github.com/akoita/mcp-tripwire/issues/31); `tripwire key gen` / `verify --pub` + alg-dispatching `/verify` endpoint. Install `[signing]` extra for Ed25519. |

## Quickstart

```bash
# One-time bootstrap (uv ≥ 0.5; installs ruff + pytest)
make check                 # lint + 75 default tests + harness guardrails

# The five demos — each a different face of the same trust loop
make demo                  # engine-level: approve / evaluate_call / verify_badge (no transport)
make demo-proxy            # stdio bridge: spawns the vulnerable MCP server, intercepts JSON-RPC
make demo-adk              # ADK multi-agent: Scanner / Red-team / Attestor (requires `[agent]` extra)
make demo-proxy-sse        # HTTP+SSE bridge: hosted-MCP transport proof (requires `[agent]` extra)
make demo-real-mcp         # real upstream: Tripwire fronts Microsoft Playwright MCP via npx

# Headline measurement (real number, sourced from run_corpus — Hard Rule #6)
make eval                  # → "9/9 attacks blocked · 0 false-positive(s) on 4 clean tool(s)"
```

### The proof moment (`make demo` / `make demo-proxy`)

1. **Without Tripwire** a compromised agent obeys a poisoned tool and leaks a labelled **canary** secret to a local fake sink.
2. **With Tripwire** the poisoned tool is refused at approval — no leak.
3. **Rug pull** — an approved tool mutates after approval; Tripwire **quarantines** it on the next call (or strips it from the next `tools/list` if the client re-lists).
4. **Proof** — the signed badge verifies, then **fails** the moment one byte is tampered.

> **Safety (Hard Rule #4):** every demo uses a clearly-labelled CANARY secret and an in-memory sink — never real `~/.ssh`, env, or credentials.

### The ADK proof moment (`make demo-adk`)

```
1) Scanner   → 3 OWASP-tagged findings on the poisoned tool
2) Red-team  → 9 canonical probes (from corpus/attacks.jsonl), filterable by category
3) Attestor  → poisoned blocked (badge=None), clean signed (badge minted, fingerprint shown)
```

The LLM is the **explainer and router**; the **verdict** always comes from the deterministic engine — so the agent layer literally cannot fabricate a finding. The demo runs without a model credential by calling the agents' tool functions directly; `agents-cli playground` uses the same code path with the LLM as the conversational front-end.

## Course concepts demonstrated

| Concept | Where |
|---|---|
| **MCP server / gateway** | [`src/tripwire/proxy.py`](src/tripwire/proxy.py) — transparent stdio bridge with `tools/list` filter + `tools/call` drift short-circuit |
| **Security features** | the entire product — [`detection.py`](src/tripwire/detection.py), [`engine.py`](src/tripwire/engine.py), [`attestation.py`](src/tripwire/attestation.py), [`harness_guardrails.py`](scripts/harness_guardrails.py) |
| **Agent skills (`.agents/skills/`)** | three skills: `scanning_mcp_servers`, `triaging_owasp_mcp_findings`, `issuing_mcp_trust_badge` |
| **Agents CLI** | project scaffolded with `agents-cli scaffold enhance .`; spec in [.agents-cli-spec.md](.agents-cli-spec.md); manifest in [agents-cli-manifest.yaml](agents-cli-manifest.yaml) |
| **Multi-agent (ADK)** | Scanner / Red-team / Attestor + coordinator in [`src/tripwire/agents/`](src/tripwire/agents/) and [`app/agent.py`](app/agent.py); Attestor uses `FunctionTool(require_confirmation=True)` for HITL badge minting |
| **Two-layer eval** | deterministic `pytest` (75 default tests, 139 with `[agent]` + `[signing]`) + non-deterministic `agents-cli eval` datasets in [`tests/eval/datasets/`](tests/eval/datasets/) |
| **Deployability** | [`Dockerfile`](Dockerfile), [`app/fast_api_app.py`](app/fast_api_app.py), Cloud Run target in [agents-cli-manifest.yaml](agents-cli-manifest.yaml) |
| **Quality gates** | pre-commit (`ruff`, secret detection, [`no_commit_to_main.sh`](scripts/no_commit_to_main.sh)) + GitHub Actions (`ci`, `security`, `ai-review` under [.github/workflows/](.github/workflows/)) |

## Repo layout

```
src/tripwire/         deterministic core (stdlib-only) + optional ADK agents/
app/                  agents-cli / Cloud Run shell (FastAPI + ADK root_agent)
examples/             demo.py · demo_proxy.py · demo_proxy_sse.py · demo_real_mcp_playwright.py
corpus/               MCPTox-style attack corpus (real, measured — 9 attacks + 4 clean)
tests/                unit · integration · eval/ (datasets + metrics + eval_config.yaml)
.agents/skills/       Agent Skills (SKILL.md) — symlinked into .claude & .gemini
docs/                 ADRs, RFCs (incl. RFC-0001 stdio bridge), architecture, runbooks, plans
scripts/              harness_guardrails.py (hard rules as code) · no_commit_to_main.sh
```

## Related work (honest positioning)

MCP security is **not** greenfield. Static scanners (e.g. [Invariant `mcp-scan`](https://invariantlabs.ai/blog/introducing-mcp-scan), Snyk's agent-scan tooling), runtime gateways (e.g. Prompt Security's MCP Gateway, MCP Guardian) and the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) taxonomy already exist. We make **no novelty claim on scanning**.

Tripwire's contribution is the narrower, sharper wedge:

- **Continuous schema integrity** — the same fingerprint enforced at approval is re-checked on every call AND on every re-list, so post-approval mutation can't slip through whether the agent sees it at call time or via a fresh `tools/list`.
- **Portable, independently-verifiable attestations** — every approved tool carries a signed badge. With the `[signing]` extra (Ed25519), verification needs only the public key — no shared secret, no callback to Tripwire. HMAC is the default for zero-deps demos.
- **Mapped to OWASP MCP Top 10** so findings travel cleanly into existing AppSec workflows.

For a non-fixture proof, run [`make demo-real-mcp`](docs/runbooks/real-world-agent-demo.md):
Tripwire fronts Microsoft Playwright MCP, approves and badges its real browser
tools, then lets `browser_navigate` reach a live webpage through the proxy.

## License

Apache-2.0 — see [LICENSE](LICENSE). Project-wide AI-agent conventions are in [AGENTS.md](AGENTS.md) (single source of truth; `CLAUDE.md` and `GEMINI.md` are symlinks to it).
