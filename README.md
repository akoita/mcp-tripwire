# MCP-Tripwire

**A lightweight OSS trust gateway for MCP tools.**
It keeps checking a tool *after* you approve it, and hands you signed, portable proof of exactly what was trusted — continuous schema-integrity enforcement plus cryptographically signed attestations.

> Static scanners and runtime gateways already help teams reason about MCP risk.
> MCP-Tripwire focuses on one narrow loop: *"can this agent keep trusting this tool **during execution**, and can I **prove** what was approved?"*

<p align="center">
  <img src="docs/assets/demo-proxy.gif" width="720"
       alt="make demo-proxy: a poisoned MCP tool is stripped at tools/list, a clean tool is badged, and a post-approval rug-pull is quarantined with JSON-RPC -32001">
</p>
<p align="center"><em>One command — <a href="docs/runbooks/real-world-agent-demo.md"><code>make demo-proxy</code></a>: the poisoned tool is stripped, the clean tool is badged, and a post-approval <strong>rug-pull is quarantined</strong> — real output, no edits.</em></p>

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

> **Who guards the guardian?** Tripwire is built so you can *verify* its claims rather than trust the gateway. The trust anchor, threat model, assumptions, and roadmap are in [Trust model, assumptions & limitations](#trust-model-assumptions--limitations).

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

Every capability above is implemented on `main` and covered by tests; the precise, file-by-file map — and the one item still **staged** (Cloud Run deploy) — lives in the **[feature catalog](docs/features/README.md)**.

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

## Where to read next

Full index: [`docs/README.md`](docs/README.md). The main entry points, by what you're after:

| If you want to… | Read |
|---|---|
| See exactly what ships, capability by capability (the precise reference) | [Feature catalog](docs/features/README.md) |
| Understand the problem, the wedge, and the success criteria | [Product spec — `docs/SPEC.md`](docs/SPEC.md) |
| See how the pieces compose (components, trust loop, data flow) | [Architecture — `docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Decide what to trust, and why (threat model, assumptions, limits) | [Trust model — `docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) |
| Run it yourself — deploy, demos, a live ADK session | [Runbooks](docs/runbooks/): [deploy](docs/runbooks/deploy.md) · [real-MCP demo](docs/runbooks/real-world-agent-demo.md) · [ADK live playground](docs/runbooks/adk-live-playground-demo.md) |
| Understand *why* it's built this way | [ADRs](docs/adr/) (decisions) · [RFCs](docs/rfc/) (designs, e.g. the stdio bridge and Ed25519) |
| Read the capstone story end-to-end | [Kaggle writeup — `docs/writeup.md`](docs/writeup.md) |
| See the engineering rules every coding agent follows | [`AGENTS.md`](AGENTS.md) + [`docs/AGENTIC_SDLC.md`](docs/AGENTIC_SDLC.md) |
| Check where the project is and where it's going | [STATUS](docs/STATUS.md) · [ROADMAP](docs/ROADMAP.md) |

## Trust model, assumptions & limitations

A trust gateway has to answer the obvious question — *why trust the thing that decides what to trust?* Tripwire's answer is that it is built **not** to require trust in itself: every claim it makes is independently checkable, which pushes trust down to one well-understood anchor.

**What you can verify yourself (no trust in Tripwire required):**

- **A badge verifies offline.** Ed25519 verification needs only the public key — no callback to Tripwire ([`attestation.py`](src/tripwire/attestation.py)). Change one byte and verification fails.
- **The verdict is a deterministic function, not an LLM opinion.** `approve` / `evaluate_call` in [`engine.py`](src/tripwire/engine.py) decide allow / block / quarantine; the agent layer only *explains* the verdict and cannot fabricate it ([`attestor_agent.py`](src/tripwire/agents/attestor_agent.py) just wraps `engine.approve`).
- **The fingerprint is reproducible.** `sha256(canonicalize(tool))` ([`detection.py`](src/tripwire/detection.py)) — anyone can recompute it and confirm "unchanged since approval" without trusting us.
- **The numbers are reproducible.** `make eval` re-derives `9/9 blocked · 0/4 false positives` from the committed corpus on your machine (Hard Rule #6 forbids invented metrics).

**The one irreducible anchor is the signing key.** HMAC (default) is a *shared secret* — anyone holding it can forge a badge, so it is demo-grade only. Ed25519 (`[signing]` extra) is the real anchor: private signer, public verifier. Trust ultimately bottoms out at **key custody and public-key distribution** — which is exactly where it should rest, not in a running service.

### Assumptions / hypotheses (where the approach holds)

1. **Trust flows through the manifest.** Tripwire guards the declared schema/description surface. An attack that bypasses the manifest — e.g. a tool returning malicious *content at runtime* to steer the agent — is out of scope for schema-integrity enforcement.
2. **Integrity ≠ goodness (trust-on-first-use).** The fingerprint pins *whatever was approved*. Drift detection proves *unchanged since approval*, not *safe* — if the first approval trusted an already-malicious tool the scanner missed, drift will not catch it.
3. **Detection is heuristic.** It catches the modeled OWASP MCP classes (poisoning, prompt injection, invisible-unicode, homoglyph). A novel payload outside the corpus can be a false negative — hence **no novelty claim on scanning**.
4. **The gateway is in the path and honest.** You trust the proxy process not to tamper in real time — mitigated by a small, stdlib-only, auditable core that never logs raw payloads, but it remains an assumption.
5. **Manifests are meant to be stable.** Legitimately dynamic tool catalogs will trip drift and require re-approval — correct by design, but a real UX cost worth naming.

### Where it helps most — and least

- **Most useful:** long-running agents; multi-tenant or shared tool registries; audit and compliance ("prove weeks later exactly what was approved"); supply-chain-sensitive or cross-org tool sharing, where portable badges verify without the issuer in the loop.
- **Least useful:** single-shot scripts over one fixed, already-trusted local tool; content-level prompt injection that never touches the schema; and intentionally fluid tool catalogs.

### Roadmap — where this goes next

- **Key management as a first-class concern:** KMS / Secret Manager integration, key-rotation windows, and transparency-log / Sigstore-style anchoring so verification stops depending on out-of-band key sharing.
- **From first-seen to publisher trust:** bind badges to a publisher signature so *goodness* can be asserted by a trusted issuer — directly closing the trust-on-first-use gap.
- **Beyond the schema:** runtime tool-*output* inspection for the injection-via-content class, plus policy-as-code for approval decisions.
- **Deeper detection:** semantic / model-assisted manifest analysis (with the deterministic verdict still authoritative) and a community-grown attack corpus.
- **Operational trust:** badge TTL / expiry, revocation lists, and multi-signer / quorum attestation.

Full write-up, including the threat-model table: [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md).

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
