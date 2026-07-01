# ADK multi-agent layer (Scanner / Red-team / Attestor)

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / operator)

A conversational front-end for the trust loop. Where the CLI is for scripts and the HTTP gateway is for batch jobs, the ADK layer is for an **LLM-driven operator session** — a security engineer asking *"scan this tool descriptor"* or *"give me a probe I can test the gateway against"* and getting routed to the right specialist.

Three specialists wrap the same deterministic engine as ADK `FunctionTool`s:

- **Scanner** — runs `scan_tool_descriptor` on a pasted tool, explains the findings in natural language with the OWASP category and rule that fired.
- **Red-team** — `seed_probes()` returns the 9 canonical attacks from the corpus; `propose_probe("rug-pull")` returns a category-filtered pick.
- **Attestor** — wraps `engine.approve` in `FunctionTool(require_confirmation=True)` so badge minting requires explicit human OK at runtime. The LLM cannot sign a badge on its own, even if it tried.

A coordinator agent routes operator requests to the right specialist. **The LLM never decides allow/block** — it explains; the engine decides.

## Audience

- **Security engineer** sitting in `agents-cli playground` doing exploratory analysis on an unknown MCP server.
- **LLM operator workflows** built on top of agents-cli that need a security-domain specialist available.

## How it works today

The project is enhanced via `agents-cli scaffold enhance .` — `agents-cli info` recognises it; `app/agent.py` exports `root_agent` (a coordinator `Agent` with the three sub_agents) and `app = App(name="app", root_agent=root_agent)`. App name matches the agent directory ("app") so `agents-cli eval` finds the session correctly.

Each specialist factory lives in `src/tripwire/agents/`. ADK imports are deferred (lazy import inside the factory) so the deterministic core stays stdlib-only (Hard Rule #2 — `src/tripwire/agents/` is the documented exception). The Attestor's tool requires confirmation at runtime via ADK's `FunctionTool(require_confirmation=True)` and refuses to mint badges unless `TRIPWIRE_SIGNING_KEY` is set.

The Phase 0 spec is [`.agents-cli-spec.md`](../../.agents-cli-spec.md) at the project root.

## Contract

```python
# src/tripwire/agents/
from tripwire.agents import (
    create_scanner_agent,        # Agent(name="tripwire_scanner", model="gemini-3-pro", ...)
    create_redteam_agent,        # Agent(name="tripwire_redteam", ...)
    create_attestor_agent,       # Agent(name="tripwire_attestor", ...)
    scan_tool_descriptor,        # FunctionTool, returns dict
    seed_probes,                 # FunctionTool, returns dict from corpus
    propose_probe,               # FunctionTool, category-filtered probe
    issue_if_clean,              # FunctionTool (require_confirmation=True)
)

# app/agent.py
root_agent = Agent(
    name="root_agent",
    sub_agents=[create_scanner_agent(), create_attestor_agent(), create_redteam_agent()],
    ...,
)
app = App(name="app", root_agent=root_agent)
```

## Surfaces

| Surface | How to reach it |
|---|---|
| `make demo-adk` | Standalone narrative — builds all three agents and exercises their *deterministic tool functions directly* (no LLM call needed). Proves the topology is real even without a model credential. |
| `agents-cli playground` | Interactive — opens the ADK web playground, the operator chats with the coordinator. Requires `agents-cli login --interactive` for Gemini creds. Scripted live-demo scenario: [runbook](../runbooks/adk-live-playground-demo.md). |
| `agents-cli run "..."` | One-shot prompts against the coordinator. |
| `agents-cli eval` | Datasets live in [`tests/eval/datasets/`](../../tests/eval/datasets/) — `tool_poisoning/v1` and `schema_drift/v1`. |
| Python | `from app.agent import root_agent, app` — the same wiring `agents-cli` uses. |

## Verification

- Unit (deterministic surface): [`tests/unit/test_agents.py`](../../tests/unit/test_agents.py) — 10 tests on the tool functions (shape contracts, JSON-serialisable, expected dict keys); 3 skip-on-no-`google-adk` tests for the factory construction + app load.
- Integration: [`tests/integration/test_demo_adk_script.py`](../../tests/integration/test_demo_adk_script.py) — runs `make demo-adk` as a subprocess, asserts exit 0 and the three section beats.
- ADK eval datasets: prepared but `agents-cli eval generate / grade` requires Gemini creds; runs locally when credentials are set up.

## Guarantees and limitations

- **Verdict ≠ LLM output.** Every "block" / "allow" / "quarantine" comes from the deterministic engine. The Scanner explains, the Red-team selects, the Attestor mints — none of them *decide*. This is Hard Rule #6 (never invent metrics) extended to "never invent verdicts."
- **Badge minting fails closed.** The Attestor returns a refused decision if `TRIPWIRE_SIGNING_KEY` is missing; user confirmation alone cannot create a badge.
- **`[agent]` extra required** — `google-adk` is heavy (~50 transitive packages). The `[dev]` venv skips it; ADK-gated tests skip cleanly with a clear reason.
- **Model is `gemini-3-pro`** — chosen by the stub author; not changed without an explicit ask (agents-cli convention "never change models" — see [google-agents-cli-workflow §Principle 1](https://google.github.io/agents-cli/)).
- **No conversation memory beyond the session.** Memory Bank integration is a v1.x concern.
- **HITL is per-call, not per-session.** The Attestor prompts the operator every badge mint, not once per session. That's deliberate (Hard Rule #1: every trust action is explicit).

## Cross-references

- Spec: [`.agents-cli-spec.md`](../../.agents-cli-spec.md) — the Phase-0 intent doc.
- Companions: the tool-function half of each agent is the same code as the CLI / HTTP surfaces — [descriptor-scanning.md](descriptor-scanning.md), [signed-trust-badges.md](signed-trust-badges.md).
- Workflow: agents-cli's published [development workflow skill](https://google.github.io/agents-cli/guide/getting-started/) — Phase 0 spec → 3 build → 4 eval.
- Workflow context: [docs/AGENTIC_SDLC.md](../AGENTIC_SDLC.md).
