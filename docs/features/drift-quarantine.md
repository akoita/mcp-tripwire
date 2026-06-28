# Drift quarantine (rug-pull defense)

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

A tool that was clean when the operator approved it can mutate later — same name, same advertised purpose, malicious instruction injected into the description. This is the **rug pull** failure mode (OWASP MCP-04). Static scanners can't see it; only a runtime check against the *originally approved* fingerprint can.

Tripwire catches drift two ways, so it fires whichever path the agent takes first:

1. **At `tools/call` time** — the proxy looks up the cached descriptor, re-fingerprints it, compares against the approved fingerprint. Mismatch → **quarantine**, call short-circuited, JSON-RPC error returned to the agent before the tool runs.
2. **At the next `tools/list`** — the proxy re-runs the trust check; drifted tools are stripped from the approved list the agent sees, and a new `tools/list` won't silently re-approve them.

The agent ends up unable to invoke the mutated tool, period.

## Audience

- **LLM agent** that approved a tool earlier in the session and might still trust it.
- **MCP gateway** (the proxy bridge) enforcing trust transparently.
- **CI pipeline** running a corpus check that includes a drift case.

## How it works today

The engine separates **approval-time** and **call-time** semantics:

```python
# src/tripwire/engine.py
def approve(self, tool: dict) -> Decision:
    # scan + fingerprint + mint badge; stores fingerprint in self._approved[name]

def evaluate_call(self, tool: dict) -> Decision:
    # if not approved -> REQUIRE_APPROVAL
    # if approved AND fingerprint matches -> ALLOW
    # if approved AND fingerprint differs -> QUARANTINE
```

The fingerprint is a SHA-256 of a canonical serialisation of the tool descriptor (`detection.fingerprint()`), so any byte-level change to name / description / inputSchema flips it.

The proxy's `bridge()` loop holds a `_live_tools: dict[name, dict]` cache populated on every `tools/list` response. On `tools/call`, it looks up the cached descriptor by name and feeds it to `guard_tool_call → evaluate_call`. On a subsequent `tools/list`, `guard_tools_list` runs `evaluate_call` for already-approved tools (catching drift on re-list) before considering re-approval.

## Contract

```python
class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"          # drift caught here
    REQUIRE_APPROVAL = "require_approval"

class Decision:
    action: Action
    reason: str                         # "schema drift since approval — rug pull suspected"
    tool: str
    findings: list[Finding]
    fingerprint: str | None
    badge: dict | None
```

Through the proxy, a quarantined `tools/call` becomes a JSON-RPC error (see [stdio-mcp-proxy.md](stdio-mcp-proxy.md) for the shape).

## Surfaces

| Surface | How drift manifests |
|---|---|
| Python | `engine.evaluate_call(mutated_tool).action is Action.QUARANTINE` |
| Stdio proxy | Re-list strips the drifted tool; `tools/call` returns JSON-RPC error −32001 with `data.tripwire.action == "quarantine"` |
| HTTP gateway | `/scan` against the mutated descriptor still flags it as findings (if mutation introduces a poisoning marker); drift-vs-approved comparison requires the engine state, which the HTTP `/scan` endpoint doesn't carry across calls — drift is a stateful concern best handled by the proxy bridge |
| Corpus | Case `d1` (`rug-pull-exfil`) exercises the full path: approve clean → mutate → evaluate_call → expected QUARANTINE; counted in `make eval`'s **9/9** number |
| Demo | `make demo` Section 3 and `make demo-proxy` Section C both show the drift catch end-to-end |

## Verification

- Unit (engine): [`tests/unit/test_engine.py::test_drifted_tool_is_quarantined`](../../tests/unit/test_engine.py)
- Unit (corpus): [`tests/unit/test_corpus.py::test_drift_attack_quarantine_counts_as_blocked`](../../tests/unit/test_corpus.py) + the negative case `test_drift_no_actual_drift_is_allowed` (identical re-list ≠ drift, prevents false-positives on re-approval).
- Integration (proxy): [`tests/integration/test_proxy_bridge.py`](../../tests/integration/test_proxy_bridge.py) — section 3/4 of the test sequence triggers `_admin/mutate` on the fake MCP server, re-lists, then calls and asserts the JSON-RPC error.
- Integration (demo script): [`tests/integration/test_proxy_demo_script.py`](../../tests/integration/test_proxy_demo_script.py).
- Eval: `make eval` → `d1 (rug-pull-exfil): expected block, got quarantine ✓`.

## Guarantees and limitations

- **Catches descriptor mutation only** — if the upstream server keeps its `tools/list` identical but changes what the tool *does* at execution time, that's an execution-side compromise Tripwire can't see (Tripwire is a trust-evidence layer, not a sandbox).
- **Stateful** — drift detection requires a session in which the approval happened. A fresh process with no prior approval just sees the mutated descriptor and runs the scanner against it (will catch poisoning markers if present, won't call it "drift").
- **Per-session, per-tool** — no cross-session memory yet. If the operator restarts and re-approves, they're approving the post-mutation version, which is the right semantics (they get a fresh chance to reject it).
- **Live-tools cache is wholesale-refreshed** on every `tools/list` response — so drift detection between calls only fires if the agent re-lists; pure `tools/call` traffic against a stale cache wouldn't see a server-side mutation until the next list. Documented in [RFC-0001 §"Why a live-tools cache is necessary"](../rfc/RFC-0001-e2-stdio-proxy-bridge.md).

## Cross-references

- Companion: [descriptor-scanning.md](descriptor-scanning.md) — runs at approval time.
- Companion: [signed-trust-badges.md](signed-trust-badges.md) — the fingerprint is what the badge attests to.
- Companion: [stdio-mcp-proxy.md](stdio-mcp-proxy.md) — the transport that wires drift into a real MCP session.
- ADR: [docs/adr/ADR-0001-mcp-trust-gateway.md](../adr/ADR-0001-mcp-trust-gateway.md).
- RFC: [RFC-0001 §Live-tools cache](../rfc/RFC-0001-e2-stdio-proxy-bridge.md#why-a-live-tools-cache-is-necessary).
