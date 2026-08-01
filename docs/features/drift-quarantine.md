# Drift quarantine (rug-pull defense)

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

**This is the deterministic guarantee at the centre of the product.** A tool your agent already approved cannot silently change underneath it. The check is a SHA-256 comparison against the fingerprint captured at approval — not a judgement call, not a heuristic:

- **Deterministic.** Same descriptor in, same verdict out. It compares fingerprints instead of reading intent.
- **Zero false positives by construction.** It never guesses whether a descriptor "looks malicious", so an unusual-but-honest tool cannot be flagged. Only an actual change to the approved bytes fires it (the negative case `test_drift_no_actual_drift_is_allowed` pins this).
- **No coverage gap to argue about.** *Any* change to the manifest surface flips the fingerprint — there is no rule list to keep up to date, and no novel-payload false negative.

That is what a static scanner structurally cannot do. A tool that was clean when the operator approved it can mutate later — same name, same advertised purpose, malicious instruction injected into the description. This is the **rug pull** failure mode (OWASP MCP03:2025 Tool Poisoning — contract/schema tampering). Only a runtime check against the *originally approved* fingerprint catches it.

The descriptor scanner ([descriptor-scanning.md](descriptor-scanning.md)) is the best-effort first pass in front of this; drift quarantine is the part that carries a guarantee. See [TRUST_MODEL.md §1](../TRUST_MODEL.md#1-two-tiers-of-strength--read-this-first) for the full hierarchy.

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

### Proof against a published attack: `rw-09`

The claim "the scanner can't see this, drift can" is easy to assert and easy to fake — a corpus we wrote, graded by rules we wrote, proves nothing. Case `rw-09` of the [real-world attack suite](real-world-attack-suite.md) is the non-circular version, and `test_drift_catches_what_the_scanner_misses` asserts **both halves**:

1. `scan_tool(case["mutate_to"])` returns **zero findings** on the mutated descriptor — the content scanner is *provably blind* to this payload, so drift is not being handed an attack the scanner already flagged; and
2. after the benign descriptor is approved, `evaluate_call(mutate_to)` returns **`QUARANTINE`** anyway.

An attack that no content rule in this repo can see, stopped by comparing a fingerprint. Across the nine published-research cases the audit measures **4 blocked · 1 advisory · 3 missed · 1 out-of-scope**, and **2 of the 4 blocks come from drift, not scanning** — half the wins in that suite come from this layer.

The mirror-image limit is `rw-04` (the real `postmark-mcp` compromise): its published manifest stayed byte-identical while the server *implementation* changed, so the fingerprint never moved. That case is recorded as `out_of_scope` rather than `missed`, because no manifest-integrity gate could have caught it — see the limitations below.

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
| Corpus | Cases `d1`–`d6` exercise the full path: approve clean → mutate → evaluate_call → expected QUARANTINE; counted in `make eval`'s **40/40** number |
| Demo | `make demo` Section 3 and `make demo-proxy` Section C both show the drift catch end-to-end |

## Verification

- Unit (engine): [`tests/unit/test_engine.py::test_drifted_tool_is_quarantined`](../../tests/unit/test_engine.py)
- Unit (corpus): [`tests/unit/test_corpus.py::test_drift_attack_quarantine_counts_as_blocked`](../../tests/unit/test_corpus.py) + the negative case `test_drift_no_actual_drift_is_allowed` (identical re-list ≠ drift, prevents false-positives on re-approval).
- Integration (proxy): [`tests/integration/test_proxy_bridge.py`](../../tests/integration/test_proxy_bridge.py) — section 3/4 of the test sequence triggers `_admin/mutate` on the fake MCP server, re-lists, then calls and asserts the JSON-RPC error.
- Integration (demo script): [`tests/integration/test_proxy_demo_script.py`](../../tests/integration/test_proxy_demo_script.py).
- Eval: `make eval` → `d1`–`d6`: expected block, got quarantine ✓.
- Published-research audit: [`tests/security/test_real_world_attacks.py::test_drift_catches_what_the_scanner_misses`](../../tests/security/test_real_world_attacks.py) — `rw-09`, scanner-blind **and** drift-quarantined, both asserted. Reported by `make audit`.

## Guarantees and limitations

- **Guaranteed for any change to the manifest surface** — this is the one claim Tripwire makes that is not best-effort. It is a hash comparison, so it cannot miss a descriptor mutation and cannot fire on a descriptor that did not mutate.
- **Integrity is not goodness** — drift proves *unchanged since approval*, never *benign*. A tool that was already malicious at first approval is faithfully pinned in its malicious state.
- **Catches descriptor mutation only** — if the upstream server keeps its `tools/list` identical but changes what the tool *does* at execution time, that's an execution-side compromise Tripwire can't see (Tripwire is a trust-evidence layer, not a sandbox). `rw-04` is the real-world instance of exactly this limit.
- **Stateful** — drift detection requires a session in which the approval happened. A fresh process with no prior approval just sees the mutated descriptor and runs the scanner against it (will catch poisoning markers if present, won't call it "drift").
- **Per-session, per-tool** — no cross-session memory yet. If the operator restarts and re-approves, they're approving the post-mutation version, which is the right semantics (they get a fresh chance to reject it).
- **Live-tools cache is wholesale-refreshed** on every `tools/list` response — so drift detection between calls only fires if the agent re-lists; pure `tools/call` traffic against a stale cache wouldn't see a server-side mutation until the next list. Documented in [RFC-0001 §"Why a live-tools cache is necessary"](../rfc/RFC-0001-e2-stdio-proxy-bridge.md).

## Cross-references

- Evidence: [real-world-attack-suite.md](real-world-attack-suite.md) — the published-research audit; `rw-09` is the case this layer catches while the scanner is blind.
- Companion: [descriptor-scanning.md](descriptor-scanning.md) — the best-effort first pass, runs at approval time.
- Trust model: [TRUST_MODEL.md](../TRUST_MODEL.md) — why this layer is Tier 1 and scanning is Tier 2.
- Companion: [signed-trust-badges.md](signed-trust-badges.md) — the fingerprint is what the badge attests to.
- Companion: [stdio-mcp-proxy.md](stdio-mcp-proxy.md) — the transport that wires drift into a real MCP session.
- ADR: [docs/adr/ADR-0001-mcp-trust-gateway.md](../adr/ADR-0001-mcp-trust-gateway.md).
- RFC: [RFC-0001 §Live-tools cache](../rfc/RFC-0001-e2-stdio-proxy-bridge.md#why-a-live-tools-cache-is-necessary).
