# Tool descriptor scanning

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

Before an agent calls a tool advertised by an MCP server, Tripwire tells it whether the tool's **descriptor itself is hostile** — independent of what the tool actually does at runtime. A poisoned description (instruction-override, hidden-from-user, exfil instructions, invisible Unicode payloads, homoglyph name) is detected and tagged with an OWASP MCP Top-10 category, so the agent (or the operator / CI gating the agent) can refuse to call it.

Without this, the agent treats `tools/list` as ground truth — which is exactly how tool-poisoning attacks succeed in the wild.

## Audience

- **LLM agent** that wants to vet a tool descriptor before invoking it.
- **CI pipeline** running `tripwire scan tools.json` against committed manifests.
- **Operator** running ad-hoc scans during incident response.

## How it works today

`tripwire.detection.scan_tool(tool: dict) -> list[Finding]` runs a deterministic, stdlib-only rule set against the descriptor:

- **Instruction-override phrases** (`MCP06:2025`) — `"ignore previous instructions"`-class hijacks in name/description.
- **Invisible / zero-width characters** (`MCP03:2025`) — Unicode payloads that hide instructions from a casual reader.
- **Mixed-script homoglyph names** (`MCP03:2025`) — `"gеt_weather"` with a Cyrillic `е` shadowing a legitimate tool.
- **Exfil instructions** (`MCP01:2025`) — descriptors that tell the agent to send secrets / credentials / env vars out-of-band.
- **Outbound URLs in metadata** (`MCP06:2025`) — embedded `https://attacker.example/collect`-style targets.
- **"Don't tell the user"** patterns (`MCP06:2025`) — instructions to hide actions from the operator.

Each `Finding` carries `rule`, `title`, `severity` (`LOW / MEDIUM / HIGH / CRITICAL`), `owasp` (the `MCPnn:2025` id), `evidence` (a snippet), and `tool` (the descriptor's name).

The CLI groups output by OWASP category; the HTTP `/scan` endpoint returns the same shape; the ADK Scanner agent wraps the same function as its only `FunctionTool`.

## Contract

```python
# src/tripwire/detection.py
def scan_tool(tool: dict) -> list[Finding]: ...

@dataclass(frozen=True)
class Finding:
    rule: str           # e.g. "INJ-IGNORE"
    title: str          # human-readable rule title
    severity: Severity  # LOW / MEDIUM / HIGH / CRITICAL
    owasp: str          # "MCP01:2025" through "MCP10:2025"
    evidence: str       # short snippet showing the matched text
    tool: str           # the descriptor's "name"
```

The `scan_tool_descriptor()` ADK tool returns a richer dict (`{"status", "findings", "owasp_categories", "counts_by_category", "worst_severity"}`) — defined in `src/tripwire/agents/scanner_agent.py`.

## Surfaces

| Surface | How to reach it |
|---|---|
| CLI | `tripwire scan <manifest.json>` (exit 1 on HIGH+) |
| HTTP | `POST /scan` body `{"tool": {...}}` → JSON; same shape with `Accept: application/sarif+json` once [#32](https://github.com/akoita/mcp-tripwire/issues/32) ships |
| ADK | The Scanner agent ([`src/tripwire/agents/scanner_agent.py`](../../src/tripwire/agents/scanner_agent.py)) — calls `scan_tool_descriptor` as its FunctionTool |
| Python | `from tripwire import scan_tool` |

## Verification

- Unit: [`tests/unit/test_detection.py`](../../tests/unit/test_detection.py) — every rule has at least one positive case.
- CLI: [`tests/unit/test_cli.py`](../../tests/unit/test_cli.py) — exit codes and OWASP-grouped output.
- HTTP: [`tests/integration/test_http_endpoints.py`](../../tests/integration/test_http_endpoints.py) — happy path + malformed body.
- ADK: [`tests/unit/test_agents.py`](../../tests/unit/test_agents.py) — tool function return shape; factory construction.
- Corpus: 8 of the 9 corpus attacks in [`corpus/attacks.jsonl`](../../corpus/attacks.jsonl) exercise the scanner path; the 9th (`d1`) exercises drift-quarantine instead — see [drift-quarantine.md](drift-quarantine.md).

## Guarantees and limitations

- **Deterministic** — the same descriptor always produces the same finding set.
- **Stdlib-only** — Hard Rule #2 enforced by `harness_guardrails.py`. No third-party dep can creep into the scanner.
- **No false negatives are guaranteed**, but every rule has a corpus case proving it fires when expected.
- **Rule-based, not LLM-based** — won't catch novel attack phrasings that don't match a pattern. Adding LLM-judge as an *additive* layer is tracked in [`docs/TECH_DEBT.md`](../TECH_DEBT.md).
- **Per-descriptor, not per-server** — doesn't cross-correlate tools (e.g. detect that two tools with similar names are shadowing each other across MCP servers). Tracked in v0.3 as part of the multi-upstream registry.

## Cross-references

- Companion: [signed-trust-badges.md](signed-trust-badges.md) — what the agent gets back when a descriptor passes.
- Companion: [drift-quarantine.md](drift-quarantine.md) — what catches post-approval mutation.
- Taxonomy: [owasp-mcp-mapping.md](owasp-mcp-mapping.md).
- Spec: [docs/SPEC.md](../SPEC.md) §detection.
- ADR: [docs/adr/ADR-0001-mcp-trust-gateway.md](../adr/ADR-0001-mcp-trust-gateway.md).
