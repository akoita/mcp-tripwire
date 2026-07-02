# OWASP MCP Top-10 taxonomy

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

Every Tripwire finding carries an `owasp` field with the canonical [OWASP MCP Top-10](https://owasp.org/www-project-mcp-top-10/) category id. This lets:

- **Security teams** route findings through existing AppSec workflows (Jira queues, GH Code Scanning categories, SARIF taxonomies) without re-mapping Tripwire's vocabulary.
- **LLM agents** explain *why* a tool was refused in a vocabulary their human operator already knows.
- **Downstream auditors** aggregate findings across multiple tools by category — "how many MCP03:2025 tool-poisoning events did we see this week?" is a one-liner.

The taxonomy isn't a feature on its own; it's the **lingua franca** that makes every other feature legible to a security audience.

## Audience

- **Security team / SOC operator** consuming Tripwire output.
- **LLM agent** that needs to explain a verdict in standard terminology.
- **CI / SARIF consumer** (post-[#32](https://github.com/akoita/mcp-tripwire/issues/32)) — the SARIF `rules[].properties.owasp_mcp` field is keyed on these ids.

## How it works today

`src/tripwire/owasp.py` is a 10-entry dict mapping IDs to human titles:

```python
OWASP_MCP_TOP_10: dict[str, str] = {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    "MCP06:2025": "Intent Flow Subversion",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}

def title(owasp_id: str) -> str: ...   # "MCP03:2025" -> "Tool Poisoning"
def is_valid(owasp_id: str) -> bool: ...
```

The ids/titles are the official OWASP MCP Top 10 (2025) working draft. Tripwire originally shipped an early community numbering (`MCP-01` … `MCP-10`); the old→new remap and the per-rule rationale live in [docs/OWASP_MCP_COVERAGE.md](../OWASP_MCP_COVERAGE.md).

Every detection rule in `src/tripwire/detection.py` is tagged with its category at declaration time; the synthetic `DRIFT-RUGPULL` finding emitted by the corpus runner for caught rug-pulls (post-[#32](https://github.com/akoita/mcp-tripwire/issues/32) implementation; named `MCP04-DRIFT` in RFC-0003) carries `MCP03:2025` directly.

The CLI's `scan` command groups findings by category in its human output; the JSON / SARIF outputs preserve the id for machine consumption.

## Where the mapping shows up

| Surface | Form |
|---|---|
| `Finding.owasp` field | bare id (`"MCP06:2025"`) |
| `tripwire scan` human output | `MCP06:2025 — Intent Flow Subversion` heading per group |
| `tripwire scan` SARIF (post-#32) | each `tool.driver.rules[].properties.owasp_mcp` |
| ADK Scanner agent tool return | `owasp_categories: ["Intent Flow Subversion", ...]` plus `counts_by_category: {"MCP06:2025": 1}` |
| HTTP `/scan` response | same dict the ADK Scanner returns |

## Verification

- Unit: [`tests/unit/test_detection.py`](../../tests/unit/test_detection.py) — every rule's positive case asserts the OWASP id it carries.
- Unit (CLI): [`tests/unit/test_cli.py::test_scan_poisoned_groups_by_owasp_category`](../../tests/unit/test_cli.py).
- ADK: [`tests/unit/test_agents.py::test_scan_tool_descriptor_poisoned_groups_owasp_categories`](../../tests/unit/test_agents.py).

## Guarantees and limitations

- **Snapshot of the working draft** — the OWASP MCP Top 10 is still a working draft and may evolve. The current dict reflects the official project page as of 2026-07; updates ship as an `owasp.py` change plus a refresh of [docs/OWASP_MCP_COVERAGE.md](../OWASP_MCP_COVERAGE.md).
- **Breaking id change for stored findings** — findings emitted before the 2025 remap carry the old `MCP-nn` ids; the old→new table in the coverage matrix is the migration reference.
- **Per-finding tagging, not per-tool** — one tool can fire multiple rules across multiple categories. The agent gets the per-finding ids; aggregation is the consumer's job.
- **The `DRIFT-RUGPULL` synthetic rule** (added by [RFC-0003](../rfc/RFC-0003-sarif-output.md) §Prerequisite as `MCP04-DRIFT`, implementation tracked under [#32](https://github.com/akoita/mcp-tripwire/issues/32)) is the *only* "rule" not produced by `scan_tool` — it's emitted by the corpus runner so caught rug-pulls show up in SARIF output. Documented separately because the lifecycle is different.

## Cross-references

- Companion: [descriptor-scanning.md](descriptor-scanning.md) — the source of the per-finding tag.
- Coverage: [docs/OWASP_MCP_COVERAGE.md](../OWASP_MCP_COVERAGE.md) — which of the ten Tripwire addresses vs out-of-scope, plus the old→new id remap.
- Future: [sarif-output.md](sarif-output.md) — the surface that makes the mapping consumable by GH Code Scanning.
- Source: <https://owasp.org/www-project-mcp-top-10/> ([repo](https://github.com/OWASP/www-project-mcp-top-10)).
