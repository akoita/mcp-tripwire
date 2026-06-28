# OWASP MCP Top-10 taxonomy

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM)

Every Tripwire finding carries an `owasp` field with the canonical [OWASP MCP Top-10](https://owasp.org/www-project-mcp-top-10/) category id. This lets:

- **Security teams** route findings through existing AppSec workflows (Jira queues, GH Code Scanning categories, SARIF taxonomies) without re-mapping Tripwire's vocabulary.
- **LLM agents** explain *why* a tool was refused in a vocabulary their human operator already knows.
- **Downstream auditors** aggregate findings across multiple tools by category — "how many MCP-04 rug-pull events did we see this week?" is a one-liner.

The taxonomy isn't a feature on its own; it's the **lingua franca** that makes every other feature legible to a security audience.

## Audience

- **Security team / SOC operator** consuming Tripwire output.
- **LLM agent** that needs to explain a verdict in standard terminology.
- **CI / SARIF consumer** (post-[#32](https://github.com/akoita/mcp-tripwire/issues/32)) — the SARIF `rules[].properties.owasp_mcp` field is keyed on these ids.

## How it works today

`src/tripwire/owasp.py` is a 10-entry dict mapping IDs to human titles:

```python
OWASP_MCP_TOP_10: dict[str, str] = {
    "MCP-01": "Prompt / Tool-Description Injection",
    "MCP-02": "Tool Poisoning",
    "MCP-03": "Excessive Permissions / Over-Privilege",
    "MCP-04": "Rug Pull (Post-Approval Tool Mutation)",
    "MCP-05": "Tool Shadowing / Name Collision",
    "MCP-06": "Sensitive Data & Secret Exfiltration",
    "MCP-07": "Confused Deputy",
    "MCP-08": "Supply-Chain / Slopsquatting",
    "MCP-09": "Insufficient Authentication & Identity",
    "MCP-10": "Inadequate Logging & Monitoring",
}

def title(owasp_id: str) -> str: ...   # "MCP-01" -> "Prompt / Tool-Description Injection"
def is_valid(owasp_id: str) -> bool: ...
```

Every detection rule in `src/tripwire/detection.py` is tagged with its category at declaration time; the synthetic `MCP04-DRIFT` finding emitted by the corpus runner for caught rug-pulls (post-[#32](https://github.com/akoita/mcp-tripwire/issues/32) implementation) carries `MCP-04` directly.

The CLI's `scan` command groups findings by category in its human output; the JSON / SARIF outputs preserve the id for machine consumption.

## Where the mapping shows up

| Surface | Form |
|---|---|
| `Finding.owasp` field | bare id (`"MCP-01"`) |
| `tripwire scan` human output | `MCP-01 — Prompt / Tool-Description Injection` heading per group |
| `tripwire scan` SARIF (post-#32) | each `tool.driver.rules[].properties.owasp_mcp` |
| ADK Scanner agent tool return | `owasp_categories: ["Prompt / Tool-Description Injection", ...]` plus `counts_by_category: {"MCP-01": 1}` |
| HTTP `/scan` response | same dict the ADK Scanner returns |

## Verification

- Unit: [`tests/unit/test_detection.py`](../../tests/unit/test_detection.py) — every rule's positive case asserts the OWASP id it carries.
- Unit (CLI): [`tests/unit/test_cli.py::test_scan_poisoned_groups_by_owasp_category`](../../tests/unit/test_cli.py).
- ADK: [`tests/unit/test_agents.py::test_scan_tool_descriptor_poisoned_groups_owasp_categories`](../../tests/unit/test_agents.py).

## Guarantees and limitations

- **Snapshot of the spec at fork time** — the OWASP MCP Top 10 is itself a moving target. The current dict reflects the project page as of 2026-06; updates ship as a one-line `owasp.py` change with a corresponding documentation refresh.
- **Per-finding tagging, not per-tool** — one tool can fire multiple rules across multiple categories. The agent gets the per-finding ids; aggregation is the consumer's job.
- **The `MCP04-DRIFT` synthetic rule** (added by [RFC-0003](../rfc/RFC-0003-sarif-output.md) §Prerequisite, implementation tracked under [#32](https://github.com/akoita/mcp-tripwire/issues/32)) is the *only* "rule" not produced by `scan_tool` — it's emitted by the corpus runner so caught rug-pulls show up in SARIF output. Documented separately because the lifecycle is different.

## Cross-references

- Companion: [descriptor-scanning.md](descriptor-scanning.md) — the source of the per-finding tag.
- Future: [sarif-output.md](sarif-output.md) — the surface that makes the mapping consumable by GH Code Scanning.
- Source: <https://owasp.org/www-project-mcp-top-10/>.
