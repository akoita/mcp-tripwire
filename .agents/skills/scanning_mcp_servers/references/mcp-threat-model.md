# MCP Threat Model (reference)

Loaded on demand by the `scanning-mcp-servers` skill. Each detection rule maps to an
OWASP MCP Top-10 category (`src/tripwire/owasp.py`).

| Threat | OWASP | Detection signal |
|---|---|---|
| Instruction override in tool metadata | MCP-01 | "ignore previous instructions" phrasing |
| Hidden action ("don't tell the user") | MCP-01 | concealment phrasing |
| Invisible / zero-width payload | MCP-01 | U+200B/C/D, U+2060, U+FEFF present |
| Tool poisoning | MCP-02 | malicious behaviour described in manifest |
| Rug pull (post-approval mutation) | MCP-04 | fingerprint drift vs approved baseline |
| Tool shadowing / homoglyph name | MCP-05 | mixed-script tool name |
| Secret / credential exfiltration | MCP-06 | "send/exfiltrate … secret/token/key"; ~/.ssh, .env, PRIVATE KEY |
| Outbound network call in metadata | MCP-06 | curl/wget/http(s) URL |

Defence-in-depth: deterministic rules here are the spine; an LLM-judge (eval layer) is an
additive second opinion, never the load-bearing claim.
