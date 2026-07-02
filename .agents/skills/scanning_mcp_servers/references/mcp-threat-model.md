# MCP Threat Model (reference)

Loaded on demand by the `scanning-mcp-servers` skill. Each detection rule maps to an
OWASP MCP Top-10 category (`src/tripwire/owasp.py`).

| Threat | OWASP (2025) | Detection signal |
|---|---|---|
| Instruction override in tool metadata | MCP06:2025 | "ignore previous instructions" phrasing |
| Hidden action ("don't tell the user") | MCP06:2025 | concealment phrasing |
| Invisible / zero-width payload | MCP03:2025 | U+200B/C/D, U+2060, U+FEFF present |
| Tool poisoning | MCP03:2025 | malicious behaviour described in manifest |
| Rug pull (post-approval mutation) | MCP03:2025 | fingerprint drift vs approved baseline |
| Tool shadowing / homoglyph name | MCP03:2025 | mixed-script tool name |
| Secret / credential exfiltration | MCP01:2025 | "send/exfiltrate … secret/token/key"; ~/.ssh, .env, PRIVATE KEY |
| Outbound network call in metadata | MCP06:2025 | curl/wget/http(s) URL |

Defence-in-depth: deterministic rules here are the spine; an LLM-judge (eval layer) is an
additive second opinion, never the load-bearing claim.
