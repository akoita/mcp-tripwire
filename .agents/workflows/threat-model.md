---
description: Threat-model a change against the OWASP MCP Top 10 before merging.
---
# Threat model a change

1. List new/changed tool surfaces, inputs, and trust boundaries.
2. For each, ask which OWASP MCP Top-10 categories apply (`src/tripwire/owasp.py`).
3. Add a corpus case for any newly-handled attack (`corpus/attacks.jsonl`) — test-first.
4. Confirm `tripwire ci` still reports all attacks blocked, 0 false-positives.
5. Record residual risk in the PR description.
