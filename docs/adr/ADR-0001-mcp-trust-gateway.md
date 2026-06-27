# ADR-0001: An MCP trust gateway, not "another scanner"

- **Status:** accepted
- **Date:** 2026-06-27

## Context
MCP security already has static scanners (Invariant mcp-scan, Snyk), runtime gateways
(Prompt Security), and a taxonomy (OWASP MCP Top 10). Claiming to be "the first MCP scanner"
would be false and would lose credibility with an expert jury. We have 9 days, solo.

## Decision
Build a small, explainable, OSS **trust gateway** centred on *continuous schema integrity +
portable signed attestations*. The deterministic core is **stdlib-only** so the spine cannot
flake and stays auditable. We do not try to out-feature incumbents (an explicit non-goal).

## Consequences
- Hard Rule #2 (core stays dependency-free) follows directly and is guardrail-enforced.
- Positioning is honest: scanning is table-stakes; verifiable trust evidence is the wedge ([ADR-0003](ADR-0003-signed-attestations.md)).
- Breadth is sacrificed for a sharp, demoable primitive.
