---
name: triaging-owasp-mcp-findings
description: |
  Classifies a raw MCP scan finding against the OWASP MCP Top 10, assigns severity, and
  proposes remediation. Use this skill when the user asks to triage, classify, or prioritize
  an MCP security finding, or to map an issue to the OWASP MCP taxonomy.
  Do NOT use to run the scan itself (use scanning-mcp-servers) or to issue a badge.
version: 1.0.0
license: Apache-2.0
allowed-tools: Read
metadata:
  author: akoita
---
# Triaging OWASP MCP Findings

## When to use
- "Triage / classify / prioritize this MCP finding."
- "Which OWASP MCP category is this?"

## When NOT to use
- Running the scan (use `scanning-mcp-servers`).
- Signing a trust badge (use `issuing-mcp-trust-badge`).

## Workflow
1. Take the finding(s) from a scan.
2. Map each to its OWASP MCP id using `references/owasp-mcp-top10.md`.
3. Assign severity (critical/high/medium/low) and a residual-risk note.
4. Produce a report using `assets/finding_report_template.md`.

## Output format
- One row per finding: id · OWASP · severity · evidence · remediation. Then an overall verdict.

## Anti-patterns to avoid
- Don't downgrade a critical exfiltration finding to "informational."
- Don't fabricate an OWASP id; only use the canonical ten.
