---
name: issuing-mcp-trust-badge
description: |
  Generates a signed, tamper-evident trust-badge attestation for a vetted MCP server. Use
  this skill when the user asks to issue, mint, or generate a trust badge / attestation
  after a clean scan. Do NOT use before a scan completes, on a server with unresolved
  findings, or for any irreversible/financial action.
version: 1.0.0
license: Apache-2.0
allowed-tools: Read Bash
metadata:
  author: akoita
---
# Issuing an MCP Trust Badge

## When to use
- "Issue / mint a trust badge for this server."
- After `scanning-mcp-servers` returns clean and a human has approved.

## When NOT to use
- Before a scan, or with any open critical/high finding.
- As a substitute for human approval — this is an action skill (request confirmation first).

## Workflow
1. Confirm a clean scan exists for every tool in the manifest.
2. Confirm explicit human approval (this signs evidence; treat as high-stakes).
3. Run `python scripts/sign_badge.py <manifest.json>` (uses `$TRIPWIRE_SIGNING_KEY`).
4. Return the badge JSON (see `assets/badge.json.tmpl`) and how to verify it (`tripwire verify`).

## Output format
- The signed badge object + the exact `tripwire verify badge.json` command.

## Anti-patterns to avoid
- Never sign blindly or to "save time."
- Never embed the signing key in output, prompts, or logs (Hard Rule #3).
