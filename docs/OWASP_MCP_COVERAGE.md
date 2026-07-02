# OWASP MCP Top 10 (2025) — Tripwire coverage matrix

> Which of the ten official categories Tripwire addresses, partially addresses, or
> deliberately leaves out of scope — and how each detection rule maps onto the
> taxonomy. Canonical ids/titles follow the
> [OWASP MCP Top 10 working draft](https://owasp.org/www-project-mcp-top-10/)
> ([source repo](https://github.com/OWASP/www-project-mcp-top-10)). The threat
> model behind these choices is [TRUST_MODEL.md](TRUST_MODEL.md).

## History: early community ids → official 2025 ids

Tripwire originally shipped with an early community numbering of the list
(`MCP-01` Prompt Injection … `MCP-10` Inadequate Logging). The published OWASP
working draft renumbered and re-scoped the categories. All emitted ids now use
the official `MCPnn:2025` notation. For consumers migrating stored findings:

| Old (early community) | Official (2025) |
|---|---|
| MCP-01 Prompt / Tool-Description Injection | MCP06:2025 Intent Flow Subversion (instruction-override, system-prompt, concealment) · MCP03:2025 Tool Poisoning (invisible-unicode smuggling) |
| MCP-02 Tool Poisoning | MCP03:2025 Tool Poisoning |
| MCP-03 Excessive Permissions / Over-Privilege | MCP02:2025 Privilege Escalation via Scope Creep |
| MCP-04 Rug Pull (Post-Approval Tool Mutation) | MCP03:2025 Tool Poisoning (contract/schema tampering) |
| MCP-05 Tool Shadowing / Name Collision | MCP03:2025 Tool Poisoning (deceptive homoglyph descriptor) |
| MCP-06 Sensitive Data & Secret Exfiltration | MCP01:2025 Token Mismanagement & Secret Exposure (secret-targeting rules) · MCP06:2025 Intent Flow Subversion (outbound-beacon rule) |
| MCP-07 Confused Deputy | MCP02:2025 Privilege Escalation via Scope Creep |
| MCP-08 Supply-Chain / Slopsquatting | MCP04:2025 Software Supply Chain Attacks & Dependency Tampering |
| MCP-09 Insufficient Authentication & Identity | MCP07:2025 Insufficient Authentication & Authorization |
| MCP-10 Inadequate Logging & Monitoring | MCP08:2025 Lack of Audit and Telemetry |

The synthetic corpus rule formerly named `MCP04-DRIFT` is now `DRIFT-RUGPULL`,
so rule ids no longer embed taxonomy numbering and cannot go stale again.

## Coverage matrix

| # | Category (2025) | Coverage | How / why |
|---|---|---|---|
| MCP01:2025 | Token Mismanagement & Secret Exposure | **Partial** | `EXF-SECRET` / `EXF-SSHENV` block descriptors that instruct the agent to expose secrets, tokens, or credential material. Tripwire does **not** audit how a deployment stores or rotates its own credentials. |
| MCP02:2025 | Privilege Escalation via Scope Creep | Out of scope | Tripwire has no view of the permission model behind a tool; it checks the declared manifest surface, not granted scopes. |
| MCP03:2025 | Tool Poisoning | **Core** | The reason Tripwire exists. Scan-time blocking of poisoned descriptors (`INJ-INVISIBLE` zero-width smuggling, `SHADOW-HOMOGLYPH` deceptive names) plus the fingerprint-drift quarantine (`DRIFT-RUGPULL`) that catches post-approval contract tampering — the rug pull. |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering | Out of scope | No dependency or package analysis. Adjacent help: fingerprint pinning + signed badges make the *tool contract* tamper-evident, which narrows the blast radius of an upstream compromise. |
| MCP05:2025 | Command Injection & Execution | Out of scope | Runtime input validation belongs to the tool/server, not the gateway. `EXF-URL` incidentally flags `curl`/`wget` phrasing in metadata, but that is not command-injection defense. |
| MCP06:2025 | Intent Flow Subversion | **Partial** | `INJ-IGNORE`, `INJ-SYSPROMPT`, `INJ-HIDE`, and `EXF-URL` catch descriptor-embedded instructions that hijack the agent's goal. Static and descriptor-level only: injection carried in *runtime tool output* is an explicit non-goal (see [TRUST_MODEL.md §3](TRUST_MODEL.md)). |
| MCP07:2025 | Insufficient Authentication & Authorization | Out of scope | Tripwire assumes an honest gateway process and does not authenticate callers. Adjacent help: Ed25519 badges give *verifiable approval provenance*, but that is attestation, not authn/authz. |
| MCP08:2025 | Lack of Audit and Telemetry | **Partial** | Signed, tamper-evident attestations plus SARIF output create a portable audit trail of what was approved and what fired. Tripwire does not provide runtime call logging (payload logging is deliberately avoided — see [ADR-0004](adr/ADR-0004-secret-and-payload-hygiene.md)). |
| MCP09:2025 | Shadow MCP Servers | Out of scope | Discovering unapproved server deployments is an org-governance problem. Adjacent help: routing traffic through the Tripwire proxy makes "only approved tools reach the agent" enforceable for the servers you *do* front. |
| MCP10:2025 | Context Injection & Over-Sharing | Out of scope | Tripwire does not manage context windows, memory, or cross-session isolation. |

**Summary:** one core category (MCP03), three partials (MCP01, MCP06, MCP08),
six out of scope. Tripwire is a *manifest-integrity gateway*, not a full MCP
security suite — the out-of-scope rows are deliberate (see the non-goals in
[TRUST_MODEL.md](TRUST_MODEL.md)).

## Rule → category reference

| Rule | Detects | OWASP (2025) |
|---|---|---|
| `INJ-IGNORE` | "ignore previous instructions" override phrasing | MCP06:2025 |
| `INJ-SYSPROMPT` | references to the system/developer prompt | MCP06:2025 |
| `INJ-HIDE` | "do not tell the user" concealment phrasing | MCP06:2025 |
| `INJ-INVISIBLE` | zero-width / invisible characters smuggled into metadata | MCP03:2025 |
| `SHADOW-HOMOGLYPH` | mixed-script (homoglyph) tool name shadowing a legit tool | MCP03:2025 |
| `EXF-SECRET` | instructions to exfiltrate secrets / tokens / credentials | MCP01:2025 |
| `EXF-SSHENV` | references to credential material (ssh / env / private key) | MCP01:2025 |
| `EXF-URL` | outbound network call embedded in tool metadata | MCP06:2025 |
| `DRIFT-RUGPULL` | post-approval schema mutation (fingerprint drift) — synthetic, emitted by the corpus runner | MCP03:2025 |

Rationale for the two judgment calls:

- **Rug pull → MCP03:2025.** The official Tool Poisoning write-up is explicitly
  about tampering with "the contract or schema definitions that govern
  agent-to-tool interactions" — a post-approval descriptor mutation is exactly
  that, so the old standalone MCP-04 "Rug Pull" category folds into it.
- **Exfil split (MCP01 vs MCP06).** Rules whose signal is *secret-targeting*
  (`EXF-SECRET`, `EXF-SSHENV`) are tagged with the risk they realize — secret
  exposure (MCP01:2025). `EXF-URL` (a beacon/exfil endpoint with no
  secret-specific signal) matches OWASP's MCP06 "agent pivots to export data to
  attacker.com" scenario, so it rides with intent-flow subversion.
