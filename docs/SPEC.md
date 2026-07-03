# MCP-Tripwire — Product Spec (PRD)

**Status:** Living document · **Owner:** Aboubakar Koïta
**One-liner:** *A lightweight OSS trust gateway for MCP tools — continuous schema-integrity enforcement plus portable, cryptographically signed attestations.*

## Problem Statement
Agents increasingly call external tools via MCP servers, but a tool's manifest is trusted implicitly: a malicious description can hijack the agent (tool poisoning), and an already-approved tool can silently mutate after approval (rug pull). The space already includes static scanners (Invariant mcp-scan, Snyk agent-scan), runtime gateways (Prompt Security MCP Gateway), and a shared taxonomy (OWASP MCP Top 10) — so we do **not** claim others "only scan once." Tripwire's niche is narrower and sharper: **a lightweight, open trust gateway focused on continuous schema-integrity enforcement plus portable, cryptographically verifiable attestations** that travel with the tool and break on tamper — the verifiable-evidence angle others don't center.

## Goals
1. **Catch the two headline MCP threats at runtime** — tool-poisoning at approval and rug-pull (schema drift) mid-session — with a visible block/quarantine.
2. **Produce verifiable trust evidence** — a signed attestation per approved tool whose signature breaks on any tamper, verifiable offline with only the public key (Ed25519) and no callback to Tripwire.
3. **Prove it works, measurably** — an A/B where an agent exfiltrates a labeled **canary** secret without Tripwire and is blocked with it; `tripwire ci` reports **N/M attacks blocked** on the bundled corpus (real measured numbers, never invented ones).
4. **Be verifiable rather than trusted** — deterministic verdicts (never an LLM opinion), reproducible fingerprints, and headline numbers that re-derive on the user's machine.
5. **Reach production usefulness** — installable, deployable, and runnable in front of a real team's MCP servers with a clear operator path.

## Non-Goals (and why)
- **Out-feature the incumbents (Invariant/mcp-scan, etc.)** — breadth is not the wedge; verifiable trust evidence is. We make no novelty claim on scanning.
- **A complete commercial MCP gateway** — scope explosion; this is a sharp OSS primitive that stays plumbing, not a platform.
- **Perfect injection classification** — the deterministic core (hashing, drift, allowlist) is the load-bearing spine; the LLM classifier is one additive layer, not the claim.
- **Non-MCP agent surfaces (raw function tools, other protocols)** — keeps the primitive crisp; architectural hooks left for later.
- **Ledger-anchored attestations** — offline signing is right-sized; anchoring stays "vision" until a real user needs it.

## User Stories

**Agent developer (primary)**
- As an agent developer, I want every MCP tool call screened against an approved, fingerprinted baseline so a poisoned or mutated tool is blocked before my agent acts on it.
- As an agent developer, I want a signed trust badge for each approved tool so I can prove to a teammate/auditor that what ran is what was reviewed.
- As an agent developer, I want a CI command that red-teams my MCP server and fails the build if attacks survive, so regressions can't ship.

**Security / platform lead (secondary)**
- As a platform lead, I want each finding mapped to OWASP MCP Top 10 so I can communicate risk in a recognized taxonomy.
- As a platform lead, I want findings in SARIF so they land in GitHub Code Scanning / GitLab SAST with zero integration code.
- As a platform lead, I want tamper-evident audit evidence so a post-incident review can prove what the agent was allowed to do and why.

## Requirements

### Core (shipped)
1. **Transparent MCP proxy** — sits in front of the MCP server (stdio and HTTP/SSE transports), intercepts every tool call, enforces allow / block / quarantine before execution.
2. **Schema fingerprint + drift detection (rug-pull)** — hash each tool's full schema at approval; re-verify on every call and every re-list; quarantine on mismatch and surface the diff.
3. **Tool-poisoning / injection detection** — scan manifests/descriptions for injection markers at approval; refuse to approve on high-severity findings.
4. **Signed trust attestation (the wedge)** — issue a signed badge per approved tool; verification fails on any tamper and names the broken element. HMAC default; Ed25519 (public-key, offline-verifiable) behind the `[signing]` extra.
5. **`tripwire ci` + attack corpus** — run an MCPTox-style corpus; output **N/M attacks blocked** (real numbers) and exit non-zero if any survive.
6. **SARIF output** — `scan`/`ci --sarif` and HTTP content-negotiation, so findings flow into existing SAST pipelines.
7. **The proof-moment demo (A/B)** — same agent + poisoned server: a labeled **canary** secret is exfiltrated to a **local fake sink** without Tripwire and **blocked** with it. Never touches real `~/.ssh`, environment, or credential material.
8. **OWASP MCP Top 10 mapping** on every finding.

### Extended (shipped)
- **ADK multi-agent layer** — Scanner, Red-team, Attestor agents drive the loop; the LLM explains, the deterministic engine decides.
- **HTTP gateway + local Docker deploy**; Cloud Run staged.
- **Real-upstream proof** — Tripwire fronts Microsoft Playwright MCP end-to-end.

### Future (design-for, not yet built)
- Multi-upstream: one proxy fronting N servers + central tool registry + per-tool policy-as-code (v0.3).
- Observability beyond stderr (Cloud Logging / queryable audit store).
- Ledger-anchored attestations; multi-framework support beyond MCP; hosted control plane — all gated on real external pull.

## Success Metrics
- *Leading:* attack-survival rate driven to 0/N on the corpus; setup-to-first-badge < 5 min; zero false-block on a clean reference server; CI runs the full extras-gated suite.
- *Lagging:* adoption (installs / stars); Tripwire integrated into a real agent's CI; a real team running it in front of production MCP servers.

## Open Questions
- **[Eng]** Multi-upstream policy format — YAML policy-as-code shape and precedence rules (v0.3 design).
- **[Eng]** Packaging & distribution — publish to PyPI + a hosted image for the "plug me in" path.
- **[Product]** First-user profile — which friendly team / workload makes the sharpest v1.0 validation.

## Timeline & sequencing
See [ROADMAP.md](ROADMAP.md) for the current "Now → v0.3 → v1.0" ordering and the live issue tracker for in-flight work.
