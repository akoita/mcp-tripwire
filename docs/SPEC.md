# MCP-Tripwire — Product Spec (PRD)

**Status:** Living document · **Owner:** Aboubakar Koïta
**One-liner:** *A tool your agent already approved can change underneath it. MCP-Tripwire makes that impossible to do silently — and hands you portable, signed proof of exactly what was trusted. Descriptor scanning rides along as a best-effort first pass.*

## Problem Statement
Agents increasingly call external tools via MCP servers, and a tool's manifest is trusted implicitly — once, at approval time, and then never again. That leaves the load-bearing gap: **an already-approved tool can silently mutate after approval** (rug pull), and nothing in the protocol tells the agent. A second, softer problem sits alongside it: a malicious description can hijack the agent at approval time (tool poisoning).

These two problems are **not** equally tractable, and Tripwire does not pretend they are:

- **Contract integrity is decidable.** "Is this tool byte-for-byte what you approved, and can you prove what you approved?" is a hash comparison plus a signature check. It is deterministic, has zero false positives by construction, is verifiable offline by anyone holding a public key, and is structurally out of reach for a one-shot static scan.
- **Intent is not decidable.** "Is this description malicious?" is a judgement call. Pattern rules catch known shapes and miss unknown ones; we treat them as a cheap first filter, never as a guarantee.

The space already includes static scanners (Invariant mcp-scan, Snyk agent-scan), runtime gateways (Prompt Security MCP Gateway), and a shared taxonomy (OWASP MCP Top 10) — so we do **not** claim others "only scan once," and we claim no novelty for descriptor scanning at all. Tripwire's niche is narrower and sharper: **a lightweight, open trust gateway focused on continuous tool-contract integrity plus portable, cryptographically verifiable attestations** that travel with the tool and break on tamper — the verifiable-evidence angle others don't center.

## Goals
1. **Guarantee tool-contract integrity at runtime — the primary claim.** Fingerprint each approved tool's full schema and re-verify on every call and every re-list; any post-approval mutation is quarantined with a visible diff. A hash comparison, not an opinion: deterministic, **zero false positives by construction**, and independent of whether any rule can read the payload.
2. **Produce verifiable trust evidence** — a signed attestation per approved tool whose signature breaks on any tamper, verifiable offline with only the public key (Ed25519) and no callback to Tripwire. Together with (1) this is the product: *a tool your agent approved cannot silently change, and you hold cryptographic proof of exactly what was approved.*
3. **Flag known-bad descriptor patterns as a bounded best-effort first pass** — scan manifests/descriptions at approval and refuse high-severity findings. Explicitly *best-effort*: it guesses at intent, it has real false negatives (three are published, below), it is never presented as a guarantee, and it is never the headline number. No novelty claim — static MCP scanners already exist and are cited above as related work.
4. **Prove it works, measurably — including where it fails.** Three distinct kinds of evidence, never conflated:
   - *Independent efficacy audit* — [`corpus/real_world/attacks.jsonl`](../corpus/real_world/attacks.jsonl) reproduces 9 attacks from **published security research**, each carrying its citation; `make audit` runs them through the real engine and reports **4 blocked · 1 advisory · 3 missed · 1 out-of-scope**, with **2 of the 4 blocks coming from drift, not scanning**. The headline, non-circular case is `rw-09`: `scan_tool()` returns **zero findings** on the mutated descriptor — the scanner is *provably blind* — and `evaluate_call()` returns **QUARANTINE** anyway. An attack no content rule in this repo can see, stopped by comparing a fingerprint. Details: [docs/features/real-world-attack-suite.md](features/real-world-attack-suite.md).
   - *Regression gate* — `tripwire ci` reports **N/M attacks blocked** on the hand-curated bundled corpus and fails the build on any survivor. This is a **regression gate, not an efficacy claim**, and must never be quoted as one.
   - *Proof moment* — an A/B where an agent exfiltrates a labeled **canary** secret without Tripwire and is blocked with it.

   All numbers are measured, never invented (Hard Rule #6).
5. **Publish the misses.** A security tool that reports only its wins cannot be audited. The real-world suite records its false negatives (`rw-02` shadowing, `rw-08` silent forwarding, `rw-07` keyword-avoiding exfiltration — tracked in [#101](https://github.com/akoita/mcp-tripwire/issues/101) and deliberately *not* fixed by pattern-matching those exact strings) and one explicit out-of-scope case (`rw-04`, the real postmark-mcp compromise: the server *implementation* changed while its published manifest stayed byte-identical, so no manifest-integrity gate could catch it). Tests enforce that those records stay truthful.
6. **Be verifiable rather than trusted** — deterministic verdicts (never an LLM opinion), reproducible fingerprints, and headline numbers that re-derive on the user's machine.
7. **Reach production usefulness** — installable, deployable, and runnable in front of a real team's MCP servers with a clear operator path.

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
- *Leading:* **no regression** on the curated gate (0 survivors on `corpus/attacks.jsonl` — a regression gate, not an efficacy target); **movement on the real-world audit**, where the honest number today is 4 blocked / 1 advisory / 3 missed / 1 out-of-scope, improved only by rules that *generalise* — never by pattern-matching the recorded cases; setup-to-first-badge < 5 min; zero false-block on a clean reference server (the Morpho fixture stays at 0 findings); CI runs the full extras-gated suite.
- *Lagging:* adoption (installs / stars); Tripwire integrated into a real agent's CI; a real team running it in front of production MCP servers.

## Open Questions
- **[Eng]** Multi-upstream policy format — YAML policy-as-code shape and precedence rules (v0.3 design).
- **[Eng]** Packaging & distribution — publish to PyPI + a hosted image for the "plug me in" path.
- **[Product]** First-user profile — which friendly team / workload makes the sharpest v1.0 validation.

## Timeline & sequencing
See [ROADMAP.md](ROADMAP.md) for the current "Now → v0.3 → v1.0" ordering and the live issue tracker for in-flight work.
