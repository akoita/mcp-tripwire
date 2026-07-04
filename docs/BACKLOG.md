# BACKLOG

Prioritised work not yet scheduled. The live, authoritative queue is the
[GitHub issue tracker](https://github.com/akoita/mcp-tripwire/issues); this file is the
themed summary. P0 = do next · P1 = strongly targeted · P2 = design-for.

## P0 — hardening the shipped surface
- [ ] CI runs the full extras-gated suite (Ed25519 / SSE / HTTP-gateway / ADK) — [#60](https://github.com/akoita/mcp-tripwire/issues/60).
- [ ] Coverage reporting in CI — [#66](https://github.com/akoita/mcp-tripwire/issues/66).
- [ ] Per-rule detection test matrix (one positive + one negative per rule) — [#61](https://github.com/akoita/mcp-tripwire/issues/61).
- [ ] Proxy error-path tests (bridge pump, malformed frames, reconnect) — [#62](https://github.com/akoita/mcp-tripwire/issues/62).
- [ ] Refresh stale `TECH_DEBT.md` — shipped features still listed as stubs — [#59](https://github.com/akoita/mcp-tripwire/issues/59).

## P1 — depth & breadth
- [x] Grow the attack corpus to 50+ data-driven cases — [#64](https://github.com/akoita/mcp-tripwire/issues/64).
- [ ] Extend homoglyph / mixed-script detection from names to descriptions — [#65](https://github.com/akoita/mcp-tripwire/issues/65).
- [ ] Wire the LLM-judge `explanation_quality` eval metric into the harness — [#63](https://github.com/akoita/mcp-tripwire/issues/63).
- [ ] Release automation (changelog + tag flow) and stale-branch pruning — [#67](https://github.com/akoita/mcp-tripwire/issues/67).
- [ ] Cloud Run deploy (or a clearly-documented local-Docker fallback) — [#9](https://github.com/akoita/mcp-tripwire/issues/9).

## P2 — future (design-for, don't build yet)
- [ ] v0.3 multi-upstream: one proxy fronting N servers + central tool registry + policy-as-code.
- [ ] Observability beyond stderr (Cloud Logging / queryable audit store).
- [ ] Publish to PyPI + a hosted image for the "plug me in" path (v1.0).
- [ ] Ledger-anchored attestations (sigstore / Rekor) — gated on real user pull.
- [ ] Multi-framework support (LangChain, Cursor, raw tools) — gated on real user pull.
