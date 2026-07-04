# TECH DEBT

Known shortcuts, each with a payoff trigger. Honesty over polish (Hard Rule #9).

## Current debt

| Item | Why it exists | Payoff trigger |
|---|---|---|
| Injection detection is rule-based | the deterministic spine must not flake; a rule that fires is reproducible and auditable | add an LLM-judge as an *additive* eval layer, never load-bearing — tracked in [#63](https://github.com/akoita/mcp-tripwire/issues/63) |
| Homoglyph / mixed-script check runs on tool **names** only | cheap heuristic; names are the classic shadowing vector | extend the same check to descriptions — tracked in [#65](https://github.com/akoita/mcp-tripwire/issues/65) |

That's the honest remaining list. Everything the deterministic core *claims* to do, it does — see the [feature catalog](features/README.md) for the file-by-file map.

## Resolved

Kept for the record — these were real shortcuts that have since shipped in full.

| Item | Resolved by | Notes |
|---|---|---|
| `proxy.serve()` was a `# STUB(E2)` | [RFC-0001](rfc/RFC-0001-e2-stdio-proxy-bridge.md) (stdio) + [RFC-0004](rfc/RFC-0004-http-sse-proxy-transport.md) (HTTP/SSE) | `StdioTripwireProxy.serve()` and `SseTripwireProxy` are implemented and integration-tested; no stub markers remain in `proxy.py`. |
| ADK agents were `# STUB(E3)` skeletons | v0.1 ADK wiring | Scanner / Red-team / Attestor + coordinator are real in `src/tripwire/agents/` and `app/agent.py`; the LLM explains, the deterministic engine decides. |
| HMAC signing only (no asymmetric) | [RFC-0002](rfc/RFC-0002-ed25519-signing.md) | Ed25519 ships in `src/tripwire/signing/ed25519_backend.py` behind the `[signing]` extra; **HMAC intentionally remains the zero-deps default**, not debt. |
