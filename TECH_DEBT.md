# TECH DEBT

Known shortcuts, each with a payoff trigger. Honesty over polish (Hard Rule #9).

| Item | Why it exists | Payoff trigger |
|---|---|---|
| `proxy.serve()` is a `# STUB(E2)` | guard logic is tested; the stdio bridge is wiring | before any live MCP demo over real transport |
| ADK agents are `# STUB(E3)` skeletons | core works without ADK; agents are the P1 layer | when building the multi-agent video segment |
| HMAC signing (not Ed25519) | zero-dep, deterministic, demo-sufficient | P1, or first real external verifier |
| Injection detection is rule-based | deterministic spine must not flake | add LLM-judge as an *additive* layer (eval) |
| Homoglyph check is script-mixing only | cheap heuristic | if shadowing cases appear in the corpus |
