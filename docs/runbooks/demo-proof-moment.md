# Runbook: the 5-minute proof-moment demo

This is the video script and the live-demo checklist. Everything is deterministic and uses a
clearly-labelled **canary** secret + a local fake sink (never real credentials).

## Run it
```bash
make demo      # the A/B + rug-pull + tamper sequence
make eval      # tripwire ci → "N/M attacks blocked"
make check     # lint + test + guardrails all green
```

## Beats (≈5 min)
1. **The problem (45s)** — agents trust MCP tool manifests blindly; poisoning + rug pulls.
2. **A/B — the wow (90s)** — WITHOUT Tripwire a compromised agent leaks the canary to the fake
   sink; WITH Tripwire the poisoned tool is refused at approval → no leak. Say "canary secret."
3. **Rug pull (45s)** — approve a clean tool, mutate it, watch the next call get **quarantined**.
4. **Proof (45s)** — show the signed badge verify, then **tamper one byte → verification fails**.
5. **The build (60s)** — `make check` green; multi-convention harness (AGENTS.md → CLAUDE/GEMINI);
   findings mapped to OWASP MCP Top 10; honest Related Work (we don't claim "first scanner").

## Safety call-outs (say these on camera)
- "This is a labelled canary, not a real credential."
- "The sink is local and in-memory — nothing leaves this machine."

## Fallback
If anything is slow live, play pre-recorded clips of `make demo` (deterministic output, won't flake).
