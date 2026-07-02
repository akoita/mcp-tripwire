# Runbook: the quick live proof-moment demo

For giving the demo **live, in person** (a meetup, a review, a judge Q&A) in
under three minutes with zero setup risk. The full recorded-video script —
beats, narration, timings, tabs — is
[`docs/video-script.md`](../video-script.md); this page is the minimal
in-person version. Everything is deterministic and uses a clearly-labelled
**canary** secret + a local fake sink (never real credentials).

## Run it

```bash
make demo      # the A/B + rug-pull + badge-tamper sequence
make eval      # tripwire ci → "9/9 attacks blocked · 0 false positives"
make check     # lint + test + guardrails all green (run beforehand)
```

`make demo` alone carries the whole argument: a compromised agent leaks the
canary WITHOUT Tripwire, the poisoned tool is refused WITH it, an approved
tool that mutates gets quarantined, and the signed badge breaks the moment
one byte is tampered.

## Safety call-outs (say these out loud — Hard Rule #4)

- "This is a labelled canary, not a real credential."
- "The sink is local and in-memory — nothing leaves this machine."

## Fallback

If anything is slow live, play a pre-recorded clip of `make demo` — the
output is deterministic and won't flake. For the richer surfaces (real
Playwright MCP, live Gemini-driven agents), use the
[real-world demo](real-world-agent-demo.md) and the
[ADK live playground](adk-live-playground-demo.md) runbooks.
