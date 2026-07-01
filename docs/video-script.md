# MCP-Tripwire — 5-minute video script

> Hard cap: **5:00**.
> Open with the proof moment in the first 90 seconds. No live coding —
> pre-bake every terminal in a separate window before you hit record.

## Recording setup (do this once, before pressing record)

In a clean shell, with the repo cloned and `make check` already green:

```bash
# Pre-warm uv so the demos don't show package-resolution noise during the take.
make check                          >/dev/null
uv sync --extra dev --extra agent --extra signing >/dev/null
# Tabs you'll switch between:
#   T1 — README on github.com (Mermaid diagram visible)
#   T2 — terminal, prompt clean, ready for `make demo-real-mcp`
#   T3 — terminal, prompt clean, ready for `make demo-proxy`
#   T4 — terminal, prompt clean, ready for `make demo-proxy-sse`
#   T5 — terminal, prompt clean, ready for `make demo-adk`
#   T6 — terminal, prompt clean, ready for `make eval`
#   T7 — VS Code on src/tripwire/proxy.py around the bridge() pump
#   T8 — terminal with `make demo` ALREADY RUN, scrolled to the final
#        "Proof: the signed trust badge breaks on tamper" section
```

Speak from the `Say:` lines verbatim or paraphrase, but **do not skip a Show**.

---

## 0:00 — 0:15 · The hook

**Show:** terminal T2, blank prompt. Title card optional (just text):
`MCP-Tripwire — trust evidence for MCP tools`.

**Say:**
> Agents read tool descriptions and obey them. That's the whole MCP trust
> story. Watch what happens when one of those descriptions is hostile.

---

## 0:15 — 1:05 · Real MCP proof (`make demo-real-mcp`)

**Show:** terminal T2. Type and run:

```bash
make demo-real-mcp
```

**Say:**
> This is not the fake attack fixture. This is Microsoft Playwright MCP,
> started through `npx`, with real browser automation tools. Tripwire sits in
> front, approves and badges the live tool catalog, then lets a real
> `browser_navigate` call reach `example.com`.
>
> The point is adoption: useful MCPs still work. Tripwire is a trust gateway,
> not a demo that only succeeds because the upstream was invented for it.

---

## 1:05 — 1:55 · Security proof moment (`make demo-proxy`)

**Show:** terminal T3. Type and run:

```bash
make demo-proxy
```

Wait for the output. The narrator pauses; let the terminal speak.

```
A) WITHOUT Tripwire: the naive client sees the poisoned tool
  - get_weather
  - summarize_notes (POISONED)
  total tools advertised: 2

B) WITH Tripwire: same upstream, vetted at tools/list
  ✓ get_weather  badge=attached
  approved tools: ['get_weather']  (was 2; proxy stripped 1)

C) Rug pull: upstream mutates after approval; proxy quarantines
  re-list after mutation → approved: []  (clean tool now drifted)
  tools/call → JSON-RPC error -32001: action='quarantine' tool='get_weather'  ✅
```

**Say (while the terminal is on screen):**
> Section A: a naive MCP client sees two tools advertised. The second one's
> description hides an instruction telling the agent to leak a secret.
>
> Section B: same upstream server, but now we sit a Tripwire proxy in
> front. It vets every `tools/list` response — the poisoned tool is
> stripped before the agent ever sees it. The clean tool gets a signed
> trust badge attached.
>
> Section C: the upstream server mutates the clean tool after approval —
> a classic rug pull. On the next `tools/list`, Tripwire spots the drift
> and strips it. If the client tries to call it anyway, the proxy
> short-circuits with a JSON-RPC error carrying full context.

---

## 1:55 — 2:25 · How the bridge does it

**Show:** tab T7 (`src/tripwire/proxy.py`). Scroll to `bridge`, `guard_tools_list`,
or `guard_call`.

**Say:**
> Under the hood: a two-task asyncio pump between the client and the
> upstream server. On every `tools/list` response we refresh a live cache
> and run `guard_tools_list` — known-good tools get re-checked for drift
> via `evaluate_call`; new tools go through full approval.
>
> On every `tools/call` we look up the cached descriptor and re-fingerprint
> it. Any non-`ALLOW` verdict short-circuits with JSON-RPC error `-32001`
> and structured tripwire metadata. The upstream server never sees the
> call. The design is in RFC-0001 in the repo.

---

## 2:25 — 2:50 · Hosted-MCP transport (`make demo-proxy-sse`)

**Show:** terminal T4:

```bash
make demo-proxy-sse
```

**Say:**
> The stdio bridge is the local subprocess path. The fourth demo proves the
> same guard semantics over HTTP plus server-sent events — the transport shape
> hosted MCP servers use. Poisoned tools are stripped, the rug pull is
> quarantined, and the short-circuit is still JSON-RPC error `-32001`.

---

## 2:50 — 3:25 · The ADK layer

**Show:** terminal T5:

```bash
make demo-adk
```

Let it run. The output is three labelled sections — `1) Scanner`,
`2) Red-team`, `3) Attestor`.

**Say:**
> Course Day-4 — multi-agent. Three ADK agents drive the same engine.
> Scanner reads a tool descriptor and explains the OWASP-tagged findings.
> Red-team can hand the operator nine canonical probes from our corpus
> to stress-test the gateway. Attestor mints the signed badge — gated
> by `FunctionTool(require_confirmation=True)`, so the model cannot sign
> a badge on its own, even if it tried.
>
> The LLM is the explainer and router. The verdict always comes from the
> deterministic engine. That split is the whole point: the agent layer
> literally cannot fabricate a finding.

---

## 3:25 — 4:00 · Measured evaluation

**Show:** terminal T6:

```bash
make eval
```

```
9/9 attacks blocked · 0 false-positive(s) on 4 clean tool(s)
  ✓ a1..a8 (8 poisoning categories)
  ✓ c1..c4 (clean tools — no false positives)
  ✓ d1 (rug-pull-exfil) → quarantine
CI PASS.
```

**Say:**
> Real numbers — no invented metrics. Eight poisoning attacks across
> different OWASP categories, four clean tools, and one drift case caught
> by the rug-pull path we just demoed. Nine of nine attacks blocked,
> zero false positives. The corpus runner streams the same numbers to
> JSON for downstream CI — there's no scoreboard in the README that
> doesn't come from this command.

---

## 4:00 — 4:15 · Attestation proof — the badge breaks on tamper

**Show:** tab T8 (`make demo` output, already scrolled to the final section):

```
Proof: the signed trust badge breaks on tamper
  verify(original badge): True (valid) ✅
  verify(tampered badge): False (signature mismatch — badge or payload was tampered with) ✅
```

**Say:**
> One more claim to back: the badges are portable evidence, not decoration.
> Here a signed badge verifies — then we swap a single field, and
> verification fails with a signature mismatch. Anyone holding the key —
> or the Ed25519 public key — can check a badge without ever calling
> Tripwire. That's the attestation half of the story.

---

## 4:15 — 4:40 · The harness story

**Show:** tab T1 (README on github.com). Scroll the hero block, then open
`docs/features/README.md` — the feature catalog, one verified page per
capability.

**Say:**
> This is a Kaggle Freestyle entry, but the engineering discipline matters
> as much as the product. Hard rules in `AGENTS.md` are machine-enforced:
> the deterministic core stays stdlib-only, no secrets ever land in code,
> demos are canary-only, every commit goes through a feature branch and
> a PR — there's a local pre-commit hook that refuses commits to `main`.
>
> Two-layer eval per the course Day-4 convention: deterministic pytest
> for code correctness, plus a measured attack corpus for behavioural
> evaluation. The repo is public, the latest `main` CI and security checks
> are green, and every claim in the README has a backing PR on `main` and a
> test.

---

## 4:40 — 5:00 · Close

**Show:** title card or the README hero block.

**Say:**
> Three commands to reproduce the useful path: `git clone`, `make check`,
> `make demo-real-mcp`. Add `make demo-proxy` for the canary attack proof and
> `make eval` for the scoreboard. Repo at github.com slash akoita slash
> mcp-tripwire. Thanks for watching.

---

## Cuts to have ready if you run long

- **Drop the `bridge()` source walk** (1:55–2:25) — the feature catalog
  (`docs/features/stdio-mcp-proxy.md`) covers the same ground.
- **Skip `make demo-proxy-sse` live** and point at its feature-catalog page
  instead — useful if the terminal output eats time.
- **Replace `make demo-adk` with `make demo`** — engine A/B is faster to
  narrate than the multi-agent run (and T8 already shows its tail).
- **Skip the harness story** (4:15–4:40) — judges who care can read
  `AGENTS.md`.
- **Compress the tamper proof** (4:00–4:15) into one narrated sentence over
  the eval beat — keep the claim, drop the tab switch. Buys ~15 seconds;
  prefer any other cut first, since this is the only on-screen proof of the
  attestation half of the pitch.

Each full cut buys ~45 seconds. Recoverable target is 3:30 if needed.

## Pre-flight checklist

- [ ] `make check` green on the recording machine.
- [ ] `make demo-real-mcp` runs. If the browser is missing, run `npx -y @playwright/mcp@latest install-browser chrome-for-testing`.
- [ ] `make demo-proxy` runs in <5 seconds, output identical to the script.
- [ ] `make demo-proxy-sse` runs (needs `[agent]` extra).
- [ ] `make demo-adk` runs (needs `[agent]` extra).
- [ ] `make eval` reports `9/9 attacks blocked · 0 false-positive(s)`.
- [ ] `make demo` run in T8 and scrolled to the tamper-proof section.
- [ ] Recording resolution ≥ 1080p; terminal font ≥ 14pt so text is readable.
- [ ] Audio normalised; no background noise.
- [ ] No real credentials in any window, even off-screen tabs.
- [ ] Final cut is **under 5:00**.
- [ ] Hosted somewhere stable (YouTube unlisted is fine); link added to
      `docs/writeup.md` before submitting #13.
