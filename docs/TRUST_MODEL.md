# Trust model

> Why should a user or an agent trust Tripwire — the component whose whole job is
> to decide what to trust? This document is the honest answer: what is an actual
> guarantee versus a best-effort signal, what you can verify yourself, what you
> must assume, what the measured evidence says (including the attacks Tripwire
> misses), and where the approach does not help. It expands the README's
> [Trust model, assumptions & limitations](../README.md#trust-model-assumptions--limitations).

## 1. Two tiers of strength — read this first

Tripwire has two capabilities. They are **not** equally strong, and this
document never presents them as if they were.

**Tier 1 — the deterministic guarantee. This is the product.**
Continuous **tool-contract integrity** plus **portable signed attestation**: a
tool your agent approved cannot silently change underneath it, and you hold
cryptographic proof of exactly what was approved.

- It is a hash comparison plus a signature check, not a judgement call.
- **Zero false positives by construction** — it does not guess intent, so it
  cannot mistake an unusual-but-honest descriptor for an attack.
- Verifiable by anyone, offline, with only a public key.
- This is what a static scanner structurally *cannot* do.

**Tier 2 — the descriptor scanner. A coarse first pass, honestly bounded.**
Pattern rules that catch known poisoning shapes at approval time.

- Best-effort. Real false negatives, and historically real false positives.
- Useful as a cheap first filter; **never** presented as a guarantee.
- No novelty claim — static MCP scanners already exist and are cited as
  related work.

So the accurate one-line statement of what Tripwire does is:

> Tripwire **proves** a tool has not changed since you approved it, and **flags**
> known-bad descriptor patterns as a first pass.

Not "Tripwire detects malicious tools". It cannot promise that, and this
document will not imply it.

## 2. The principle: verify, don't trust

Nothing Tripwire asserts has to be taken on faith. Each claim reduces to
something you can recompute or check with public information — but note the
**Strength** column: *reproducible* is not the same as *guaranteed*. Every row
below is reproducible; only the Tier-1 rows are guarantees.

| Tripwire claims… | Strength | You verify it by… | Trust in Tripwire required? |
|---|---|---|---|
| "this tool is unchanged since approval" | **Tier 1 — deterministic guarantee** | recomputing `sha256(canonicalize(tool))` and comparing | **none** |
| "this tool is approved + signed" | **Tier 1 — deterministic guarantee** | verifying the badge signature with the public key (Ed25519) | **none** — offline, math only |
| "this descriptor matches / does not match a known poisoning pattern" | **Tier 2 — best-effort** (no-match ≠ safe) | re-running the deterministic scanner; reading `detection.py` | **none** — same input, same verdict |
| "N/M corpus attacks are blocked" | **regression gate**, not an efficacy claim | running `make eval` against the committed corpus | **none** — reproducible |
| "here is what happened against attacks from published research" | **measurement**, misses included | running `make audit` against `corpus/real_world/attacks.jsonl` | **none** — reproducible |

The verdict is never an LLM judgement. The ADK Scanner / Red-team / Attestor
agents *explain and route*; the allow / block / quarantine decision always comes
from the deterministic engine, so the model layer cannot fabricate a finding.

## 3. Evidence: measured against published attack research

The honest weakness of a curated corpus is that we wrote both the attacks and
the rules that catch them. [`corpus/real_world/attacks.jsonl`](../corpus/real_world/attacks.jsonl)
exists to break that circularity: **9 cases reproduced from published security
research**, each carrying its citation, replayed through the real engine by
`make audit`. The full write-up is
[docs/features/real-world-attack-suite.md](features/real-world-attack-suite.md).

Sources reproduced:

- Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks",
  2025-04-01 — <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
- Invariant Labs, "WhatsApp MCP Exploited" —
  <https://invariantlabs.ai/blog/whatsapp-mcp-exploited>
- MCPTox benchmark, arXiv 2508.14925 — <https://arxiv.org/abs/2508.14925>
- Snyk, malicious `postmark-mcp` npm package, 2025-09 —
  <https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/>

The measured outcome, unrounded:

> **4 blocked · 1 advisory · 3 missed · 1 out-of-scope** (of 9 cases)
> **2 of the 4 blocks come from drift, not scanning.**

### The non-circular case: `rw-09`

`test_drift_catches_what_the_scanner_misses` asserts both halves:

1. `scan_tool()` returns **zero findings** on the mutated descriptor — the
   scanner is *provably blind* here, so this is not the scanner grading its own
   homework; and
2. `evaluate_call()` returns **QUARANTINE** anyway.

An attack that no content rule in this repo can see, stopped by comparing a
fingerprint. That is Tier 1 doing what Tier 2 structurally cannot.

### The misses, and why they stay

Three cases are recorded as `missed`: `rw-02` (shadowing), `rw-08` (silent
forwarding) and `rw-07` (keyword-avoiding exfiltration). They are tracked in
[issue #101](https://github.com/akoita/mcp-tripwire/issues/101) and are
deliberately **not** fixed by pattern-matching those exact strings — that would
convert measured evidence into a memorised answer key.

`rw-04` is **out-of-scope, not missed**: the real `postmark-mcp` compromise
changed the server *implementation* while its published manifest stayed
byte-identical, so no manifest-integrity gate could have caught it. It is
documented and pinned by a test rather than papered over.

### We publish our misses

This is a deliberate stance, not an apology. **A security tool that reports only
its wins cannot be audited.** The real-world suite records false negatives and
an explicit out-of-scope case, and
[`tests/security/test_real_world_attacks.py`](../tests/security/test_real_world_attacks.py)
enforces that those records stay truthful: if detection behaviour changes, the
test fails and the recorded expectation must be re-measured with `make audit`
and updated deliberately.

Keep this distinct from the curated regression gate. `make eval` reporting
**40/40 attacks blocked · 0 false-positive(s) on 12 clean tool(s)** says the
implementation has not regressed against cases we wrote; it is *not* an efficacy
claim about the real threat landscape. The audit above is the efficacy
measurement, and it is a smaller, more interesting number.

## 4. The trust anchor: the signing key

Everything above reduces trust to a single question: **who holds the signing
key, and how did you obtain the verification key?**

- **HMAC-SHA256 (default, zero-deps).** Symmetric shared secret. Anyone with the
  secret can both sign and forge. Fine for local demos and single-tenant use;
  **not** a basis for cross-party trust.
- **Ed25519 (`[signing]` extra).** Asymmetric. The private key signs; the public
  key verifies. A verifier needs only the public key and never contacts Tripwire.
  This is the anchor intended for real deployments.

Trust therefore bottoms out at **key custody** (protect the private key — KMS /
Secret Manager, never `demo-only` in production) and **public-key distribution**
(how a verifier obtains an authentic public key). Tripwire makes trust explicit,
portable, and verifiable; it does not make it free.

## 5. Threat model

### In scope — what Tripwire is designed to stop

The **Tier** column is the load-bearing one: Tier 1 rows hold whenever the
attack touches the manifest surface; Tier 2 rows hold only when a pattern rule
happens to match.

| Class | Tier | OWASP MCP (2025) | How Tripwire addresses it |
|---|---|---|---|
| Rug pull (post-approval schema mutation) | **1 — guarantee** | MCP03:2025 | Fingerprint drift → quarantine on next call **and** on re-list. Any byte-level change flips the fingerprint; intent is never inferred. Empirically: `rw-09`. |
| Undetectable tampering of trust evidence | **1 — guarantee** | — | Signed badge; any change fails verification, offline, with only the public key |
| Tool poisoning (malicious description / instructions) | **2 — best-effort** | MCP03:2025 · findings tagged MCP01:2025 / MCP06:2025 | Blocked at scan time *if a rule matches*; never approved. Misses are real — see `rw-02` / `rw-07` / `rw-08` in §3 |
| Invisible-unicode / homoglyph payloads | **2 — best-effort** | MCP03:2025 | Detected during the manifest scan when the pattern is one the ruleset knows |

The full category-by-category picture — which of the ten Tripwire addresses,
partially addresses, or deliberately leaves out — is in
[OWASP_MCP_COVERAGE.md](OWASP_MCP_COVERAGE.md).

### Out of scope — explicit non-goals

- **Content-level injection** — a tool whose *manifest is clean* but whose
  *runtime output* manipulates the agent. Schema integrity does not inspect
  payloads (and Tripwire deliberately does not log them).
- **A tool that was already malicious at first approval** and slipped past the
  heuristic scanner — drift detection then faithfully pins the bad version.
  **Integrity is not goodness.** This is the structural cost of the Tier-1 /
  Tier-2 split: Tier 1 guarantees *unchanged*, never *benign*.
- **A server whose published manifest never changes while its implementation
  does** — the `postmark-mcp` shape (`rw-04`). No manifest-integrity gate can
  see this; it is recorded as out-of-scope, not as a miss.
- **Compromise of the signing key** — forged badges become indistinguishable.
  This is the anchor; protect it accordingly.
- **A compromised gateway process** tampering in the request path — mitigated by
  a small, auditable, stdlib-only core, but assumed honest.

## 6. Assumptions

Assumptions 1, 2, 4 and 5 are what **Tier 1** needs in order to be a guarantee.
Assumption 3 is the one that carries all of **Tier 2**'s weakness — it is an
assumption we already know to be partly false, and we measure how false.

1. **(Tier 1)** Trust flows through the declared manifest surface. An attack
   that never touches the manifest is invisible to integrity checking by
   construction — see `rw-04`.
2. **(Tier 1)** The first approval is a sound trust decision
   (trust-on-first-use). Integrity pins whatever was approved, good or bad.
3. **(Tier 2 — best-effort, no guarantee)** Detection heuristics cover the
   relevant attack classes; novel payloads may be
   false negatives (no novelty claim on scanning), and the coarse pattern rules
   may also over-fire on novel benign real-world descriptors. Common JSON-Schema
   `$schema` / `$id` URLs and ordinary "fetch" descriptions are now handled, with
   the [Morpho manifest fixture](../corpus/samples/morpho-tools.json) kept as a
   clean regression — a real production manifest of 17 tools that scans
   **clean — 0 findings**. Scanning is best-effort; the deterministic guarantees
   are integrity and provenance. §3 quantifies the gap: 3 of 9 published
   real-world cases are recorded as `missed`.
4. **(Tier 1)** The gateway process is honest and not logging payloads.
5. **(Tier 1)** Tool manifests are intended to be stable between approvals — an
   intentionally dynamic catalog will trip drift by design.

## 7. Where the approach is most / least useful

**Most useful:** long-running agents; multi-tenant or shared tool registries;
audit and compliance ("prove later what was approved"); supply-chain-sensitive
and cross-organisation tool sharing, where portable badges verify without the
issuer in the loop.

**Least useful:** one-shot scripts over a single fixed, already-trusted local
tool; content-level injection that never touches the schema; and intentionally
dynamic tool catalogs (which will trip drift by design).

## 8. Roadmap

- **Key management:** KMS / Secret Manager, rotation windows, transparency-log /
  Sigstore-style anchoring for key distribution.
- **Publisher trust:** bind badges to publisher signatures so *goodness* can be
  asserted by a trusted issuer — closing the trust-on-first-use gap.
- **Beyond schema:** runtime tool-output inspection; policy-as-code approvals.
- **Detection depth:** semantic / model-assisted analysis (deterministic verdict
  still authoritative); community-grown corpus.
- **Operational trust:** badge TTL / expiry, revocation lists, multi-signer /
  quorum attestation.

---

See also: [ADR-0003 — signed attestations](adr/ADR-0003-signed-attestations.md),
[ADR-0005 — two-layer verification](adr/ADR-0005-two-layer-verification.md),
[RFC-0002 — HMAC → Ed25519 signing](rfc/RFC-0002-ed25519-signing.md),
[Real-world attack suite](features/real-world-attack-suite.md) (the evidence in §3),
[Drift quarantine](features/drift-quarantine.md) (the Tier-1 runtime check).
