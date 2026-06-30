# Trust model

> Why should a user or an agent trust Tripwire — the component whose whole job is
> to decide what to trust? This document is the honest answer: what you can
> verify yourself, what you must assume, where the approach helps, and where it
> does not. It expands the README's
> [Trust model, assumptions & limitations](../README.md#trust-model-assumptions--limitations).

## 1. The principle: verify, don't trust

Nothing Tripwire asserts has to be taken on faith. Each claim reduces to
something you can recompute or check with public information:

| Tripwire claims… | You verify it by… | Trust in Tripwire required? |
|---|---|---|
| "this tool is approved + signed" | verifying the badge signature with the public key (Ed25519) | **none** — offline, math only |
| "this tool is unchanged since approval" | recomputing `sha256(canonicalize(tool))` and comparing | **none** |
| "this manifest is clean / poisoned" | re-running the deterministic scanner; reading `detection.py` | **none** — same input, same verdict |
| "N/M attacks are blocked" | running `make eval` against the committed corpus | **none** — reproducible |

The verdict is never an LLM judgement. The ADK Scanner / Red-team / Attestor
agents *explain and route*; the allow / block / quarantine decision always comes
from the deterministic engine, so the model layer cannot fabricate a finding.

## 2. The trust anchor: the signing key

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

## 3. Threat model

### In scope — what Tripwire is designed to stop

| Class | OWASP MCP | How Tripwire addresses it |
|---|---|---|
| Tool poisoning (malicious description / instructions) | MCP-02 / MCP-06 | Blocked at scan time; never approved |
| Rug pull (post-approval schema mutation) | MCP-04 | Fingerprint drift → quarantine on next call **and** on re-list |
| Invisible-unicode / homoglyph payloads | MCP-02 | Detected during the manifest scan |
| Undetectable tampering of trust evidence | — | Signed badge; any change fails verification |

### Out of scope — explicit non-goals

- **Content-level injection** — a tool whose *manifest is clean* but whose
  *runtime output* manipulates the agent. Schema integrity does not inspect
  payloads (and Tripwire deliberately does not log them).
- **A tool that was already malicious at first approval** and slipped past the
  heuristic scanner — drift detection then faithfully pins the bad version.
  Integrity is not goodness.
- **Compromise of the signing key** — forged badges become indistinguishable.
  This is the anchor; protect it accordingly.
- **A compromised gateway process** tampering in the request path — mitigated by
  a small, auditable, stdlib-only core, but assumed honest.

## 4. Assumptions

1. Trust flows through the declared manifest surface.
2. The first approval is a sound trust decision (trust-on-first-use).
3. Detection heuristics cover the relevant attack classes; novel payloads may be
   false negatives (no novelty claim on scanning).
4. The gateway process is honest and not logging payloads.
5. Tool manifests are intended to be stable between approvals.

## 5. Where the approach is most / least useful

**Most useful:** long-running agents; multi-tenant or shared tool registries;
audit and compliance ("prove later what was approved"); supply-chain-sensitive
and cross-organisation tool sharing, where portable badges verify without the
issuer in the loop.

**Least useful:** one-shot scripts over a single fixed, already-trusted local
tool; content-level injection that never touches the schema; and intentionally
dynamic tool catalogs (which will trip drift by design).

## 6. Roadmap

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
[RFC-0002 — HMAC → Ed25519 signing](rfc/RFC-0002-ed25519-signing.md).
