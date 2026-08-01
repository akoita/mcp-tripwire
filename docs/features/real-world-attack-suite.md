# Real-world attack suite (published-research efficacy audit)

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / operator)

An honest answer to the question a curated corpus can never answer: **"does Tripwire stop attacks that real researchers actually published?"**

[`corpus/real_world/attacks.jsonl`](../../corpus/real_world/attacks.jsonl) reproduces attack descriptors from public security research — Invariant Labs' tool-poisoning and WhatsApp rug-pull notifications, the MCPTox benchmark, Snyk's postmark-mcp supply-chain writeup — and **every case carries its citation** (`source.name`, `source.url`, `source.date`, and a `repro` pointer where one exists). `make audit` runs them through the real engine and prints what actually happened, including the cases Tripwire does **not** catch.

This is deliberately **not** a scoreboard to be maximised. It is evidence, with the negative results left in.

## Audience

- **Judge / reviewer** asking "is this tested against anything other than its own corpus?"
- **Operator** deciding what Tripwire does and does not cover before deploying it.
- **Contributor** who changes a detection rule and needs to see what moved.

## How it works today

```
corpus/real_world/attacks.jsonl  (JSONL — one case per line)
    │   {id, technique, source{name,url,date,repro}, note,
    │    expected_layer, expected_outcome, tool[, mutate_to]}
    ▼
TripwireEngine(signing_key="audit").approve(tool)
    │
    ├── mutate_to absent → BLOCK        → blocked / scanner
    │                      findings only → advisory / scanner
    │                      nothing       → missed / none
    │
    └── mutate_to present → evaluate_call(mutate_to)
                            QUARANTINE  → blocked / drift
                            otherwise   → out_of_scope / none
```

The same classification runs in two places, and they must agree: [`scripts/real_world_audit.py`](../../scripts/real_world_audit.py) (the human-readable report) and [`tests/security/test_real_world_attacks.py`](../../tests/security/test_real_world_attacks.py) (the contract).

### The four outcome classes

| Outcome | Meaning |
|---|---|
| `blocked` | Tripwire stopped it — either the scanner refused approval, or the drift layer quarantined the call. |
| `advisory` | The scanner produced findings but below the block threshold: the operator gets a signal, the call proceeds. |
| `missed` | A false negative. Tripwire *should* plausibly have caught this and did not. Recorded, not hidden. |
| `out_of_scope` | No manifest-integrity gate could have caught it — the published tool descriptor never changed. |

### The headline result: drift catches what the scanner misses

`test_drift_catches_what_the_scanner_misses` asserts **both halves** for case `rw-09`:

1. `scan_tool(case["mutate_to"])` returns **zero findings** — the content scanner is genuinely blind to the payload, so this is not the scanner grading its own homework; and
2. after the benign descriptor is approved, `evaluate_call(mutate_to)` returns `QUARANTINE`.

That is the project's central non-circular piece of evidence: the deterministic, stateful drift layer stops an attack that no content-matching rule in this repo can see, because it compares fingerprints instead of reading intent.

### Misses are the point

Three cases are recorded as `missed`, and the suite exists partly to say so out loud:

- **`rw-02` / `rw-08` — shadowing & silent forwarding.** Instructions that redirect or copy data to a third party, phrased without any exfiltration keyword the ruleset knows.
- **`rw-07` — keyword-avoiding exfiltration.** A paraphrase-resistant variant from the MCPTox threat model.

**Do not "fix" these by tuning detection rules against these specific strings.** That would convert measured evidence into a memorised answer key. They stay until a rule generalises honestly — and if one does, `make audit` will show the movement and the recorded expectation gets updated deliberately.

`rw-04` (postmark-mcp) is `out_of_scope` rather than `missed` for a structural reason: its `tool` and `mutate_to` are byte-identical because the real incident changed the *server implementation*, not the published manifest. Tripwire guards the manifest surface; that limit is documented, not papered over.

## Relationship to `corpus/attacks.jsonl` — two different jobs

| | [`corpus/attacks.jsonl`](../../corpus/attacks.jsonl) (`make eval`) | `corpus/real_world/attacks.jsonl` (`make audit`) |
|---|---|---|
| Purpose | Pass/fail **regression gate** | Real-world **efficacy measurement** |
| Cases | Hand-curated by this project | Reproduced from published research, cited |
| Required result | **100% blocked** — `tripwire ci` fails the build otherwise | Whatever actually happens, misses included |
| Exit code | Non-zero on any survivor | Always 0 — it is a report, not a gate |

They must not be conflated. The eval gate staying at **40/40 attacks blocked · 0 false-positive(s) on 12 clean tool(s)** says the implementation has not regressed. The audit says how much of the published threat landscape that actually covers, which is a smaller and more interesting number.

## Surfaces

| Surface | How to reach it |
|---|---|
| `make audit` | Prints the table (id · technique · layer · outcome · source name + URL) plus the summary counts. Exits 0. |
| `python scripts/real_world_audit.py` | Same, without `make`. Stdlib-only. |
| `pytest tests/security` | The contract: measured outcome must equal the recorded one for all cases. |

## Verification

- Characterization: [`tests/security/test_real_world_attacks.py`](../../tests/security/test_real_world_attacks.py) — one parametrized test per case asserting measured `(outcome, layer)` equals the recorded `expected_outcome`/`expected_layer`. A failure means detection behaviour **changed**, not that the code is broken; the expectation is re-measured with `make audit` and updated deliberately.
- Headline: `test_drift_catches_what_the_scanner_misses` (scanner-blind + drift-quarantined, both asserted).
- Citation integrity: every case must have a non-empty `source.name`, an `https://` `source.url`, and a non-empty `source.date` — no case may claim "real-world" without a checkable source (Hard Rule #6).
- Scope boundary: `test_postmark_supply_chain_change_is_out_of_scope` pins the identical-descriptor limit.
- `tests/security` is in `testpaths`, so this runs inside `make check` and both CI legs.

## Guarantees and limitations

- **Every printed number is measured.** The report computes counts from a live engine run; nothing is transcribed by hand (Hard Rule #6).
- **Small sample.** Nine cases. It demonstrates coverage and gaps; it is not a statistical benchmark.
- **Descriptor-level only.** Cases are tool manifests, not live servers — server-side behaviour changes are structurally invisible (see `rw-04`).
- **Some cases are adaptations.** Where a source published a technique rather than a copy-pasteable descriptor, the `note` field says so explicitly; the `source` still points at the research.
- **Expectations are recorded behaviour, not aspirations.** The suite pins today's reality so a change is always visible; it never asserts what detection *ought* to do.

## Cross-references

- Companions: [attack-corpus-runner.md](attack-corpus-runner.md) (the pass/fail gate), [descriptor-scanning.md](descriptor-scanning.md) (the scanner that misses `rw-07`), [drift-quarantine.md](drift-quarantine.md) (the layer that catches `rw-09`).
- ADR: [docs/adr/ADR-0005-two-layer-verification.md](../adr/ADR-0005-two-layer-verification.md) — why there are two layers at all; this suite is the evidence that the second one earns its place.
