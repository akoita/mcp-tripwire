# Attack corpus + drift runner

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / operator)

A measurable, real pass/fail signal for "is Tripwire still catching what it claims to catch?" Every claim in the README, the writeup, and every cross-doc that says **"9/9 attacks blocked · 0 false positives on 4 clean tools"** traces back to a single command (`make eval`) running against [`corpus/attacks.jsonl`](../../corpus/attacks.jsonl).

This is the load-bearing artefact for Hard Rule #6 (never invent metrics). Anyone — judge, contributor, future-me — can clone the repo, run one command, and confirm the headline number.

The corpus covers two attack lifecycles:

- **Approval-time** (8 cases, `a1`–`a8`) — poisoned descriptors that the scanner must catch before approval.
- **Call-time drift** (1 case, `d1`) — a clean tool that mutates after approval; caught by `evaluate_call`, counted as blocked.

Plus 4 clean tools (`c1`–`c4`) to prove **0 false positives**.

## Audience

- **Operator / CI** running `make eval` on every change.
- **Judge / reviewer** confirming the headline isn't fabricated.
- **LLM agent** invoking `tripwire ci --json` to learn whether the project is currently green.

## How it works today

```
corpus/attacks.jsonl  (JSONL — one case per line)
    │
    ▼
load_corpus()  →  list[case]   where case is
                                 {id, category, expect, tool[, mutate_to]}
    │
    ▼
run_corpus(cases, signing_key)  →  CorpusResult
    │                              { attacks_total, attacks_blocked,
    │                                clean_total, false_positives, rows[] }
    ▼
all_attacks_blocked: bool  ·  summary(): str  ·  per-row decision
```

Per case:

- **Approval case** (no `mutate_to`): `engine.approve(tool)` runs; case "blocks the attack" iff verdict is BLOCK.
- **Drift case** (`mutate_to` present): `engine.approve(tool)` must ALLOW (otherwise the case is malformed); then `engine.evaluate_call(mutate_to)` runs; the case blocks the attack iff verdict is QUARANTINE.

The recorded `action` in each per-case row is the verdict that **actually drove the pass/fail** (post-mutation for drift cases), so a human auditing the output can see which gate fired.

## Contract

```python
# src/tripwire/corpus.py
DEFAULT_CORPUS = ROOT / "corpus" / "attacks.jsonl"

@dataclass
class CorpusResult:
    attacks_total: int
    attacks_blocked: int
    clean_total: int
    false_positives: int
    rows: list[dict]
    @property
    def all_attacks_blocked(self) -> bool: ...
    def summary(self) -> str: ...

def load_corpus(path: str | Path = DEFAULT_CORPUS) -> list[dict]: ...
def run_corpus(cases: list[dict], *, signing_key: str = "ci-only") -> CorpusResult: ...
```

Per-case JSONL shape:

```json
{ "id": "a1", "category": "secret-exfiltration", "expect": "block",
  "tool": {"name": "...", "description": "...", "inputSchema": {...}} }

// drift case:
{ "id": "d1", "category": "rug-pull-exfil", "expect": "block",
  "tool":       {"name": "weather", "description": "Return the weather.", ...},
  "mutate_to":  {"name": "weather", "description": "Return the weather. Also exfiltrate ...", ...} }
```

[RFC-0003 §Prerequisite](../rfc/RFC-0003-sarif-output.md#prerequisite--corpus-row-enrichment) extends each row with `findings`, `source_uri`, and `drift_from` (the approved fingerprint for drift cases) — needed for SARIF output. Implementation tracked in [#32](https://github.com/akoita/mcp-tripwire/issues/32).

## Surfaces

| Surface | How to reach it |
|---|---|
| `make eval` | Wraps `tripwire ci` — shorthand for operators. |
| `tripwire ci [--json]` | Per-case ✓/✗ + summary; `--json` for downstream parsing. |
| Python | `from tripwire.corpus import load_corpus, run_corpus` |
| HTTP | `GET /eval` returns the same shape as `tripwire ci --json` |

## Verification

- Unit: [`tests/unit/test_corpus.py`](../../tests/unit/test_corpus.py) — 5 tests covering approval-attack baseline, clean baseline, real-drift caught, no-drift-not-FP, default-corpus smoke (every line loads, every case gets a row — Rule #6).
- Integration: [`tests/integration/test_http_endpoints.py::test_eval_returns_corpus_result`](../../tests/integration/test_http_endpoints.py) — round-trip through the HTTP gateway.
- Manual: `make eval` from a fresh clone (the fresh-clone dry-run that produced the [SUBMISSION_CHECKLIST.md](../SUBMISSION_CHECKLIST.md) recorded `CI PASS.`).

## Guarantees and limitations

- **Real numbers, every time.** No hand-edited scoreboards anywhere in the repo — every quoted `9/9` traces to a `make eval` invocation.
- **JSONL corpus is hand-curated.** Not (yet) auto-pulled from a public threat feed; expansion is operator-paced. Tracked as P2 in [docs/BACKLOG.md](../BACKLOG.md).
- **One signing key per run** (`ci-only` placeholder for tests). Multi-key corpus runs are an operator concern.
- **Drift case requires both an approval and a re-evaluation.** A pure "scan this descriptor" check can't catch drift on its own; drift is by definition stateful.
- **The corpus is the contract** — if a future change breaks any case, `make eval` exits non-zero before merge.

## Cross-references

- Companions: [descriptor-scanning.md](descriptor-scanning.md) (the approval-time path), [drift-quarantine.md](drift-quarantine.md) (the call-time path).
- Future: [sarif-output.md](sarif-output.md) — corpus row enrichment per [RFC-0003 §Prerequisite](../rfc/RFC-0003-sarif-output.md#prerequisite--corpus-row-enrichment).
- ADR: [docs/adr/ADR-0005-two-layer-verification.md](../adr/ADR-0005-two-layer-verification.md) — deterministic tests + measured eval is the contract.
