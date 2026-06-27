# MCP-Tripwire — Capstone Roadmap

**Goal:** Ship a winning Kaggle AI Agents capstone (Freestyle track) by **Jul 6, 2026, 11:59 PM PT**.
**Today:** Jun 27, 2026 · **Builder:** solo · **One-liner:** *"Can this agent keep trusting this tool during execution — and can I prove it?"*

## Status Overview
- **Done:** 1 epic (tested core + POC)
- **Now:** 1 epic in progress (proof-moment spine)
- **Remaining:** 8 epics across 9 days
- **At risk:** ADK integration, Cloud Run deploy (both have fallbacks)

## Deliverables (all required to be a valid submission)
1. Public GitHub repo + README w/ setup — **Not Started**
2. 5-min YouTube video + cover image — **Not Started**
3. ≤2,500-word Kaggle Writeup, Freestyle track — **Not Started**
4. Public project link (repo or live demo) — **Not Started**
5. ≥3 of 6 course concepts — 4 without ADK (MCP server, security, deployability, agents-cli); 5 with ADK (P1) — **On Track**

## Timeline

### NOW — the spine (Jun 27–28, Sat–Sun)
| Item | Detail | Status |
|---|---|---|
| E1 Core | detection / engine / attestation, 11 tests | **Done** |
| E2 Transparent MCP proxy (stdio) | Spawn MCP server as subprocess; intercept tool calls; enforce allow/block/quarantine | **In Progress** |
| E4a Demo scenarios | Hand-rolled vulnerable MCP server + poisoned tool + rug-pull + **labeled canary secret → local fake sink** | Not Started |
| **🎯 Milestone** | **Proof moment runs end-to-end (poison blocked, rug-pull caught, signed badge breaks on tamper)** | — |

### NEXT — depth + the win condition (Jun 29 – Jul 2)
| Item | Detail | Target | Status |
|---|---|---|---|
| E3 ADK multi-agent (top-priority P1) | Scanner / Red-team / Attestor agents on the core; descope only if ADK integration fights | Jun 29–30 | Not Started |
| E4b A/B proof | Agent exfiltrates a **labeled canary** secret to a local fake sink WITHOUT Tripwire → blocked WITH it; `tripwire ci` reports **N/M attacks blocked** + small MCPTox-style corpus | Jul 1 | Not Started |
| E7a OWASP map | Map every finding to OWASP MCP Top 10 (cheap credibility) | Jul 1 | Not Started |
| E6 Deploy | Cloud Run + agents-cli packaging (timeboxed) | Jul 2 | Not Started |
| E5 Signing | Ed25519/sigstore upgrade from HMAC (if time) | Jul 2 | Not Started |
| **🎯 Milestone** | **Feature-complete + CODE FREEZE (EOD Jul 2)** | — | — |

### LATER — tell the story (Jul 3–6)
| Item | Detail | Target | Status |
|---|---|---|---|
| E7b README | Related-Work/wedge framing, architecture diagram, setup | Jul 3 | Not Started |
| E8 Video | Record + edit 5-min demo; cover image | Jul 3–4 | Not Started |
| E9 Writeup | ≤2,500 words; submit to Freestyle | Jul 4 | Not Started |
| E10 Submit | Repo public, links verified, video on YouTube, dry-run | Jul 5 | Not Started |
| Buffer | Pure contingency — no planned work | Jul 6 | Not Started |
| **🎯 Milestone** | **Submit early (Jul 5); Jul 6 = contingency only** | — | — |

## Risks & Dependencies
| Risk | Impact | Mitigation |
|---|---|---|
| ADK integration friction | Could eat 1–2 days | Core works without ADK; ADK is a layer. If it fights, demo still stands on core+proxy (graceful degradation). |
| Cloud Run deploy slips | 1 day | Deployment NOT required for judging → fall back to documented local run. |
| Video/writeup underestimated (30% of score) | Lose easy points | Reserved 1.5 days + buffer; treat as first-class, not afterthought. |
| Live demo flakiness | Bad video | Deterministic core can't flake; pre-record fallback clips. |
| Solo single-point-of-failure (life/illness) | Total | Jul 5–6 buffer absorbs; submit early. |
| Scope creep (out-feature Invariant) | Time sink | Explicit WON'T list below. |

## Scope discipline (MoSCoW)
- **Must:** E2 proxy, E4 proof moment (+ signed badge), `tripwire ci`, README, video, writeup, public repo. *(No ADK dependency — this is the minimum valid, winnable submission.)*
- **Should:** E3 ADK multi-agent (highest priority — build right after the spine), Cloud Run deploy, OWASP mapping.
- **Could:** Ed25519 upgrade, fuller MCPTox corpus, CI badge polish.
- **Won't (this round):** out-feature Invariant/mcp-scan, ledger anchoring, multi-framework support.

## Capacity note
Solo, ~9 days. Roadmap is zero-sum against capacity: **every added feature comes off the buffer.** Priority is a *complete, well-told* submission over an over-built, rushed one. The proof-moment demo is the single highest-leverage asset — it drives both the 70% technical score and the video.
