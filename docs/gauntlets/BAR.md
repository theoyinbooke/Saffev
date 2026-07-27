# The Bar — competitive references and Saffev's standing

Research snapshot: **July 2026**. Vendor-reported precision/latency numbers
(Lakera 98%, Nightfall 95%) are marketing claims, not independent measurements.
Field notes: ClickHouse acquired Langfuse (Jan 2026); Helicone is in maintenance
mode (Mintlify, Mar 2026); Lakera is part of Check Point; Prompt Security is part
of SentinelOne; Protect AI is Palo Alto Prisma AIRS.

Verdicts: ✅ at/above bar · 🟡 partial · ❌ gap · 🚫 deliberately out of scope.

## 1. Where Saffev is alone (the moat — defend and deepen)

Validated across three research sweeps: **nobody** — open or closed source — does
these today:

| Unique capability | Nearest attempt | Saffev status |
|---|---|---|
| On-device, per-app attributed live view of local LLM traffic | LM Studio logs raw requests with **no client attribution** (its bug tracker #567 even mislabels models); Ollama has journald only | ✅ shipping (PID attribution w/ confidence levels) |
| Unified timeline of proxy traffic **+** coding-agent sessions | ccusage unifies cost aggregates only; SpecStory unifies capture only; Prompt Security splits IDE/browser into a cloud console | ✅ shipping (Timeline page) |
| Tamper-evident local archive of AI activity | All competitor "archives" are mutable Markdown/HTML; WitnessAI/Nightfall keep audit records in *their* cloud | ✅ shipping (SHA-256 chain, deletion detection) |
| At-rest encryption **by default** for the trace store | Every self-hosted OSS tool stores prompts in plaintext Postgres/ClickHouse | ✅ shipping (SQLCipher + OS keyring) |
| Zero telemetry | Only OpenLLMetry matches; self-hosted Langfuse/Opik phone home unless disabled | ✅ shipping |
| PII/secret scanning of local agent session histories | Nobody scans `~/.claude` etc. transcripts (a real risk — SpecStory Cloud syncs them raw) | 🟡 partial (`/api/agents/privacy`, archive redaction) — deepen in G1/G5 |
| On-device DLP over local engine traffic | All 8 commercial DLP vendors watch **cloud** AI only; zero air-gapped offering exists | ✅ unique position; entity breadth is the gap (G1) |

## 2. Capability bars and verdicts

### Privacy / detection

| Capability | Bar-setter | The bar, concretely | Saffev | Verdict |
|---|---|---|---|---|
| PII entity breadth (open) | **Presidio** | ~100+ entity types; 19 country packs; medical entities; regex + checksum + NER + context scoring | 6 kinds: email, phone, card (Luhn), API key (prefix+entropy), IP, custom regex | ❌ **G1** |
| PII/secrets breadth (commercial) | **Nightfall** | 100+ ML detectors incl. PHI code sets, API/crypto keys, image detection, prompt-defined custom detectors | No private-key blocks, JWTs, connection strings, national IDs, IBAN, MAC, crypto wallets | ❌ **G1** |
| Detection measurement | ClickBench-style discipline | Scored precision/recall on a fixed public corpus | **No corpus, no scoring harness — cannot currently measure any detection claim** | ❌ **G1 first loop** |
| Prompt-attack detection | **Lakera** | 98%+ injection detection claim, <50ms, 100+ languages | DeterministicGuard (8 categories) shipped; ModelGuard scaffold unused | 🟡 **G7** |
| Redaction UX | **Harmonic** | Pre-paste nudges, plain-language policies, steer-don't-block | Observe/dry-run/mask modes, stream-aware masking, team policy TOML | 🟡 (posture aligned; coaching UX absent) |
| Compliance reporting | **Nightfall** | Named SOC 2 / HIPAA / GDPR framework pages + violation reports | None — findings shown in Studio only | ❌ **G4** |

### Session analytics / preservation

| Capability | Bar-setter | The bar, concretely | Saffev | Verdict |
|---|---|---|---|---|
| Multi-tool local coverage | **ccusage** | 15 agent CLIs parsed from local files | 5 adapters: Claude Code, Codex, Cursor, VS Code, OpenCode | ❌ **G2** |
| Cost/billing modeling | **ccusage** | Model-specific pricing, cache-token accounting, 5-hour billing-block reports, plan modes | Token counts + tiktoken estimation; no per-model $ pricing, no cache tokens, no billing blocks | ❌ **G3** |
| Session forensics | **token-dashboard** / **sniffly** | Per-prompt cost, subagent attribution, tool/file heatmaps, error analysis | Full transcripts w/ thinking + tool calls; no per-prompt cost or heatmaps | 🟡 **G3** |
| Archival | **SpecStory** | Auto-capture at session time to Markdown, searchable | Incremental archive + integrity chain + deletion detection + MD/JSON export — **stronger** on evidence, weaker on capture-time UX | ✅→deepen **G5** |
| Team rollup | Cursor Admin API / Copilot Metrics API (closed, cloud) | Per-developer breakdowns, CSV export, daily refresh | None (single-user) | 🚫 cloud control plane; a privacy-preserving local export is **G4** |
| Outcome linkage | **nobody** | Join sessions ↔ git commits/PRs locally | Has project + git branch per session already | 🟡 open white space — **G5** stretch |

### Observability / gateway

| Capability | Bar-setter | The bar, concretely | Saffev | Verdict |
|---|---|---|---|---|
| Tracing depth | **Langfuse** | Trace→span→generation hierarchy, sessions, user attribution, zero-latency async SDK | Request/response metadata + timeline; no span hierarchy (single-hop proxy = simpler domain) | 🟡 **G4** judges the UX, not span parity |
| Request analytics | **Portkey** | 40+ attributes and 40+ metrics per request, filterable in one pane | ~15 attributes; Analytics page with p50/p95/p99, deltas, explorer | 🟡 **G4** |
| Alerting | **Langfuse** | Threshold monitors on cost/latency/score → Slack/webhook/CI | None | ❌ **G6** (local desktop notifications, not webhooks) |
| Budgets/virtual keys | **LiteLLM** | Per-key/team/model hard budgets, 429 at cap | None | 🚫 blocking violates observe-only; *visibility* budgets (alerts) → **G6** |
| Routing/fallback/caching | OpenRouter / Portkey / Kong | 500+ models, semantic caching, circuit breakers | None | 🚫 out of scope by invariant |
| Zero-config capture | **Helicone** (historic) | One base-URL change captures everything | `saffev run/env/shell` + Gateway adoption (Linux systemd) — **no code change at all** in Gateway mode | ✅ |

### Local app / platform experience

| Capability | Bar-setter | The bar, concretely | Saffev | Verdict |
|---|---|---|---|---|
| Linux packaging | **Jan** (deb+AppImage) / **Ollama** (script+systemd) — whole category weak; nobody ships flatpak/snap/rpm | Native package + service integration | curl installer (cargo-dist), Linux x86_64 binary | 🟡 **G8** |
| Tray/background presence | **Ollama/LM Studio** | Autostart, tray icon, server survives window close (LM Studio's Linux tray is buggy — #576) | macOS tray only (`tray` feature); daemonized start/stop everywhere | 🟡 **G8** |
| Engine management UX | **LM Studio** | HF-wide search, per-quant RAM-fit badges | Detect/adopt/revert/doctor — control-plane, not model management | 🚫 not Saffev's lane (it fronts engines, doesn't replace them) |
| Auto-update | Ollama app | Silent self-update | `saffev update` + Studio banner, GitHub metadata only | ✅ |

## 3. Benchmark credibility bar (for publishing any of this)

From ClickBench, the aider polyglot leaderboard, and uv's BENCHMARKS.md — see
README.md §"Credibility rules". The bar is: **every published number is
reproducible by an outsider with one command against a pinned commit.**
