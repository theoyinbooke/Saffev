# Benchmarks

Every number on this page is produced by a committed harness, runs against a
committed fixture corpus, and is re-checked on every push — the CI workflows
fail if a claim drifts from what the code actually does (`git diff
--exit-code` on each `bench/*.json` artifact). No number here is hand-typed
first and measured later.

Measured at commit `c5983cd` on `main` (2026-08). Methodology follows the
rules in [`docs/gauntlets/README.md`](docs/gauntlets/README.md): ship the
harness, pin versions, state the measurement boundary, show unfavorable
results, and let competitors correct us by PR.

---

## Sensitive-data detection (vs. Microsoft Presidio)

```
cargo test --test pii_bench -- --nocapture
```

Scored on a hand-labeled public corpus
([`tests/fixtures/pii/corpus.jsonl`](tests/fixtures/pii/corpus.jsonl):
185 cases, 74 of them adversarial negatives — traps count against us).

| | Saffev (deterministic) | Presidio (deterministic recognizers) |
|---|---|---|
| Overall on this corpus | **118 TP · 0 FP · 0 FN** (P = R = 1.0) | mixed, see below |

Per-kind, on the **7 kinds both tools cover** (Presidio's numbers from
[`bench/presidio-baseline.json`](bench/presidio-baseline.json), produced by
[`scripts/presidio_baseline.py`](scripts/presidio_baseline.py) on the same
corpus — run manually, needs a Python venv, not in CI):

| Kind | Saffev P / R | Presidio P / R |
|---|---|---|
| email | 1.00 / 1.00 | 1.00 / 1.00 |
| credit card | 1.00 / 1.00 | 1.00 / 1.00 |
| phone | 1.00 / 1.00 | 0.83 / 0.91 |
| IP address | 1.00 / 1.00 | 0.92 / 1.00 |
| SSN | 1.00 / 1.00 | ~0.7 / 1.00 |
| IBAN | 1.00 / 1.00 | 1.00 / 0.82 |
| crypto wallet | 1.00 / 1.00 | 1.00 / 0.67 |

The other 6 of Saffev's 13 scored kinds — API keys, JWTs, private-key blocks,
connection strings, env/config secret assignments, MAC addresses — have no
Presidio deterministic counterpart; they are scored against the corpus only
(all at P = R = 1.0) and are deliberately **not** framed as a comparison.

**Boundaries.** `Detector::scan` on corpus text only — no proxy, no store, no
masking in the timed path. The corpus is finite and public; a perfect score
here means "no known failure", not "no failure". One known gap is committed as
an expected failure: an obfuscated email (`user [at] example [dot] com`) is
outside deterministic scope by design. Presidio's ML/context-enhanced
recognizers are not measured — this compares deterministic floors only.

---

## Cost analytics (vs. ccusage)

```
cargo test --test costs_bench -- --nocapture
```

Saffev's on-device usage engine vs `ccusage 20.0.19 --offline --timezone UTC`
on the same fixture `~/.claude` directory
([`bench/ccusage-reference.json`](bench/ccusage-reference.json) is the
committed ccusage output, so the check is hermetic — no node in CI).

| Compared | ccusage | Saffev | delta |
|---|---|---|---|
| Total cost | $0.9771 | $0.9771 | **0.0%** |
| Daily buckets (each) | — | — | 0.0% |
| Token sums (input/output/cache r+w) | — | — | exact |
| 5-hour billing-block boundaries | — | — | exact |

**Boundaries.** Parity is proven on the fixture set, not on every history
shape in the wild; when a stored `costUSD` is present Saffev trusts it (as
ccusage's `auto` mode does) rather than re-deriving it. Pricing-table drift
between releases shows up as a delta and is documented when it exceeds ±2%.

---

## Agent-history coverage

```
cargo test --test agents_bench -- --nocapture
```

**12 tools ingested** with committed, sanitized fixtures proving field
extraction (session id, title, project, timestamps, roles, token counts):
Claude Code, Codex, Cursor, VS Code Copilot, OpenCode, Gemini CLI, Copilot
CLI, Cline, Roo Code, Aider, Goose, Amp. Reference point: ccusage parses 15
agent CLIs — but token/cost metadata only; Saffev reads full transcripts.

Every adapter also has a corrupted-fixture test proving non-fatal degradation,
and token coverage is reported three-valued per tool — `proven`,
`absent_in_format` (the tool never writes it), or `present_but_unpopulated` —
so a missing number is attributed to the format, not silently zeroed.

**Boundaries.** Fixtures are synthetic-but-faithful copies of each tool's real
on-disk format; adapters are validated end-to-end on macOS only. Windsurf is
excluded for a reason we verified: its transcripts are per-conversation
encrypted `.pb` files.

---

## Observability surface

```
cargo test --test observability_bench -- --nocapture
```

**34 metadata-only attributes** per request visible in History detail
(rubric bar: ≥ 30; reference: Portkey documents 40+ per-request
attributes/metrics). The same harness deterministically regenerates the
committed sample privacy report
([`docs/examples/privacy-report.md`](docs/examples/privacy-report.md)) from
`saffev report` — offline, boundary statements included.

**Boundaries.** Attribute count is of *meaningful, populated-when-applicable*
fields, and every one is metadata (sizes, truncated headers, sampling params,
shape counts) — never content. Portkey's 40+ includes gateway-side data
(retries, routing) that an observe-only local proxy correctly does not have.

---

## Preservation (archive freshness, integrity, git linkage)

```
cargo test --test preservation_bench -- --nocapture
```

| Claim | Measured |
|---|---|
| Freshness: session durable without manual action | ≤ 5 min (default cadence) |
| Full-text search across preserved tools | 3 tools matched in one query |
| Tampered archive row detected and named | yes — chain + content check |
| Sessions linked to git commits made during them | **83.3%** (bar: ≥ 80%) |

**Boundaries** (quoted from the harness): the integrity chain proves
self-consistency — any edit after capture breaks it — not resistance to an
attacker who controls the machine and recomputes every digest; that needs the
head digest anchored off-machine. Git linkage is time-window correlation
(±10 min pad), not proof the session authored the commit. Freshness is the
scheduler's cadence; a stopped Studio archives nothing until it runs again.

---

## Signals (local monitors)

```
cargo test --test signals_bench -- --nocapture
```

All **six** monitor rule classes (PII spike, new source app, exposure change,
latency p95, spend/day, sessions-at-risk-and-unpreserved) fire on a fixture
that trips them simultaneously and deduplicate on re-evaluation — including
across a state reload. Zero outbound network: every rule input is a local
store read or a caller-supplied observation, and notifications are local OS
subprocesses (`notify-send` / `osascript`), never webhooks.

---

## Guard baseline (the bar a model guard must beat)

```
cargo test --test guard_bench -- --nocapture
```

The shipped deterministic safety guard, scored on a labeled prompt-attack
corpus ([`tests/fixtures/guard/corpus.jsonl`](tests/fixtures/guard/corpus.jsonl):
12 benign prompts that must not flag, 16 unsafe across 8 categories).

| Metric | Deterministic floor |
|---|---|
| Precision / false positives | **1.00 · 0 of 12 benign** |
| Recall | **0.125 (2 of 16 unsafe)** |

This is reported as a weakness on purpose: the deterministic floor is
high-precision and **low-recall** — it fires on explicitly-phrased intent and
misses paraphrases and the whole prompt-injection class. That gap is exactly
what a model-backed guard (gauntlet G7, in progress) has to close, and this
harness is the bar it must clear: higher recall at no worse than zero false
positives, with zero request-path latency (guards run off the hot path). The
corpus is realistic and is **not** tuned to the floor's patterns; the 14 misses
are listed in [`bench/guard-results.json`](bench/guard-results.json), not
hidden.

---

## Reproducing

Each table's command runs from a clean checkout (`--no-default-features`
skips the SQLCipher/OpenSSL build if you want speed over at-rest encryption).
The CI workflows in [`.github/workflows/`](.github/workflows/) run the same
commands on every push and fail on any drift between code and the committed
artifacts in [`bench/`](bench/). Corrections welcome — especially from the
projects we compare against.
