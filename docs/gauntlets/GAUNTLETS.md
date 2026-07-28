# The Gauntlets

Eight loops — the smallest pieces of Saffev that can be improved and judged
separately. Ordered by build priority: **G1–G3 are P0** (they include the
measurement harnesses everything else needs), **G4–G6 are P1**, **G7–G8 are P2**.

Each gauntlet names: the goal, the bar (concrete competitor reference), the
artifact the builder must produce, and the critic rubric. Critic sessions get
ONLY this section + the bar reference + the artifacts. Round logs live in
`docs/gauntlets/log/`.

---

## G1 · Privacy Lens — detection breadth & proof

**Goal.** Saffev's on-device detector suite is measurably competitive with
Presidio's deterministic coverage and covers the secrets classes Presidio lacks —
scored, not asserted.

**Bar.** Presidio's supported-entities list (open baseline, ~100 entity types) and
Nightfall's secrets/credential classes (commercial reference). Judged on a fixed
fixture corpus, ClickBench-style.

**Build first (the harness IS loop 1):**
- `tests/fixtures/pii/` — a public, hand-labeled corpus:真 positives + adversarial
  negatives per entity kind (the anti-gaming rule: negatives count).
- `saffev bench pii` (or `cargo test --test pii_bench`) — emits per-kind
  precision/recall JSON. One command, reproducible.

**Then build (the breadth):** deterministic, high-confidence detectors for —
private key blocks (`-----BEGIN … PRIVATE KEY-----`), JWTs, DB/connection strings
with embedded credentials, `.env`-style assignments, cloud secret formats beyond
current prefixes, SSN/national IDs (with checksums where they exist), IBAN
(ISO 7064), MAC, crypto wallet addresses. Apply the same suite to **agent session
transcripts** (`/api/agents/privacy`), not just proxy traffic — that surface is
part of the moat.

**Artifact.** `bench/pii-results.json` + a scorecard table (per-kind P/R) at a
pinned commit.

**Critic rubric.** (a) On the corpus: recall ≥ Presidio's deterministic
recognizers for every overlapping kind, at FP rate ≤ current shipped detectors.
(b) ≥ 8 new kinds landed with per-kind scores — *new* means not shipped when
the gauntlet opened; the build list above deliberately includes
Presidio-overlapping kinds (SSN, IBAN, MAC), so new-vs-Presidio is NOT the
reading. (c) Same scores reproduced from a clean checkout with one command.
Name the weakest detector as the next gap.

---

## G2 · Agent coverage — read every tool's sessions

**Goal.** Saffev ingests the session histories of every agent tool a developer
plausibly has on disk.

**Bar.** ccusage parses **15 agent CLIs**. Saffev has 5 adapters (Claude Code,
Codex, Cursor, VS Code, OpenCode) — and reads *full transcripts*, which ccusage
does not.

**Build first:** `tests/fixtures/agents/<tool>/` — one committed, sanitized
fixture per tool format (the corpus that makes adapter claims testable).

**Then build:** adapters for **Gemini CLI (done, round 3), Copilot CLI, Amp,
Goose, Cline, Aider** (priority order — install base). Copilot CLI transcripts
live in `~/.copilot/history-session-state/` — the `~/.copilot/otel` dir this
list originally pointed at is telemetry counters, not transcripts (G2 round-1
critic). **Windsurf is ruled out for transcripts**: Cascade conversations are
per-UUID ENCRYPTED `.pb` files (verified round 3; SpecStory reached the same
verdict) — a metadata-only inventory is possible later but cannot meet the
rubric fields. Format-drift tolerance rules as today: unparseable records
skip, never fatal.

**Artifact.** Adapter fixture suite passing per tool; `saffev status`-style
coverage table (tool → sessions found) on a machine with fixtures installed.

**Critic rubric.** (a) ≥ 10 tools ingested with fixtures proving extraction of:
session id, title, project, model, timestamps, per-message roles, token counts.
(b) A corrupted-fixture test per adapter proving non-fatal degradation. Name the
most-requested missing tool as the gap.

---

## G3 · Cost & usage analytics — ccusage parity from the Studio

**Goal.** A developer never needs ccusage next to Saffev: per-model dollar costs,
cache-token accounting, and billing-window views, on-device.

**Bar.** ccusage's daily / monthly / per-session / **5-hour billing-block**
reports with model-specific pricing and cache-read/write token pricing, run
against the same `~/.claude` data.

**Build.** A versioned, on-disk pricing table (no network fetch — invariant);
cache token extraction in the Claude Code/Codex adapters; block-window
aggregation; Analytics tab surfacing $ per model/project/day and block burn;
plan-limit progress (Pro/Max) computed locally.

**Artifact.** Side-by-side: `ccusage --json` vs `saffev` analytics export on the
same fixture home directory; deltas explained.

**Critic rubric.** (a) Totals within ±2% of ccusage on the fixture set (pricing
table drift documented when larger). (b) Blocks report present with live burn.
(c) Zero new outbound calls (verify with the exposure/doctor tooling). Name the
largest unexplained delta as the gap.

---

## G4 · Observability surface — the request record & the report

**Goal.** Saffev's per-request record and analytics read as rich as the
commercial panes, and a local compliance-style report exists.

**Bar.** Portkey logs 40+ attributes/metrics per request; Nightfall frames
findings against SOC 2 / GDPR / HIPAA. Judged by artifact comparison
(side-by-side screenshots + attribute count), not vibes.

**Build.** Widen the request record toward 40 attributes (headers subset, sampled
params, retry/stream diagnostics, engine version, attribution confidence — all
metadata-only). Add **`saffev report`**: a local Markdown/HTML privacy report
(period, apps, models, findings by kind/app, masking posture, exposure verdict,
archive integrity status) suitable for handing to a security reviewer.

**Artifact.** Attribute-count table (Saffev vs Portkey docs list) + a generated
sample report committed as `docs/examples/privacy-report.md`.

**Critic rubric.** (a) ≥ 30 meaningful per-request attributes visible in History
detail. (b) Report generates offline, names its measurement boundaries, and a
security reviewer persona can answer "what left this machine?" from it alone.
Name the weakest section of the report as the gap.

---

## G5 · Preservation — the evidence-grade archive

**Goal.** The archive is the reference for "my AI sessions, preserved and
provable" — capture-time freshness plus evidence Nobody else has.

**Bar.** SpecStory (capture-time Markdown, searchable) for UX; Saffev's own
SHA-256 chain (already unique) for evidence; the open white space: session ↔ git
commit linkage.

**Build.** Continuous/scheduled archive runs (capture-time freshness instead of
manual `archive/run`); full-text search across archived transcripts (SQLite FTS,
encrypted store); `verify` surfaced in Studio with a human-readable proof
statement; stretch — link sessions to git commits made during the session window
(repo + branch + time overlap already stored).

**Artifact.** Archive of a live fixture session appearing ≤ N minutes after the
session writes; FTS query results; a verify transcript demonstrating tamper
detection on a mutated row.

**Critic rubric.** (a) Freshness ≤ 5 min without manual action. (b) Search
returns across ≥ 3 tools' archives. (c) A deliberately tampered archive row is
detected and reported precisely. (d) Stretch: ≥ 80% of fixture sessions correctly
linked to their commits. Name the biggest preservation risk still open.

---

## G6 · Signals — local monitors & notifications

**Goal.** Saffev tells you when something needs attention, without a cloud.

**Bar.** Langfuse Monitors (threshold alerts on cost/latency/score → channels),
translated to the on-device idiom: OS notifications + tray badge + CLI exit
codes, never webhooks by default.

**Build.** Local monitor rules (PII findings spike, new source app seen first
time, exposure verdict change, latency p95 threshold, spend-per-day threshold
from G3); desktop notifications (notify-send / macOS UNUserNotification);
`saffev status --check` non-zero exit for scripting.

**Artifact.** A demo script that trips each rule class and screenshots/captures
of each notification.

**Critic rubric.** (a) All five rule classes fire correctly and deduplicate.
(b) Zero outbound network. (c) Rules configurable in the same TOML/policy plane
as everything else. Name the noisiest rule (worst signal-to-noise) as the gap.

---

## G7 · Guard — activate the judgment layer

**Goal.** The shipped-but-dormant safety machinery starts earning its place:
model-backed guard sampling live traffic through the local engine.

**Bar.** Lakera's detection framing (injection/jailbreak classes, latency budget)
minus the cloud: everything runs against the user's own local model, off-path,
observe-only.

**Build.** Wire `ModelGuard` to sample N% of traffic through a configured local
model; populate `safety_findings`; surface flagged exchanges in Studio (schema
and badges already exist); a labeled prompt-attack fixture set to score against.

**Artifact.** Guard scorecard on the fixture set (detection rate, FP rate,
added latency = must be 0 on the request path — it's off-path).

**Critic rubric.** (a) Findings appear with honest confidence and guard version.
(b) Request-path latency delta = 0 (measured). (c) Fixture detection ≥
DeterministicGuard baseline with FP ≤ baseline. Name the attack class with the
worst detection as the gap.

---

## G8 · Linux experience — first-class, not a port

**Goal.** Linux is Saffev's best platform (it's the only one with Gateway mode) —
packaging and presence should say so.

**Bar.** Jan (deb + AppImage), Ollama (installer + systemd unit); the category-wide
absence of flatpak/rpm is an open flank. LM Studio's broken Linux tray (#576) is
the anti-reference.

**Build.** `.deb` + `.rpm` (+ AppImage or flatpak — pick per effort/reach) via
cargo-dist/CI; optional systemd user unit for `saffev start`; enable the `tray`
feature on Linux (tray-icon/tao support it — StatusNotifier/appindicator), with
graceful absence on trayless DEs.

**Artifact.** CI-produced packages installed on a clean Ubuntu + Fedora VM;
screenshot of tray on GNOME (with appindicator) and KDE; uninstall leaves no
residue (journal-verified).

**Critic rubric.** (a) Install→start→Studio on a clean VM in ≤ 2 commands.
(b) Tray works or degrades silently, never crashes (the LM Studio failure mode).
(c) Package uninstall + `revert` restores the pre-Saffev state exactly. Name the
worst distro experience as the gap.

---

## Cross-cutting: the public benchmark page

When any gauntlet's harness produces numbers worth publishing, they go to
`BENCHMARKS.md` at the repo root under the credibility rules in README.md —
harness shipped, versions pinned, boundaries stated, unfavorable configs shown,
competitor-correctable via PR.
