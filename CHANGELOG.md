# Changelog

## v0.9.1

**Hardened, faster, and cleaner end-to-end.**

### Security & Reliability
- **Studio auth & DNS-rebinding hardening.** The Host-header allowlist now guards the static Studio and menu-bar shells (`index.html`, `menubar.html`) as well as `/api/*`, adds `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, escapes `<` in the injected token, rejects empty bearer tokens, and mints an ephemeral 256-bit session token if the OS keyring is unavailable.
- **SSRF & path-traversal defenses.** Upstream forwarding disables automatic HTTP redirects; archive export/audit paths canonicalize safely across symlinks and verify mount presence before writing; Codex server config serializes model names safely; notification and restart helpers pass paths without shell interpolation.
- **SQLCipher size-based retention fix.** `PRAGMA page_size` under SQLCipher returns text (`cipher_page_size`), which previously broke `Retention::Size`. Retention now parses numeric pragmas cleanly, tracks live `(page_count - freelist_count) * page_size`, and purges in batches while preserving the archive.
- **Data integrity & backups.** Added schema migrations v11–v12 (`UNIQUE` on `responses(request_id)`, denormalized `archived_sessions.content_bytes`, covering and partial indexes), transactional migrations, atomic upserts, incremental delta deduplication, and `BackupCursor` regression detection so retention resets trigger a fresh full backup.
- **Graceful shutdown.** Open `/api/stream` SSE connections now close immediately on `SIGTERM`/`SIGINT` instead of waiting for the 5-second drain timeout, and the store flushes pending writes before exit.

### Privacy & Proxy Accuracy
- **Stronger PII & streaming masking.** Added Anthropic/base64url API key detection, O(log M) span tracking, multi-KB PEM block suppression, long JWT holdback, and fixed backward whitespace snapping so space-separated secrets (credit cards, phones, IBANs) are never split across chunks.
- **Single-pass JSON-aware masking & bounded buffers.** Request policy runs in a single pass with compressed-body safety; response buffering is capped at 16 MiB with proper `ResponseFinished` cleanup on early disconnects; proxy-side TTFT and decoded completion PII scanning are recorded accurately.
- **Accurate local vs. cloud pricing.** Bounded model-ID matching keeps local Ollama models (e.g. `marco-o1:latest`) at `$0`, adds specific `-mini`/`-nano`/`-flash` tiers, supports Bedrock/OpenRouter `:` prefixes, and wires live pricing overrides into agent analytics.

### Performance & Polish
- **SQL pushdown & read-pool bounds.** Replaced multi-hundred-row scans in Live, Privacy, Quality, Analytics, and Timeline with targeted SQL aggregations; bounded concurrent SQLCipher read connections via semaphore; coalesced concurrent cold archive integrity checks; offloaded backup, export, audit, and agent endpoints to `spawn_blocking`.
- **Faster coding-agent readers.** Replaced `4N+1`/`2N+1` SQLite queries in OpenCode and Goose with bulk queries; cached Aider walks, Claude Code usage files, and Codex titles; skipped unnecessary message decoding during metadata scans; fixed an infinite re-mirroring loop when redaction is enabled on PII-bearing titles.
- **Studio & macOS menu-bar polish.** Multiplexed Studio live updates onto a single shared `/api/stream` SSE connection; parallelized Live/Engines refreshes; eliminated stale-response races across drawers and tabs; serialized Settings saves without losing input focus; tightened tray panel origin/reveal boundaries and supervisor lifecycle checks.

## v0.9.0

**Backups that compound, and a menu bar that's fast to read.**

### A redesigned menu-bar app
- New panel: one consistent system of tiles, rows and controls, dark first
  with a light theme, and much shorter copy. Four tabs: **Today**, **Keep**,
  **Privacy**, **Spend**. Alerts move to a bell inbox; Settings opens as its
  own page.
- **Keep** shows the backup chain (full copy + changes), the next scheduled
  backup, the destination, and Back up now / Show in Finder.
- **Privacy** turns masking into one control: Observe, Dry run or Redact.
- **Spend** shows daily cost or tokens stacked by tool, the current 5-hour
  block, and spend per tool.
- New app icon (ink with the mint recorder mark) and a menu-bar glyph with
  three states: recording, paused, and needs you (service failed to start).

### Backups: incremental, scheduled, and restorable
- **Incremental backups.** After the first full copy, each backup writes only
  what changed since the previous one (new chain entries plus the current text
  of every session they touch, new proxy history, settings) into a small
  sibling folder. `[backup] full_every` (default 7) starts a fresh chain.
- **Scheduled backups** (`[backup] auto`, `interval_hours`, off by default;
  also in the panel's quick settings and Studio Settings). A backup missed while
  asleep or unplugged runs soon after.
- **`saffev restore <folder>`** rebuilds a database from any link of a chain,
  into a new file, after an integrity check. Never overwrites.
- Optional retention: `[backup] keep_chains` (0 = keep everything).

### Fixes
- **Back up no longer closes the panel.** It used to open Finder by itself,
  which stole focus and hid the panel (and its result). The panel now backs up
  through the Studio and offers *Show in Finder*.
- A backup folder path containing a space (e.g. iCloud Drive) was reported as
  a failed backup.
- Backups are atomic (built in a hidden `.partial` folder, renamed when done);
  two in the same second no longer collide; an unplugged destination is
  refused instead of being recreated on the internal disk.
- "Changed since last backup" now counts new proxy history, not only the archive.
- Alerts for sessions near their deletion line offer **Preserve now** (what
  protects them) instead of a full backup.

### Performance
- The menu-bar panel no longer fetches or streams while hidden (it used to,
  from launch and after every service restart).
- The integrity check is reused while the archive is unchanged (any archival
  re-verifies; Studio's explicit check always recomputes) and streams instead
  of holding each transcript twice in memory.
- The archive size total, the privacy report and the update check are cached;
  the privacy report rescans only sessions that changed.
- Re-archiving a growing session keeps its stored prefix instead of deleting
  and re-indexing the whole transcript every few minutes.
- Claude Code and Codex transcripts are parsed **incrementally**: a session
  file that only grew is read from where the last parse stopped, so one new
  message costs one line instead of the whole file (64 MB transcript: 219 ms →
  4 ms). Cached parse state is capped at 64 MB and dropped after 15 idle
  minutes, so only sessions that are actively growing stay in memory.
- The menu-bar run loop no longer redraws the icon and re-reads the pid file on
  every mouse move, and the Studio probe runs off the UI thread.

## v0.8.0

**The menu-bar panel release.**

### Saffev.app: click the icon, get the whole picture
The macOS menu-bar app now opens a custom drop-down panel instead of a menu.
Five tabs, all on-device:

- **Overview** – requests today, leaks caught, current 5-hour block spend
  (gauges), engine + exposure, recent requests, suggestions.
- **Keep** – sessions preserved, integrity chain, which tools are near their
  deletion line, and one **Back up** button: preserves anything new, then
  exports the encrypted archive to the folder you choose (**Change…** opens a
  native folder picker; the choice is remembered). Offered only when the
  archive changed since the last backup.
- **Privacy** – masking posture, findings today / all-time, by kind.
- **Spend** – daily cost or tokens **by tool** (translucent layered chart,
  hover for a day), current block burn + plan allowance, by tool, local savings.
- **Alerts** – everything that needs you, evaluated locally, plus live monitor
  signals while the panel is open.
- Light/dark toggle, pin-to-keep-open, service controls (Start/Stop/Restart,
  logs, open at login) in the footer. The panel is served by your own local
  Studio and never reaches the network.

### Fixes
- **Preserved sessions were still flagged "overdue"** — the at-risk count never
  subtracted the archive. Preserving now clears the flag.
- **No more macOS privacy prompts on first launch.** The Aider reader stays
  out of Desktop, Documents, Downloads and every media folder (it used to
  trigger Apple Music / Photos / folder prompts). Opt in with
  `[agents] aider_roots` in `saffev.toml`.
- **"Too many open files"** under a polling client: the store no longer opens a
  fresh SQLCipher connection (with a keychain round-trip) per read, and the
  Aider home walk is memoized.
- Settings written from the Studio now save back to an explicit `--config`
  file instead of `data_dir/saffev.toml`.
- `saffev backup` records when and where it ran so the UI can say
  "Backed up · 3h ago".

### API
- `GET /api/agents/analytics` gains `dailyByTool` + `toolLabels`.
- `GET /api/agents` archive status gains `latestTs`, `lastBackupTs`,
  `lastBackupDir`, `changedSinceBackup`.
- New `[agents]` config section (`aider_roots`).
