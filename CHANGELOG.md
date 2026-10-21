# Changelog

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
