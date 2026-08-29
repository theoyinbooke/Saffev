# Changelog

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
