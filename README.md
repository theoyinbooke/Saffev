# Saffev — the black box recorder for AI on your machine

**Saffev remembers what every AI tool on your computer did, protects what you did
not mean to share, and keeps the record even after those tools throw theirs away.**

It is one Rust binary and a local web Studio. Nothing is uploaded, nothing is
sent to us, and there is no account. Three things it does:

### See

Every model call your apps make, recorded on this machine: which app, which
model, how long it took, what it cost, what failed. Plus every coding session
from Claude Code, Codex, Cursor, OpenCode, and VS Code Copilot, read straight
from the files those tools already write. One **Timeline** shows all of it
together, and one search box looks through all of it at once, including what was
actually said inside your conversations.

### Protect

An on-device detector finds personal data and credentials in your traffic. It can
show you where they are, quietly replace them before they reach a model, or stop
the request entirely for the things that must never be sent. There is a
whole-history **Privacy report** that answers the question people actually have:
*what have I been pasting into AI tools, and where?*

### Keep

This is the part nobody else does. Your AI coding tools delete their own history
on their own clocks (Claude Code prunes transcripts after about 30 days, Cursor
rotates its store). You are not warned and you cannot get it back. Saffev shows
you what is scheduled to disappear and keeps an encrypted copy that survives it,
with a tamper-evident record so you can prove a session was not altered
afterwards. Export any of it to Markdown or JSON at any time. It is your data.

> **Positioning.** Cloud observability tools watch the app *you are building* and
> need you to instrument your code. Enterprise DLP sits on the network and belongs
> to IT. Saffev watches the *machine you are sitting at*, needs no instrumentation,
> and never phones home.

## Install

**macOS & Linux — one command:**

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/theoyinbooke/Saffev/releases/latest/download/saffev-installer.sh | sh
```

This pulls the prebuilt `saffev` binary for your OS/arch from the latest GitHub
release, installs it to `~/.cargo/bin` (added to your `PATH`), and is fully
self-contained — SQLCipher is bundled, so there are no other dependencies. Re-run
the same command to update. (Prebuilt targets: macOS arm64 + x86_64, Linux
x86_64. Build from source for others — see **Build / run / test**.)

**macOS — prefer a menu-bar app?** The latest release also ships a signed &
notarized **`Saffev.app`** (Apple Silicon) as a drag-install disk image.
Download
**[`Saffev-macos-arm64.dmg`](https://github.com/theoyinbooke/Saffev/releases/latest/download/Saffev-macos-arm64.dmg)**,
open it, and drag `Saffev.app` onto the `Applications` shortcut inside — no
unzip. It lives in the menu bar (no Dock icon, no terminal) and keeps the proxy +
Studio running: **Open Studio · Start · Stop · Restart · Open at Login · Quit**.
Under the hood it is the same `saffev` binary running `saffev tray`.

**Updating in place.** Installer installs can update themselves: run `saffev
update` (or `saffev update --check` to just look), or click **Update** in the
Studio banner when a newer release is out. Both apply the same installer in
place. **Privacy:** the update check contacts **GitHub release metadata only**
(the latest version number + the installer script) — it sends **no** user or
content data, nothing about what you run through Saffev. This is the one
deliberate outbound call besides the local engine, and it is consistent with the
on-device invariant below. (A dev / `cargo install` build has no install receipt,
so it can't self-update — it reports the current version and points you at the
installer instead, never erroring.)

> **macOS, first run:** release builds are code-signed + notarized once the
> maintainer's Apple signing secrets are configured (see **Releasing / macOS
> signing**); Gatekeeper then verifies them online with no extra steps. If you
> run a build cut before signing was enabled, Gatekeeper may say it "cannot be
> verified" — allow it once via **System Settings → Privacy & Security → Open
> Anyway**, or `xattr -d com.apple.quarantine "$(which saffev)"`. macOS may also
> prompt to allow **Keychain** access on first start (for the encryption key +
> Studio token) — choose **Always Allow**.

Then just start it — **no config required**:

```sh
saffev start          # zero-config first run; opens the Studio in your browser
```

On a true first run (no config yet) Saffev auto-configures itself to run
**alongside** your existing engine in Cooperative mode — it never touches your
engine. It detects your engine on the well-known port (Ollama `:11434` / LM
Studio), keeps it as the upstream, and picks the first **free** ports for the
proxy and the Studio (so a running Ollama on `:11434` is no longer a conflict —
it's the expected setup). It persists the resolved config so later runs are
stable, prints a calm summary (Studio URL, proxy base URL, engine status), and
opens the Studio in your default browser. Use `--no-open` to skip the browser
(handy on headless/CI hosts).

The summary tells you the two URLs it chose, for example:

```text
● studio      http://localhost:7100
● proxy       http://localhost:8088 · OpenAI base: /v1
● engine      ollama v0.30.6 · :11434
```

Open the **Studio** at the printed URL to watch traffic, and point your apps'
Ollama base URL (or OpenAI `…/v1` base URL) at the **proxy** URL. `saffev status`
/ `saffev logs -f` / `saffev stop` to manage it.

**Advanced — pin your own ports.** If you'd rather fix the ports yourself (or run
multiple instances), write a config and pass it with `--config`; an existing
config is always honored exactly and never overridden:

```sh
mkdir -p ~/.config/saffev
cat > ~/.config/saffev/saffev.toml <<'TOML'
mode = "cooperative"
[ports]
proxy = 8088      # point your apps' Ollama base URL here
studio = 7100     # open the Studio here
upstream = 11434  # your real Ollama
TOML

saffev start --config ~/.config/saffev/saffev.toml
```

Full details in **Build / run / test** and **Configuration** below.

## Point your apps at Saffev (Cooperative mode)

**This is the step people miss.** In Cooperative mode (the default) Saffev is a
proxy — it only sees requests **sent to its port**. It does **not** silently
sniff everything hitting Ollama on `:11434`. So an app that calls Ollama
*directly* is invisible to Saffev. To trace an app, point its **Ollama base URL
(or OpenAI base URL) at Saffev's proxy** — Saffev records the call and forwards
it to your real engine, unchanged:

```text
your app ──▶ Saffev proxy (:8088) ──▶ Ollama :11434  /  LM Studio :1234
                  └─ records it → Studio (Live / History / Privacy)
```

Saffev works the same whether your engine is **Ollama** or **LM Studio** — it
forwards whatever path your client sends to whichever engine is running.

### The easy way — `saffev run` (no config edits)

Wrap the command that talks to your model and Saffev injects the base-URL env
vars for you (both the Ollama and OpenAI-compatible ones, so Ollama *and* LM
Studio clients are covered):

```sh
saffev run -- python app.py        # trace any command
saffev run -- npm run dev
```

Prefer to set it in your own shell? `eval "$(saffev env)"` exports the same vars
for the current session, or `saffev shell` opens a subshell with them already
set. Add `--start` to `run`/`shell` to auto-start Saffev first if it isn't
running (otherwise they warn and run your command untraced — never blocking it).

### Or set the base URL manually

Change the base URL wherever your app sets it — replace the engine port
(`…:11434` for Ollama, `…:1234` for LM Studio) with the **proxy port Saffev
printed** (`…:8088` by default):

| If your app uses… | Set it to |
|---|---|
| An env var (`OLLAMA_HOST` / `OLLAMA_BASE_URL`) | `http://localhost:8088` |
| **Ollama SDK** (JS / Python) | `new Ollama({ host: 'http://localhost:8088' })` · `Client(host='http://localhost:8088')` |
| **LangChain** `ChatOllama` | `baseUrl: 'http://localhost:8088'` |
| **Vercel AI SDK** (`ollama-ai-provider`) | `createOllama({ baseURL: 'http://localhost:8088/api' })` |
| **OpenAI SDK** / **LM Studio** (`OPENAI_BASE_URL`) | `http://localhost:8088/v1` |
| **Raw `fetch` / HTTP** | the URL string `http://localhost:11434` → `http://localhost:8088` |

Then **restart your app** so it picks up the new URL, trigger an action, and
watch the call appear in the Studio. Concrete example — an app that reads
`OLLAMA_BASE_URL` (Node ≥ 20.6 loads a `.env` with `--env-file`):

```sh
# .env  — route this app's Ollama traffic through Saffev
OLLAMA_BASE_URL=http://localhost:8088
```
```jsonc
// package.json — load it on start
"scripts": { "start": "node --env-file-if-exists=.env server.js" }
```

To bypass Saffev again, point the app back at `http://localhost:11434`.

> **Want app-transparent capture with no per-app change?** That's **Gateway
> mode** — Saffev owns the engine's well-known port and supervises the real
> engine behind it, so it sees *all* local traffic automatically. It's clean on
> Linux (systemd) for **Ollama**; on macOS the Ollama app resists it, so
> Cooperative mode (above) is the supported path there. **LM Studio** has no
> systemd service to rebind, so it's Cooperative-only on every platform — use
> `saffev run` (above) for the same zero-config feel.

## Hard invariants

These are enforced throughout the codebase and are the reason to trust it in
front of your inference path:

- **Fail-open, always.** Any internal error (tee, PII scan, store, supervisor)
  is logged to Saffev's own diagnostic log and swallowed — the request still
  reaches the engine and the response still reaches your app.
- **Transparent streaming.** Ollama NDJSON and OpenAI SSE stream through
  token-by-token via a bounded, drop-oldest tee. The proxy never buffers or
  aggregates a stream before forwarding it.
- **Zero model-based work inline.** Only deterministic, microsecond-cheap checks
  (regex PII) run on the request path. Everything else is async / off-path.
- **Privacy true by default.** The database stores **metadata only**; raw
  prompt/response text is written only behind an explicit, logged opt-in
  (`payload_storage`). Detected PII is **hashed**, never stored raw.
- **Nothing leaves the device**, with exactly two exceptions, both named here
  rather than buried:
  1. The **update check** contacts GitHub release metadata to ask "what is the
     latest version?" It sends nothing about you or your traffic.
  2. The optional **AI summary** sends one session's text to OpenAI through your
     own Codex sign-in. It is **off by default**, it happens **only when you
     click the button**, and the button says so before you press it. This is the
     one path where your content is transmitted. If that is not acceptable, leave
     it off and everything else still works.

  There are no other outbound calls except to your local engine on loopback.
- **Observe by default.** Traffic is never mutated unless you explicitly opt in
  to PII masking *and* leave dry-run. Masking is fail-open: any error forwards the
  original request untouched.
- **Blocking is never accidental.** A request is only ever stopped when you have
  enabled masking, left dry-run, *and* named that kind of data as blockable. No
  internal error can block traffic; every failure path still forwards.

## What's new

The most recent work, on top of everything below: the unified **Timeline**,
**full-text search** inside preserved conversations, the whole-history **privacy
report**, **redaction on preservation**, **blocking** as an alternative to
masking, and a **tamper-evident archive** with an audit bundle. Listing a large
history also went from ~27 seconds to ~30 milliseconds, and a token
double-counting bug that overstated estimated cost more than tenfold is fixed.

Before that, v1 built on the passive core with seven shipped features, all
preserving the invariants above (fail-open, on-device, observe-by-default,
transparent streaming):

- **At-rest encryption ON by default.** The stock build links bundled SQLCipher;
  the database is encrypted with a key from the OS keyring (or `SAFFEV_DB_KEY`).
  Opt out with `--no-default-features` for a plain SQLite build.
- **Opt-in PII masking with dry-run.** Off by default. When enabled in dry-run,
  traffic passes through unchanged and findings are recorded as `would_mask`.
  Flip dry-run off to redact high-confidence request-side PII (email, card, API
  key, IP, phone) to typed placeholders (`[EMAIL]`, `[CARD]`, …) **before** the
  request reaches the engine — the model never sees the raw value. Recorded as
  `masked`. Low-confidence findings are never masked. Responses are masked too:
  a single JSON body is buffered and redacted, and **streaming responses**
  (Ollama NDJSON, OpenAI SSE) flow through a bounded-holdback masker — frames
  are forwarded as they arrive while a small tail (~160 chars) of decoded text
  is held back so a PII span that straddles chunks is still caught. The stream
  is never buffered whole; on any framing error it degrades to verbatim
  passthrough (fail-open).
- **Socket-PID source-app attribution.** The client peer address is resolved to
  a process name via `lsof` (macOS) / `/proc` (Linux) off the request path, with
  a header fallback then `Unknown`. Findings carry the real confidence
  (`pid` / `header` / `unknown`).
- **Cooperative engine card.** In Cooperative mode (no adoption, no store row)
  the Studio Engines panel now probes the configured upstream and surfaces the
  running engine (e.g. Ollama on `:11434`) instead of "No engine detected".
- **Self-hosted Studio fonts.** The three font families are bundled as local
  woff2 files; the Google Fonts CDN links are gone, so the Studio is fully
  offline (nothing leaves the device, even build-time-fetched fonts are vendored).
- **Daemonized `start` / `stop`.** `saffev start` detaches into the background,
  writes a PID file, and returns promptly. `saffev stop` sends SIGTERM for a
  graceful shutdown (in-flight requests drain), cleans up the PID file, and
  reports stale/unmanaged instances honestly. `--foreground` still runs attached.
- **Config load/save/validate test coverage** for round-trips and port-collision
  rejection.

> Note: settings written via the Studio Settings page (`PUT /api/settings`)
> persist to the TOML config. The running process holds the config in a live,
> atomically-swappable handle (`ArcSwap<Config>`) shared by the proxy and Studio,
> so most changes apply **live, with no restart**:
>
> - **Apply live (no restart):** PII masking (enabled / dry-run / kinds),
>   payload storage, retention, and handover policy. A `PUT` swaps the new
>   snapshot in place and the running proxy + Studio observe it on the very next
>   request — verified end-to-end against a live engine (masking toggled on then
>   off mid-process; the engine received `[EMAIL]` while masking was live and the
>   raw value once it was disabled, all without restarting).
> - **Restart-required:** `mode` and ports. These rebind the listeners / re-adopt
>   the engine, so they are persisted to the TOML config and applied on the next
>   `saffev start`. `PUT /api/settings` reports them in the response's
>   `restartRequired` field with a `restartNote` rather than swapping them live.

## Agents & Preservation

Beyond observing live traffic, Saffev reads your **AI coding tools' local session
history on-device** and helps you own it. This is pure file reading — **it does
not need the proxy running**; open the **Agents** page and it reads directly from
each tool's on-disk history.

**Sources (auto-detected):** Claude Code (`~/.claude/projects/**.jsonl`), OpenAI
Codex (`~/.codex/sessions/**/rollout-*.jsonl`), OpenCode (`opencode.db`), Cursor
(`state.vscdb`), and VS Code / GitHub Copilot Chat (`workspaceStorage/**/
chatSessions/*.jsonl`). Each session and message is **tagged with its source**;
SQLite stores are read via a read-only snapshot that never touches the live DB.
Reads are cached per file, keyed on modification time and size, so a finished
session is parsed once and never re-read. (This matters: on a real 521-session
history, listing took **27 seconds** before that cache and takes about **30
milliseconds** after it. The cache is warmed in the background at startup, so
your first visit to the page is fast too.)

- **See everything, per tool.** Sessions, models, message/tool-call counts, token
  usage, and estimated cost, in a per-tool table plus a source-tagged session list
  with a full-transcript drawer.
- **Search what was actually said.** A full-text index over your preserved
  transcripts, so you can find a conversation by its content rather than guessing
  at its title. Results show the matching excerpts inline. Titles and projects are
  always searchable; searching *inside* conversations covers preserved sessions,
  and the UI says so rather than pretending otherwise.
- **Privacy report.** A whole-history answer to "where did I leak a secret?",
  broken down by kind, tool and project, with the sessions to go and look at.
  Counts and kinds only, never the secret itself.

  It deliberately separates what is worth trusting from what is not. IP and phone
  detection is pattern-only, and source code is full of version strings, ports and
  numeric ids that look just like them. On a real archive those two were **83%**
  of all matches while API keys were 0.1%. So they are shown, clearly marked as
  low confidence, and kept out of the headline number. A privacy tool that claims
  eleven thousand leaks teaches you to ignore it.
- **Preservation (opt-in, off by default).** These tools delete their own history
  on their own clocks (Claude Code prunes after `cleanupPeriodDays`, default 30;
  Cursor rotates its DB). Saffev surfaces **what is scheduled for deletion** per
  tool, and — when you enable it — keeps a **durable, encrypted copy in its own
  SQLCipher store that survives the source app deleting theirs.** The snapshot is
  incremental (unchanged sessions are skipped), never mutates source files, and
  flags but never deletes sessions the source has removed ("resurrected" from the
  archive). Our own retention defaults to keep-forever.
- **Redaction on preservation (opt-in).** By default the archive keeps transcripts
  exactly as they were, secrets included. Turn this on and detected secrets are
  replaced with a placeholder before anything is stored, so you keep a safe copy
  rather than a complete one. It is lossy on purpose, the setting says so, and
  switching it on re-archives what you already have so you are never left with old
  raw transcripts you believe are safe.
- **Tamper-evident.** Every preservation appends an entry to an append-only log,
  each committing to a SHA-256 digest of the session's content *and* to the entry
  before it. Change or remove anything and the chain stops verifying. The Agents
  page shows the verdict and a head digest you can record elsewhere to anchor your
  archive at a point in time.
- **Audit bundle.** One click writes a folder containing every transcript, the
  full integrity chain, and a README explaining how to recompute the digests
  yourself. It is meant to be handed to someone who has never run Saffev. That
  README is also honest about the limit: this proves the archive is internally
  consistent and unedited, not that someone who controls the machine could not
  have rewritten the whole chain deliberately.
- **Export.** Any session (or all of them, bulk) to open **Markdown / JSON**, to a
  folder you own — your data, portable, yours to keep.
- **AI summaries (opt-in).** If you have the Codex CLI installed and signed in,
  Saffev can summarize a session using **your own Codex + ChatGPT subscription**
  via a hardened, sandboxed `codex app-server` (read-only, no tools, minimal
  config). This is the **one** path where content leaves the device (sent to
  OpenAI through your own Codex); it is strictly opt-in and runs only on an
  explicit click.

> **Verification note:** these adapters are validated against real on-disk data on
> **macOS**. The Linux/Windows storage paths are implemented but not yet verified
> on those platforms. The archive's first snapshot is proportional to history size
> (about 100 seconds for 521 sessions / 69k messages); subsequent runs skip
> anything unchanged and are near-instant.

## Timeline — one record of everything

Saffev learns about AI activity two different ways: calls proxied through it, and
coding sessions read off disk. **Timeline** merges them into one chronological,
searchable list, because you should not have to already know which half a memory
lives in before you can look for it.

Every row is tagged with where it came from, badged if it failed, contained PII,
was flagged by the safety guard, or is preserved. One search box covers proxy
metadata, session metadata, and the contents of preserved conversations. Clicking
a row opens the right detail view for its kind.

## Blocking, not just masking

Masking quietly rewrites a secret out of a prompt, which is the right default. But
some things must never reach a model at all, and for those "we replaced it for
you" is the wrong answer.

In **Settings → PII masking → Block outright**, pick the kinds that should stop a
request. Nothing is blocked unless you pick something *and* dry-run is off. A
blocked request never reaches the engine and the calling app gets a clear,
well-formed error saying exactly why:

```json
{"error": {"message": "Saffev blocked this request: it contains api_key that your
policy does not allow to be sent to a model. Nothing was forwarded to the engine.",
"type": "saffev_policy_block", "code": "pii_blocked",
"blocked_kinds": ["api_key"]}}
```

Only high-confidence findings can block; a low-confidence guess never stops your
traffic.

## Plugging in your own safety guard

Saffev has long said a purpose-trained guard could plug into its judgment socket.
That was an intention, not a fact: the safety path called the built-in
deterministic guard as a concrete type, so there was nothing to plug into. There
is now.

```toml
[eval]
enabled = true
safety = true
guard_model = "your-guard:1b"   # runs on your own local engine
```

Two deliberate choices:

- **It is additive, not a replacement.** The deterministic floor keeps running
  alongside it. Every finding records which guard produced it, so the two never
  get confused in the store or the UI.
- **It is gated exactly like the judge.** Same non-blocking concurrency cap, so
  under load an extra guard call is dropped rather than queued, and it can never
  thrash the VRAM your own model needs.

Verified live with a small general model standing in for a trained guard. On a
single unsafe prompt both guards fired and stayed distinguishable:

```text
guard=deterministic:v2   category=weapons        verdict=flagged
guard=gemma3:1b          category=illicit        verdict=flagged
```

They disagreed on the category. That is the honest state of the art for small
local guards, and it is precisely why the deterministic floor stays: a model
guard adds recall, it does not earn trust on its own. Small guards are
particularly unreliable on adversarial input and markedly worse on African and
other low-resource languages, which is the gap purpose-trained localized guards
exist to close.

**Writing a guard:** implement `brain::guard::SafetyGuard`, or use `ModelGuard` as
a reference. One non-obvious constraint: the backend Saffev injects forces
Ollama's `format:"json"`, because that is what stops small "thinking" models
returning empty content. Prompt for JSON and parse JSON.

## Team policy, without a server

A team usually wants one agreed answer to "what must never be sent to a model".
The normal way to do that is a hosted control plane with accounts and sync, which
would cost Saffev the one claim nobody else can make.

So: **a policy is a TOML file you commit to your own repo.** A lead writes it,
everyone points their Saffev at it, and every install enforces the same rules
locally. No accounts, no sync, no telemetry, and no way for anyone to check up on
you, because that would require reporting your activity somewhere.

```toml
# in each person's saffev.toml
policy_file = "~/work/our-repo/saffev-policy.toml"
```

See [`examples/saffev-policy.toml`](examples/saffev-policy.toml) for a commented
starting point. A policy can set the masking posture, which kinds are blocked
outright, and shared custom patterns. It deliberately **cannot** set ports, data
directories, or retention: a file in a repo should not be able to reconfigure
someone's machine.

Two deliberate behaviours:

- **The policy wins.** Settings it names become read-only in the Studio, which
  refuses the change rather than accepting it and quietly ignoring it. A rule an
  individual can silently switch off is not a policy.
- **A broken policy is loud, not silent.** A missing or invalid file never blocks
  startup or your traffic, but it is reported at startup and shown in the Studio,
  because the dangerous failure is everyone believing they are covered when they
  are not.

## About the numbers

Cost and token figures are estimates, and the tool says so where it shows them:

- **Prices are configurable.** They used to be hardcoded constants, which meant a
  published price change silently made every figure wrong. Override them under
  `[pricing]` in your config; the built-in table is only a default.
- **Cached tokens are priced as cache.** Vendors disagree on reporting here:
  Anthropic reports input tokens excluding cache reads, OpenAI reports a total
  with cached tokens as a subset. Counting the cached portion at full input price
  overstated one real history's cost by more than tenfold. Readers now normalize
  to non-cached input.
- **Estimated vs exact is visible.** When the engine reports token counts we use
  them; otherwise we estimate with a bundled tokenizer. The Analytics tokens
  figure now tells you what share of the total was estimated instead of blending
  the two silently.

## Build / run / test

`cargo` lives at `~/.cargo/bin`. If it is not on your `PATH`:

```sh
source "$HOME/.cargo/env"
```

### Build

```sh
cargo build              # debug; encrypted-at-rest (bundled SQLCipher, default)
cargo build --release    # optimized
```

At-rest DB encryption (SQLCipher) is **on by default** (acceptance §10.5). The
stock build links bundled SQLCipher and opens the database with a key pulled from
the OS keyring (Keychain on macOS, Secret Service / libsecret on Linux) via a
`PRAGMA key` handshake that runs before any other statement.

Set `SAFFEV_DB_KEY` to override the keyring (headless/CI/dev) — when present it is
used verbatim as the SQLCipher key instead of the keyring entry. The same key
must be supplied on every open, or the database cannot be decrypted.

Set `SAFFEV_INSTALL_TOKEN` to pin the per-install Studio bearer token (headless/
CI/dev, and unsigned dev rebuilds) instead of the keyring-generated one. Both env
overrides bypass the OS keyring entirely, so no Keychain/Secret-Service prompt
appears — useful for automated runs:

```sh
SAFFEV_INSTALL_TOKEN=dev SAFFEV_DB_KEY=devkey ./target/debug/saffev start
# Studio API then accepts:  Authorization: Bearer dev
```

For a plain, unencrypted build with no system-crypto compile step:

```sh
cargo build --no-default-features
```

### Test

```sh
cargo test               # 207 unit tests across all modules
```

### Run

```sh
./target/debug/saffev --help
./target/debug/saffev status            # engines, ports, mode, health, exposure
./target/debug/saffev doctor            # port conflicts, exposure, permissions
./target/debug/saffev start             # daemonize: detach, write PID file, return
./target/debug/saffev start --foreground # run attached (Ctrl-C to stop)
./target/debug/saffev stop              # graceful SIGTERM, drain, remove PID file
./target/debug/saffev logs -f           # stream recorded activity
./target/debug/saffev update            # check + install a newer release (installer installs only)
./target/debug/saffev update --check    # just report whether one is available
```

`saffev start` re-execs a detached `--foreground` copy of itself, writes a PID
file (`saffev.pid`) into the data dir, prints the Studio URL, and returns. It
refuses to start a second daemon or to steal a port held by a foreign process.
`saffev stop` reads the PID file, sends SIGTERM (servers drain in-flight requests
via graceful shutdown), waits up to 5s, then removes the PID file; a stale PID
file is cleaned up, and a running-but-unmanaged (foreground) instance is reported.

By default the proxy binds the well-known Ollama port `11434` (Gateway intent)
and the Studio binds `7100`. To run **alongside** an existing Ollama without
touching it (Cooperative mode), point the proxy at a spare port and forward
upstream to the real engine — see the smoke-test section below. Config is read
from a TOML file; an explicit one can be passed with `--config <path>` or the
`SAFFEV_CONFIG` env var.

The CLI is designed so `--help`, `status`, and `doctor` always render sensible
output even before anything is configured or running (the fail-open ethos applied
to the control plane: every call into a downstream module is isolated so a
stubbed/unavailable dependency degrades a single status line, never the command).

## Configuration

A single TOML file in the per-OS app-data dir (`saffev.toml`), holding ports,
mode, the payload-storage flag, retention, custom PII patterns, supervisor
handover policy, and the data dir. The Studio Settings page writes through to it.
First run materializes a default file. Example:

```toml
mode = "cooperative"          # "cooperative" | "gateway"
payload_storage = false       # metadata-only by default
handover = "handover"         # on stop, leave the engine serving (gateway)
data_dir = "/path/to/data"

[ports]
bind = "127.0.0.1"            # loopback only unless you opt out
proxy = 11434                 # public port the proxy owns
studio = 7100                 # local web UI
shadow = 11999               # where the engine is relocated (gateway)
upstream = 11434              # the real engine port the proxy forwards to (cooperative)

[retention]
kind = "age"                  # "age" | "size" | "unlimited"
days = 30

[masking]                     # opt-in PII masking (off by default)
enabled = false              # master switch; false = pure observe
dry_run = true               # when enabled, true = preview only (would_mask)
# kinds = ["email", "credit_card"]  # omit for all high-confidence kinds
# block_kinds = ["api_key"]  # STOP these requests instead of masking them.
                             # Empty (default) = nothing is ever blocked. Only
                             # applies when enabled = true and dry_run = false.

[archive]                     # Preservation (off by default)
enabled = false              # keep a durable copy of coding-agent history
auto = false                 # snapshot on start and periodically
redact = false               # replace secrets with a placeholder before storing
                             # (lossy: turning this on re-archives what you have)
# retention_days = 365       # omit to keep forever, which is the default

[pricing]                     # cost estimates — override when prices change
cloud_input_per_m = 2.50     # the baseline "cost avoided" compares against
cloud_output_per_m = 10.0
cloud_label = "GPT-4o list price"
# USD per 1M tokens, matched by substring against the model name, first wins.
# Omit `models` entirely to use the built-in table.
# [[pricing.models]]
# match = "opus"
# input = 15.0
# output = 75.0
# cache = 1.5
```

`Config::validate()` rejects port collisions (e.g. in Cooperative mode the proxy
port must differ from the upstream engine port — the proxy cannot forward to
itself).

## Architecture / module map

One binary, two HTTP servers (proxy + Studio) sharing a single store, fed by a
deterministic brain. The platform-independent **brain** is kept strictly free of
any dependency on the proxy existing, so it can later compile as an embeddable
library. The per-OS **engine** layer is the only place with platform-specific
code.

```
client app ──▶ proxy (:proxy) ──▶ upstream engine (Ollama :11434)
                  │  tee (bounded, drop-oldest)
                  ▼
              async logger ──▶ PII scan (brain) ──▶ store (SQLite, single-writer)
                                                        ▲
              Studio (:studio) ── JSON API + SSE ───────┘  (token-gated)
```

| Module            | Responsibility |
|-------------------|----------------|
| `main.rs` / `cli` | Entry point; `clap` CLI: `adopt status start stop doctor revert logs update`. Handlers wire config → store → engine → proxy → studio, rendered with the calm status-dot palette. |
| `config`          | The single TOML config: load/save/validate, per-OS data dir, ports, mode, privacy + retention. |
| `proxy`           | The transparent reverse-proxy spine. `proxy/handlers.rs` mirrors `/api/*` (NDJSON) + `/v1/*` (SSE) with a verbatim catch-all; `proxy/upstream.rs` is the streaming forwarder + tee; `proxy/mod.rs` runs the async logger that assembles records, scans PII, and enqueues writes off the request path. |
| `store`           | Encrypted-capable SQLite, **single-writer** model (one thread owns the connection; WAL; readers concurrent). Metadata/payload split. `store/schema.rs` owns migrations. `store::keys` manages keyring secrets (DB key + per-install Studio token). |
| `brain`           | Platform-independent judgment + PII. `brain/pii.rs` is the deterministic detector (email, phone, Luhn-validated cards, entropy-gated API keys, IPv4/IPv6, custom patterns) — findings carry **hashed** values only. `brain/mod.rs` defines the (no-op in v0) judgment interface research later plugs into. |
| `engine`          | The only per-OS code. `engine/detect.rs` finds running engines; `engine/cooperative.rs` is the everywhere-impl (no system changes); `engine/systemd.rs` is Linux-only reversible Gateway adoption; `engine/adopt.rs` orchestrates detect → adopt → journal; `engine/supervise.rs` supervises a Gateway-managed engine with handover policy. |
| `studio`          | The local web UI server. `studio/assets.rs` serves the `rust-embed`'d SPA (`studio-web/`); `studio/api.rs` is the JSON API + SSE stream; `studio/auth.rs` enforces bearer-token + Host allowlist + CORS on `/api/*`; `studio/dto.rs` is the wire contract. |
| `exposure`        | The "is your engine exposed to the network?" doctor (the acquisition hook). |
| `update`          | In-app auto-update over `axoupdater`: reads the cargo-dist install receipt, queries the latest GitHub release, applies it via the shipped installer. Powers `saffev update` + the Studio `/api/update` routes. **Contacts GitHub release metadata only — no user/content data leaves the device.** No-receipt (dev) builds degrade gracefully, never panic. |
| `attribution`     | Source-app attribution (PID lookup → header fallback), computed off the tee. |
| `tokens`          | Token/usage accounting: trust engine `usage` (exact) else estimate off-path (`~`). |
| `ui`              | The CLI palette (status dots, alignment, color detection). |
| `brand`           | Single source of truth for the product name. |
| `studio-web/`     | The embedded SPA (`index.html`, `app.js`, `styles.css`, `tokens.css`). |

## Status: v0/v1 implemented vs deferred

**Implemented and verified in this build:**

- Transparent streaming passthrough for Ollama NDJSON **and** OpenAI SSE, teeing
  both into a bounded, decoupled logger (`proxy`).
- On-device SQLite store, single-writer, with the metadata/payload split and a
  migrated schema (`store`). Retention by age/size. **Encrypted at rest by
  default** (bundled SQLCipher). 329 passing unit tests.
- Deterministic PII detection: email, phone, Luhn-validated cards, entropy-gated
  API keys, IPv4/IPv6, and custom patterns — values hashed, never stored raw
  (`brain/pii.rs`). Masking of requests, non-streamed responses, and live streams
  (bounded holdback). Optional **blocking** for kinds that must never be sent.
- Coding-agent history: five readers, full-text search over preserved
  transcripts, the whole-history privacy report, opt-in redaction, and the
  tamper-evident archive with an audit bundle.
- The unified **Timeline** across proxied calls and coding sessions.
- The eval pipeline: a deterministic 8-category safety guard and an opt-in,
  sampled, concurrency-capped LLM-as-judge, both **off by default** and never on
  the request path.
- The Studio web server: embedded SPA + token-gated JSON API + SSE live stream,
  loopback-bound with Host allowlist + CORS (`studio`).
- The CLI: `status`, `doctor`, `start`, `stop`, `logs`, `adopt`, `revert`,
  `run`/`env`/`shell`, `update`, with fail-open rendering (`cli`).
- Cooperative mode everywhere (no system changes), the default on macOS.
- Exposure doctor, source-app attribution, token accounting, keyring-backed
  secrets, config load/save/validate.
- Linux/Ollama Gateway adoption + reversible revert via systemd drop-ins
  (`engine/systemd.rs`, compiled `cfg(target_os = "linux")`).

**Known limits — stated plainly rather than discovered later:**

- **The coding-agent readers are proven on macOS only.** The Linux and Windows
  storage paths are implemented but not yet validated against real on-disk data.
- **Linux Gateway adoption now has an end-to-end test** in CI
  (`.github/workflows/linux-gateway.yml`). GitHub's ubuntu runners are full VMs
  with systemd, so every push exercises the real path: write the drop-in, disable
  autostart, relocate the engine to the shadow port, then revert and assert the
  host came back exactly as it was. The engine itself is a small stand-in
  (`.github/ci/fake-ollama.py`) because the thing under test is a systemd
  mechanism, not inference.
- **The Windows binary is unsigned**, so SmartScreen will warn. There is no
  PowerShell installer yet; the shell installer covers macOS and Linux.
- **Searching inside conversations covers preserved sessions**, not every session
  on disk. Scanning every live transcript per keystroke would mean re-parsing
  hundreds of megabytes; the archive exists to pay that cost once. The UI says
  which it is doing.
- **Small local guards are unreliable on adversarial input**, and markedly worse
  on African and other low-resource languages. That is why no guard runs inline
  and why the judgment interface is a socket rather than a shipped verdict.

**Deferred (not in this build):**

- **macOS Gateway adoption** — Homebrew/CLI, only if it passes the reversibility
  bar. macOS today runs Cooperative.
- **LM Studio Gateway** — Cooperative only; LM Studio is a GUI app with no
  systemd unit to rebind, so `adopt --engine lmstudio` deliberately stays
  Cooperative.
- **Purpose-trained localized guards** — the highest-value thing that could plug
  into the judgment socket, and a research effort rather than a code change.

## Smoke test (the exact commands used to verify this build)

Non-destructive end-to-end check against a **live** Ollama, run in Cooperative
mode on a spare port so the real engine on `11434` is never touched.

```sh
source "$HOME/.cargo/env"

# 0. Build (encrypted-by-default) and run the unit suite.
cargo build                       # Finished, green
cargo test                        # 207 passed; 0 failed

# 1. No-keyring env (headless): pin both secrets so nothing prompts.
export SAFFEV_INSTALL_TOKEN=dev SAFFEV_DB_KEY=devkey

# 2. Cooperative config on spare ports -> real Ollama on 11434, isolated data dir.
SMOKE=$(mktemp -d /tmp/saffev-smoke.XXXX)
cat > "$SMOKE/saffev.toml" <<TOML
mode = "cooperative"
payload_storage = false
data_dir = "$SMOKE"
[ports]
bind = "127.0.0.1"
proxy = 8090
studio = 7102
shadow = 11999
upstream = 11434
[retention]
kind = "age"
days = 30
TOML

# 3. Daemonize Saffev; it detaches and returns. (--config or SAFFEV_CONFIG.)
./target/debug/saffev --config "$SMOKE/saffev.toml" start --foreground \
  > "$SMOKE/saffev.log" 2>&1 &

# 4. Send a request WITH PII (an email) THROUGH the proxy.
curl -s http://127.0.0.1:8090/api/generate \
  -d '{"model":"qwen3.5:2b","prompt":"My email is a@b.com, say hi","stream":false}'

# 5. ENCRYPTION: the DB has no plaintext "SQLite format 3" header, system
#    sqlite3 cannot read it, and the raw email never appears on disk.
head -c 16 "$SMOKE/saffev.db" | grep -aq 'SQLite format 3' \
  && echo PLAINTEXT || echo encrypted
grep -a -c 'a@b.com' "$SMOKE"/saffev.db*    # -> 0 0 0 (raw secret never stored)

# 6. ENGINE CARD + auth: token-gated API surfaces the cooperative upstream.
curl -s -H 'Authorization: Bearer dev' -H 'Host: 127.0.0.1:7102' \
  http://127.0.0.1:7102/api/engines            # ollama :11434 cooperative healthy
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7102/api/engines  # 401

# 7. FONTS: served HTML/CSS reference no Google CDN; a local woff2 is 200.
curl -s http://127.0.0.1:7102/fonts.css | grep -c googleapis  # -> 0
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' \
  http://127.0.0.1:7102/fonts/jetbrains-mono.woff2            # 200 font/woff2

# 8. Stop gracefully (Ollama on 11434 is left untouched).
./target/debug/saffev --config "$SMOKE/saffev.toml" stop
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:11434/api/tags  # 200
```

**Result of this run:**

- Build green; all 207 unit tests pass.
- The request proxied through `:8090` to Ollama on `:11434` verbatim.
- **Encryption:** the on-disk DB header is random (no `SQLite format 3` magic),
  system `sqlite3` rejects it ("file is not a database"), and `grep` of the DB +
  WAL for the raw email returns 0 — encrypted at rest, and metadata-only held.
- **Attribution:** the `/api/generate` POST resolved `source_app=curl` with
  `confidence=pid` (socket-PID lookup), GETs fell back to `header`.
- **Engine card:** `/api/engines` showed `ollama :11434 cooperative healthy`;
  the same route without a bearer token returned `401` (auth gate works).
- **Fonts:** `fonts.css` had 0 `googleapis` references; `/fonts/*.woff2` returned
  `200 font/woff2` — the Studio is fully offline.
- **Masking:** with `[masking] enabled=true`, dry-run recorded request-side
  findings as `would_mask` (traffic unchanged); with `dry_run=false` a prompt
  whose email was echoed back came through as `[EMAIL]` (the model never saw the
  raw value) and the finding was recorded as `masked`.
- **Stop:** `saffev stop` shut the daemon down gracefully, removed the PID file,
  and Ollama's `/api/tags` still returned `200` — the engine was never modified.

## Releasing / macOS signing

Releases are cut by `dist` (cargo-dist 0.32.0): push a version tag and
`.github/workflows/release.yml` builds the archives, the shell installer, and the
GitHub Release. macOS **code-signing + notarization** is wired in and **gated on
Apple secrets** — until the secrets below exist, the pipeline still produces
working (unsigned) builds, so nothing breaks before you opt in (fail-open).

**How it works (mechanism).**

- **Code-signing** uses `dist`'s native `macos-sign = true`. On the macOS build
  runner `dist` creates an ephemeral keychain, imports your Developer ID
  Application cert, and runs `codesign --sign` on each binary **before** it is
  tarred and checksummed — so the published `.tar.xz` and the checksums baked
  into `saffev-installer.sh` are computed over the signed binary.
- A pre-build step (`.github/build-setup.yml`) sets `CODESIGN_OPTIONS=runtime`
  so the signature uses the **hardened runtime** (required for notarization).
- **Notarization** runs as a post-announce job (`.github/workflows/notarize-macos.yml`):
  after the release is published it downloads each macOS archive, verifies the
  signature has a hardened runtime + secure timestamp, zips the signed binary,
  and submits it with `xcrun notarytool submit --wait`. A bare CLI binary can't
  be *stapled*, so the notarization ticket is registered with Apple and
  **Gatekeeper verifies it online** on first run — the published archive is never
  modified or re-uploaded (that would break the installer's checksums).

**GitHub Actions secrets to add** (Settings → Secrets and variables → Actions).
Signing turns on when the first three are set; notarization turns on when the
last three are set.

| Secret | What it is / how to get it |
| --- | --- |
| `CODESIGN_CERTIFICATE` | Your **Developer ID Application** certificate exported from Keychain Access as a `.p12`, then base64-encoded: `base64 -i DeveloperID.p12 \| pbcopy`. Paste the base64 string. |
| `CODESIGN_CERTIFICATE_PASSWORD` | The password you set when exporting the `.p12`. |
| `CODESIGN_IDENTITY` | The signing identity string, e.g. `Developer ID Application: Your Name (TEAMID)`. Find it with `security find-identity -v -p codesigning`. |
| `APPLE_ID` | Your Apple Developer account email (the Apple ID used for notarization). |
| `APPLE_APP_PASSWORD` | An **app-specific password** for that Apple ID — appleid.apple.com → Sign-In & Security → App-Specific Passwords. |
| `APPLE_TEAM_ID` | Your 10-character Apple Developer **Team ID** (developer.apple.com → Membership). |

Notes:

- Export the `.p12` with the **private key** included (select both the cert and
  its key in Keychain Access before exporting), or `codesign` can't use it.
- Notarization authenticates with your Apple ID + an app-specific password +
  Team ID (`notarytool --apple-id --password --team-id`). An App Store Connect
  API key is a more robust alternative (not tied to a personal account) — switch
  by editing `.github/workflows/notarize-macos.yml` if you prefer it later.
- After adding the secrets, the next tagged release signs + notarizes
  automatically. Verify a downloaded build with
  `codesign --verify --strict --verbose=2 ./saffev` and
  `spctl -a -vvv -t install ./saffev` (Gatekeeper assessment).
- **Do not** commit any cert, `.p8`, or password to the repo — only the GitHub
  secret store. The pipeline reads them by `secrets.*` env at run time.

## License

MIT OR Apache-2.0.
