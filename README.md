# Saffev — local ai studio

Saffev is a single Rust binary that sits transparently **in front of a local LLM
engine** (Ollama on `127.0.0.1:11434`, LM Studio later) and **observes** its
traffic on-device. It is a reverse proxy + a local web "Studio" that lets you
see, structure, and protect everything your local models send and receive —
without ever leaving the machine and without changing what the engine returns.

It is the **passive core** of a larger vision: usable today with zero research
dependency, with a pluggable judgment interface that later guard/eval work plugs
into.

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

> **macOS, first run:** the binary is not yet code-signed, so Gatekeeper may say
> it "cannot be verified". Allow it once via **System Settings → Privacy &
> Security → Open Anyway**, or `xattr -d com.apple.quarantine "$(which saffev)"`.
> Signed + notarized builds are on the way. macOS may also prompt to allow
> **Keychain** access on first start (for the encryption key + Studio token) —
> choose **Always Allow**.

Then start it **alongside** your existing Ollama (Cooperative mode — it never
touches your engine):

```sh
mkdir -p ~/.config/saffev
cat > ~/.config/saffev/saffev.toml <<'TOML'
mode = "cooperative"
[ports]
proxy = 8088      # point your apps' Ollama base URL here
studio = 7100     # open the Studio here
upstream = 11434  # your real Ollama
TOML

saffev start --config ~/.config/saffev/saffev.toml   # daemonizes; prints the Studio URL
```

Open the Studio at **http://localhost:7100** and point your apps' Ollama base URL
at **http://localhost:8088** to see their traffic. `saffev status` / `saffev logs
-f` / `saffev stop` to manage it. Full details in **Build / run / test** and
**Configuration** below.

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
- **Nothing leaves the device.** The only outbound network call is to the local
  engine on loopback.
- **Observe by default.** Traffic is never mutated unless you explicitly opt in
  to PII masking *and* leave dry-run. Masking is fail-open: any error forwards the
  original request untouched.

## What's new in v1

v1 builds on the passive core with seven shipped features, all preserving the
invariants above (fail-open, on-device, observe-by-default, transparent
streaming):

- **At-rest encryption ON by default.** The stock build links bundled SQLCipher;
  the database is encrypted with a key from the OS keyring (or `SAFFEV_DB_KEY`).
  Opt out with `--no-default-features` for a plain SQLite build.
- **Opt-in PII masking with dry-run.** Off by default. When enabled in dry-run,
  traffic passes through unchanged and findings are recorded as `would_mask`.
  Flip dry-run off to redact high-confidence request-side PII (email, card, API
  key, IP, phone) to typed placeholders (`[EMAIL]`, `[CARD]`, …) **before** the
  request reaches the engine — the model never sees the raw value. Recorded as
  `masked`. Low-confidence findings are never masked. Streaming responses are
  left untouched (a span can cross chunks; the transparent-streaming invariant
  forbids buffering).
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
| `main.rs` / `cli` | Entry point; `clap` CLI: `adopt status start stop doctor revert logs`. Handlers wire config → store → engine → proxy → studio, rendered with the calm status-dot palette. |
| `config`          | The single TOML config: load/save/validate, per-OS data dir, ports, mode, privacy + retention. |
| `proxy`           | The transparent reverse-proxy spine. `proxy/handlers.rs` mirrors `/api/*` (NDJSON) + `/v1/*` (SSE) with a verbatim catch-all; `proxy/upstream.rs` is the streaming forwarder + tee; `proxy/mod.rs` runs the async logger that assembles records, scans PII, and enqueues writes off the request path. |
| `store`           | Encrypted-capable SQLite, **single-writer** model (one thread owns the connection; WAL; readers concurrent). Metadata/payload split. `store/schema.rs` owns migrations. `store::keys` manages keyring secrets (DB key + per-install Studio token). |
| `brain`           | Platform-independent judgment + PII. `brain/pii.rs` is the deterministic detector (email, phone, Luhn-validated cards, entropy-gated API keys, IPv4/IPv6, custom patterns) — findings carry **hashed** values only. `brain/mod.rs` defines the (no-op in v0) judgment interface research later plugs into. |
| `engine`          | The only per-OS code. `engine/detect.rs` finds running engines; `engine/cooperative.rs` is the everywhere-impl (no system changes); `engine/systemd.rs` is Linux-only reversible Gateway adoption; `engine/adopt.rs` orchestrates detect → adopt → journal; `engine/supervise.rs` supervises a Gateway-managed engine with handover policy. |
| `studio`          | The local web UI server. `studio/assets.rs` serves the `rust-embed`'d SPA (`studio-web/`); `studio/api.rs` is the JSON API + SSE stream; `studio/auth.rs` enforces bearer-token + Host allowlist + CORS on `/api/*`; `studio/dto.rs` is the wire contract. |
| `exposure`        | The "is your engine exposed to the network?" doctor (the acquisition hook). |
| `attribution`     | Source-app attribution (PID lookup → header fallback), computed off the tee. |
| `tokens`          | Token/usage accounting: trust engine `usage` (exact) else estimate off-path (`~`). |
| `ui`              | The CLI palette (status dots, alignment, color detection). |
| `brand`           | Single source of truth for the product name. |
| `studio-web/`     | The embedded SPA (`index.html`, `app.js`, `styles.css`, `tokens.css`). |
| `design/`         | Brand + design-system source (`brand.json`, `tokens.css`, the reference HTML). |

## Status: v0/v1 implemented vs deferred

Per `04-implementation-plan.md`, this build is the **passive core, v1 complete**
(see "What's new in v1" above). The model-based capabilities are in the deferred
set. Everything in scope is independently reliable and ships no unreliable model
signal.

**Implemented and verified in this build:**

- Transparent streaming passthrough for Ollama NDJSON **and** OpenAI SSE, teeing
  both into a bounded, decoupled logger (`proxy`).
- On-device SQLite store, single-writer, with the metadata/payload split and a
  migrated schema (`store`). Retention by age/size. **Encrypted at rest by
  default** (bundled SQLCipher). 207 passing unit tests.
- Deterministic PII detection (observe-only): email, phone, Luhn-validated cards,
  entropy-gated API keys, IPv4/IPv6, and custom patterns — values hashed, never
  stored raw (`brain/pii.rs`).
- The Studio web server: embedded SPA + token-gated JSON API + SSE live stream,
  loopback-bound with Host allowlist + CORS (`studio`).
- The CLI: `status`, `doctor`, `start`, `stop`, `logs`, `adopt`, `revert`, with
  fail-open rendering (`cli`).
- Cooperative mode everywhere (no system changes), the default on macOS.
- Exposure doctor, source-app attribution, token accounting, keyring-backed
  secrets, config load/save/validate.
- Linux/Ollama Gateway adoption + reversible revert via systemd drop-ins
  (`engine/systemd.rs`, compiled `cfg(target_os = "linux")`).

**Deferred (not in this build):**

- **macOS Gateway adoption** — Homebrew/CLI, only if it passes the reversibility
  bar (v2). macOS today runs Cooperative.
- **LM Studio Gateway** — Cooperative only later; LM Studio's Auto-Evict and
  opt-in server make adoption unsafe until the serving research lands.
- **Windows** — out of scope.
- **Model-based capabilities** — guards, judges, evaluation, and the scheduler.
  The schema and a pluggable judgment interface are *ready* (Safety / Evaluation
  tables and Studio panels exist as disabled placeholders), but this build ships
  **none** of them. They light up only once those components graduate, behind a
  device-capability gate, labeled honestly.

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

## License

MIT OR Apache-2.0.
