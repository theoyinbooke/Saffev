# Saffev — local ai studio

Saffev is a single Rust binary that sits transparently **in front of a local LLM
engine** (Ollama on `127.0.0.1:11434`, LM Studio later) and **observes** its
traffic on-device. It is a reverse proxy + a local web "Studio" that lets you
see, structure, and protect everything your local models send and receive —
without ever leaving the machine and without changing what the engine returns.

It is the **passive core** of a larger vision: usable today with zero research
dependency, and also the instrument the lab's research track later plugs into.

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
- **Observe-only.** v0/v1 never block or mutate traffic. (Opt-in PII masking is
  the last item of the v1 plan, behind a dry-run.)

## Build / run / test

`cargo` lives at `~/.cargo/bin`. If it is not on your `PATH`:

```sh
source "$HOME/.cargo/env"
```

### Build

```sh
cargo build              # debug; guaranteed-green, plain bundled SQLite
cargo build --release    # optimized
```

At-rest DB encryption (SQLCipher) is **off by default** so the stock build needs
no system crypto deps. Enable it with:

```sh
cargo build --features sqlcipher
```

With the feature on, the DB is opened with a key pulled from the OS keyring via a
`PRAGMA key` handshake. (Acceptance §10.5 requires this for release builds.)

### Test

```sh
cargo test               # 152 unit tests across all modules
```

### Run

```sh
./target/debug/saffev --help
./target/debug/saffev status      # engines, ports, mode, health, exposure
./target/debug/saffev doctor      # port conflicts, exposure, permissions
./target/debug/saffev start       # run the proxy + Studio (foreground in v0)
./target/debug/saffev logs -f     # stream recorded activity
```

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

## Status: v0 implemented vs deferred

Per `04-implementation-plan.md`, this build is the **passive core (v0 → v1)**.
The validation refuted four of six original "smart" claims; all four are in the
deferred set. Everything in scope is independently reliable and ships no
unreliable model signal.

**Implemented and verified in this build:**

- Transparent streaming passthrough for Ollama NDJSON **and** OpenAI SSE, teeing
  both into a bounded, decoupled logger (`proxy`).
- On-device SQLite store, single-writer, with the metadata/payload split and a
  migrated schema (`store`). Retention by age/size. 152 passing unit tests.
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

- **At-rest encryption is gated behind the `sqlcipher` cargo feature** (OFF by
  default). The default build's DB is plain bundled SQLite. v1's acceptance bar
  requires the feature on for release; flipping the default to on is a v1 item.
- **macOS Gateway adoption** — Homebrew/CLI, only if it passes the reversibility
  bar (v2). macOS today runs Cooperative.
- **LM Studio Gateway** — Cooperative only later; LM Studio's Auto-Evict and
  opt-in server make adoption unsafe until the serving research lands.
- **Windows** — out of scope.
- **Opt-in PII masking** (behind a dry-run) — the last item of the v1 plan.
- **The research track** — model-based guards, judges, evaluation, and the
  scheduler. The schema and a pluggable judgment interface are *ready* (Safety /
  Evaluation tables and Studio panels exist as disabled placeholders), but this
  build ships **none** of them. They light up only after `03-research-agenda.md`
  components graduate, behind a device-capability gate, labeled honestly.

## Smoke test (the exact commands used to verify this build)

Non-destructive end-to-end check against a **live** Ollama, run in Cooperative
mode on a spare port so the real engine on `11434` is never touched.

```sh
source "$HOME/.cargo/env"

# 0. Build (ground truth) and run the unit suite.
cargo build                       # Finished, green
cargo test                        # 152 passed; 0 failed

# 1. CLI renders.
./target/debug/saffev --help
./target/debug/saffev status

# 2. Pick an installed model from the live engine.
curl -s http://127.0.0.1:11434/api/tags    # -> qwen3.5:2b (used below)

# 3. Cooperative config: proxy on a spare port -> real Ollama on 11434.
SMOKE=/tmp/saffev-smoke
mkdir -p "$SMOKE"
cat > "$SMOKE/saffev.toml" <<'TOML'
mode = "cooperative"
payload_storage = false
data_dir = "/tmp/saffev-smoke"
[ports]
bind = "127.0.0.1"
proxy = 8088
studio = 7100
shadow = 11999
upstream = 11434
[retention]
kind = "age"
days = 30
TOML

# 4. Start Saffev in the background (foreground process, detached).
SAFFEV_CONFIG="$SMOKE/saffev.toml" ./target/debug/saffev start --foreground \
  > "$SMOKE/saffev.log" 2>&1 &
echo $! > "$SMOKE/pid"

# 5. Send a streaming chat WITH PII (an email) THROUGH the proxy.
curl -s http://127.0.0.1:8088/api/chat \
  -d '{"model":"qwen3.5:2b","messages":[{"role":"user","content":"My email is a@b.com, say hi"}],"stream":true}'

# 6. Confirm a row was logged, and the email PII was detected (hashed).
sqlite3 "$SMOKE/saffev.db" "SELECT source_app, model, endpoint FROM requests;"
sqlite3 "$SMOKE/saffev.db" "SELECT type, side, action FROM pii_findings WHERE type='email';"
grep -a -c 'a@b.com' "$SMOKE"/saffev.db*    # -> 0  (raw secret never stored)

# 7. Studio serves HTML; its API is token-gated.
curl -s -i http://127.0.0.1:7100/ | head -3                 # 200 text/html
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7100/api/health  # 401

# 8. Stop the background Saffev (Ollama on 11434 is left untouched).
kill "$(cat "$SMOKE/pid")"
```

**Result of this run:**

- Build green; all 152 unit tests pass.
- The streaming response proxied through `:8088` from Ollama on `:11434`,
  verbatim, token-by-token (NDJSON).
- One `requests` row logged (`source_app=curl`, `model=qwen3.5:2b`,
  `endpoint=/api/chat`, `stream=1`) with a joined `responses` row.
- The request-side email `a@b.com` was detected (`type=email`, `high`,
  `observed`) and stored **hashed** — `grep` of the DB for the raw email
  returns 0 matches. The `payloads` table is empty (metadata-only default held).
- The Studio served the SPA (`200 text/html`); `/api/health` returned `401`
  without a bearer token (auth gate works).
- After stop, both Saffev ports were down and Ollama's `/api/tags` still
  returned `200` — the engine was never relocated or modified.

One precision note surfaced: the model's long "thinking" output emitted many
timestamp-like digit runs that the phone regex matched (2229 phone findings on
the response side). The detect → hash → store pipeline handled them correctly;
tightening phone-number precision against numeric noise is a v1 detector item.

## License

MIT OR Apache-2.0.
