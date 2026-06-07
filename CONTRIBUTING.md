# Contributing to Saffev

Thanks for your interest in improving Saffev. This is a single Rust binary that
sits transparently in front of a local LLM engine and observes its traffic
on-device.

## Build

```sh
cargo build
```

The build is self-contained (SQLCipher is bundled). See the README for the
one-command install and the smoke test.

## Run tests

```sh
cargo test
```

Please keep the suite green and add tests for new behavior. Run `cargo fmt`
before opening a PR.

## Design system

UI and brand work should match the existing Studio styling in `studio-web/`
(`styles.css` + `tokens.css`) and the CLI palette in `src/ui/palette.rs`.

## Hard invariants (please keep them)

PRs must preserve the product's hard invariants. These are not negotiable:

- **Fail-open.** If anything in the tool errors — proxy, PII, storage,
  supervisor — the request still reaches the engine and the response still
  reaches the app. A bug must never break the user's app.
- **On-device.** Nothing leaves the box. No cloud, no content telemetry, no
  external calls except to the local engine the tool supervises.
- **Observe by default.** The tool never blocks or mutates traffic by default.
  Any change (e.g. PII masking) is explicit opt-in, behind a dry-run.

PRs that weaken any of these will be asked to change before merge.
