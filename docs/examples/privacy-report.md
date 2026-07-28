# Saffev privacy report — last 30 days

Generated 2025-07-28 10:53 UTC · saffev v0.7.1 · **generated offline — producing this report performs no network calls**

## What left this machine?

- **2 model exchanges** were proxied in the period; every one went to a **local engine** (see Exposure below for whether anything else could reach it).
- Saffev stored **metadata only — raw prompt/response text was never written to disk** for those exchanges. 
- **Masking was off** (observe-only): request bodies passed through unchanged; findings below are what a masking policy WOULD have caught.

> **Boundary:** this report covers traffic that went THROUGH the Saffev proxy and agent transcripts on THIS machine's disk. Traffic that bypassed the proxy (apps pointed directly at an engine or a cloud API) is invisible to it and is not claimed.

## Traffic

| | |
|---|---|
| Exchanges | 2 |
| Failed / errored | 1 (50%) |
| Applications seen | 2 |
| Models used | 2 |
| Engines | 1 |

**By application** (requests):

- Continue: 1
- aider: 1

**By model**:

- llama3.3:70b: 1
- qwen3:8b: 1

> **Boundary:** application attribution is socket-PID based where possible (high confidence) and header-based otherwise; "unknown" rows had neither.

## Sensitive-data findings

**2 findings** across 2 kinds — 2 on the request side (outbound to the engine), 0 on responses.

**By kind**:

- ApiKey: 1
- Email: 1

**By application**:

- Continue: 1
- aider: 1

> **Boundary:** findings come from Saffev's deterministic detector suite (see `bench/pii-results.json` for its measured precision/recall on the public corpus). Only hashed spans are stored — the report never contains matched values.

## Network exposure

- engine reachable from loopback only (127.0.0.1) — not exposed to the network

> **Boundary:** the verdict inspects the OS socket table at generation time; it says nothing about past bindings.

## Coding-agent sessions on this machine

- Claude Code: 12 sessions
- Codex: 5 sessions
- Aider: 3 sessions

> **Boundary:** session counts come from each tool's own on-disk store (see `bench/agents-results.json` for the fixture-proven coverage per tool). Tools that encrypt their history (e.g. Windsurf) cannot be read and are not counted.

## Archive integrity

- **INTACT** — 42 chain entries over 17 sessions recomputed correctly; no post-hoc edits detected.
- 17 preserved sessions · 812 messages · 1204224 bytes

> **Boundary:** integrity is a SHA-256 hash chain over archived content; it proves the archive was not edited after capture, not that the source tools' files were unmodified before capture.

## Configuration at generation time

- Payload storage: **off (default)**
- Masking: **off (observe-only)**
- Retention: Age { days: 30 }
- Pricing table verified: 2026-07-28 (estimates only; never fetched)
