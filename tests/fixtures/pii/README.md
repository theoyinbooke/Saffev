# PII fixture corpus (G1 harness)

Hand-labeled corpus scored by `cargo test --test pii_bench -- --nocapture`
(see `docs/gauntlets/GAUNTLETS.md` §G1). Results land in
`bench/pii-results.json`.

Every value in this file is fake: documentation test numbers (4111…,
AKIAIOSFODNN7EXAMPLE, the DE89 example IBAN), example.com-family domains, and
invented tokens shaped like real ones. Never add a real secret, even revoked.

## Schema (one JSON object per line)

| Field | Meaning |
|---|---|
| `id` | Stable case id (`<kind>-NNN` positive, `<kind>-tNN` trap, `xfail-NNN`) |
| `text` | The text scanned |
| `expect` | Findings a correct detector must emit: `{kind, value}` where `kind` is a `PiiKind` wire key and `value` the exact matched substring |
| `trap` | Marks an adversarial negative aimed at one detector (`expect` is `[]`) |
| `xfail` | Out-of-scope case naming the future kind it targets (`ssn`, `iban`, `jwt`, `private_key`, `connection_string`, `mac_address`, …). Not scored; reported as a known gap. These are the G1 breadth targets — when a detector lands, promote the case to a scored positive. |
| `note` | Why the case exists |

## Scoring rules (anti-gaming contract)

- A finding counts as a true positive only on exact `(kind, value)` match —
  a truncated span is a miss **and** a false positive, because masking a
  truncated span would leak the remainder.
- False positives are charged to the kind the detector claimed, on every
  scored case (traps and positives alike).
- `xfail` cases are exempt from scoring both ways: nothing they fire is
  penalized, nothing they miss counts. The price of the exemption is that they
  are listed verbatim in the results artifact as `known_gaps`.
- The harness refuses to run if the scored corpus shrinks below 55 cases or
  the trap count below 15 — deleting hard cases is not a way to raise a score.
- Floors in `tests/pii_bench.rs` may only move up. A change that needs a floor
  lowered must fix the detector or add a documented `xfail` — never silently.
