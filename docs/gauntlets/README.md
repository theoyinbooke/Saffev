# Saffev Gauntlets

Saffev's adaptation of the **Gauntlet Loop** (somethingbig.ai/gauntlet-loop): cycle
builder/critic rounds against a **measurable bar built from concrete best-in-class
references** until the output meets or beats the bar. Never vibes — artifacts vs.
references.

The three documents here:

| File | What it is |
|---|---|
| [`BAR.md`](BAR.md) | The competitive bar — best-in-class per capability (open **and** closed source), Saffev's verdict against each, and the moat nobody else covers. Research dated **July 2026**. |
| [`GAUNTLETS.md`](GAUNTLETS.md) | The eight gauntlets — the smallest pieces of Saffev that can be improved and judged separately, each with its bar, artifacts, and critic rubric. |
| This file | The rules of the loop. |

## The loop, adapted to Saffev

1. **Goal with references, not implementation.** Each gauntlet states a destination
   and names the concrete competitor artifact that is the bar (e.g. "ccusage's
   `blocks` report on the same `~/.claude` data", "Presidio's entity list on the
   fixture corpus"). The builder decides how.
2. **The bar is measurable.** Every gauntlet defines its artifact (a score from a
   harness, a side-by-side screenshot, a fixture-suite pass count) and the number
   or comparison that means "bar met". If a gauntlet's bar can't be measured yet,
   building the measurement harness IS the first loop of that gauntlet.
3. **Builder–critic separation.** *Never let the builder grade itself.* The critic
   runs with fresh context, is given only the gauntlet definition, the bar
   references, and the produced artifacts, and must answer two questions:
   **(a)** bar met — yes/no with evidence, **(b)** the single biggest remaining gap.
4. **Loop until the bar.** No fixed round count. A gauntlet closes when the critic
   says the bar is met **and** the evidence is committed (harness output, fixture
   results, screenshots) so the claim is reproducible.

## Hard constraints every gauntlet inherits

These are Saffev's invariants; a gauntlet round that violates one fails
automatically, whatever the score:

- **On-device.** No feature may introduce an outbound call beyond the local engine
  and the GitHub release check.
- **Observe-only, fail-open.** The proxy never blocks or degrades the inference
  path; all analysis stays off the hot path.
- **Metadata-only by default; encrypted at rest; zero telemetry.**
- **Honest confidence.** Findings and attribution carry their real confidence;
  benchmark claims carry their measurement boundary.

Deliberately **out of scope** (misaligned with the invariants, do not build to
these bars): gateway routing/fallbacks/semantic caching (LiteLLM/Portkey/Kong
territory), cloud team control planes, in-path blocking as a default posture.

## Running a gauntlet round

```
1. Pick the gauntlet (GAUNTLETS.md) — or the one whose critic last named the
   biggest gap across the board.
2. Builder session: implement toward the bar. Produce the artifact(s) the
   gauntlet names. Commit.
3. Critic session (FRESH context — new conversation/agent, no builder history):
   give it the gauntlet section + bar references + artifacts only.
   It returns: bar met? / biggest remaining gap / evidence.
4. Record the round in the gauntlet's log (docs/gauntlets/log/<gauntlet>.md):
   date, commit, artifact, critic verdict.
5. Repeat from 2 until bar met; then keep the harness running in CI so the
   bar can't silently regress.
```

## Credibility rules for any published benchmark numbers

Adopted from ClickBench / aider polyglot / uv BENCHMARKS.md practice:

1. Ship the harness, not just the chart — one command reproduces every number.
2. Pin versions, hardware, and the Saffev commit hash for every run.
3. Fixed public fixture corpus + written anti-gaming rules and stated limitations.
4. Show unfavorable configurations too; never silently omit a bad result.
5. State the measurement boundary (what is and isn't inside the timed/scored path).
6. Version the results: date-stamped runs, methodology changelog, re-run
   competitors when they release.
