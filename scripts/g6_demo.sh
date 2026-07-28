#!/usr/bin/env bash
# G6 demo — trip all five monitor rule classes and capture the evidence
# (docs/gauntlets/GAUNTLETS.md §G6).
#
# What this does:
#   1. Runs the signals bench (`tests/signals_bench.rs`), which builds a fixture
#      store tripping every rule class — PII spike, new source app, exposure
#      verdict change, latency p95, spend-per-day — then evaluates twice to
#      prove each rule FIRES and then DEDUPLICATES.
#   2. Shows the emitted artifact (`bench/signals-results.json`): per-rule
#      fired/deduped, plus the zero-network and config-plane notes.
#   3. Fires one real desktop notification through the same code path the
#      monitor loop uses (`saffev::notify` → notify-send / osascript), so you
#      can see the toast this machine would show. Fail-soft: on a headless box
#      this is a silent no-op, exactly like production.
#
# Everything is local: no daemon needed, no network touched.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== G6 signals demo · tripping all five rule classes =="
cargo test --test signals_bench -- --nocapture

echo
echo "== artifact =="
echo "bench/signals-results.json:"
cat bench/signals-results.json

echo
echo "== live notification (the toast the monitor loop would show) =="
# The bench proved the rules; this shows the delivery channel on THIS machine.
# Uses the same argv-only invocation as src/notify.rs (no shell interpolation).
if command -v notify-send >/dev/null 2>&1; then
  notify-send --app-name=Saffev "Saffev demo signal" \
    "This is what a monitor signal looks like (e.g. 'PII findings spike')."
  echo "sent via notify-send — check your notification area"
elif command -v osascript >/dev/null 2>&1; then
  osascript -e 'on run argv' \
    -e 'display notification (item 2 of argv) with title (item 1 of argv)' \
    -e 'end run' "Saffev demo signal" \
    "This is what a monitor signal looks like (e.g. 'PII findings spike')."
  echo "sent via osascript — check Notification Center"
else
  echo "no notifier on this machine — production fails soft the same way"
fi

echo
echo "== enable monitors for real =="
cat <<'EOF'
Add to your saffev.toml (Studio → Settings shows its location), then restart
is NOT needed — the monitor loop reads the live config every 60s tick:

  [monitors]
  enabled = true            # master switch (off by default)
  pii_spike_per_hour = 20   # findings/hour before the spike rule fires
  latency_p95_ms = 30000    # p95 threshold over the last hour (>=20 samples)
  spend_per_day_usd = 10.0  # today's estimated coding-agent spend (UTC)
  notify = true             # desktop toast per signal (log + SSE always on)

Scripting hook (exit code 2 when any rule fires):

  saffev status --check || echo "something needs attention"
EOF
