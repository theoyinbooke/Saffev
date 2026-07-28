#!/usr/bin/env python3
"""Score Presidio's deterministic recognizers against the G1 corpus.

The G1 rubric (docs/gauntlets/GAUNTLETS.md) requires Saffev's recall to be
>= Presidio's deterministic recognizers for every overlapping kind — this
script MEASURES Presidio instead of assuming it (the round-7 critic's
methodological finding: recall 1.0 made the comparison vacuously true, but
the competitor's score was never produced).

Overlapping kinds and their Presidio entities:
  email        <- EMAIL_ADDRESS
  phone        <- PHONE_NUMBER
  credit_card  <- CREDIT_CARD
  ip_address   <- IP_ADDRESS
  ssn          <- US_SSN
  iban         <- IBAN_CODE
  crypto_wallet<- CRYPTO

Scoring mirrors tests/pii_bench.rs: an expect entry is a hit when Presidio
reports the mapped entity overlapping the expected value's span; a trap of an
overlapping kind counts an FP when the mapped entity fires on it. Kinds
Presidio lacks (api_key, jwt, private_key, connection_string, env_assignment,
mac_address) are out of scope here — that absence is the moat, not a score.

Run:  /tmp/presidio-venv/bin/python scripts/presidio_baseline.py
Writes bench/presidio-baseline.json (committed alongside pii-results.json).
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "fixtures" / "pii" / "corpus.jsonl"
OUT = ROOT / "bench" / "presidio-baseline.json"

KIND_TO_ENTITY = {
    "email": "EMAIL_ADDRESS",
    "phone": "PHONE_NUMBER",
    "credit_card": "CREDIT_CARD",
    "ip_address": "IP_ADDRESS",
    "ssn": "US_SSN",
    "iban": "IBAN_CODE",
    "crypto_wallet": "CRYPTO",
}
ENTITIES = list(KIND_TO_ENTITY.values())


def main() -> None:
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    )
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())

    tally = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    misses, false_hits = [], []

    for line in CORPUS.read_text().splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        text = case["text"]
        results = analyzer.analyze(text=text, language="en", entities=ENTITIES)
        spans = [(r.entity_type, r.start, r.end) for r in results]

        for exp in case.get("expect", []):
            kind = exp["kind"]
            if kind not in KIND_TO_ENTITY:
                continue
            want = KIND_TO_ENTITY[kind]
            vstart = text.find(exp["value"])
            vend = vstart + len(exp["value"])
            hit = any(e == want and s < vend and vstart < e2 for e, s, e2 in spans)
            tally[kind]["tp" if hit else "fn"] += 1
            if not hit:
                misses.append(f"[{case['id']}] {kind} missed {exp['value']!r}")

        trap = case.get("trap")
        if trap in KIND_TO_ENTITY:
            want = KIND_TO_ENTITY[trap]
            for e, s, e2 in spans:
                if e == want:
                    tally[trap]["fp"] += 1
                    false_hits.append(f"[{case['id']}] {trap} fired on {text[s:e2]!r}")

    kinds = {}
    for kind, t in sorted(tally.items()):
        denom_r = t["tp"] + t["fn"]
        denom_p = t["tp"] + t["fp"]
        kinds[kind] = {
            **t,
            "recall": t["tp"] / denom_r if denom_r else None,
            "precision": t["tp"] / denom_p if denom_p else None,
        }

    out = {
        "tool": "presidio-analyzer (deterministic/pattern recognizers, en_core_web_sm)",
        "command": "/tmp/presidio-venv/bin/python scripts/presidio_baseline.py",
        "scope": "overlapping kinds only — kinds Presidio lacks are the moat, not a score",
        "kinds": kinds,
        "misses": misses,
        "false_hits": false_hits,
    }
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: {kk: v[kk] for kk in ("tp", "fn", "fp")} for k, v in kinds.items()}, indent=1))
    print(f"misses: {len(misses)}, false_hits: {len(false_hits)} -> {OUT}")


if __name__ == "__main__":
    sys.exit(main())
