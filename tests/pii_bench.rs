//! G1 privacy-lens scoring harness (docs/gauntlets/GAUNTLETS.md §G1).
//!
//! One command, reproducible:
//!
//! ```sh
//! cargo test --test pii_bench -- --nocapture
//! ```
//!
//! Scores the SHIPPED detector (`saffev::brain::pii::Detector`, default set, no
//! custom patterns) against the hand-labeled corpus in
//! `tests/fixtures/pii/corpus.jsonl`, prints the per-kind scorecard, writes the
//! machine-readable artifact to `bench/pii-results.json`, and asserts the
//! regression floors at the bottom so a detector change can never silently
//! lower a score.
//!
//! Scoring rules (the anti-gaming contract, see the corpus README):
//! - An expected `(kind, value)` matched by a finding with the same kind whose
//!   byte span slices to exactly `value` → true positive; unmatched expected →
//!   false negative; any leftover finding → false positive charged to the kind
//!   it CLAIMED (a version string flagged as an IP charges `ip_address`).
//! - `xfail` cases exempt only the MISS (the target kind has no detector yet);
//!   anything that FIRES on an xfail case is real detector output on real text
//!   and is charged as a false positive like anywhere else. If a detector
//!   starts genuinely catching one, promote the case to a scored positive.

use std::collections::BTreeMap;

use saffev::brain::pii::{kind_key, Detector};
use saffev::brain::Side;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const CORPUS: &str = include_str!("fixtures/pii/corpus.jsonl");

#[derive(Deserialize)]
struct Case {
    id: String,
    text: String,
    expect: Vec<Expect>,
    #[serde(default)]
    trap: Option<String>,
    #[serde(default)]
    xfail: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct Expect {
    kind: String,
    value: String,
}

#[derive(Default, Clone, Copy)]
struct Tally {
    tp: usize,
    fp: usize,
    fn_: usize,
}

impl Tally {
    fn precision(&self) -> Option<f64> {
        match self.tp + self.fp {
            0 => None,
            d => Some(self.tp as f64 / d as f64),
        }
    }
    fn recall(&self) -> Option<f64> {
        match self.tp + self.fn_ {
            0 => None,
            d => Some(self.tp as f64 / d as f64),
        }
    }
}

#[test]
fn pii_bench_scorecard() {
    let detector = Detector::new(&[]).expect("default detector compiles");

    let cases: Vec<Case> = CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad corpus line: {e}\n{l}")))
        .collect();

    // Corpus-shape floors: a shrunk or trap-free corpus would make any score
    // meaningless, so the harness refuses to run on one (anti-gaming rule).
    let traps = cases.iter().filter(|c| c.trap.is_some()).count();
    let xfails = cases.iter().filter(|c| c.xfail.is_some()).count();
    let scored = cases.len() - xfails;
    assert!(scored >= 174, "scored corpus shrank to {scored} cases");
    assert!(traps >= 68, "adversarial trap count shrank to {traps}");

    let mut kinds: BTreeMap<String, Tally> = BTreeMap::new();
    let mut known_gaps: Vec<serde_json::Value> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let findings = detector.scan(Side::Request, &case.text);
        let found: Vec<(String, &str)> = findings
            .iter()
            .map(|f| (kind_key(&f.kind).to_string(), &case.text[f.start..f.end]))
            .collect();

        if let Some(target) = &case.xfail {
            // The miss is exempt (no detector for the target kind yet), but
            // anything that fired here is real output on real text — charge it.
            for (k, v) in &found {
                kinds.entry(k.clone()).or_default().fp += 1;
                failures.push(format!("[{}] FALSE-POSITIVE {k} matched {v:?} (on xfail case)", case.id));
            }
            known_gaps.push(serde_json::json!({
                "id": case.id,
                "target_kind": target,
                "fired": found.iter().map(|(k, v)| serde_json::json!({"kind": k, "matched_len": v.len()})).collect::<Vec<_>>(),
                "note": case.note,
            }));
            continue;
        }

        // Greedy match expects against findings on exact (kind, value).
        let mut used = vec![false; found.len()];
        for exp in &case.expect {
            let hit = found
                .iter()
                .enumerate()
                .find(|(i, (k, v))| !used[*i] && *k == exp.kind && *v == exp.value);
            let tally = kinds.entry(exp.kind.clone()).or_default();
            match hit {
                Some((i, _)) => {
                    used[i] = true;
                    tally.tp += 1;
                }
                None => {
                    tally.fn_ += 1;
                    failures.push(format!(
                        "[{}] MISSED {} {:?} (found: {:?})",
                        case.id, exp.kind, exp.value, found
                    ));
                }
            }
        }
        for (i, (k, v)) in found.iter().enumerate() {
            if !used[i] {
                kinds.entry(k.clone()).or_default().fp += 1;
                failures.push(format!("[{}] FALSE-POSITIVE {k} matched {v:?}", case.id));
            }
        }
    }

    let overall = kinds.values().fold(Tally::default(), |a, t| Tally {
        tp: a.tp + t.tp,
        fp: a.fp + t.fp,
        fn_: a.fn_ + t.fn_,
    });

    // ---- artifact ----------------------------------------------------------
    let corpus_sha = format!("{:x}", Sha256::digest(CORPUS.as_bytes()));
    let kinds_json: BTreeMap<&str, serde_json::Value> = kinds
        .iter()
        .map(|(k, t)| {
            (
                k.as_str(),
                serde_json::json!({
                    "tp": t.tp, "fp": t.fp, "fn": t.fn_,
                    "precision": t.precision(), "recall": t.recall(),
                }),
            )
        })
        .collect();
    let results = serde_json::json!({
        "harness": "pii_bench v1 (G1 loop 1 — docs/gauntlets/GAUNTLETS.md)",
        "command": "cargo test --test pii_bench -- --nocapture",
        "detector": "saffev::brain::pii::Detector, default set, no custom patterns",
        "measurement_boundary": "Detector::scan on corpus text only — no proxy, no store, no masking",
        "corpus": {
            "file": "tests/fixtures/pii/corpus.jsonl",
            "sha256": corpus_sha,
            "cases": cases.len(), "scored": scored, "traps": traps, "xfail": xfails,
        },
        "kinds": kinds_json,
        "overall": {
            "tp": overall.tp, "fp": overall.fp, "fn": overall.fn_,
            "precision": overall.precision(), "recall": overall.recall(),
        },
        "known_gaps": known_gaps,
    });

    let pretty = serde_json::to_string_pretty(&results).expect("serialize results");
    println!("{pretty}");
    for f in &failures {
        println!("  {f}");
    }

    let out_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/bench");
    std::fs::create_dir_all(out_dir).expect("create bench dir");
    std::fs::write(format!("{out_dir}/pii-results.json"), pretty + "\n")
        .expect("write bench/pii-results.json");

    // ---- regression floors ---------------------------------------------------
    // Set from the measured run at the commit that introduced this harness.
    // Raising a floor is progress; a change that would need one LOWERED must
    // instead fix the detector or add the miss to the corpus as a documented
    // xfail with a note — never silently.
    let floor = |k: &str| kinds.get(k).copied().unwrap_or_default();
    let assert_floor = |k: &str, min_p: f64, min_r: f64| {
        let t = floor(k);
        let p = t.precision().unwrap_or(1.0);
        let r = t.recall().unwrap_or(1.0);
        assert!(p >= min_p, "{k} precision {p:.3} fell below floor {min_p:.3}");
        assert!(r >= min_r, "{k} recall {r:.3} fell below floor {min_r:.3}");
    };
    assert_floor("email", 1.0, 1.0);
    assert_floor("credit_card", 1.0, 1.0);
    assert_floor("api_key", 1.0, 1.0);
    assert_floor("ip_address", 1.0, 1.0);
    assert_floor("phone", 1.0, 1.0);
    assert_floor("private_key", 1.0, 1.0);
    assert_floor("jwt", 1.0, 1.0);
    assert_floor("connection_string", 1.0, 1.0);
    assert_floor("ssn", 1.0, 1.0);
    assert_floor("iban", 1.0, 1.0);
    assert_floor("mac_address", 1.0, 1.0);
    assert_floor("env_assignment", 1.0, 1.0);
    assert_floor("crypto_wallet", 1.0, 1.0);
}
