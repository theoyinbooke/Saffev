//! Deterministic PII detection — observe-only, inline-cheap (04 §6.1).
//!
//! Each detector returns [`Finding`]s with byte offsets into the scanned text
//! and a hashed value (never the raw secret). Runs inline only because it is
//! microsecond-cheap; everything else is async/off-path.
//!
//! Detected by default (04 §6.1): email, phone, credit cards (Luhn-validated),
//! API keys (prefix + Shannon entropy), IPv4/IPv6, plus a configurable custom
//! list. Only high-confidence deterministic patterns ship in v0 — no name/place
//! NER (that is research, R5) — to avoid over-flagging.
//!
//! Privacy invariant: [`Finding::value_hash`] is a stable, non-reversible hash
//! of the matched substring. The raw matched value is **never** returned or
//! stored. Offsets are byte offsets, always landing on UTF-8 char boundaries
//! because every detector matches ASCII-only structure.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::brain::{Confidence, Finding, PiiKind, Side};
use crate::config::CustomPattern;

/// Minimum Shannon entropy (bits/char) a prefixed token must clear to be
/// treated as a real API key rather than a placeholder like `sk-xxxxxxxx`.
const API_KEY_MIN_ENTROPY: f64 = 3.0;

/// Minimum length of the random portion (after a known prefix) for a token to
/// even be considered an API key candidate.
const API_KEY_MIN_BODY: usize = 16;

// --- Default detector regexes (compiled once, shared). ----------------------

/// Email: pragmatic RFC-lite local-part + domain with a TLD. ASCII only.
static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9](?:[A-Z0-9\-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9\-]*[A-Z0-9])?)*\.[A-Z]{2,24}\b")
        .expect("email regex")
});

/// Phone numbers: spaceless E.164 (`+15551234567`), or optional country code,
/// common separators, 7–14 significant digits. Tightened to avoid swallowing
/// arbitrary digit runs / card numbers.
static RE_PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\+[1-9]\d{6,14}\b|(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{1,4}\)[ .\-]?)?\d{2,4}(?:[ .\-]\d{2,4}){1,3}",
    )
    .expect("phone regex")
});

/// Date shapes the loose phone candidate would otherwise swallow (ISO
/// `2026-06-06`, `06.06.2026`, `2026 06 06`, …). Anchored to the whole candidate,
/// so a genuine phone number is never rejected as a date.
static RE_DATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:\d{4}[-. ]\d{1,2}[-. ]\d{1,2}|\d{1,2}[-. ]\d{1,2}[-. ]\d{4})$")
        .expect("date regex")
});

/// Candidate credit-card: 13–19 digits in groups separated by space/hyphen or
/// run together. Luhn-validated before a finding is emitted.
static RE_CARD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d[ \-]?){12,18}\d\b").expect("card regex"));

/// API key / token by known prefix. The whole token (prefix + body) is captured
/// and then entropy-gated. Covers OpenAI, GitHub, AWS, Google, Slack, Stripe,
/// generic `xoxb`/`xapp`, and bearer-ish `key-` forms.
static RE_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:sk-(?:proj-)?[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{22,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{16,}|xox[baprs]-[A-Za-z0-9\-]{10,}|xapp-[A-Za-z0-9\-]{10,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|glpat-[A-Za-z0-9_\-]{16,})\b",
    )
    .expect("api key regex")
});

/// IPv4 dotted quad with each octet 0–255.
static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
    )
    .expect("ipv4 regex")
});

/// IPv6 — full, compressed (`::`), and IPv4-mapped tails.
///
/// Branch ORDER matters for scanning: `find_iter` takes the first branch that
/// matches at a position, so the most-specific / longest-reaching shapes come
/// first. The old grammar put the bare `(?:h:){1,7}:` branch ahead of the
/// compressed head::tail forms and truncated `2001:db8::8a2e:370:7334` to
/// `2001:db8::` — masking that span would leak the rest of the address
/// (caught by the G1 bench corpus, round 1).
static RE_IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|(?:[0-9a-f]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|:(?::[0-9a-f]{1,4}){1,7}",
    )
    .expect("ipv6 regex")
});

/// PEM private-key block — header through the matching footer when present,
/// else the header line alone (a truncated paste is still a leak). The WHOLE
/// block is the finding so masking removes the key material, not just the
/// banner. `PUBLIC KEY` / `CERTIFICATE` blocks intentionally do not match.
static RE_PRIVATE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?s:.)*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    )
    .expect("private key regex")
});

/// JWT: three dot-joined base64url segments whose header starts with `eyJ`
/// (base64url of `{"`). The strong prefix makes this deterministic without an
/// entropy gate.
static RE_JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}")
        .expect("jwt regex")
});

/// Connection string with embedded credentials: `scheme://user:password@rest`.
/// The whole URL is the finding so masking removes the credential pair AND the
/// host it unlocks. A URL without a `user:pass@` section never matches.
static RE_CONN_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:@/]+:[^\s@/]+@[^\s"']+"#)
        .expect("connection string regex")
});

/// US SSN, dashed form only (`AAA-GG-SSSS`). The bare 9-digit form is far too
/// FP-prone for a deterministic v0 detector. Candidates are structurally
/// validated by [`ssn_valid`] before a finding is emitted.
static RE_SSN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex"));

/// IBAN candidate: canonical uppercase (spaced groups or compact), plus a
/// COMPACT-only lowercase branch (lowercase pastes are real — G1 round-9
/// critic). Lowercase must be compact because a blanket `(?i)` let the
/// greedy spaced-group tail glue a following ordinary word into the
/// candidate (`ES91… activa` absorbed `acti`+`va`, failed mod-97, and the
/// true IBAN vanished — caught by the bench, round 10). Validated by ISO
/// 7064 mod-97 ([`iban_valid`]) before emission, so a random letter/digit
/// run has a 1-in-97 chance of surviving the gate.
static RE_IBAN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?|[a-z]{2}\d{2}[a-z0-9]{11,30})\b",
    )
    .expect("iban regex")
});

/// MAC address — six colon- or hyphen-separated hex pairs. (The regex crate
/// has no backreferences, hence the two spelled-out branches.)
static RE_MAC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|(?i)\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b",
    )
    .expect("mac regex")
});

/// `.env`-style assignment candidate (`KEY=value`, `KEY="value"`). The regex
/// only proposes; [`env_key_is_secret`] must accept the key (it names a
/// credential) and [`env_value_is_real`] the value (placeholders and
/// interpolations don't count) before a finding is emitted. The whole
/// assignment is the finding so masking removes the value, not just part.
static RE_ENV_ASSIGN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\b[A-Za-z_][A-Za-z0-9_]*=(?:"(?:\\.|[^"\\\r\n]){4,}"|'[^'\r\n]{4,}'|[^\s"';]{6,})"#,
    )
    .expect("env assignment regex")
});

/// Quoting in these grammars is PAIRED: the regex crate has no
/// backreferences, so every quote kind is a spelled-out alternation branch —
/// a `['"]…['"]` class would let a `"` open and an apostrophe close
/// (`password_hint: "mother's maiden name"` mangled its span to `"mother'`;
/// G1 round-8 critic's span-correctness bug). Double-quoted branches accept
/// backslash escapes (`"hu\"nter99"`), single-quoted stay literal. Because
/// alternation multiplies capture groups, the claim loop reads captures
/// positionally: first participating group = key, second = value.

/// JSON / Python-dict member candidate (`"password": "hunter2"`,
/// `'password': 'hunter2'` — single quotes cover Python dict reprs).
static RE_JSON_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:"([A-Za-z0-9_.\-]+)"|'([A-Za-z0-9_.\-]+)')\s*:\s*(?:"((?:\\.|[^"\\\r\n]){4,})"|'((?:\\.|[^'\\\r\n]){4,})')"#,
    )
    .expect("json secret regex")
});

/// Object-literal member candidate: UNQUOTED key, quoted value, anywhere on a
/// line — `{password: "hunter2"}` (JS), `opts = {password: 'x'}` (Ruby 1.9
/// keyword hash), `` {password: `tpl`} `` (JS template literal). The round-7
/// critic called this the single most common secret-paste shape in logs. The
/// mandatory QUOTED value is what separates an object literal from prose —
/// mid-line `password: hunter2` unquoted stays out of scope.
static RE_OBJ_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:"((?:\\.|[^"\\\r\n]){4,})"|'((?:\\.|[^'\\\r\n]){4,})'|`([^`\r\n]{4,})`)"#,
    )
    .expect("object literal secret regex")
});

/// Ruby hash-rocket member candidate (`"password"=>"hunter2"` — every Rails
/// console/log paste; G1 round-5 critic's missed grammar). Same gates as the
/// JSON form; paired quotes (see the note above RE_JSON_SECRET).
static RE_RUBY_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#""([A-Za-z0-9_.\-]+)"\s*=>\s*(?:"((?:\\.|[^"\\\r\n]){4,})"|'((?:\\.|[^'\\\r\n]){4,})')"#,
    )
    .expect("ruby secret regex")
});

/// Ruby SYMBOL-key hash-rocket candidate (`:password=>"hunter2"` — the older,
/// very common form; G1 round-6 critic's miss: the quoted-key grammar above
/// doesn't reach it). Paired quotes.
static RE_RUBY_SYM_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#":([A-Za-z_][A-Za-z0-9_]*)\s*=>\s*(?:"((?:\\.|[^"\\\r\n]){4,})"|'((?:\\.|[^'\\\r\n]){4,})')"#,
    )
    .expect("ruby symbol secret regex")
});

/// YAML mapping candidate (`password: hunter2` at line start, any indent).
/// The `[ \t]+` after the colon is load-bearing: `12:30` and `https://…`
/// never qualify. Capture 1 = key, 2 = value (to end of line, `#` comments
/// excluded).
static RE_YAML_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^[ \t]*([A-Za-z0-9_.\-]+):[ \t]+([^\s#][^\r\n#]{2,}[^\s#])")
        .expect("yaml secret regex")
});

/// TOML/INI candidate with spaces around `=` and a paired-quote value
/// (`password = "hunter2"`, single or double). The space-less shell form is
/// [`RE_ENV_ASSIGN`]'s.
static RE_TOML_SECRET: Lazy<Regex> = Lazy::new(|| {
    // TOML basic strings take backslash escapes; literal (single-quoted)
    // strings by spec do not — the asymmetry here is TOML's, not ours.
    Regex::new(
        r#"(?m)^[ \t]*([A-Za-z0-9_.\-]+)[ \t]*=[ \t]*(?:"((?:\\.|[^"\\\r\n]){4,})"|'([^'\r\n]{4,})')"#,
    )
    .expect("toml secret regex")
});

/// `Key=Value;`-style connection string (ODBC / ADO.NET / JDBC properties)
/// carrying a `Password=`/`Pwd=` pair among other pairs. Mirrors the URL form:
/// the whole property run is the finding, so the credential AND the
/// coordinates it unlocks are masked together. A lone `PASSWORD=…` with no
/// sibling pairs is not a connection string — the env-assignment detector
/// owns that shape.
static RE_CONN_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:[a-z][a-z0-9 _]{1,24}=[^;\r\n]{1,128};\s*){1,10}(?:password|pwd) ?= ?[^;\r\n]{1,128};?(?: ?[a-z][a-z0-9 _]{1,24}=[^;\r\n]{1,128};?){0,10}",
    )
    .expect("kv connection string regex")
});

/// Cryptocurrency wallet candidates: legacy base58 BTC (`1…`/`3…`), bech32
/// (`bc1…`), EVM `0x` + 40 hex. Every branch is checksum-verified: base58check
/// double-SHA-256, BIP-173/350 polymod, and EIP-55 Keccak casing for
/// mixed-case EVM addresses ([`evm_valid`]) — lookalike tokens die at
/// validation, not in the regex. The mandatory `0x` prefix and exact 40-hex
/// length already exclude bare git SHAs and 64-hex tx hashes.
static RE_WALLET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,87}|0x[0-9a-fA-F]{40})\b",
    )
    .expect("wallet regex")
});

/// SSN in dash-less or spaced form (`078051120`, `078 05 1120`) — claimed only
/// inside explicit SSN context ([`ssn_context`]): a bare nine-digit run is far
/// too common to claim deterministically without it. The dashed form needs no
/// context and is handled by [`RE_SSN`].
static RE_SSN_LOOSE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{3} ?\d{2} ?\d{4}\b").expect("ssn loose regex"));

/// File extensions that shape like a TLD but are unambiguous asset suffixes
/// (`image@2x.png`), so an email hit ending in one is a filename, not an
/// address. Deliberately excludes every real ccTLD (`.md`, `.sh`, `.rs`, …).
const NON_TLD_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tif", "tiff", "mp3", "mp4",
    "mov", "avi", "wav", "woff", "woff2", "ttf", "eot", "otf",
];

/// A compiled, ready-to-run set of detectors.
///
/// Build it once (compiling the custom regexes) and reuse it across scans. It is
/// `Send + Sync` so the proxy can share one behind an `Arc`. The default
/// detectors are shared `Lazy` statics; only custom patterns are owned here.
pub struct Detector {
    /// User-defined patterns, pre-compiled. `(label, regex, confidence)`.
    custom: Vec<(String, Regex, Confidence)>,
}

impl Detector {
    /// Build the default detector set with the user's custom patterns.
    ///
    /// Returns an error if a custom regex fails to compile (control-plane error,
    /// surfaced at startup — not a request-path failure). Compiling the shared
    /// default regexes is forced here so a malformed builtin would fail loud.
    pub fn new(custom: &[CustomPattern]) -> crate::Result<Self> {
        // Force-init the default set so any builtin breakage surfaces eagerly.
        Lazy::force(&RE_EMAIL);
        Lazy::force(&RE_PHONE);
        Lazy::force(&RE_CARD);
        Lazy::force(&RE_API_KEY);
        Lazy::force(&RE_IPV4);
        Lazy::force(&RE_IPV6);
        Lazy::force(&RE_ENV_ASSIGN);
        Lazy::force(&RE_JSON_SECRET);
        Lazy::force(&RE_RUBY_SECRET);
        Lazy::force(&RE_RUBY_SYM_SECRET);
        Lazy::force(&RE_OBJ_SECRET);
        Lazy::force(&RE_YAML_SECRET);
        Lazy::force(&RE_TOML_SECRET);
        Lazy::force(&RE_CONN_KV);
        Lazy::force(&RE_WALLET);
        Lazy::force(&RE_SSN_LOOSE);

        let mut compiled = Vec::with_capacity(custom.len());
        for pat in custom {
            let re = Regex::new(&pat.regex).map_err(|e| {
                crate::Error::Config(format!(
                    "custom PII pattern '{}' has an invalid regex: {e}",
                    pat.name
                ))
            })?;
            compiled.push((pat.name.clone(), re, pat.confidence));
        }
        Ok(Detector { custom: compiled })
    }

    /// Scan one side's text, returning all findings with correct byte offsets.
    /// The hot-path entry point; allocation-light and fast. Order of emission is
    /// stable (built-ins first, then custom) but callers should not depend on
    /// it for correctness.
    pub fn scan(&self, side: Side, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        // Track byte spans already claimed so a higher-precision detector wins
        // over a looser one (e.g. a card or API key is not also a "phone").
        let mut claimed: Vec<(usize, usize)> = Vec::new();

        let overlaps = |claimed: &[(usize, usize)], s: usize, e: usize| {
            claimed.iter().any(|&(cs, ce)| s < ce && cs < e)
        };

        // Detector order = claim precedence: the most specific, highest-severity
        // spans claim first so a looser detector can never relabel (or split) a
        // secret. Secrets → identifiers → the loose phone pattern last.

        // 1. Private-key blocks (largest, most catastrophic spans claim first).
        for m in RE_PRIVATE_KEY.find_iter(text) {
            out.push(make_finding(
                PiiKind::PrivateKey,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 2. Credentialed connection strings — before email, or the
        //    `user:pass@host` section reads as an address. URL form first,
        //    then the `Key=Value;` property form (ODBC / ADO.NET / JDBC).
        for m in RE_CONN_STRING.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::ConnectionString,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }
        for m in RE_CONN_KV.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::ConnectionString,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 2b. Config-file credential assignments — shell/.env, JSON, YAML and
        //     TOML forms share the same key/value gates. Before email so an
        //     address-shaped value (`SMTP_PASSWORD=p@ss.example`) is claimed
        //     whole, and after connection strings so a `DATABASE_URL=…` value
        //     stays a connection string, not two halves. Candidates from all
        //     forms are pooled and offset-sorted first: where two grammars
        //     propose the same text (`KEY="v"` is both shell and TOML), the
        //     first claim wins and the duplicate dies on the overlap check.
        let mut config_candidates: Vec<(usize, usize, String, String)> = Vec::new();
        for m in RE_ENV_ASSIGN.find_iter(text) {
            if let Some((key, value)) = m.as_str().split_once('=') {
                config_candidates.push((m.start(), m.end(), key.to_string(), value.to_string()));
            }
        }
        // JSON/rocket spans start at the whole match (the key's opening quote
        // or `:`); YAML/TOML spans start at the key so line indent stays
        // unmasked. `quote_wrap`: those grammars capture the value INSIDE its
        // mandatory quotes, so the quoting is restored before the value gate —
        // a quoted real secret starting with `[` must survive the marker kill
        // in every form, not just shell (G1 round-6 critic's over-kill).
        for (re, from_key, prose_gate, quote_wrap) in [
            (&RE_JSON_SECRET, false, false, true),
            (&RE_RUBY_SECRET, false, false, true),
            (&RE_RUBY_SYM_SECRET, false, false, true),
            (&RE_OBJ_SECRET, false, false, true),
            (&RE_YAML_SECRET, true, true, false),
            (&RE_TOML_SECRET, true, false, true),
        ] {
            for caps in re.captures_iter(text) {
                let Some(whole) = caps.get(0) else {
                    continue;
                };
                // Positional read: quote alternation multiplies group
                // numbers, but group ORDER is fixed — the first
                // participating group is always the key, the second the
                // value, whichever quote branch matched.
                let mut participating = (1..caps.len()).filter_map(|i| caps.get(i));
                let (Some(key), Some(value)) = (participating.next(), participating.next())
                else {
                    continue;
                };
                // The YAML form is the only grammar whose value is unquoted
                // free text, which makes line-start prose shape-legal
                // ("token: expired yesterday" — G1 round-4 critic, three
                // constructed FPs of exactly this class). A real YAML secret
                // is a single token or a quoted string, so an unquoted value
                // containing whitespace is prose, not material.
                let val = value.as_str();
                if prose_gate
                    && !val.starts_with('"')
                    && !val.starts_with('\'')
                    && val.contains(char::is_whitespace)
                {
                    continue;
                }
                let start = if from_key { key.start() } else { whole.start() };
                let carried = if quote_wrap {
                    format!("\"{val}\"")
                } else {
                    val.to_string()
                };
                config_candidates.push((start, whole.end(), key.as_str().to_string(), carried));
            }
        }
        config_candidates.sort_by_key(|c| (c.0, c.1));
        for (start, end, key, value) in config_candidates {
            if overlaps(&claimed, start, end) {
                continue;
            }
            if !env_key_is_secret(&key) || !env_value_is_real(&value) {
                continue;
            }
            // Defer to the more specific secret detectors — but ONLY when the
            // hand-off will actually be claimed (G1 round-9 critic's severe
            // FN: base64-encoded JSON starts `eyJ` without being a JWT, and a
            // below-entropy `sk-…` value clears neither detector — a naive
            // prefix defer made both vanish entirely). A real JWT shape or an
            // accepted key keeps its specific label; everything else stays a
            // config credential.
            let v = value
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            if RE_JWT.is_match(v)
                || RE_API_KEY
                    .find(v)
                    .is_some_and(|m| api_key_accepts(m.as_str()))
            {
                continue;
            }
            out.push(make_finding(
                PiiKind::EnvAssignment,
                None,
                side,
                start,
                end,
                Confidence::High,
                &text[start..end],
            ));
            claimed.push((start, end));
        }

        // 3. Email (high-precision structure; filename guard for `img@2x.png`).
        for m in RE_EMAIL.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            let tld = m
                .as_str()
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if NON_TLD_EXTENSIONS.contains(&tld.as_str()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::Email,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 4. API keys (prefix + entropy gate). High precision; claim early so a
        //    key body is never re-read as a phone/card.
        for m in RE_API_KEY.find_iter(text) {
            let token = m.as_str();
            if !api_key_accepts(token) {
                continue;
            }
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::ApiKey,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                token,
            ));
            claimed.push((m.start(), m.end()));
        }

        // 5. JWTs (strong `eyJ` prefix, no entropy gate needed).
        for m in RE_JWT.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::Jwt,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 6. IBAN (mod-97 gated) — before cards, whose Luhn gate an IBAN's
        //    digit tail could coincidentally pass.
        for m in RE_IBAN.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            if !iban_valid(m.as_str()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::Iban,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 7. Credit cards (Luhn-validated to cut false positives).
        for m in RE_CARD.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            // A digit run written with a leading `+` is an international phone
            // number, never a card — 13–15 digit phones pass Luhn by luck ~10%
            // of the time (caught by the G1 bench corpus, round 1).
            if text[..m.start()].chars().next_back() == Some('+') {
                continue;
            }
            // A digit run right after an IBAN-style prefix (`DE89 …`) is a bank
            // account tail — a typo'd IBAN fails mod-97 upstream, but its tail
            // can still pass Luhn by luck (caught by the G1 corpus, round 2).
            let head = text[..m.start()].trim_end_matches(' ');
            let iban_prefixed = head
                .as_bytes()
                .get(head.len().wrapping_sub(4)..)
                .is_some_and(|t| {
                    t.len() == 4
                        && t[0].is_ascii_uppercase()
                        && t[1].is_ascii_uppercase()
                        && t[2].is_ascii_digit()
                        && t[3].is_ascii_digit()
                });
            if iban_prefixed {
                continue;
            }
            let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
            if digits.len() < 13 || digits.len() > 19 {
                continue;
            }
            if !luhn_valid(&digits) {
                continue;
            }
            out.push(make_finding(
                PiiKind::CreditCard,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 8. SSN (dashed, structurally validated) — before phone, which would
        //    otherwise catch the same span and mislabel it. The dash-less and
        //    spaced forms additionally require explicit SSN context.
        for m in RE_SSN.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            if !ssn_valid(m.as_str()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::Ssn,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }
        for m in RE_SSN_LOOSE.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            if !ssn_context(text, m.start()) {
                continue;
            }
            let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
            if !ssn_digits_valid(&digits) {
                continue;
            }
            out.push(make_finding(
                PiiKind::Ssn,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 9. IPv6 before IPv4 (the v6 grammar may embed a v4 tail). The regex
        //    cannot use \b (':' splits words), so reject matches glued to
        //    alphanumeric neighbors — `std::vector` must not yield `d::`.
        for m in RE_IPV6.find_iter(text) {
            // Require at least one colon — guards the alternation against a lone
            // bare token sneaking through on degenerate inputs.
            if !m.as_str().contains(':') {
                continue;
            }
            if !ipv6_boundaries_clean(text, &m) {
                continue;
            }
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::IpAddress,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 10. IPv4. A dotted quad right after version-context wording
        //     ("build 1.2.3.4", "version 1.2.3.4") is a version string, not an
        //     address (G1 corpus, ip-t04) — the only shipped detector FP of
        //     round 2. The gate fires on those exact preceding tokens only, so
        //     addresses in prose ("ping 1.2.3.4", "from 1.2.3.4") are untouched.
        for m in RE_IPV4.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            if version_context(text, m.start()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::IpAddress,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 11. MAC addresses (after IP: the v6 grammar never matches six hex
        //     pairs with single colons, but keep the claim order explicit).
        for m in RE_MAC.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::MacAddress,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 11b. Crypto wallets — checksum-validated (base58check / bech32
        //      polymod), so this runs on shape candidates only. After MAC/IP
        //      (no shape overlap, keep the order explicit), before the loose
        //      phone pattern.
        for m in RE_WALLET.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            if !wallet_valid(m.as_str()) {
                continue;
            }
            out.push(make_finding(
                PiiKind::CryptoWallet,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 12. Phone (loosest builtin — runs last, never re-claims a card/IP/key).
        for m in RE_PHONE.find_iter(text) {
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            if !looks_like_phone(text, &m) {
                continue;
            }
            out.push(make_finding(
                PiiKind::Phone,
                None,
                side,
                m.start(),
                m.end(),
                Confidence::High,
                m.as_str(),
            ));
            claimed.push((m.start(), m.end()));
        }

        // 13. Custom user patterns (carry their label + configured confidence).
        for (label, re, conf) in &self.custom {
            for m in re.find_iter(text) {
                if overlaps(&claimed, m.start(), m.end()) {
                    continue;
                }
                out.push(make_finding(
                    PiiKind::Custom,
                    Some(label.clone()),
                    side,
                    m.start(),
                    m.end(),
                    *conf,
                    m.as_str(),
                ));
                claimed.push((m.start(), m.end()));
            }
        }

        // Stable, offset-ordered output for deterministic Studio rendering.
        out.sort_by_key(|f| (f.start, f.end));
        out
    }
}

/// Would the API-key detector claim this exact token? Shared by the scan
/// step and the config-secret deferral check — deferral must only skip when
/// the hand-off will actually be caught (G1 round-9 critic).
fn api_key_accepts(token: &str) -> bool {
    let body_len = token.split(['-', '_']).next_back().map_or(0, str::len);
    body_len >= API_KEY_MIN_BODY && shannon_entropy(token) >= API_KEY_MIN_ENTROPY
}

/// Structural validation for a dashed SSN candidate: area 001–899 excluding
/// 666, group 01–99, serial 0001–9999 (the SSA's never-issued ranges).
fn ssn_valid(s: &str) -> bool {
    let digits: String = s.chars().filter(char::is_ascii_digit).collect();
    ssn_digits_valid(&digits)
}

/// The same SSA never-issued-range check on a bare nine-digit string
/// (area-group-serial as 3-2-4).
fn ssn_digits_valid(digits: &str) -> bool {
    let (Some(area), Some(group), Some(serial)) =
        (digits.get(0..3), digits.get(3..5), digits.get(5..9))
    else {
        return false;
    };
    if digits.len() != 9 {
        return false;
    }
    let Ok(area_n) = area.parse::<u32>() else {
        return false;
    };
    area_n != 0 && area_n != 666 && area_n < 900 && group != "00" && serial != "0000"
}

/// Dash-less / spaced SSN candidates only count inside explicit SSN context:
/// "ssn" or "social security" within the preceding few words. Presidio's
/// recognizer leans on the same context signal — a bare nine-digit run has no
/// deterministic claim to being an SSN.
fn ssn_context(text: &str, start: usize) -> bool {
    let from = text[..start]
        .char_indices()
        .rev()
        .nth(31)
        .map_or(0, |(i, _)| i);
    let head = text[from..start].to_ascii_lowercase();
    head.contains("ssn") || head.contains("social security")
}

/// A dotted quad immediately after version-context wording is a version
/// string, not an address (G1 corpus, ip-t04). Only these exact preceding
/// tokens gate.
fn version_context(text: &str, start: usize) -> bool {
    let head = text[..start].trim_end();
    let last = head
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or("");
    matches!(
        last.to_ascii_lowercase().as_str(),
        "build" | "version" | "release" | "ver" | "rev"
    )
}

/// Does an assignment KEY name a credential? Segment-based so `AUTHOR` never
/// matches on its `AUTH` substring: the key is split on `_` and a segment must
/// equal a credential word, or an `X_KEY` pair must qualify (so `PUBLIC_KEY`
/// and `CACHE_KEY` stay out while `API_KEY` / `SIGNING_KEY` are in).
fn env_key_is_secret(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    // '.', '-' — JSON/YAML keys segment on those too (`db.password`,
    // `api-token`).
    let segments: Vec<&str> = upper
        .split(['_', '.', '-'])
        .filter(|s| !s.is_empty())
        .collect();
    const SECRET_WORDS: &[&str] = &[
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASSPHRASE",
        "PASS", // DB_PASS et al. — segment match, so BYPASS never qualifies
        "PWD",
        "TOKEN",
        "APIKEY",
        "CREDENTIAL",
        "CREDENTIALS",
    ];
    const KEY_QUALIFIERS: &[&str] = &[
        "API", "ACCESS", "PRIVATE", "SIGNING", "ENCRYPTION", "MASTER", "LICENSE", "SSH",
    ];
    if segments.iter().any(|s| SECRET_WORDS.contains(s)) {
        return true;
    }
    segments
        .windows(2)
        .any(|w| w[1] == "KEY" && KEY_QUALIFIERS.contains(&w[0]))
}

/// Is an assignment VALUE real secret material rather than a placeholder?
///
/// The marker checks run on a NORMALIZED view — quotes stripped, then
/// surrounding decoration trimmed and lowercased — so a scrub convention
/// can't escape by dressing up (`[FILTERED]`, `***MASKED***`, `(REDACTED)`
/// all normalize to a known marker word; G1 round-6 critic showed the
/// exact-match list regrew the FP family one decoration away). Interpolation
/// prefixes (`$`, `{{`, `%`) reject in any quoting — tools interpolate inside
/// quotes too — but the `[`/`<` marker-prefix kills apply to UNQUOTED values
/// only, so a quoted real secret that happens to start with `[` survives
/// (the same critic's over-kill finding). `_`/`-`-joined compounds reject
/// only when EVERY segment is known non-material vocabulary
/// (`invalid_token`, `access_denied`), so `secret_dragon` stays material.
fn env_value_is_real(value: &str) -> bool {
    let trimmed = value.trim();
    let quoted = trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')));
    let v = if quoted {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if v.len() < 4 {
        return false;
    }
    if v.starts_with('$') || v.starts_with("{{") || v.starts_with('%') {
        return false;
    }
    if !quoted && (v.starts_with('[') || v.starts_with('<')) {
        return false;
    }
    // Markers (scrub conventions), status vocabulary, protocol nouns, and
    // classic template fillers. Nouns like "token" are here for the compound
    // rule — a value that is literally protocol vocabulary is not material.
    const NON_MATERIAL: &[&str] = &[
        // template fillers
        "changeme",
        "change_me",
        "change-me",
        "placeholder",
        "example",
        "your-key-here",
        "true",
        "false",
        "none",
        "null",
        // scrub markers
        "redacted",
        "filtered",
        "masked",
        "scrubbed",
        "removed",
        "hidden",
        // status vocabulary
        "incorrect",
        "expired",
        "invalid",
        "missing",
        "required",
        "unknown",
        "unset",
        "denied",
        "error",
        "failed",
        "rejected",
        "unauthorized",
        "forbidden",
        "wrong",
        "mismatch",
        // filler connectors — `not_set`, `to_be_filled` are template noise,
        // not material (G1 round-7 critic)
        "not",
        "set",
        "to",
        "be",
        "filled",
        "pending",
        "todo",
        "tbd",
        "blank",
        "empty",
        // protocol nouns (compound segments)
        "token",
        "password",
        "secret",
        "key",
        "access",
        "auth",
        "credentials",
        "grant",
        "request",
    ];
    let normalized: String = v
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_ascii_lowercase();
    if NON_MATERIAL.contains(&normalized.as_str()) {
        return false;
    }
    let segments: Vec<&str> = normalized
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    // A value whose FIRST word is a scrub verb or filler lead is an
    // annotated marker — `REDACTED_BY_SOC_TEAM`, `MASKED (by proxy)`,
    // `TBD-final` — the annotation doesn't make it material (G1 round-7/8
    // critics). Leads only: `hidden` stays out so a passphrase like
    // `hidden-gem-x9` isn't collateral, and `was-removed-x9q` is material
    // because `removed` isn't FIRST.
    const NON_MATERIAL_LEADS: &[&str] = &[
        "redacted",
        "filtered",
        "masked",
        "scrubbed",
        "removed",
        "tbd",
        "todo",
        "placeholder",
        "changeme",
    ];
    if segments.first().is_some_and(|s| NON_MATERIAL_LEADS.contains(s)) {
        return false;
    }
    if !segments.is_empty() && segments.iter().all(|s| NON_MATERIAL.contains(s)) {
        return false;
    }
    shannon_entropy(v) >= 2.0
}

/// Wallet candidate dispatch: base58check for legacy BTC, BIP-173/350 polymod
/// for bech32, EIP-55 for EVM `0x` hex.
fn wallet_valid(s: &str) -> bool {
    if s.starts_with("0x") {
        evm_valid(s)
    } else if s.starts_with("bc1") {
        bech32_valid(s)
    } else {
        base58check_valid(s)
    }
}

/// EIP-55 checksum validation for an EVM address candidate. A mixed-case
/// address must match the Keccak-256-derived casing exactly (each hex letter
/// is uppercase iff the corresponding digest nibble ≥ 8). Single-case
/// addresses carry no checksum information and are accepted on shape — the
/// round-3 critic's finding was that case-corrupted MIXED addresses slipped
/// through, and this closes exactly that.
fn evm_valid(s: &str) -> bool {
    let hex = &s[2..];
    let has_lower = hex.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = hex.bytes().any(|b| b.is_ascii_uppercase());
    if !(has_lower && has_upper) {
        return true;
    }
    use sha3::{Digest, Keccak256};
    let digest = Keccak256::digest(hex.to_ascii_lowercase().as_bytes());
    hex.bytes().enumerate().all(|(i, b)| {
        if !b.is_ascii_alphabetic() {
            return true;
        }
        let nibble = (digest[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        if nibble >= 8 {
            b.is_ascii_uppercase()
        } else {
            b.is_ascii_lowercase()
        }
    })
}

/// Real base58check validation: decode, require the 25-byte
/// version+hash160+checksum layout, and verify the double-SHA-256 checksum. A
/// random base58-alphabet string has a ~2⁻³² chance of surviving.
fn base58check_valid(s: &str) -> bool {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut payload: Vec<u8> = Vec::with_capacity(25);
    for c in s.bytes() {
        let Some(digit) = ALPHABET.iter().position(|&a| a == c) else {
            return false;
        };
        let mut carry = digit as u32;
        for byte in payload.iter_mut().rev() {
            carry += *byte as u32 * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            payload.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1's encode leading zero bytes.
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend_from_slice(&payload);
    if full.len() != 25 {
        return false;
    }
    use sha2::{Digest, Sha256};
    let once = Sha256::digest(&full[..21]);
    let twice = Sha256::digest(once);
    twice[..4] == full[21..25]
}

/// BIP-173 (bech32) / BIP-350 (bech32m) checksum verification for a `bc1…`
/// candidate. Accepts either constant so both segwit v0 and taproot addresses
/// validate.
fn bech32_valid(s: &str) -> bool {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let Some((hrp, data)) = s.rsplit_once('1') else {
        return false;
    };
    if hrp.is_empty() || data.len() < 6 {
        return false;
    }
    let mut chk: u32 = 1;
    let mut polymod = |v: u32| {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    };
    for b in hrp.bytes() {
        polymod((b >> 5) as u32);
    }
    polymod(0);
    for b in hrp.bytes() {
        polymod((b & 0x1f) as u32);
    }
    for c in data.bytes() {
        let Some(v) = CHARSET.iter().position(|&a| a == c) else {
            return false;
        };
        polymod(v as u32);
    }
    chk == 1 || chk == 0x2bc8_30a3
}

/// ISO 7064 mod-97 validation for an IBAN candidate (spaces allowed): move the
/// first four chars to the end, map A–Z to 10–35, and the resulting number
/// must be ≡ 1 (mod 97). Computed as a streaming remainder — no bignum.
fn iban_valid(candidate: &str) -> bool {
    let compact: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    let rearranged = compact[4..].chars().chain(compact[..4].chars());
    let mut rem: u32 = 0;
    for c in rearranged {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            'a'..='z' => c as u32 - 'a' as u32 + 10,
            _ => return false,
        };
        rem = if v < 10 {
            (rem * 10 + v) % 97
        } else {
            (rem * 100 + v) % 97
        };
    }
    rem == 1
}

/// The IPv6 regex cannot anchor on \b (':' is a non-word char), so a candidate
/// glued to an alphanumeric neighbor is a fragment of something else —
/// `std::vector` would otherwise yield `d::`. A following '.' only disqualifies
/// when it starts a decimal continuation (digit after), so a sentence-final
/// `…::1.` still counts.
fn ipv6_boundaries_clean(text: &str, m: &regex::Match) -> bool {
    let before_ok = text[..m.start()]
        .chars()
        .next_back()
        .map_or(true, |c| !c.is_ascii_alphanumeric() && c != ':');
    let after_ok = {
        let mut it = text[m.end()..].chars();
        match it.next() {
            None => true,
            Some(c) if c.is_ascii_alphanumeric() || c == ':' => false,
            Some('.') => !it.next().is_some_and(|c| c.is_ascii_digit()),
            Some(_) => true,
        }
    };
    before_ok && after_ok
}

/// Luhn checksum validation for candidate credit-card digit strings.
/// Used to cut false positives before emitting a [`PiiKind::CreditCard`]
/// finding. Returns `false` for empty or non-digit input.
pub fn luhn_valid(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    // Walk right-to-left, doubling every second digit.
    for &b in bytes.iter().rev() {
        if !b.is_ascii_digit() {
            return false;
        }
        let mut d = (b - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

/// Shannon entropy (bits per char) of a candidate token. Used with a prefix
/// match to qualify [`PiiKind::ApiKey`] findings. Empty input is `0.0`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total_f = total as f64;
    let mut entropy = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total_f;
        entropy -= p * p.log2();
    }
    entropy
}

/// Stable, non-reversible hash of a matched value for [`Finding::value_hash`].
///
/// **Never** returns or stores the raw secret. Uses the std hasher (no crypto
/// dependency); the goal is a stable, redacted fingerprint for dedup/lookup in
/// the Studio, not a security primitive. Prefixed with `h:` and rendered as a
/// fixed-width hex string so it is obviously not a plaintext value.
/// Precision guard for the loose phone candidate, so numeric-heavy model output
/// (timestamps, JSON numbers, decimals, durations) does not flood the Privacy
/// view with false positives.
///
/// A candidate is accepted only when it: (a) is **not embedded** inside a longer
/// number — no digit / `.` / `,` immediately adjacent; (b) carries a real phone
/// signal — a leading `+`, or a space/hyphen separator (dot-only or paren-only
/// runs are rejected); (c) has **7–15 significant digits** (the E.164 range);
/// and (d) is **not a date** shape.
fn looks_like_phone(text: &str, m: &regex::Match) -> bool {
    let s = m.as_str();

    // (a) Reject only when the candidate is a CONTINUATION of a longer number:
    // an adjacent digit, or a '.'/',' that is itself flanked by a digit (a
    // decimal or thousands run, e.g. `1234.56`, `1.234.567`). A trailing sentence
    // '.' or list ',' is fine — a phone often ends a sentence.
    let before_is_num = {
        let mut it = text[..m.start()].chars().rev();
        match it.next() {
            Some(c) if c.is_ascii_digit() => true,
            Some('.') | Some(',') => it.next().is_some_and(|c| c.is_ascii_digit()),
            _ => false,
        }
    };
    let after_is_num = {
        let mut it = text[m.end()..].chars();
        match it.next() {
            Some(c) if c.is_ascii_digit() => true,
            Some('.') | Some(',') => it.next().is_some_and(|c| c.is_ascii_digit()),
            _ => false,
        }
    };
    if before_is_num || after_is_num {
        return false;
    }

    // (b) Must look like a phone, not a dot-grouped number / version / IP-ish
    // run. Dot separators only qualify in the unambiguous NANP 3.3.4 shape
    // (`555.123.4567`) — never the 1.2.3.4 shapes versions use.
    let has_plus = s.trim_start().starts_with('+');
    let has_space_or_dash = s.bytes().any(|b| b == b' ' || b == b'-');
    let nanp_dots = {
        let groups: Vec<&str> = s.split('.').collect();
        groups.len() == 3
            && [3, 3, 4]
                == [groups[0].len(), groups[1].len(), groups[2].len()]
            && groups
                .iter()
                .all(|g| g.bytes().all(|b| b.is_ascii_digit()))
    };
    if !has_plus && !has_space_or_dash && !nanp_dots {
        return false;
    }

    // (c) E.164 significant-digit range.
    let digits = s.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digits) {
        return false;
    }

    // (d) Not a date the loose pattern would otherwise swallow.
    if RE_DATE.is_match(s) {
        return false;
    }

    // (e) Not an adversarial digit-run (G1 round-7/8 critics). Three serial
    // shapes, none a dialable format anywhere common:
    //   - every group one repeated digit   (`1111-2222-3333`, `0000-0000-0000`)
    //   - all groups identical             (`1212-1212-1212`)
    //   - exactly three quads              (`1111-2222-3334` — 4-4-4 is a
    //     serial/PIN-block shape; NANP is 3-3-4, and no plan groups 12
    //     digits as quads)
    // A leading `+` exempts the candidate: the explicit country-code prefix
    // is a deliberate phone signal, and real numbers can look degenerate
    // (`+7 777 777 7777` is a plausible Kazakh mobile — G1 round-9 critic's
    // over-kill).
    let groups: Vec<&str> = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|g| !g.is_empty())
        .collect();
    if !has_plus && !groups.is_empty() {
        let all_repeated = groups.iter().all(|g| {
            let first = g.as_bytes()[0];
            g.bytes().all(|b| b == first)
        });
        let all_identical = groups.len() >= 2 && groups.iter().all(|g| *g == groups[0]);
        let three_quads = groups.len() == 3 && groups.iter().all(|g| g.len() == 4);
        if all_repeated || all_identical || three_quads {
            return false;
        }
    }

    // (f) Not SSN-shaped. A 3-2-4 dashed group is an SSN (valid or garbage),
    // never a real phone format — NANP is 3-3-4. Structurally valid SSNs are
    // claimed by the SSN detector before phone runs; this rejects the invalid
    // remainder instead of mislabeling it.
    !RE_SSN_SHAPE.is_match(s)
}

/// Anchored SSN shape used by [`looks_like_phone`] to reject 3-2-4 dashed runs.
static RE_SSN_SHAPE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{3}-\d{2}-\d{4}$").expect("ssn shape regex"));

/// The typed placeholder a masked span of `kind` is replaced with (04 §7.6).
///
/// Only the high-confidence deterministic kinds have a placeholder; a [`Custom`]
/// pattern maps to a generic `[REDACTED]` so a user pattern is never silently
/// left in place when masking is on for it. Phone/email/etc. get their own tag
/// so the masked text stays self-describing for the reader.
///
/// [`Custom`]: PiiKind::Custom
pub fn placeholder(kind: PiiKind) -> &'static str {
    match kind {
        PiiKind::Email => "[EMAIL]",
        PiiKind::CreditCard => "[CARD]",
        PiiKind::ApiKey => "[API_KEY]",
        PiiKind::IpAddress => "[IP]",
        PiiKind::Phone => "[PHONE]",
        PiiKind::PrivateKey => "[PRIVATE_KEY]",
        PiiKind::Jwt => "[JWT]",
        PiiKind::ConnectionString => "[CONNECTION_STRING]",
        PiiKind::Ssn => "[SSN]",
        PiiKind::Iban => "[IBAN]",
        PiiKind::MacAddress => "[MAC]",
        PiiKind::EnvAssignment => "[ENV_SECRET]",
        PiiKind::CryptoWallet => "[WALLET]",
        PiiKind::Custom => "[REDACTED]",
    }
}

/// The stable wire key for a kind (`api_key`, `credit_card`, …).
///
/// Matches the `serde(rename_all = "snake_case")` representation of [`PiiKind`],
/// so config files, the API, and human-facing messages all name a kind the same
/// way.
pub fn kind_key(kind: &PiiKind) -> &'static str {
    match kind {
        PiiKind::Email => "email",
        PiiKind::CreditCard => "credit_card",
        PiiKind::ApiKey => "api_key",
        PiiKind::IpAddress => "ip_address",
        PiiKind::Phone => "phone",
        PiiKind::PrivateKey => "private_key",
        PiiKind::Jwt => "jwt",
        PiiKind::ConnectionString => "connection_string",
        PiiKind::Ssn => "ssn",
        PiiKind::Iban => "iban",
        PiiKind::MacAddress => "mac_address",
        PiiKind::EnvAssignment => "env_assignment",
        PiiKind::CryptoWallet => "crypto_wallet",
        PiiKind::Custom => "custom",
    }
}

/// Whether a finding is eligible to be masked.
///
/// **Hard rule:** only HIGH-confidence findings are ever masked — best-effort /
/// low-confidence matches are never touched (04 §7.6, §6.1). `kinds`, when
/// `Some`, further restricts masking to that allow-list; `None` means *all*
/// high-confidence kinds. This is the single gate every masking path goes
/// through, so the low-confidence guarantee can never be bypassed.
pub fn should_mask(finding: &Finding, kinds: Option<&[PiiKind]>) -> bool {
    if finding.confidence != Confidence::High {
        return false;
    }
    match kinds {
        Some(allowed) => allowed.contains(&finding.kind),
        None => true,
    }
}

/// Redact `text`, replacing each maskable span with its typed placeholder.
///
/// Given the already-computed `findings` for `text`, returns a new string where
/// every finding that passes [`should_mask`] (HIGH-confidence, in `kinds`) is
/// replaced by [`placeholder`]. Low-confidence / out-of-allow-list spans are
/// left verbatim. Returns the number of spans actually masked alongside the
/// redacted string so callers can record the action.
///
/// ## Safety / correctness
/// - Spans are applied **left-to-right, highest-offset-first** is not needed
///   because we rebuild the string in a single forward pass; overlapping spans
///   cannot occur (the detector claims byte ranges so findings never overlap),
///   but we still skip any finding whose start is behind the last emitted
///   cursor as a defensive guard.
/// - Offsets are byte offsets on UTF-8 boundaries (the detector guarantees
///   this); we slice on them directly. A finding with out-of-range or
///   non-boundary offsets is skipped rather than panicking (fail-open).
pub fn mask(text: &str, findings: &[Finding], kinds: Option<&[PiiKind]>) -> (String, usize) {
    // Collect maskable spans in offset order. The detector already emits
    // offset-sorted, non-overlapping findings, but sort defensively so this
    // function is correct for any caller-supplied slice.
    let mut spans: Vec<(usize, usize, PiiKind)> = findings
        .iter()
        .filter(|f| should_mask(f, kinds))
        .map(|f| (f.start, f.end, f.kind))
        .collect();
    spans.sort_by_key(|&(s, e, _)| (s, e));

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut masked = 0usize;

    for (start, end, kind) in spans {
        // Defensive bounds + boundary checks: skip a malformed span (fail-open).
        if start < cursor || end > text.len() || start > end {
            continue;
        }
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(placeholder(kind));
        cursor = end;
        masked += 1;
    }
    out.push_str(&text[cursor..]);
    (out, masked)
}

pub fn hash_value(matched: &str) -> String {
    let mut hasher = DefaultHasher::new();
    matched.hash(&mut hasher);
    format!("h:{:016x}", hasher.finish())
}

/// Construct a finding from a raw match. Convenience used by detector impls.
/// Hashes `matched` immediately so the raw value is never carried in a
/// [`Finding`].
pub fn make_finding(
    kind: PiiKind,
    label: Option<String>,
    side: Side,
    start: usize,
    end: usize,
    confidence: Confidence,
    matched: &str,
) -> Finding {
    Finding {
        kind,
        label,
        side,
        start,
        end,
        confidence,
        value_hash: hash_value(matched),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> Detector {
        Detector::new(&[]).expect("default detector compiles")
    }

    fn kinds(findings: &[Finding]) -> Vec<PiiKind> {
        findings.iter().map(|f| f.kind).collect()
    }

    fn has_kind(findings: &[Finding], kind: PiiKind) -> bool {
        findings.iter().any(|f| f.kind == kind)
    }

    // --- Luhn ---------------------------------------------------------------

    #[test]
    fn luhn_accepts_known_valid_cards() {
        // Well-known test numbers (all Luhn-valid, not real accounts).
        assert!(luhn_valid("4111111111111111")); // Visa
        assert!(luhn_valid("5500005555555559")); // Mastercard
        assert!(luhn_valid("340000000000009")); // Amex (15)
        assert!(luhn_valid("6011000000000004")); // Discover
        assert!(luhn_valid("79927398713")); // textbook Luhn example
    }

    #[test]
    fn luhn_rejects_invalid_and_garbage() {
        assert!(!luhn_valid("4111111111111112")); // one digit off
        assert!(!luhn_valid("1234567890123456")); // random 16
        assert!(!luhn_valid("79927398710"));
        assert!(!luhn_valid("")); // empty
        assert!(!luhn_valid("4")); // too short
        assert!(!luhn_valid("4111-1111")); // non-digit chars
        assert!(!luhn_valid("abcd")); // letters
    }

    // --- Shannon entropy ----------------------------------------------------

    #[test]
    fn entropy_low_for_repetitive_high_for_random() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0); // single symbol -> 0 bits
        let repetitive = shannon_entropy("xxxxxxxxxxxxxxxx");
        let random = shannon_entropy("aF9zQ2mP7vK1xR4t");
        assert!(repetitive < 1.0);
        assert!(random > 3.0, "random token entropy was {random}");
        assert!(random > repetitive);
    }

    // --- value_hash never leaks the secret ----------------------------------

    #[test]
    fn hash_value_is_stable_and_redacted() {
        let secret = "sk-proj-abcdef0123456789ABCDEF";
        let h1 = hash_value(secret);
        let h2 = hash_value(secret);
        assert_eq!(h1, h2, "hash must be stable");
        assert!(h1.starts_with("h:"));
        assert!(!h1.contains(secret), "hash must not embed the raw value");
        assert_ne!(hash_value("a"), hash_value("b"));
    }

    #[test]
    fn findings_never_carry_raw_value() {
        let d = det();
        let text = "key sk-proj-Zk3Qx9Pa7Lm2Vb8Nc4Rt6Yh1Wd5Sf0 here";
        let findings = d.scan(Side::Request, text);
        assert!(has_kind(&findings, PiiKind::ApiKey));
        for f in &findings {
            assert!(f.value_hash.starts_with("h:"));
            // The raw matched slice must not appear anywhere in the finding.
            let raw = &text[f.start..f.end];
            assert!(!f.value_hash.contains(raw));
        }
    }

    // --- Email --------------------------------------------------------------

    #[test]
    fn detects_emails_with_correct_offsets() {
        let d = det();
        let text = "contact me at jane.doe+test@example.co.uk please";
        let f = d.scan(Side::Request, text);
        let email = f.iter().find(|f| f.kind == PiiKind::Email).expect("email");
        assert_eq!(&text[email.start..email.end], "jane.doe+test@example.co.uk");
        assert_eq!(email.side, Side::Request);
        assert_eq!(email.confidence, Confidence::High);
    }

    #[test]
    fn rejects_non_emails() {
        let d = det();
        for neg in ["not@an", "@nope.com", "plain text", "a@b", "user@localhost"] {
            let f = d.scan(Side::Response, neg);
            assert!(
                !has_kind(&f, PiiKind::Email),
                "should not flag '{neg}' as email"
            );
        }
    }

    // --- Credit cards (Luhn-gated) ------------------------------------------

    #[test]
    fn detects_valid_card_rejects_invalid() {
        let d = det();
        // Valid Visa, spaced.
        let valid = d.scan(Side::Request, "pay with 4111 1111 1111 1111 now");
        assert!(has_kind(&valid, PiiKind::CreditCard));

        // Same length but Luhn-invalid -> NOT a card.
        let invalid = d.scan(Side::Request, "ref 1234 5678 9012 3456 done");
        assert!(
            !has_kind(&invalid, PiiKind::CreditCard),
            "Luhn-invalid run must not be flagged as a card"
        );
    }

    #[test]
    fn card_offsets_cover_the_match() {
        let d = det();
        let text = "card=4111111111111111;";
        let f = d.scan(Side::Request, text);
        let card = f
            .iter()
            .find(|f| f.kind == PiiKind::CreditCard)
            .expect("card");
        assert_eq!(&text[card.start..card.end], "4111111111111111");
    }

    // --- API keys (prefix + entropy) ----------------------------------------

    #[test]
    fn detects_real_looking_api_keys() {
        let d = det();
        let cases = [
            "sk-proj-Zk3Qx9Pa7Lm2Vb8Nc4Rt6Yh1Wd5Sf0aBcDeFgHi",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-2345678901-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
            "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEF",
        ];
        for c in cases {
            let f = d.scan(Side::Request, &format!("token: {c}"));
            assert!(has_kind(&f, PiiKind::ApiKey), "should detect key '{c}'");
        }
    }

    #[test]
    fn rejects_low_entropy_or_unprefixed_keys() {
        let d = det();
        // Prefixed but obviously a placeholder (low entropy) -> not flagged.
        let placeholder = d.scan(Side::Request, "sk-xxxxxxxxxxxxxxxxxxxxxxxx");
        assert!(!has_kind(&placeholder, PiiKind::ApiKey));

        // No known prefix -> not flagged as a key.
        let random = d.scan(Side::Request, "aF9zQ2mP7vK1xR4tBn8Lc3Wd6Yh0Sg5");
        assert!(!has_kind(&random, PiiKind::ApiKey));

        // Too-short body after prefix.
        let short = d.scan(Side::Request, "sk-ab12");
        assert!(!has_kind(&short, PiiKind::ApiKey));
    }

    // --- IP addresses -------------------------------------------------------

    #[test]
    fn detects_ipv4() {
        let d = det();
        let f = d.scan(Side::Response, "server at 192.168.1.100 responded");
        let ip = f
            .iter()
            .find(|f| f.kind == PiiKind::IpAddress)
            .expect("ipv4");
        assert_eq!(
            &"server at 192.168.1.100 responded"[ip.start..ip.end],
            "192.168.1.100"
        );
    }

    #[test]
    fn rejects_out_of_range_ipv4() {
        let d = det();
        let f = d.scan(Side::Response, "not an ip 999.999.999.999 here");
        assert!(!has_kind(&f, PiiKind::IpAddress));
    }

    #[test]
    fn detects_ipv6() {
        let d = det();
        for ip in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8::8a2e:370:7334",
            "::1",
            "fe80::1ff:fe23:4567:890a",
        ] {
            let f = d.scan(Side::Request, &format!("addr {ip} end"));
            assert!(
                has_kind(&f, PiiKind::IpAddress),
                "should detect ipv6 '{ip}'"
            );
        }
    }

    // --- Phone --------------------------------------------------------------

    #[test]
    fn detects_phone_numbers() {
        let d = det();
        for phone in ["+1 (555) 123-4567", "555-123-4567", "+44 20 7946 0958"] {
            let f = d.scan(Side::Request, &format!("call {phone} today"));
            assert!(
                has_kind(&f, PiiKind::Phone),
                "should detect phone '{phone}'"
            );
        }
    }

    #[test]
    fn does_not_flag_card_as_phone() {
        let d = det();
        // A valid card must surface as CreditCard, not Phone (claim precedence).
        let f = d.scan(Side::Request, "4111 1111 1111 1111");
        assert!(has_kind(&f, PiiKind::CreditCard));
        assert!(!has_kind(&f, PiiKind::Phone));
    }

    #[test]
    fn does_not_flag_numeric_noise_as_phone() {
        let d = det();
        // The kind of numeric-heavy text local-model output produces — none of
        // these should be flagged as phone numbers (was a 1,690-hit FP source).
        let noise = [
            "logged at 2026-06-06T13:32:50 and again 2026-06-06",
            "scheduled for 06.06.2026 / 31-12-2025",
            r#"{"total_duration":32980116750,"eval_count":1759,"eval_duration":30678908000}"#,
            "pi is 3.14159 and the ratio was 1234.5678 exactly",
            "coords 12.34, 56.78 and prices 1999.00, 2499.00",
            "build 1.2.3.4 shipped; uptime 99.99 percent",
        ];
        for t in noise {
            let f = d.scan(Side::Response, t);
            assert!(
                !has_kind(&f, PiiKind::Phone),
                "numeric noise wrongly flagged as phone: {t:?} -> {f:?}"
            );
        }
    }

    #[test]
    fn still_detects_phones_amid_noise() {
        let d = det();
        // Real phones must still be caught even next to numeric noise.
        let f = d.scan(
            Side::Response,
            "on 2026-06-06 call +1 (555) 123-4567 or 020 7946 0958 re: invoice 1234.56",
        );
        let phones = f.iter().filter(|x| x.kind == PiiKind::Phone).count();
        assert!(phones >= 2, "expected >=2 phones, got {phones}: {f:?}");
    }

    #[test]
    fn detects_phone_at_end_of_sentence() {
        // A trailing full stop or list comma must NOT suppress a real phone
        // (regression: a sentence '.' was misread as a decimal continuation).
        let d = det();
        for t in [
            "my number is +1 (555) 987-6543.",
            "reach me at 555-123-4567, thanks",
            "call +44 20 7946 0958.",
        ] {
            let f = d.scan(Side::Request, t);
            assert!(has_kind(&f, PiiKind::Phone), "missed phone in {t:?}");
        }
    }

    // --- Private-key blocks ---------------------------------------------------

    #[test]
    fn detects_private_key_block_whole_span() {
        let d = det();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq4\n-----END RSA PRIVATE KEY-----";
        let f = d.scan(Side::Request, text);
        let k = f
            .iter()
            .find(|f| f.kind == PiiKind::PrivateKey)
            .expect("private key");
        // The WHOLE block must be the span — masking only the banner would
        // leave the key material in place.
        assert_eq!(&text[k.start..k.end], text);
    }

    #[test]
    fn detects_truncated_private_key_header() {
        let d = det();
        let f = d.scan(Side::Request, "paste: -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNz");
        assert!(has_kind(&f, PiiKind::PrivateKey), "header alone is a leak");
    }

    #[test]
    fn ignores_public_key_blocks() {
        let d = det();
        let f = d.scan(
            Side::Request,
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
        );
        assert!(!has_kind(&f, PiiKind::PrivateKey), "public keys are not secrets");
    }

    // --- JWT -------------------------------------------------------------------

    #[test]
    fn detects_jwt() {
        let d = det();
        let text = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U sent";
        let f = d.scan(Side::Request, text);
        let j = f.iter().find(|f| f.kind == PiiKind::Jwt).expect("jwt");
        assert!(&text[j.start..j.end].starts_with("eyJhbGciOi"));
        assert!(&text[j.start..j.end].ends_with("THsR8U"), "full three-part span");
    }

    #[test]
    fn ignores_dotted_filenames_as_jwt() {
        let d = det();
        let f = d.scan(Side::Request, "file config.prod.yaml loaded");
        assert!(!has_kind(&f, PiiKind::Jwt));
    }

    // --- Connection strings ------------------------------------------------------

    #[test]
    fn detects_credentialed_connection_strings() {
        let d = det();
        for cs in [
            "postgres://admin:hunter2@db.internal:5432/prod",
            "mysql://root:p4ssw0rd@localhost:3306/app",
            "mongodb+srv://user:secret@cluster0.example.mongodb.net/db",
            "redis://default:changeme@10.0.0.5:6379/0",
        ] {
            let f = d.scan(Side::Request, &format!("export URL={cs} done"));
            let hit = f
                .iter()
                .find(|f| f.kind == PiiKind::ConnectionString)
                .unwrap_or_else(|| panic!("missed connection string {cs}"));
            let text = format!("export URL={cs} done");
            assert_eq!(&text[hit.start..hit.end], cs, "whole URL is the span");
            // The credential local-part must NOT also be read as an email.
            assert!(!has_kind(&f, PiiKind::Email), "claimed before email: {cs}");
        }
    }

    #[test]
    fn ignores_credentialless_urls() {
        let d = det();
        for url in [
            "https://example.com/path?q=1",
            "postgres://db.internal:5432/prod",
        ] {
            let f = d.scan(Side::Request, &format!("fetch {url} now"));
            assert!(
                !has_kind(&f, PiiKind::ConnectionString),
                "no credentials in {url}"
            );
        }
    }

    // --- SSN ---------------------------------------------------------------------

    #[test]
    fn detects_valid_ssn_and_claims_before_phone() {
        let d = det();
        let f = d.scan(Side::Request, "applicant SSN 078-05-1120 on file");
        assert!(has_kind(&f, PiiKind::Ssn));
        // The old behavior mislabeled this span as a phone number.
        assert!(!has_kind(&f, PiiKind::Phone));
    }

    #[test]
    fn rejects_never_issued_ssn_ranges() {
        let d = det();
        for bad in [
            "000-12-3456", // area 000
            "666-12-3456", // area 666
            "978-05-1120", // area 900+
            "123-00-4567", // group 00
            "123-45-0000", // serial 0000
        ] {
            let f = d.scan(Side::Request, &format!("id {bad} noted"));
            assert!(!has_kind(&f, PiiKind::Ssn), "must reject {bad}");
            // …and the rejected 3-2-4 run must not fall through to phone.
            assert!(!has_kind(&f, PiiKind::Phone), "SSN shape mislabeled as phone: {bad}");
        }
    }

    // --- IBAN ----------------------------------------------------------------------

    #[test]
    fn detects_valid_ibans_spaced_and_compact() {
        let d = det();
        for iban in [
            "DE89 3704 0044 0532 0130 00",
            "GB82 WEST 1234 5698 7654 32",
            "NL91ABNA0417164300",
            "FR14 2004 1010 0505 0001 3M02 606",
        ] {
            let f = d.scan(Side::Request, &format!("wire to {iban} ref 7"));
            assert!(has_kind(&f, PiiKind::Iban), "missed IBAN {iban}");
        }
    }

    #[test]
    fn rejects_checksum_invalid_iban() {
        let d = det();
        let f = d.scan(Side::Request, "wire to DE89 3704 0044 0532 0130 01 ref 7");
        assert!(!has_kind(&f, PiiKind::Iban), "mod-97 must gate candidates");
        // The typo'd IBAN's digit tail passes Luhn by luck — it must not be
        // relabeled as a credit card either.
        assert!(!has_kind(&f, PiiKind::CreditCard), "IBAN tail is not a card");
    }

    // --- MAC ---------------------------------------------------------------------

    #[test]
    fn detects_mac_colon_and_hyphen_forms() {
        let d = det();
        for mac in ["00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E"] {
            let f = d.scan(Side::Request, &format!("nic at {mac} up"));
            assert!(has_kind(&f, PiiKind::MacAddress), "missed MAC {mac}");
        }
    }

    #[test]
    fn rejects_short_mac_and_times() {
        let d = det();
        for neg in ["00:1a:2b:3c:4d", "time 12:30:45 logged"] {
            let f = d.scan(Side::Request, neg);
            assert!(!has_kind(&f, PiiKind::MacAddress), "must reject {neg:?}");
        }
    }

    // --- Round-1 bench regressions (G1) ------------------------------------------

    #[test]
    fn ipv6_compressed_forms_match_full_span() {
        // Round 1 truncated these at the '::' — masking the truncated span
        // would leak the remainder of the address.
        let d = det();
        for ip in [
            "2001:db8::8a2e:370:7334",
            "fe80::1ff:fe23:4567:890a",
            "::ffff:192.0.2.128",
        ] {
            let text = format!("addr {ip} end");
            let f = d.scan(Side::Request, &text);
            let hit = f
                .iter()
                .find(|f| f.kind == PiiKind::IpAddress)
                .unwrap_or_else(|| panic!("missed {ip}"));
            assert_eq!(&text[hit.start..hit.end], ip, "full span for {ip}");
        }
    }

    #[test]
    fn ipv6_ignores_cpp_namespace_fragments() {
        let d = det();
        for neg in ["call std::vector now", "use std::cafe here"] {
            let f = d.scan(Side::Request, neg);
            assert!(
                !has_kind(&f, PiiKind::IpAddress),
                "namespace fragment flagged in {neg:?}: {f:?}"
            );
        }
    }

    #[test]
    fn plus_prefixed_luhn_valid_run_is_phone_not_card() {
        // +234 803 555 1234 is 13 digits and Luhn-valid by coincidence; the
        // leading '+' says international phone, never a card.
        let d = det();
        let f = d.scan(Side::Request, "+234 803 555 1234 is my number");
        assert!(has_kind(&f, PiiKind::Phone));
        assert!(!has_kind(&f, PiiKind::CreditCard));
    }

    #[test]
    fn email_ignores_asset_filenames() {
        let d = det();
        let f = d.scan(Side::Request, "see file image@2x.png here");
        assert!(!has_kind(&f, PiiKind::Email));
        // …but a real ccTLD that doubles as an extension-looking suffix stays.
        let f = d.scan(Side::Request, "mail me at info@example.md soon");
        assert!(has_kind(&f, PiiKind::Email), ".md is Moldova, keep it");
    }

    // --- Custom patterns ----------------------------------------------------

    #[test]
    fn custom_pattern_matches_with_label_and_confidence() {
        let custom = vec![CustomPattern {
            name: "employee_id".to_string(),
            regex: r"EMP-\d{6}".to_string(),
            confidence: Confidence::Low,
        }];
        let d = Detector::new(&custom).expect("compiles");
        let f = d.scan(Side::Request, "user EMP-004217 logged in");
        let hit = f
            .iter()
            .find(|f| f.kind == PiiKind::Custom)
            .expect("custom hit");
        assert_eq!(hit.label.as_deref(), Some("employee_id"));
        assert_eq!(hit.confidence, Confidence::Low);
        assert_eq!(
            &"user EMP-004217 logged in"[hit.start..hit.end],
            "EMP-004217"
        );
    }

    #[test]
    fn invalid_custom_regex_is_a_control_plane_error() {
        let custom = vec![CustomPattern {
            name: "bad".to_string(),
            regex: r"([unclosed".to_string(),
            confidence: Confidence::High,
        }];
        let err = Detector::new(&custom);
        assert!(err.is_err(), "invalid regex must error at construction");
    }

    // --- Side + cleanliness -------------------------------------------------

    #[test]
    fn side_is_propagated() {
        let d = det();
        let req = d.scan(Side::Request, "mail a@b.com");
        let resp = d.scan(Side::Response, "mail a@b.com");
        assert!(req.iter().all(|f| f.side == Side::Request));
        assert!(resp.iter().all(|f| f.side == Side::Response));
    }

    #[test]
    fn clean_text_yields_no_findings() {
        let d = det();
        let f = d.scan(
            Side::Request,
            "The quick brown fox jumps over the lazy dog.",
        );
        assert!(f.is_empty(), "unexpected findings: {:?}", kinds(&f));
    }

    // --- Masking (04 §7.6) --------------------------------------------------

    #[test]
    fn placeholders_are_typed_per_kind() {
        assert_eq!(placeholder(PiiKind::Email), "[EMAIL]");
        assert_eq!(placeholder(PiiKind::CreditCard), "[CARD]");
        assert_eq!(placeholder(PiiKind::ApiKey), "[API_KEY]");
        assert_eq!(placeholder(PiiKind::IpAddress), "[IP]");
        assert_eq!(placeholder(PiiKind::Phone), "[PHONE]");
    }

    #[test]
    fn mask_redacts_high_confidence_spans() {
        let d = det();
        let text = "email jane@example.com and ip 192.168.1.100 done";
        let findings = d.scan(Side::Request, text);
        let (redacted, n) = mask(text, &findings, None);
        assert_eq!(n, 2, "two high-confidence spans masked");
        assert_eq!(redacted, "email [EMAIL] and ip [IP] done");
        // The raw values must be gone from the redacted output.
        assert!(!redacted.contains("jane@example.com"));
        assert!(!redacted.contains("192.168.1.100"));
    }

    #[test]
    fn mask_only_touches_allowed_kinds() {
        let d = det();
        let text = "email jane@example.com and ip 192.168.1.100 done";
        let findings = d.scan(Side::Request, text);
        // Restrict to email only: the IP must survive verbatim.
        let (redacted, n) = mask(text, &findings, Some(&[PiiKind::Email]));
        assert_eq!(n, 1);
        assert!(redacted.contains("[EMAIL]"));
        assert!(redacted.contains("192.168.1.100"), "IP not in allow-list");
        assert!(!redacted.contains("[IP]"));
    }

    #[test]
    fn mask_never_touches_low_confidence() {
        // A custom Low-confidence finding must never be masked, even when its
        // kind would otherwise be in scope.
        let custom = vec![CustomPattern {
            name: "employee_id".to_string(),
            regex: r"EMP-\d{6}".to_string(),
            confidence: Confidence::Low,
        }];
        let d = Detector::new(&custom).expect("compiles");
        let text = "user EMP-004217 mailed a@b.com";
        let findings = d.scan(Side::Request, text);
        // No kind filter -> everything high-confidence is fair game, but the
        // Low-confidence custom hit must still be left verbatim.
        let (redacted, _n) = mask(text, &findings, None);
        assert!(
            redacted.contains("EMP-004217"),
            "low-confidence span must never be masked: {redacted}"
        );
        assert!(should_mask(
            &Finding {
                kind: PiiKind::Email,
                label: None,
                side: Side::Request,
                start: 0,
                end: 1,
                confidence: Confidence::High,
                value_hash: "h".into(),
            },
            None
        ));
        assert!(!should_mask(
            &Finding {
                kind: PiiKind::Custom,
                label: Some("employee_id".into()),
                side: Side::Request,
                start: 0,
                end: 1,
                confidence: Confidence::Low,
                value_hash: "h".into(),
            },
            None
        ));
    }

    #[test]
    fn mask_clean_text_is_identity() {
        let d = det();
        let text = "The quick brown fox jumps over the lazy dog.";
        let findings = d.scan(Side::Request, text);
        let (redacted, n) = mask(text, &findings, None);
        assert_eq!(n, 0);
        assert_eq!(redacted, text);
    }

    #[test]
    fn mask_skips_out_of_range_spans_fail_open() {
        // A malformed finding (offsets past the end) must be skipped, not panic.
        let text = "short";
        let bad = Finding {
            kind: PiiKind::Email,
            label: None,
            side: Side::Request,
            start: 2,
            end: 999,
            confidence: Confidence::High,
            value_hash: "h".into(),
        };
        let (redacted, n) = mask(text, &[bad], None);
        assert_eq!(n, 0, "out-of-range span skipped");
        assert_eq!(redacted, text);
    }

    #[test]
    fn findings_are_offset_sorted() {
        let d = det();
        let text = "ip 10.0.0.1 mail a@b.com card 4111 1111 1111 1111";
        let f = d.scan(Side::Request, text);
        let mut last = 0usize;
        for finding in &f {
            assert!(finding.start >= last, "findings not offset-sorted");
            last = finding.start;
            // Offsets must index valid UTF-8 boundaries.
            assert!(text.is_char_boundary(finding.start));
            assert!(text.is_char_boundary(finding.end));
        }
    }

    // --- env credential assignments (G1 round 3) ----------------------------

    #[test]
    fn detects_env_credential_assignments() {
        let d = det();
        let text = "DB_PASSWORD=hunter2secret AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let f = d.scan(Side::Request, text);
        let spans: Vec<&str> = f
            .iter()
            .filter(|f| f.kind == PiiKind::EnvAssignment)
            .map(|f| &text[f.start..f.end])
            .collect();
        assert_eq!(
            spans,
            [
                "DB_PASSWORD=hunter2secret",
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ],
            "the whole assignment is the finding"
        );
    }

    #[test]
    fn env_assignment_rejects_config_and_placeholders() {
        let d = det();
        for benign in [
            "DEBUG=true",                    // key names no credential
            "PORT=8080",                     // ditto
            "PASSWORD=changeme",             // placeholder value
            "API_TOKEN=${VAULT_TOKEN}",      // interpolation, not a secret
            "AUTHOR=JohnSmith99",            // AUTH must not match inside AUTHOR
            "PUBLIC_KEY=abcdef1234567890",   // public halves are not secrets
            "SECRET_KEY=xxxxxxxxxxxxxxxx",   // zero-entropy template filler
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign}");
        }
    }

    #[test]
    fn env_assignment_defers_to_specific_secret_kinds() {
        // A value that is itself a prefixed API key keeps its specific label.
        let d = det();
        let text = "GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a";
        let f = d.scan(Side::Request, text);
        assert!(has_kind(&f, PiiKind::ApiKey));
        assert!(!has_kind(&f, PiiKind::EnvAssignment));
    }

    // --- Key=Value; connection strings (G1 round 3) -------------------------

    #[test]
    fn detects_kv_connection_string_whole_span() {
        let d = det();
        let text = "Server=db.internal;Database=app;User Id=svc;Password=Hunter2!;Encrypt=true";
        let f = d.scan(Side::Request, text);
        let c = f
            .iter()
            .find(|f| f.kind == PiiKind::ConnectionString)
            .expect("kv connection string");
        assert_eq!(&text[c.start..c.end], text, "whole property run claimed");
    }

    #[test]
    fn kv_pairs_without_password_are_not_a_connection_string() {
        let d = det();
        let f = d.scan(Side::Request, "Server=db.internal;Database=app;Encrypt=true");
        assert!(!has_kind(&f, PiiKind::ConnectionString));
    }

    // --- version-context gate (G1 round 3, ip-t04) --------------------------

    #[test]
    fn version_strings_are_not_ip_addresses() {
        let d = det();
        for benign in ["build 1.2.3.4 shipped", "upgraded to version 2.14.0.1"] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::IpAddress), "must reject {benign}");
        }
        // The gate is token-exact: an address in plain prose is untouched.
        let f = d.scan(Side::Request, "ping 1.2.3.4 from the gateway");
        assert!(has_kind(&f, PiiKind::IpAddress));
    }

    // --- SSN context forms (G1 round 3) -------------------------------------

    #[test]
    fn ssn_dashless_and_spaced_need_context() {
        let d = det();
        for hit in ["SSN: 078051120", "her social security number is 078 05 1120"] {
            let f = d.scan(Side::Request, hit);
            assert!(has_kind(&f, PiiKind::Ssn), "missed {hit:?}");
        }
        for benign in [
            "invoice 078051120 attached", // no SSN context
            "SSN: 000051120",             // context, but never-issued area
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::Ssn), "must reject {benign:?}");
        }
    }

    // --- phone shapes (G1 round 3) ------------------------------------------

    #[test]
    fn detects_spaceless_e164_and_nanp_dots() {
        let d = det();
        for hit in ["call +15551234567 today", "fax 555.123.4567 available"] {
            let f = d.scan(Side::Request, hit);
            assert!(has_kind(&f, PiiKind::Phone), "missed {hit:?}");
        }
    }

    // --- crypto wallets (G1 round 3) ----------------------------------------

    #[test]
    fn detects_checksum_valid_wallets() {
        let d = det();
        for wallet in [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // legacy P2PKH (genesis), base58check
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", // P2SH, base58check
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", // segwit v0, BIP-173
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", // taproot, BIP-350
            "0x52908400098527886E0F7030069857D2E4169EE7", // EVM hex
        ] {
            let text = format!("refund to {wallet} please");
            let f = d.scan(Side::Request, &text);
            let m = f
                .iter()
                .find(|f| f.kind == PiiKind::CryptoWallet)
                .unwrap_or_else(|| panic!("missed {wallet}"));
            assert_eq!(&text[m.start..m.end], wallet);
        }
    }

    #[test]
    fn rejects_checksum_invalid_wallets_and_hash_lookalikes() {
        let d = det();
        for benign in [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", // base58check checksum broken
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx", // bech32 checksum broken
            "e83be5363378c9b4c41acbcb66c48dc9ab60cc10", // bare 40-hex (git SHA), no 0x
            "0xe83be5363378c9b4c41acbcb66c48dc9ab60cc1064bc79dafa2c3af769694aaa", // 64-hex tx hash
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::CryptoWallet), "must reject {benign}");
        }
    }

    // --- EIP-55 (G1 round 4) ------------------------------------------------

    #[test]
    fn evm_mixed_case_enforces_eip55() {
        let d = det();
        // EIP-55 spec examples — valid casings must fire.
        for valid in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        ] {
            let f = d.scan(Side::Request, valid);
            assert!(has_kind(&f, PiiKind::CryptoWallet), "missed {valid}");
        }
        // One flipped letter breaks the Keccak casing — must not fire.
        let f = d.scan(Side::Request, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD");
        assert!(!has_kind(&f, PiiKind::CryptoWallet), "case-corrupted EIP-55 accepted");
        // Single-case addresses carry no checksum info — accepted on shape.
        let f = d.scan(Side::Request, "0xde709f2102306220921060314715629080e2fb77");
        assert!(has_kind(&f, PiiKind::CryptoWallet));
    }

    // --- structured-config secrets (G1 round 4) -----------------------------

    #[test]
    fn detects_json_yaml_toml_config_secrets() {
        let d = det();
        let cases = [
            (r#"{"password": "hunter2secret99", "user": "svc"}"#, r#""password": "hunter2secret99""#),
            ("db:\n  host: localhost\n  db_password: hunter2secret99\n", "db_password: hunter2secret99"),
            ("[database]\napi_token = \"tok_9f8e7d6c5b4a\"\n", "api_token = \"tok_9f8e7d6c5b4a\""),
        ];
        for (text, want) in cases {
            let f = d.scan(Side::Request, text);
            let m = f
                .iter()
                .find(|f| f.kind == PiiKind::EnvAssignment)
                .unwrap_or_else(|| panic!("missed config secret in {text:?}"));
            assert_eq!(&text[m.start..m.end], want, "span in {text:?}");
        }
    }

    #[test]
    fn config_secret_rejects_benign_structured_pairs() {
        let d = det();
        for benign in [
            r#"{"username": "admin", "role": "editor"}"#, // no credential key
            r#"{"password": "changeme"}"#,                // placeholder value
            "server:\n  port: 8080\n  log_level: verbose\n", // plain config
            "password: ${SECRET_REF} # injected\n",       // interpolation
            "[build]\nversion = \"1.2.3-beta.4\"\n",      // not a credential key
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign:?}");
        }
    }

    #[test]
    fn yaml_prose_lines_are_not_secrets() {
        // The round-4 critic's constructed FP class: line-start prose whose
        // first word is a secret keyword. Unquoted multi-word values are
        // prose, not material.
        let d = det();
        for benign in [
            "token: expired yesterday",
            "password: incorrect, try again",
            "secret: the cake is a lie",
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign:?}");
        }
        // A QUOTED multi-word value is deliberate config, not prose.
        let text = "password: \"correct horse battery staple\"";
        let f = d.scan(Side::Request, text);
        assert!(has_kind(&f, PiiKind::EnvAssignment), "quoted multi-word secret missed");
    }

    #[test]
    fn detects_pass_abbreviation_and_single_quoted_toml() {
        let d = det();
        for (text, want) in [
            ("DB_PASS=q9v2x7mplt44", "DB_PASS=q9v2x7mplt44"),
            ("client_secret = 'cs_4f9a2b7c1d'", "client_secret = 'cs_4f9a2b7c1d'"),
        ] {
            let f = d.scan(Side::Request, text);
            let m = f
                .iter()
                .find(|f| f.kind == PiiKind::EnvAssignment)
                .unwrap_or_else(|| panic!("missed {text}"));
            assert_eq!(&text[m.start..m.end], want);
        }
        // BYPASS must not qualify via its PASS substring — segments, not substrings.
        let f = d.scan(Side::Request, "FEATURE_BYPASS=enabled99x");
        assert!(!has_kind(&f, PiiKind::EnvAssignment));
    }

    #[test]
    fn redaction_markers_and_status_words_are_not_secrets() {
        let d = det();
        for benign in [
            "password: [FILTERED]",         // Rails/Rack log scrubbing
            "password: [REDACTED]",
            "password: incorrect",          // status word, not material
            "token: expired",
            "export PASSWORD=incorrect",    // same class in the shell form
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign:?}");
        }
    }

    #[test]
    fn decorated_markers_and_status_compounds_are_not_secrets() {
        // Round-6 critic: the denylist must not regrow one decoration away.
        // Markers are matched on a normalized view (decoration stripped,
        // lowercased) and `_`-joined all-vocabulary compounds are protocol
        // noise, not material.
        let d = det();
        for benign in [
            "password: ***MASKED***",
            "password: (REDACTED)",
            "token: invalid_token",
            "auth_token: token_expired",
            "password: access_denied",
            "{\"password\": \"[FILTERED]\"}", // marker check reaches quoted grammars
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign:?}");
        }
    }

    #[test]
    fn quoted_bracket_secrets_and_symbol_rockets_fire() {
        let d = det();
        // Round-6 critic's over-kill: a QUOTED real secret starting with '['
        // is literal, not a marker.
        let text = "export PASSWORD='[k9!fQ2xW8z'";
        let f = d.scan(Side::Request, text);
        let m = f
            .iter()
            .find(|f| f.kind == PiiKind::EnvAssignment)
            .expect("quoted bracket secret");
        assert_eq!(&text[m.start..m.end], "PASSWORD='[k9!fQ2xW8z'");
        // Round-6 critic's missed grammar: symbol-key Ruby rockets.
        let text = r#"{:password=>"hunter2secret99", :role=>"admin"}"#;
        let f = d.scan(Side::Request, text);
        let m = f
            .iter()
            .find(|f| f.kind == PiiKind::EnvAssignment)
            .expect("symbol rocket secret");
        assert_eq!(&text[m.start..m.end], r#":password=>"hunter2secret99""#);
        // Status-word SUBSTRINGS must not kill real secrets.
        let f = d.scan(Side::Request, "password: hidden2secret");
        assert!(has_kind(&f, PiiKind::EnvAssignment));
    }

    #[test]
    fn uniform_digit_groups_are_not_phones() {
        // Round-7 critic: serials/placeholders where every group is one
        // repeated digit must not read as phones.
        let d = det();
        for benign in ["serial 1111-2222-3333 registered", "card PIN block 0000-0000-0000"] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::Phone), "must reject {benign:?}");
        }
        // A real number always has a mixed group.
        let f = d.scan(Side::Request, "call 555-123-4567");
        assert!(has_kind(&f, PiiKind::Phone));
    }

    #[test]
    fn filler_compounds_and_annotated_markers_are_not_secrets() {
        // Round-7 critic: filler connectors and marker-plus-annotation.
        let d = det();
        for benign in [
            "token: not_set",
            "password: to_be_filled",
            "PASSWORD=REDACTED_BY_SOC_TEAM",
            "password: \"MASKED (by proxy)\"",
        ] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign:?}");
        }
        // Scrub verbs gate on the FIRST segment only — a passphrase merely
        // containing one is material.
        let f = d.scan(Side::Request, "password: was-removed-x9q");
        assert!(has_kind(&f, PiiKind::EnvAssignment));
    }

    #[test]
    fn detects_object_literal_secrets() {
        // Round-7 critic's named FN class: mid-line unquoted-key object
        // literals (JS, Ruby 1.9 keyword hash, Python dict repr).
        let d = det();
        for (text, want) in [
            (
                r#"logger.info({password: "hunter2xyz99", user: "svc"})"#,
                r#"password: "hunter2xyz99""#,
            ),
            (
                "opts = {password: 'railsKw99x'}",
                "password: 'railsKw99x'",
            ),
            (
                "{'db_password': 'py2repr99x'}",
                "'db_password': 'py2repr99x'",
            ),
        ] {
            let f = d.scan(Side::Request, text);
            let m = f
                .iter()
                .find(|f| f.kind == PiiKind::EnvAssignment)
                .unwrap_or_else(|| panic!("missed {text:?}"));
            assert_eq!(&text[m.start..m.end], want);
        }
        // The quoted value is load-bearing: mid-line unquoted prose stays out.
        let f = d.scan(Side::Request, "he typed password: hunter2 and hit enter");
        assert!(!has_kind(&f, PiiKind::EnvAssignment));
    }

    #[test]
    fn quote_pairing_is_exact_and_escapes_work() {
        let d = det();
        // Round-8 critic's span bug: an apostrophe inside a double-quoted
        // value must not close the span.
        let text = r#"password_hint: "mother's maiden name""#;
        let f = d.scan(Side::Request, text);
        let m = f
            .iter()
            .find(|f| f.kind == PiiKind::EnvAssignment)
            .expect("apostrophe-in-double-quotes");
        assert_eq!(&text[m.start..m.end], text, "span must cover the full pair");
        // Escaped quote inside a double-quoted value.
        let text = r#"{password: "hu\"nter99x"}"#;
        let f = d.scan(Side::Request, text);
        let m = f
            .iter()
            .find(|f| f.kind == PiiKind::EnvAssignment)
            .expect("escaped-quote value");
        assert_eq!(&text[m.start..m.end], r#"password: "hu\"nter99x""#);
        // JS template literal.
        let text = "{password: `tpl99secret`}";
        let f = d.scan(Side::Request, text);
        assert!(has_kind(&f, PiiKind::EnvAssignment), "template literal missed");
    }

    #[test]
    fn serial_shaped_digit_groups_are_not_phones() {
        // Round-8 critic: identical groups and the 4-4-4 quad shape.
        let d = det();
        for benign in ["ref 1212-1212-1212 issued", "code 1111-2222-3334 assigned"] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::Phone), "must reject {benign:?}");
        }
    }

    #[test]
    fn filler_leads_are_not_secrets() {
        let d = det();
        let f = d.scan(Side::Request, "password: \"TBD-final\"");
        assert!(!has_kind(&f, PiiKind::EnvAssignment), "TBD-annotation is filler");
        // But a value merely CONTAINING a filler word later stays material.
        let f = d.scan(Side::Request, "password: was-removed-x9q");
        assert!(has_kind(&f, PiiKind::EnvAssignment));
    }

    #[test]
    fn deferral_only_hands_off_when_the_target_claims() {
        // Round-9 critic's severe FN: base64-encoded JSON starts `eyJ`
        // without being a JWT; a below-entropy sk- value clears neither
        // detector. Deferral must verify the hand-off.
        let d = det();
        let text = "PASSWORD=eyJ0eXBlIjoiYWNjb3VudCJ9";
        let f = d.scan(Side::Request, text);
        assert!(has_kind(&f, PiiKind::EnvAssignment), "base64-JSON credential vanished");
        assert!(!has_kind(&f, PiiKind::Jwt));
        let f = d.scan(Side::Request, "PASSWORD=sk-abcdabcdabcdabcdabcd");
        assert!(has_kind(&f, PiiKind::EnvAssignment), "below-entropy sk- value vanished");
        // A REAL key or JWT still keeps its specific label.
        let f = d.scan(Side::Request, "GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a");
        assert!(has_kind(&f, PiiKind::ApiKey));
        assert!(!has_kind(&f, PiiKind::EnvAssignment));
    }

    #[test]
    fn escaped_quotes_span_fully_in_every_grammar() {
        // Round-9 critic: the escape fix was asymmetric — TOML, shell, and
        // single-quoted branches still leaked or truncated.
        let d = det();
        for (text, want) in [
            (
                "db_password = \"hu\\\"nter99x\"",
                "db_password = \"hu\\\"nter99x\"",
            ),
            (
                "export DB_PASSWORD=\"hux\\\"nter99\"",
                "DB_PASSWORD=\"hux\\\"nter99\"",
            ),
            (
                r#"{password: 'hunter\'s99x'}"#,
                r#"password: 'hunter\'s99x'"#,
            ),
        ] {
            let f = d.scan(Side::Request, text);
            let m = f
                .iter()
                .find(|f| f.kind == PiiKind::EnvAssignment)
                .unwrap_or_else(|| panic!("missed {text:?}"));
            assert_eq!(&text[m.start..m.end], want, "span in {text:?}");
        }
    }

    #[test]
    fn passphrase_keys_and_lowercase_ibans_and_plus_phones() {
        let d = det();
        let f = d.scan(Side::Request, "GPG_PASSPHRASE=correct-horse-battery-x99");
        assert!(has_kind(&f, PiiKind::EnvAssignment), "PASSPHRASE key missed");
        let f = d.scan(Side::Request, "iban de89370400440532013000 on the invoice");
        assert!(has_kind(&f, PiiKind::Iban), "lowercase IBAN missed");
        // A '+' country prefix exempts degenerate-looking real numbers from
        // the serial-shape rules.
        let f = d.scan(Side::Request, "call +7 777 777 7777 today");
        assert!(has_kind(&f, PiiKind::Phone), "+7 Kazakh mobile over-killed");
        // Status-vocab synonyms are non-material.
        for benign in ["password: rejected", "token: unauthorized"] {
            let f = d.scan(Side::Request, benign);
            assert!(!has_kind(&f, PiiKind::EnvAssignment), "must reject {benign:?}");
        }
    }

    #[test]
    fn detects_ruby_hash_rocket_secrets() {
        let d = det();
        let text = r#"{"password"=>"hunter2secret99", "role"=>"admin"}"#;
        let f = d.scan(Side::Request, text);
        let m = f
            .iter()
            .find(|f| f.kind == PiiKind::EnvAssignment)
            .expect("hash-rocket secret");
        assert_eq!(&text[m.start..m.end], r#""password"=>"hunter2secret99""#);
    }

    #[test]
    fn yaml_secret_value_stops_before_comment() {
        let d = det();
        let text = "smtp_password: hunter2secret99 # rotate quarterly\n";
        let f = d.scan(Side::Request, text);
        let m = f
            .iter()
            .find(|f| f.kind == PiiKind::EnvAssignment)
            .expect("yaml secret");
        assert_eq!(&text[m.start..m.end], "smtp_password: hunter2secret99");
    }
}
