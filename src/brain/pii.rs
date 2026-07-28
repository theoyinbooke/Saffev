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

/// Phone numbers: optional country code, common separators, 7–14 significant
/// digits. Tightened to avoid swallowing arbitrary digit runs / card numbers.
static RE_PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{1,4}\)[ .\-]?)?\d{2,4}(?:[ .\-]\d{2,4}){1,3}")
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

/// IBAN candidate: country code + 2 check digits + grouped body, spaced or
/// compact. Validated by ISO 7064 mod-97 ([`iban_valid`]) before emission, so
/// a random uppercase/digit run has a 1-in-97 chance of surviving the gate.
static RE_IBAN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
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
        //    `user:pass@host` section reads as an address.
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
            let body_len = token.split(['-', '_']).next_back().map_or(0, str::len);
            if body_len < API_KEY_MIN_BODY {
                continue;
            }
            if shannon_entropy(token) < API_KEY_MIN_ENTROPY {
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
        //    otherwise catch the same span and mislabel it.
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

        // 10. IPv4.
        for m in RE_IPV4.find_iter(text) {
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

/// Structural validation for a dashed SSN candidate: area 001–899 excluding
/// 666, group 01–99, serial 0001–9999 (the SSA's never-issued ranges).
fn ssn_valid(s: &str) -> bool {
    let (Some(area), Some(group), Some(serial)) = (s.get(0..3), s.get(4..6), s.get(7..11)) else {
        return false;
    };
    let Ok(area_n) = area.parse::<u32>() else {
        return false;
    };
    area_n != 0 && area_n != 666 && area_n < 900 && group != "00" && serial != "0000"
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

    // (b) Must look like a phone, not a dot-grouped number / version / IP-ish run.
    let has_plus = s.trim_start().starts_with('+');
    let has_space_or_dash = s.bytes().any(|b| b == b' ' || b == b'-');
    if !has_plus && !has_space_or_dash {
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

    // (e) Not SSN-shaped. A 3-2-4 dashed group is an SSN (valid or garbage),
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
}
