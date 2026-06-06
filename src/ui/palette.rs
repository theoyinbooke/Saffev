//! Studio CLI palette — "Calm Instrument"
//!
//! The terminal counterpart to `design/tokens.css`. Same token names, same
//! colors, so the Studio and the CLI never drift. Reference module — drop into
//! the crate (e.g. `src/ui/palette.rs`) when the build starts.
//!
//! - Truecolor (24-bit) values are the DARK-mode token hexes, because terminals
//!   are dark by default. A 16-color ANSI fallback is provided for limited TERMs.
//! - Honors `NO_COLOR` (https://no-color.org) and a `--no-color` style override.
//! - Dependency-free (std only). In production you may prefer `anstyle`/`owo-colors`,
//!   but the token table below stays the source of truth.
//!
//! Voice (see 05-design-system.md §9): calm, declarative, status-dot prefixed,
//! monospaced and aligned. Example:
//!     ~ saffev status
//!     ● proxy      :11434 ▸ ollama :11999      healthy
//!     ● privacy    metadata-only · encrypted (keyring)
//!     ● exposure   localhost-only  ✓ not exposed

use std::io::IsTerminal;

/// An RGB token + its nearest ANSI-16 SGR code for fallback.
#[derive(Clone, Copy)]
pub struct Token {
    pub rgb: (u8, u8, u8),
    pub ansi16: u8, // SGR foreground code (30–37 / 90–97)
}

/// The palette tokens. Names mirror `tokens.css` (dark-mode values).
pub mod token {
    use super::Token;
    // brand / primary (violet) — prompt, accents
    pub const BRAND: Token = Token {
        rgb: (0xB7, 0xA6, 0xF2),
        ansi16: 95,
    }; // bright magenta
    pub const ON_BRAND: Token = Token {
        rgb: (0x1A, 0x14, 0x10),
        ansi16: 30,
    };
    // semantic
    pub const SAFE: Token = Token {
        rgb: (0x57, 0xC9, 0x8C),
        ansi16: 32,
    }; // green
    pub const WARN: Token = Token {
        rgb: (0xE7, 0xB2, 0x5A),
        ansi16: 33,
    }; // yellow
    pub const DANGER: Token = Token {
        rgb: (0xE2, 0x78, 0x75),
        ansi16: 31,
    }; // red
    pub const GOLD: Token = Token {
        rgb: (0xE9, 0xC0, 0x64),
        ansi16: 33,
    }; // yellow
       // text
    pub const TEXT: Token = Token {
        rgb: (0xF3, 0xEE, 0xE6),
        ansi16: 97,
    }; // bright white — values
    pub const TEXT_2: Token = Token {
        rgb: (0xAB, 0xA2, 0x94),
        ansi16: 37,
    }; // labels
    pub const TEXT_3: Token = Token {
        rgb: (0x7C, 0x74, 0x66),
        ansi16: 90,
    }; // bright black — comments/separators
}

/// How much color the active terminal supports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    None,      // NO_COLOR / not a tty / --no-color
    Ansi16,    // basic terminals
    Truecolor, // 24-bit
}

impl ColorMode {
    /// Detect from environment + whether stdout is a tty. Call once at startup.
    pub fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
            return ColorMode::None;
        }
        match std::env::var("COLORTERM").as_deref() {
            Ok("truecolor") | Ok("24bit") => ColorMode::Truecolor,
            _ => match std::env::var("TERM").as_deref() {
                Ok(t) if t.contains("256color") || t.contains("truecolor") => ColorMode::Truecolor,
                Ok("dumb") => ColorMode::None,
                _ => ColorMode::Ansi16,
            },
        }
    }
}

/// Wrap `text` in the SGR sequence for `tok` under `mode`. No-op when `None`.
pub fn paint(mode: ColorMode, tok: Token, text: &str) -> String {
    match mode {
        ColorMode::None => text.to_string(),
        ColorMode::Ansi16 => format!("\x1b[{}m{}\x1b[0m", tok.ansi16, text),
        ColorMode::Truecolor => {
            let (r, g, b) = tok.rgb;
            format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
        }
    }
}

/// Semantic helpers — the only API most call sites need.
/// Construct once: `let p = Painter::new();` then `p.success("healthy")`.
pub struct Painter {
    mode: ColorMode,
}

impl Painter {
    pub fn new() -> Self {
        Painter {
            mode: ColorMode::detect(),
        }
    }
    pub fn with_mode(mode: ColorMode) -> Self {
        Painter { mode }
    }

    fn p(&self, tok: Token, s: &str) -> String {
        paint(self.mode, tok, s)
    }

    pub fn prompt(&self, s: &str) -> String {
        self.p(token::BRAND, s)
    } // "~", "❯", command echo
    pub fn value(&self, s: &str) -> String {
        self.p(token::TEXT, s)
    } // counts, ports, ms (bright)
    pub fn label(&self, s: &str) -> String {
        self.p(token::TEXT_2, s)
    }
    pub fn muted(&self, s: &str) -> String {
        self.p(token::TEXT_3, s)
    } // ·, ▸, comments
    pub fn success(&self, s: &str) -> String {
        self.p(token::SAFE, s)
    } // ●, ✓, healthy
    pub fn warn(&self, s: &str) -> String {
        self.p(token::WARN, s)
    }
    pub fn error(&self, s: &str) -> String {
        self.p(token::DANGER, s)
    } // errors, PII counts
    pub fn accent(&self, s: &str) -> String {
        self.p(token::GOLD, s)
    }

    /// A leading status dot in the right color: success/warn/error.
    pub fn dot(&self, level: Level) -> String {
        let tok = match level {
            Level::Ok => token::SAFE,
            Level::Warn => token::WARN,
            Level::Err => token::DANGER,
        };
        self.p(tok, "●")
    }
}

impl Default for Painter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub enum Level {
    Ok,
    Warn,
    Err,
}

/* ---------------------------------------------------------------------------
Example: the `status` command rendering the same block as the Studio.

    let p = Painter::new();
    println!("{} {}", p.prompt("~"), p.value("saffev status"));
    println!("{} proxy      {} {} ollama {}      {}",
        p.dot(Level::Ok), p.value(":11434"), p.muted("▸"), p.value(":11999"), p.success("healthy"));
    println!("{} privacy    metadata-only {} encrypted (keyring)",
        p.dot(Level::Ok), p.muted("·"));
    println!("{} exposure   localhost-only  {}",
        p.dot(Level::Ok), p.success("✓ not exposed"));
    println!("{} {} requests today {} {} p50 {} {} PII findings",
        p.muted("~"), p.value("1,284"), p.muted("·"), p.value("38ms"),
        p.muted("·"), p.error("6"));
--------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_mode_is_plain() {
        let p = Painter::with_mode(ColorMode::None);
        assert_eq!(p.success("healthy"), "healthy");
    }

    #[test]
    fn truecolor_wraps_with_rgb() {
        let p = Painter::with_mode(ColorMode::Truecolor);
        assert_eq!(p.success("ok"), "\x1b[38;2;87;201;140mok\x1b[0m");
    }

    #[test]
    fn ansi16_uses_sgr_code() {
        let p = Painter::with_mode(ColorMode::Ansi16);
        assert_eq!(p.error("x"), "\x1b[31mx\x1b[0m");
    }
}
