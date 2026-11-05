//! Shared text-parsing helpers and the one error type every input parser returns.
//!
//! Errors carry a 1-based line number and a typed kind. Any text copied out of the input goes through
//! [`bounded`] first: it is cut to [`BOUND`] characters, so a hostile or accidentally huge line cannot flood
//! a diagnostic, and text with the shape of a site identifier (an address, a hardware or serial number, a host
//! name; see [`crate::redact`]) is replaced by its class and never repeated.

use std::fmt;

use crate::procfs::ProcError;

/// Longest piece of input text a diagnostic will repeat.
pub const BOUND: usize = 32;

/// The only way input text is repeated in a diagnostic or a report that the analyst did not pick: `s` cut to at
/// most [`BOUND`] characters, or `<redacted:class>` when `s` has the shape of a site identifier anywhere in it.
/// The whole of `s` is judged before it is cut, so no piece of an identifier survives the cut.
pub fn bounded(s: &str) -> String {
    if let Some(class) = crate::redact::classify(s) {
        return format!("<redacted:{}>", class.as_str());
    }
    s.chars().take(BOUND).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseKind {
    EmptyInput,
    BadHeader,
    LineTooLong,
    TooManySamples,
    TooLarge,
    UnknownTag(String),
    UnknownKey(String),
    DuplicateKey(String),
    MissingKey(&'static str),
    NotKeyValue(String),
    BadInteger(String),
    BadValue(String),
    BadIdentifier(String),
    /// A profile, series name or snapshot label with the shape of a site identifier. Names the field and the class;
    /// the text itself is never kept.
    SiteIdentifier {
        field: &'static str,
        class: &'static str,
    },
    ReservedName(String),
    DuplicateName(String),
    DuplicateRole(String),
    DuplicateMeta,
    MissingMeta,
    DeclAfterSample,
    UndeclaredSeries(String),
    NoSamples,
    UnknownSection(String),
    SectionOutsideSnapshot,
    TextOutsideSection,
    DuplicateSection(String),
    Proc(ProcError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line of the offending input; 0 when the problem is the input as a whole.
    pub line: usize,
    pub kind: ParseKind,
}

impl ParseError {
    pub fn new(line: usize, kind: ParseKind) -> Self {
        Self { line, kind }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {:?}", self.line, self.kind)
    }
}

impl std::error::Error for ParseError {}

/// A decimal unsigned integer: ASCII digits only, no sign, no whitespace, at most 20 digits.
pub fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// A decimal signed integer: an optional leading `-` and then [`parse_u64`]'s digits.
pub fn parse_i64(s: &str) -> Option<i64> {
    match s.strip_prefix('-') {
        Some(rest) => {
            if rest.is_empty() || rest.len() > 19 || !rest.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse::<i64>().ok()
        }
        None => {
            if s.len() > 19 || parse_u64(s).is_none() {
                return None;
            }
            s.parse::<i64>().ok()
        }
    }
}

/// A series name: a letter, then letters, digits and `_`, at most 64 characters.
pub fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    s.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A profile or snapshot label: like [`is_ident`] but `.` and `-` are allowed too.
pub fn is_label(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// `key=value`, split at the first `=`.
pub fn split_kv(token: &str) -> Option<(&str, &str)> {
    token.split_once('=')
}

/// The `key=value` tokens of one input line, with unknown-key and duplicate-key detection.
pub struct Kv<'a> {
    line: usize,
    pairs: Vec<(&'a str, &'a str)>,
    used: Vec<bool>,
}

impl<'a> Kv<'a> {
    pub fn new<I: Iterator<Item = &'a str>>(line: usize, tokens: I) -> Result<Self, ParseError> {
        let mut pairs: Vec<(&'a str, &'a str)> = Vec::new();
        for token in tokens {
            let (k, v) = split_kv(token)
                .ok_or_else(|| ParseError::new(line, ParseKind::NotKeyValue(bounded(token))))?;
            if k.is_empty() {
                return Err(ParseError::new(
                    line,
                    ParseKind::NotKeyValue(bounded(token)),
                ));
            }
            if pairs.iter().any(|(existing, _)| *existing == k) {
                return Err(ParseError::new(line, ParseKind::DuplicateKey(bounded(k))));
            }
            pairs.push((k, v));
        }
        let used = vec![false; pairs.len()];
        Ok(Self { line, pairs, used })
    }

    pub fn line(&self) -> usize {
        self.line
    }

    /// The value for `key`, marking it used.
    pub fn take(&mut self, key: &str) -> Option<&'a str> {
        for (i, (k, v)) in self.pairs.iter().enumerate() {
            if *k == key {
                self.used[i] = true;
                return Some(*v);
            }
        }
        None
    }

    pub fn req(&mut self, key: &'static str) -> Result<&'a str, ParseError> {
        self.take(key)
            .ok_or_else(|| ParseError::new(self.line, ParseKind::MissingKey(key)))
    }

    pub fn req_u64(&mut self, key: &'static str) -> Result<u64, ParseError> {
        let v = self.req(key)?;
        parse_u64(v)
            .ok_or_else(|| ParseError::new(self.line, ParseKind::BadInteger(key.to_string())))
    }

    pub fn opt_u64(&mut self, key: &'static str) -> Result<Option<u64>, ParseError> {
        match self.take(key) {
            None => Ok(None),
            Some(v) => parse_u64(v)
                .map(Some)
                .ok_or_else(|| ParseError::new(self.line, ParseKind::BadInteger(key.to_string()))),
        }
    }

    /// The first key nobody asked for is an error: a misspelt option must not be silently ignored.
    pub fn finish(self) -> Result<(), ParseError> {
        for (i, (k, _)) in self.pairs.iter().enumerate() {
            if !self.used[i] {
                return Err(ParseError::new(
                    self.line,
                    ParseKind::UnknownKey(bounded(k)),
                ));
            }
        }
        Ok(())
    }

    /// The pairs nobody asked for, marking them used. For lines whose remaining keys are dynamic.
    pub fn take_rest(&mut self) -> Vec<(&'a str, &'a str)> {
        let mut rest = Vec::new();
        for (i, (k, v)) in self.pairs.iter().enumerate() {
            if !self.used[i] {
                self.used[i] = true;
                rest.push((*k, *v));
            }
        }
        rest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_integers_are_strict() {
        assert_eq!(parse_u64("0"), Some(0));
        assert_eq!(parse_u64("007"), Some(7));
        assert_eq!(parse_u64("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_u64("18446744073709551616"), None);
        for bad in [
            "",
            "+5",
            "-5",
            " 5",
            "5 ",
            "1_000",
            "0x10",
            "1.5",
            "123456789012345678901",
        ] {
            assert_eq!(parse_u64(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn signed_integers_are_strict() {
        assert_eq!(parse_i64("-1"), Some(-1));
        assert_eq!(parse_i64("9223372036854775807"), Some(i64::MAX));
        assert_eq!(parse_i64("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_i64("9223372036854775808"), None);
        for bad in ["", "-", "--1", "+1", "1-", "1.0"] {
            assert_eq!(parse_i64(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn identifiers_and_labels() {
        assert!(is_ident("late_packets"));
        assert!(is_ident("a"));
        assert!(!is_ident(""));
        assert!(!is_ident("1abc"));
        assert!(!is_ident("a-b"));
        assert!(!is_ident(&"a".repeat(65)));
        assert!(is_ident(&"a".repeat(64)));
        assert!(is_label("synthetic-clean.v1"));
        assert!(is_label("0abc"));
        assert!(!is_label("-abc"));
        assert!(!is_label("a b"));
    }

    #[test]
    fn diagnostics_repeat_at_most_the_bound() {
        let long = "x".repeat(500);
        assert_eq!(bounded(&long).len(), BOUND);
        assert_eq!(bounded("short"), "short");
    }

    #[test]
    fn diagnostics_never_repeat_a_site_identifier_or_any_piece_of_one() {
        for (text, class) in [
            ("192.0.2.17", "ipv4"),
            ("00-00-5E-00-53-01", "mac"),
            ("2001:db8::1", "ipv6"),
            ("kitchen.local", "hostname"),
            ("SN0000EXAMPLE", "serial"),
            // An identifier past the cut is still judged: nothing is left to leak, and nothing is echoed.
            (
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 192.0.2.17",
                "ipv4",
            ),
        ] {
            assert_eq!(bounded(text), format!("<redacted:{class}>"), "{text:?}");
        }
    }

    #[test]
    fn kv_rejects_duplicates_unknowns_and_non_pairs() {
        let mut kv = Kv::new(3, "a=1 b=2".split_whitespace()).expect("pairs");
        assert_eq!(kv.req_u64("a"), Ok(1));
        // `b` was never asked for.
        assert_eq!(
            kv.finish(),
            Err(ParseError::new(3, ParseKind::UnknownKey("b".to_string())))
        );
        assert_eq!(
            Kv::new(4, "a=1 a=2".split_whitespace()).err(),
            Some(ParseError::new(4, ParseKind::DuplicateKey("a".to_string())))
        );
        assert_eq!(
            Kv::new(5, "novalue".split_whitespace()).err(),
            Some(ParseError::new(
                5,
                ParseKind::NotKeyValue("novalue".to_string())
            ))
        );
        assert_eq!(
            Kv::new(6, "=3".split_whitespace()).err(),
            Some(ParseError::new(6, ParseKind::NotKeyValue("=3".to_string())))
        );
    }

    #[test]
    fn kv_typed_getters() {
        let mut kv = Kv::new(1, "n=12 bad=x".split_whitespace()).expect("pairs");
        assert_eq!(kv.opt_u64("absent"), Ok(None));
        assert_eq!(kv.opt_u64("n"), Ok(Some(12)));
        assert_eq!(
            kv.req_u64("bad"),
            Err(ParseError::new(1, ParseKind::BadInteger("bad".to_string())))
        );
        assert_eq!(
            kv.req("missing"),
            Err(ParseError::new(1, ParseKind::MissingKey("missing")))
        );
    }
}
