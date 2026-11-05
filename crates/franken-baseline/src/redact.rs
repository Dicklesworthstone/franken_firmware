//! The site-identifier screen (bead ffw-za4, Logging clause: redact tokens, keys, account and site
//! identifiers).
//!
//! A real capture is taken on somebody's own speaker, so text the analyst or the device chose can carry the
//! site: an address, a hardware or serial number, a host name. Input text reaches a report or a diagnostic
//! through exactly two doors, and both are closed here:
//!
//! * The three names an analyst picks (`profile`, a series `name`, a snapshot `label`) are **refused** when
//!   they have one of the shapes below. The error ([`ParseKind::SiteIdentifier`]) names the field and the
//!   class and never repeats the text ([`screen`]).
//! * Every other piece of input text that a diagnostic or a report repeats (an unknown token, the process
//!   name in `/proc/<pid>/status`, a file name) goes through [`crate::parse::bounded`]. That replaces text
//!   with one of these shapes in it by `<redacted:class>`, and cuts anything else to
//!   [`crate::parse::BOUND`] characters.
//!
//! Comments (`#` lines) are skipped by both parsers and never copied anywhere.
//!
//! The shapes, tried in this order; the first that matches names the class. Matching is by bytes, ASCII
//! only, and fails closed (a false alarm is a refusal the analyst can rename around):
//!
//! * `mac`: six two-digit hex groups joined by one kind of separator (`:` or `-`), anywhere in the text, or
//!   a whole alphanumeric run of exactly twelve hex digits.
//! * `ipv4`: a run of digits and dots that, with its leading and trailing dots removed, is exactly four
//!   groups of one to three digits.
//! * `ipv6`: a run of hex digits and `:` with at least two colons, no group longer than four characters and
//!   at least one hex digit.
//! * `hostname`: a run of letters, digits, `.` and `-` whose last dot-separated label is one of
//!   [`HOSTNAME_SUFFIXES`] (case-insensitively) and which has a non-empty label before it.
//! * `serial`: an alphanumeric run of at least [`SERIAL_MIN_LEN`] characters with at least
//!   [`SERIAL_MIN_DIGITS`] digits and at least [`SERIAL_MIN_LETTERS`] letters.
//!
//! What this is not. It recognises shapes, not meaning: a bare host name such as `kitchen`, a person's name
//! or a serial with fewer digits than the threshold has no recognisable shape and passes. The recipe in
//! `docs/contracts/e02.md` therefore tells the person who takes a capture to use generic names, and to
//! scrub before sharing; this screen is the backstop, not the only defence.

use crate::parse::{ParseError, ParseKind};

/// The private-network suffixes: a dotted name that ends in one of them is a host name.
pub const HOSTNAME_SUFFIXES: [&str; 6] =
    ["local", "lan", "home", "internal", "localdomain", "arpa"];
pub const SERIAL_MIN_LEN: usize = 8;
pub const SERIAL_MIN_DIGITS: usize = 3;
pub const SERIAL_MIN_LETTERS: usize = 3;

/// What a piece of text looks like. The order of the variants is the order the shapes are tried in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentClass {
    Mac,
    Ipv4,
    Ipv6,
    Hostname,
    Serial,
}

impl IdentClass {
    pub fn as_str(self) -> &'static str {
        match self {
            IdentClass::Mac => "mac",
            IdentClass::Ipv4 => "ipv4",
            IdentClass::Ipv6 => "ipv6",
            IdentClass::Hostname => "hostname",
            IdentClass::Serial => "serial",
        }
    }
}

/// The class of the first site-identifier shape found anywhere in `text`, or `None`.
pub fn classify(text: &str) -> Option<IdentClass> {
    let b = text.as_bytes();
    if has_mac(b) {
        Some(IdentClass::Mac)
    } else if has_ipv4(b) {
        Some(IdentClass::Ipv4)
    } else if has_ipv6(b) {
        Some(IdentClass::Ipv6)
    } else if has_hostname(b) {
        Some(IdentClass::Hostname)
    } else if has_serial(b) {
        Some(IdentClass::Serial)
    } else {
        None
    }
}

/// Refuse `text` if it has a site-identifier shape. The error names the line, the field and the class, and
/// never contains the text.
pub fn screen(line: usize, field: &'static str, text: &str) -> Result<(), ParseError> {
    match classify(text) {
        None => Ok(()),
        Some(class) => Err(ParseError::new(
            line,
            ParseKind::SiteIdentifier {
                field,
                class: class.as_str(),
            },
        )),
    }
}

fn has_mac(b: &[u8]) -> bool {
    for w in b.windows(17) {
        let sep = w[2];
        if (sep == b':' || sep == b'-')
            && (0..6).all(|i| w[i * 3].is_ascii_hexdigit() && w[i * 3 + 1].is_ascii_hexdigit())
            && (0..5).all(|i| w[i * 3 + 2] == sep)
        {
            return true;
        }
    }
    b.split(|c| !c.is_ascii_alphanumeric())
        .any(|run| run.len() == 12 && run.iter().all(u8::is_ascii_hexdigit))
}

/// `s` without its leading and trailing dots.
fn trim_dots(mut s: &[u8]) -> &[u8] {
    while let [b'.', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b'.'] = s {
        s = rest;
    }
    s
}

fn has_ipv4(b: &[u8]) -> bool {
    b.split(|c| !(c.is_ascii_digit() || *c == b'.')).any(|run| {
        let groups: Vec<&[u8]> = trim_dots(run).split(|c| *c == b'.').collect();
        groups.len() == 4 && groups.iter().all(|g| (1..=3).contains(&g.len()))
    })
}

fn has_ipv6(b: &[u8]) -> bool {
    b.split(|c| !(c.is_ascii_hexdigit() || *c == b':'))
        .any(|run| {
            run.iter().filter(|c| **c == b':').count() >= 2
                && run.split(|c| *c == b':').all(|g| g.len() <= 4)
                && run.iter().any(u8::is_ascii_hexdigit)
        })
}

fn has_hostname(b: &[u8]) -> bool {
    b.split(|c| !(c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-'))
        .any(|run| {
            let mut labels = run.rsplit(|c| *c == b'.');
            let Some(last) = labels.next() else {
                return false;
            };
            labels.any(|label| !label.is_empty())
                && HOSTNAME_SUFFIXES
                    .iter()
                    .any(|suffix| last.eq_ignore_ascii_case(suffix.as_bytes()))
        })
}

fn has_serial(b: &[u8]) -> bool {
    b.split(|c| !c.is_ascii_alphanumeric()).any(|run| {
        let digits = run.iter().filter(|c| c.is_ascii_digit()).count();
        let letters = run.iter().filter(|c| c.is_ascii_alphabetic()).count();
        run.len() >= SERIAL_MIN_LEN && digits >= SERIAL_MIN_DIGITS && letters >= SERIAL_MIN_LETTERS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Documentation-range values only: RFC 5737 addresses, the IANA documentation MAC block (00-00-5E-00-53-xx),
    // RFC 3849 `2001:db8::/32`, and an obviously invented serial.
    const SHAPES: [(&str, Option<IdentClass>); 24] = [
        ("192.0.2.17", Some(IdentClass::Ipv4)),
        ("198.51.100.200", Some(IdentClass::Ipv4)),
        ("host-203.0.113.9", Some(IdentClass::Ipv4)),
        ("00-00-5E-00-53-01", Some(IdentClass::Mac)),
        ("00:00:5E:00:53:01", Some(IdentClass::Mac)),
        ("00005E005301", Some(IdentClass::Mac)),
        ("00-00-5E-00-53-01:9", Some(IdentClass::Mac)),
        ("2001:db8::1", Some(IdentClass::Ipv6)),
        ("2001:db8:0:0:0:0:0:1", Some(IdentClass::Ipv6)),
        ("kitchen.local", Some(IdentClass::Hostname)),
        ("speaker-01.home.arpa", Some(IdentClass::Hostname)),
        ("SN0000EXAMPLE", Some(IdentClass::Serial)),
        ("zp90a1b2c3d4", Some(IdentClass::Serial)),
        ("synthetic-clean-v1", None),
        ("synthetic-clean.v1", None),
        ("late_packets", None),
        ("kworker/0:1", None),
        ("1.2.3", None),
        ("1.2.3.4.5", None),
        ("12:30", None),
        ("packets32", None),
        ("local", None),
        ("kitchen.localx", None),
        ("ABCDEFGH12", None),
    ];

    #[test]
    fn each_shape_is_named_and_near_misses_are_not_flagged() {
        for (text, want) in SHAPES {
            assert_eq!(classify(text), want, "{text:?}");
        }
    }

    #[test]
    fn the_first_matching_shape_names_the_class() {
        // A MAC is also a run of hex digits and colons; it must be called a MAC, not an IPv6 address.
        assert_eq!(classify("00:00:5E:00:53:01"), Some(IdentClass::Mac));
        // Twelve hex digits that are also shaped like a serial (at least three digits and three letters) are a MAC.
        assert_eq!(classify("ABCDEF012345"), Some(IdentClass::Mac));
    }

    #[test]
    fn a_shape_is_found_anywhere_in_the_text() {
        assert_eq!(classify("room=192.0.2.17;x"), Some(IdentClass::Ipv4));
        assert_eq!(classify("a b 00-00-5E-00-53-01 c"), Some(IdentClass::Mac));
    }

    #[test]
    fn a_refusal_names_the_field_and_class_and_never_repeats_the_text() {
        let e = screen(7, "profile", "192.0.2.17").expect_err("an address is refused");
        assert_eq!(
            e,
            ParseError::new(
                7,
                ParseKind::SiteIdentifier {
                    field: "profile",
                    class: "ipv4"
                }
            )
        );
        assert!(!e.to_string().contains("192.0.2.17"));
        assert_eq!(screen(7, "profile", "synthetic-clean-v1"), Ok(()));
    }

    #[test]
    fn every_class_has_its_own_name() {
        let names: Vec<&str> = [
            IdentClass::Mac,
            IdentClass::Ipv4,
            IdentClass::Ipv6,
            IdentClass::Hostname,
            IdentClass::Serial,
        ]
        .iter()
        .map(|c| c.as_str())
        .collect();
        assert_eq!(names, ["mac", "ipv4", "ipv6", "hostname", "serial"]);
    }
}
