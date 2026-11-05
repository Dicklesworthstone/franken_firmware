//! A small, bounded XML reader and the escaping used on the way out (G03 / `ffw-xvv`).
//!
//! The control protocol's XML is untrusted input even on an owner-controlled network, and the bead asks
//! for bounded parsing "rather than importing unrestricted XML trees". This reader is a pull parser
//! that never builds a tree and refuses, by construction, everything an attacker would use to make a
//! parser do unbounded work or reach outside the document:
//!
//! * the whole document is measured **before** anything is decoded or allocated: a document over
//!   `max_bytes` is refused having read none of it;
//! * nesting depth, element count, attributes per element, name length and every text or attribute value
//!   are capped, and a cap that is hit ends the parse;
//! * a DOCTYPE, an entity declaration, a comment, a CDATA section and a processing instruction other
//!   than the one leading `<?xml ... ?>` declaration are refused, so there is no entity expansion and
//!   no external reference to follow. Only the five predefined entities and numeric character
//!   references are decoded.
//!
//! An error names the rule that was broken and never echoes the input.
//!
//! What it is not: a conforming XML parser. It reads the documents SOAP and GENA exchange, and refuses
//! the rest. Namespaces are not resolved; the caller reads `xmlns:*` attributes where it needs them and
//! otherwise matches local names, as the controller side does.

/// Caps for one parse. Every field is a bound; none is "unlimited".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    /// The whole document, in bytes, measured before decoding.
    pub max_bytes: usize,
    /// Deepest element nesting (the root is depth 1).
    pub max_depth: usize,
    /// Most elements in the document.
    pub max_elements: usize,
    /// Most attributes on one element.
    pub max_attributes: usize,
    /// Longest element or attribute name, in bytes.
    pub max_name_len: usize,
    /// Longest decoded text run or attribute value, in bytes.
    pub max_value_len: usize,
}

impl XmlLimits {
    /// The bounds for an incoming SOAP request. The actions in scope carry a handful of short
    /// arguments, so these are generous for them and small for an attacker.
    #[must_use]
    pub const fn soap_request() -> Self {
        Self {
            max_bytes: 8 * 1024,
            max_depth: 8,
            max_elements: 64,
            max_attributes: 8,
            max_name_len: 64,
            max_value_len: 1024,
        }
    }
}

/// Why a document was refused. No variant carries any of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    #[error("the document is {len} bytes, over the limit of {max}")]
    TooLarge { len: usize, max: usize },
    #[error("the document is not valid UTF-8")]
    NotUtf8,
    #[error("nesting is deeper than {max}")]
    TooDeep { max: usize },
    #[error("more than {max} elements")]
    TooManyElements { max: usize },
    #[error("more than {max} attributes on one element")]
    TooManyAttributes { max: usize },
    #[error("a name is longer than {max} bytes")]
    NameTooLong { max: usize },
    #[error("a text run or attribute value is longer than {max} bytes")]
    ValueTooLong { max: usize },
    #[error("this reader does not accept {what}")]
    Unsupported { what: &'static str },
    #[error("malformed XML: {what}")]
    Malformed { what: &'static str },
}

/// One thing the reader found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `<name a="v">`. `empty` is true for `<name/>`, which is followed by no `End`.
    Start {
        name: String,
        attributes: Vec<(String, String)>,
        empty: bool,
    },
    /// `</name>`.
    End { name: String },
    /// Decoded character data. Whitespace-only runs between elements are reported too; the caller
    /// decides whether they matter.
    Text(String),
}

/// A pull reader over one document.
pub struct XmlReader<'a> {
    input: &'a str,
    pos: usize,
    limits: XmlLimits,
    stack: Vec<String>,
    elements: usize,
    started: bool,
    finished_root: bool,
}

impl<'a> XmlReader<'a> {
    /// Check the size, then validate UTF-8, then ready the reader. Nothing is decoded or allocated
    /// for a document that is too large.
    pub fn new(bytes: &'a [u8], limits: XmlLimits) -> Result<Self, XmlError> {
        if bytes.len() > limits.max_bytes {
            return Err(XmlError::TooLarge {
                len: bytes.len(),
                max: limits.max_bytes,
            });
        }
        let input = std::str::from_utf8(bytes).map_err(|_| XmlError::NotUtf8)?;
        Ok(Self {
            input,
            pos: 0,
            limits,
            stack: Vec::new(),
            elements: 0,
            started: false,
            finished_root: false,
        })
    }

    fn rest(&self) -> &'a str {
        &self.input[self.pos..]
    }

    /// The next event, `Ok(None)` at a clean end of the document, or the reason it was refused.
    pub fn next_event(&mut self) -> Result<Option<Event>, XmlError> {
        if !self.started {
            self.started = true;
            self.skip_declaration()?;
        }
        if self.rest().is_empty() {
            return if self.stack.is_empty() && self.finished_root {
                Ok(None)
            } else if self.stack.is_empty() {
                Err(XmlError::Malformed {
                    what: "no root element",
                })
            } else {
                Err(XmlError::Malformed {
                    what: "the document ends inside an element",
                })
            };
        }
        if self.rest().starts_with('<') {
            self.read_markup()
        } else {
            self.read_text()
        }
    }

    /// An optional leading `<?xml version="1.0" encoding="utf-8"?>`, and nothing else of that kind.
    fn skip_declaration(&mut self) -> Result<(), XmlError> {
        if !self.rest().starts_with("<?xml") {
            return Ok(());
        }
        let after = &self.rest()[5..];
        if !after.starts_with(|c: char| c.is_ascii_whitespace()) {
            return Err(XmlError::Unsupported {
                what: "a processing instruction",
            });
        }
        let Some(end) = self.rest().find("?>") else {
            return Err(XmlError::Malformed {
                what: "an unterminated XML declaration",
            });
        };
        let declaration = &self.rest()[5..end];
        let lowered = declaration.to_ascii_lowercase();
        if lowered.contains("encoding") && !(lowered.contains("utf-8") || lowered.contains("utf8"))
        {
            return Err(XmlError::Unsupported {
                what: "an encoding other than UTF-8",
            });
        }
        if lowered.contains("standalone") {
            return Err(XmlError::Unsupported {
                what: "a standalone declaration",
            });
        }
        self.pos += end + 2;
        Ok(())
    }

    fn read_text(&mut self) -> Result<Option<Event>, XmlError> {
        let rest = self.rest();
        let end = rest.find('<').unwrap_or(rest.len());
        let raw = &rest[..end];
        self.pos += end;
        if self.stack.is_empty() {
            // Outside the root only whitespace is allowed.
            return if raw.chars().all(|c| c.is_ascii_whitespace()) {
                self.next_event()
            } else {
                Err(XmlError::Malformed {
                    what: "text outside the root element",
                })
            };
        }
        let decoded = decode(raw, self.limits.max_value_len)?;
        Ok(Some(Event::Text(decoded)))
    }

    fn read_markup(&mut self) -> Result<Option<Event>, XmlError> {
        let rest = self.rest();
        if rest.starts_with("<!") {
            return Err(XmlError::Unsupported {
                what: "a DOCTYPE, comment, CDATA section or entity declaration",
            });
        }
        if rest.starts_with("<?") {
            return Err(XmlError::Unsupported {
                what: "a processing instruction",
            });
        }
        if let Some(after) = rest.strip_prefix("</") {
            let Some(close) = after.find('>') else {
                return Err(XmlError::Malformed {
                    what: "an unterminated end tag",
                });
            };
            let name = after[..close].trim_end();
            check_name(name, self.limits.max_name_len)?;
            self.pos += 2 + close + 1;
            return match self.stack.pop() {
                Some(open) if open == name => {
                    if self.stack.is_empty() {
                        self.finished_root = true;
                    }
                    Ok(Some(Event::End {
                        name: name.to_string(),
                    }))
                }
                Some(_) => Err(XmlError::Malformed {
                    what: "an end tag that does not match its start tag",
                }),
                None => Err(XmlError::Malformed {
                    what: "an end tag with nothing open",
                }),
            };
        }
        self.read_start_tag()
    }

    fn read_start_tag(&mut self) -> Result<Option<Event>, XmlError> {
        if self.finished_root {
            return Err(XmlError::Malformed {
                what: "more than one root element",
            });
        }
        self.elements += 1;
        if self.elements > self.limits.max_elements {
            return Err(XmlError::TooManyElements {
                max: self.limits.max_elements,
            });
        }
        let rest = self.rest();
        // Find the closing `>` outside quotes.
        let mut quote: Option<char> = None;
        let mut close = None;
        for (i, c) in rest.char_indices().skip(1) {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (Some(_), _) => {}
                (None, '"' | '\'') => quote = Some(c),
                (None, '>') => {
                    close = Some(i);
                    break;
                }
                (None, '<') => {
                    return Err(XmlError::Malformed {
                        what: "a '<' inside a tag",
                    });
                }
                (None, _) => {}
            }
        }
        let Some(close) = close else {
            return Err(XmlError::Malformed {
                what: "an unterminated start tag",
            });
        };
        let mut inner = &rest[1..close];
        let empty = inner.ends_with('/');
        if empty {
            inner = &inner[..inner.len() - 1];
        }
        self.pos += close + 1;

        let name_end = inner
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(inner.len());
        let name = &inner[..name_end];
        check_name(name, self.limits.max_name_len)?;
        let attributes = self.read_attributes(&inner[name_end..])?;

        if !empty {
            if self.stack.len() >= self.limits.max_depth {
                return Err(XmlError::TooDeep {
                    max: self.limits.max_depth,
                });
            }
            self.stack.push(name.to_string());
        } else if self.stack.is_empty() {
            self.finished_root = true;
        }
        Ok(Some(Event::Start {
            name: name.to_string(),
            attributes,
            empty,
        }))
    }

    fn read_attributes(&self, mut s: &str) -> Result<Vec<(String, String)>, XmlError> {
        let mut out: Vec<(String, String)> = Vec::new();
        loop {
            s = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
            if s.is_empty() {
                return Ok(out);
            }
            if out.len() >= self.limits.max_attributes {
                return Err(XmlError::TooManyAttributes {
                    max: self.limits.max_attributes,
                });
            }
            let Some(eq) = s.find('=') else {
                return Err(XmlError::Malformed {
                    what: "an attribute without a value",
                });
            };
            let name = s[..eq].trim_end();
            check_name(name, self.limits.max_name_len)?;
            let after = s[eq + 1..].trim_start_matches(|c: char| c.is_ascii_whitespace());
            let mut chars = after.chars();
            let quote = match chars.next() {
                Some(q @ ('"' | '\'')) => q,
                _ => {
                    return Err(XmlError::Malformed {
                        what: "an unquoted attribute value",
                    });
                }
            };
            let body = &after[1..];
            let Some(end) = body.find(quote) else {
                return Err(XmlError::Malformed {
                    what: "an unterminated attribute value",
                });
            };
            let raw = &body[..end];
            if raw.contains('<') {
                return Err(XmlError::Malformed {
                    what: "a '<' in an attribute value",
                });
            }
            if out.iter().any(|(existing, _)| existing == name) {
                return Err(XmlError::Malformed {
                    what: "a repeated attribute",
                });
            }
            out.push((name.to_string(), decode(raw, self.limits.max_value_len)?));
            s = &body[end + 1..];
        }
    }
}

fn check_name(name: &str, max: usize) -> Result<(), XmlError> {
    if name.is_empty() {
        return Err(XmlError::Malformed {
            what: "an empty name",
        });
    }
    if name.len() > max {
        return Err(XmlError::NameTooLong { max });
    }
    let first_ok = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    let rest_ok = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'));
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(XmlError::Malformed {
            what: "a name with a character outside the accepted set",
        })
    }
}

/// Whether `c` may appear in an XML 1.0 document at all.
fn allowed_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&c)
        || ('\u{E000}'..='\u{FFFD}').contains(&c)
        || ('\u{10000}'..='\u{10FFFF}').contains(&c)
}

/// Decode the five predefined entities and numeric character references, refusing anything else, and
/// refusing a result longer than `max`.
fn decode(raw: &str, max: usize) -> Result<String, XmlError> {
    let mut out = String::with_capacity(raw.len().min(max));
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let Some(semi) = after.find(';') else {
            return Err(XmlError::Malformed {
                what: "an entity reference without a ';'",
            });
        };
        let entity = &after[..semi];
        let ch = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => numeric_reference(entity)?,
        };
        out.push(ch);
        if out.len() > max {
            return Err(XmlError::ValueTooLong { max });
        }
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    if out.len() > max {
        return Err(XmlError::ValueTooLong { max });
    }
    if !out.chars().all(allowed_char) {
        return Err(XmlError::Malformed {
            what: "a character that XML does not allow",
        });
    }
    Ok(out)
}

fn numeric_reference(entity: &str) -> Result<char, XmlError> {
    let digits = entity.strip_prefix('#').ok_or(XmlError::Unsupported {
        what: "an entity other than the five predefined ones",
    })?;
    let parsed = if let Some(hex) = digits.strip_prefix('x') {
        u32::from_str_radix(hex, 16)
    } else {
        digits.parse::<u32>()
    };
    let code = parsed.map_err(|_| XmlError::Malformed {
        what: "a numeric character reference that is not a number",
    })?;
    let ch = char::from_u32(code).ok_or(XmlError::Malformed {
        what: "a numeric character reference that is not a character",
    })?;
    if allowed_char(ch) {
        Ok(ch)
    } else {
        Err(XmlError::Malformed {
            what: "a numeric character reference to a character XML does not allow",
        })
    }
}

/// How much to escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    /// Element text: `&`, `<` and `>`.
    Text,
    /// An attribute value: also both quote characters.
    Attribute,
}

/// Escape `s` for output. A character XML does not allow is replaced by U+FFFD rather than written.
#[must_use]
pub fn escape(s: &str, mode: Escape) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if mode == Escape::Attribute => out.push_str("&quot;"),
            '\'' if mode == Escape::Attribute => out.push_str("&apos;"),
            c if allowed_char(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> XmlLimits {
        XmlLimits::soap_request()
    }

    fn events(doc: &str) -> Result<Vec<Event>, XmlError> {
        let mut reader = XmlReader::new(doc.as_bytes(), limits())?;
        let mut out = Vec::new();
        while let Some(event) = reader.next_event()? {
            out.push(event);
        }
        Ok(out)
    }

    fn start(name: &str) -> Event {
        Event::Start {
            name: name.to_string(),
            attributes: Vec::new(),
            empty: false,
        }
    }

    fn end(name: &str) -> Event {
        Event::End {
            name: name.to_string(),
        }
    }

    #[test]
    fn a_small_document_reads_as_start_text_end() {
        assert_eq!(
            events("<?xml version=\"1.0\" encoding=\"utf-8\"?><a x=\"1\"><b>hi</b><c/></a>"),
            Ok(vec![
                Event::Start {
                    name: "a".to_string(),
                    attributes: vec![("x".to_string(), "1".to_string())],
                    empty: false
                },
                start("b"),
                Event::Text("hi".to_string()),
                end("b"),
                Event::Start {
                    name: "c".to_string(),
                    attributes: Vec::new(),
                    empty: true
                },
                end("a"),
            ])
        );
    }

    #[test]
    fn the_five_entities_and_numeric_references_decode_and_nothing_else_does() {
        assert_eq!(
            events("<a>&amp;&lt;&gt;&quot;&apos;&#65;&#x42;&#x1F600;</a>"),
            Ok(vec![
                start("a"),
                Event::Text("&<>\"'AB\u{1F600}".to_string()),
                end("a")
            ])
        );
        for bad in [
            "<a>&nbsp;</a>",
            "<a>&foo;</a>",
            "<a>&amp</a>",
            "<a>&#xZZ;</a>",
            "<a>&#0;</a>",
            "<a>&#1;</a>",
            "<a>&#xD800;</a>",
            "<a>&#99999999;</a>",
        ] {
            assert!(events(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_doctype_an_entity_declaration_a_comment_cdata_and_a_pi_are_refused() {
        for bad in [
            "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
            "<!DOCTYPE a SYSTEM \"file:///etc/passwd\"><a/>",
            "<a><!-- hidden --></a>",
            "<a><![CDATA[x]]></a>",
            "<a><?pi data?></a>",
            "<?xml-stylesheet href=\"x\"?><a/>",
        ] {
            assert!(
                matches!(events(bad), Err(XmlError::Unsupported { .. })),
                "{bad}: {:?}",
                events(bad)
            );
        }
    }

    #[test]
    fn a_billion_laughs_document_is_refused_before_any_expansion() {
        let bomb = "<!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\">\
                    <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;\">]><l>&c;</l>";
        assert!(matches!(events(bomb), Err(XmlError::Unsupported { .. })));
    }

    #[test]
    fn the_size_is_checked_before_anything_is_read_or_allocated() {
        let big = vec![b'x'; limits().max_bytes + 1];
        assert_eq!(
            XmlReader::new(&big, limits()).err(),
            Some(XmlError::TooLarge {
                len: limits().max_bytes + 1,
                max: limits().max_bytes
            })
        );
        // Even bytes that are not UTF-8 are refused as too large first: the size is the first check.
        let junk = vec![0xFF; limits().max_bytes + 1];
        assert!(matches!(
            XmlReader::new(&junk, limits()).err(),
            Some(XmlError::TooLarge { .. })
        ));
        // At the limit it is accepted.
        let exact = format!("<a>{}</a>", "x".repeat(limits().max_bytes - 7));
        assert_eq!(exact.len(), limits().max_bytes);
        assert!(XmlReader::new(exact.as_bytes(), limits()).is_ok());
    }

    #[test]
    fn invalid_utf8_is_refused() {
        assert_eq!(
            XmlReader::new(&[b'<', b'a', b'>', 0xC0, 0xAF], limits()).err(),
            Some(XmlError::NotUtf8)
        );
    }

    #[test]
    fn nesting_elements_attributes_names_and_values_are_each_capped() {
        let l = limits();
        let deep = format!(
            "{}{}",
            "<a>".repeat(l.max_depth + 1),
            "</a>".repeat(l.max_depth + 1)
        );
        assert_eq!(events(&deep), Err(XmlError::TooDeep { max: l.max_depth }));
        let at_depth = format!(
            "{}{}",
            "<a>".repeat(l.max_depth),
            "</a>".repeat(l.max_depth)
        );
        assert!(events(&at_depth).is_ok());

        let many = format!("<r>{}</r>", "<e/>".repeat(l.max_elements));
        assert_eq!(
            events(&many),
            Err(XmlError::TooManyElements {
                max: l.max_elements
            })
        );

        let attrs: String = (0..=l.max_attributes)
            .map(|i| format!(" a{i}=\"v\""))
            .collect();
        assert_eq!(
            events(&format!("<r{attrs}/>")),
            Err(XmlError::TooManyAttributes {
                max: l.max_attributes
            })
        );

        let long_name = "n".repeat(l.max_name_len + 1);
        assert_eq!(
            events(&format!("<{long_name}/>")),
            Err(XmlError::NameTooLong {
                max: l.max_name_len
            })
        );

        let long_text = "t".repeat(l.max_value_len + 1);
        assert_eq!(
            events(&format!("<a>{long_text}</a>")),
            Err(XmlError::ValueTooLong {
                max: l.max_value_len
            })
        );
        assert_eq!(
            events(&format!("<a x=\"{long_text}\"/>")),
            Err(XmlError::ValueTooLong {
                max: l.max_value_len
            })
        );
    }

    #[test]
    fn an_expansion_that_grows_past_the_value_bound_stops_there() {
        // The value bound is 1024 decoded bytes and the document cap is 8192 encoded bytes. Each fixture
        // is far under the document cap, so it is the value bound, and only the value bound, that decides:
        // exactly 1024 decoded bytes is accepted and 1025 is refused. (The whole-document refusal has its
        // own test, `the_size_is_checked_before_anything_is_read_or_allocated`.)
        let bound = limits().max_value_len;
        let exactly = format!("<a>{}</a>", "&amp;".repeat(bound));
        let just_over = format!("<a>{}</a>", "&amp;".repeat(bound + 1));
        for fixture in [&exactly, &just_over] {
            assert!(
                fixture.len() < limits().max_bytes,
                "the fixture must be under the document cap"
            );
        }
        let accepted = events(&exactly).expect("exactly the bound is accepted");
        assert!(
            accepted.contains(&Event::Text("&".repeat(bound))),
            "all {bound} decoded bytes arrive"
        );
        assert_eq!(
            events(&just_over),
            Err(XmlError::ValueTooLong { max: bound })
        );
    }

    #[test]
    fn structure_errors_are_refused() {
        for bad in [
            "",
            "   ",
            "<a>",
            "<a></b>",
            "</a>",
            "<a><b></a></b>",
            "<a/><b/>",
            "<a/>trailing",
            "text<a/>",
            "<a",
            "<a x=1/>",
            "<a x=\"1/>",
            "<a x=\"1\" x=\"2\"/>",
            "<a x=\"<\"/>",
            "<1a/>",
            "<a b/>",
            "<a><</a>",
        ] {
            assert!(events(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn trailing_whitespace_after_the_root_is_fine() {
        assert!(events("<a/>\n  \r\n").is_ok());
        assert!(events("  \n<a></a>  ").is_ok());
    }

    #[test]
    fn declarations_other_than_plain_utf8_are_refused() {
        assert!(events("<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>").is_ok());
        assert!(events("<?xml version=\"1.0\"?><a/>").is_ok());
        for bad in [
            "<?xml version=\"1.0\" encoding=\"utf-16\"?><a/>",
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><a/>",
            "<?xmlfoo?><a/>",
            "<?xml version=\"1.0\" encoding=\"utf-8\"<a/>",
        ] {
            assert!(events(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn single_quoted_attributes_and_quotes_inside_the_other_kind_work() {
        assert_eq!(
            events("<a x='say \"hi\"' y=\"it's\"/>"),
            Ok(vec![Event::Start {
                name: "a".to_string(),
                attributes: vec![
                    ("x".to_string(), "say \"hi\"".to_string()),
                    ("y".to_string(), "it's".to_string())
                ],
                empty: true
            }])
        );
    }

    #[test]
    fn a_greater_than_inside_a_quoted_attribute_does_not_end_the_tag() {
        assert_eq!(
            events("<a x=\"1>2\"/>"),
            Ok(vec![Event::Start {
                name: "a".to_string(),
                attributes: vec![("x".to_string(), "1>2".to_string())],
                empty: true
            }])
        );
    }

    #[test]
    fn an_error_never_echoes_the_input() {
        let secret = "tok-9f3a1c77e0b2";
        for doc in [
            format!("<{secret}!/>"),
            format!("<a>&{secret};</a>"),
            format!("<a {secret}/>"),
            format!("<a>{secret}</b>"),
            format!("<!{secret}>"),
        ] {
            let shown = format!("{:?} {}", events(&doc), events(&doc).unwrap_err());
            assert!(!shown.contains("9f3a1c77e0b2"), "{shown}");
        }
    }

    #[test]
    fn escaping_round_trips_through_the_reader() {
        let nasty = "a&b<c>d\"e'f \u{1F600} g";
        for mode in [Escape::Text, Escape::Attribute] {
            let doc = format!(
                "<a x=\"{}\">{}</a>",
                escape(nasty, Escape::Attribute),
                escape(nasty, mode)
            );
            let got = events(&doc).unwrap();
            let Event::Start { attributes, .. } = &got[0] else {
                panic!("{got:?}")
            };
            assert_eq!(attributes[0].1, nasty);
            assert_eq!(got[1], Event::Text(nasty.to_string()));
        }
    }

    #[test]
    fn escaping_text_leaves_quotes_alone_and_attributes_do_not() {
        assert_eq!(escape("a\"b'c", Escape::Text), "a\"b'c");
        assert_eq!(escape("a\"b'c", Escape::Attribute), "a&quot;b&apos;c");
        assert_eq!(escape("<&>", Escape::Text), "&lt;&amp;&gt;");
        // Ampersand is escaped first in effect: an already-escaped string is escaped again, not left.
        assert_eq!(escape("&amp;", Escape::Text), "&amp;amp;");
    }

    #[test]
    fn a_character_xml_forbids_is_replaced_not_written() {
        assert_eq!(
            escape("a\u{0}b\u{8}c\u{B}d\u{FFFE}e", Escape::Text),
            "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e"
        );
        assert_eq!(escape("tab\tnl\ncr\r", Escape::Text), "tab\tnl\ncr\r");
    }
}
