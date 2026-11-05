//! A small deterministic JSON value and writer.
//!
//! Output is compact, keys keep the order they were inserted in, and numbers are exact integers, so a
//! report renders to the same bytes every time. The analyzer never parses JSON, only writes it.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn int<T: Into<i128>>(v: T) -> Json {
        Json::Int(v.into())
    }

    pub fn usize(v: usize) -> Json {
        Json::Int(v as i128)
    }

    pub fn str(s: &str) -> Json {
        Json::Str(s.to_string())
    }

    pub fn opt_u64(v: Option<u64>) -> Json {
        match v {
            Some(n) => Json::int(n),
            None => Json::Null,
        }
    }

    pub fn opt_i128(v: Option<i128>) -> Json {
        match v {
            Some(n) => Json::Int(n),
            None => Json::Null,
        }
    }

    pub fn obj(fields: Vec<(&str, Json)>) -> Json {
        Json::Obj(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// The value under `key` when `self` is an object that has it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_render_exactly() {
        assert_eq!(Json::Null.render(), "null");
        assert_eq!(Json::Bool(true).render(), "true");
        assert_eq!(Json::Bool(false).render(), "false");
        assert_eq!(Json::int(0u64).render(), "0");
        assert_eq!(Json::int(-7i64).render(), "-7");
        assert_eq!(Json::int(u64::MAX).render(), "18446744073709551615");
        assert_eq!(Json::usize(42).render(), "42");
        assert_eq!(Json::opt_u64(None).render(), "null");
        assert_eq!(Json::opt_u64(Some(9)).render(), "9");
        assert_eq!(Json::opt_i128(Some(-1)).render(), "-1");
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(Json::str("a\"b\\c").render(), "\"a\\\"b\\\\c\"");
        assert_eq!(Json::str("l1\nl2\t\r").render(), "\"l1\\nl2\\t\\r\"");
        assert_eq!(Json::str("\u{1}").render(), "\"\\u0001\"");
        assert_eq!(Json::str("plain-ascii_1").render(), "\"plain-ascii_1\"");
    }

    #[test]
    fn get_finds_a_key_of_an_object_and_nothing_else() {
        let v = Json::obj(vec![
            ("a", Json::int(1u8)),
            ("b", Json::obj(vec![("c", Json::Null)])),
        ]);
        assert_eq!(v.get("a"), Some(&Json::Int(1)));
        assert_eq!(v.get("b").and_then(|b| b.get("c")), Some(&Json::Null));
        assert_eq!(v.get("missing"), None);
        assert_eq!(Json::Arr(vec![Json::Int(1)]).get("a"), None);
        assert_eq!(Json::str("a").get("a"), None);
    }

    #[test]
    fn containers_keep_insertion_order() {
        let v = Json::obj(vec![
            ("z", Json::int(1u8)),
            (
                "a",
                Json::Arr(vec![Json::int(2u8), Json::Null, Json::str("x")]),
            ),
            ("m", Json::obj(vec![])),
            ("e", Json::Arr(vec![])),
        ]);
        assert_eq!(
            v.render(),
            "{\"z\":1,\"a\":[2,null,\"x\"],\"m\":{},\"e\":[]}"
        );
    }
}
