//! Replays `tests/s02/admission.json` (hand-written verdicts, independent of this crate) through
//! `franken_codec::admission::admit`, and holds the properties no single case shows: every refusal code is
//! exercised, every echo is bounded and redacted, the limits agree with the file, and no name falls through
//! to a default codec. Nothing here decodes anything.

use franken_codec::admission::{
    Admitted, CONFIG_MAX, Codec, FORMAT_NAME_MAX, Offer, Refusal, RefusalCode, admit,
};
use serde_json::Value;

const CASES: &str = include_str!("../../../tests/s02/admission.json");

fn doc() -> Value {
    serde_json::from_str(CASES).expect("tests/s02/admission.json parses")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("field {key} is not text in {value}"))
}

fn number(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("field {key} is not a number in {value}"))
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex length {}", hex.len());
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn small(value: u64, what: &str) -> u8 {
    u8::try_from(value).unwrap_or_else(|_| panic!("{what} {value} does not fit a byte"))
}

fn rate(value: u64) -> u32 {
    u32::try_from(value).expect("rate fits a u32")
}

/// Run one case through the function under test.
fn run(case: &Value) -> Result<Admitted, Refusal> {
    let config = unhex(text(case, "config_hex"));
    admit(&Offer {
        format: text(case, "format"),
        rate_hz: rate(number(case, "rate_hz")),
        channels: small(number(case, "channels"), "channels"),
        bits: small(number(case, "bits"), "bits"),
        config: &config,
    })
}

fn is_redacted(echo: &str) -> bool {
    echo.len() <= FORMAT_NAME_MAX
        && echo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'?'))
}

#[test]
fn every_case_gets_its_hand_written_verdict() {
    let doc = doc();
    let cases = doc["cases"].as_array().expect("cases array");
    let (mut admitted, mut refused) = (0usize, 0usize);
    for case in cases {
        let id = text(case, "id");
        let expect = &case["expect"];
        match (text(expect, "verdict"), run(case)) {
            ("admit", Ok(got)) => {
                admitted += 1;
                assert_eq!(got.codec.as_str(), text(expect, "codec"), "{id}: codec");
                assert_eq!(
                    u64::from(got.rate_hz),
                    number(expect, "rate_hz"),
                    "{id}: rate"
                );
                assert_eq!(
                    u64::from(got.channels),
                    number(expect, "channels"),
                    "{id}: channels"
                );
                assert_eq!(u64::from(got.bits), number(expect, "bits"), "{id}: bits");
                assert_eq!(
                    got.needs_bridge,
                    expect["needs_bridge"]
                        .as_bool()
                        .expect("needs_bridge is a bool"),
                    "{id}: needs_bridge"
                );
            }
            ("refuse", Err(got)) => {
                refused += 1;
                assert_eq!(
                    got.code().as_str(),
                    text(expect, "code"),
                    "{id}: code ({got})"
                );
                if let Some(want) = case["expect_echo_format"].as_str() {
                    assert_eq!(got.echo().format(), want, "{id}: echo");
                }
            }
            (verdict, got) => panic!("{id}: expected {verdict}, got {got:?}"),
        }
    }
    // The file cannot shrink unnoticed: 15 admitted offers (every mandatory ledger row, plus the cookie frame-length
    // boundaries and the twin of the config refusals) and 92 refusals.
    assert!(admitted >= 15, "admitted cases shrank to {admitted}");
    assert!(refused >= 92, "refused cases shrank to {refused}");
}

#[test]
fn every_refusal_code_is_exercised_and_the_file_names_exactly_the_codes_the_code_has() {
    let doc = doc();
    let listed: Vec<&str> = doc["codes"]
        .as_array()
        .expect("codes array")
        .iter()
        .map(|c| c.as_str().expect("code text"))
        .collect();
    let mut have: Vec<&str> = RefusalCode::ALL.iter().map(RefusalCode::as_str).collect();
    have.sort_unstable();
    assert_eq!(
        listed, have,
        "admission.json `codes` must be the code's own set"
    );
    for code in RefusalCode::ALL {
        let used = doc["cases"]
            .as_array()
            .expect("cases array")
            .iter()
            .any(|case| {
                case["expect"]["verdict"] == "refuse" && case["expect"]["code"] == code.as_str()
            });
        assert!(used, "no case expects {}", code.as_str());
    }
}

#[test]
fn the_limits_in_the_file_are_the_limits_in_the_code() {
    let doc = doc();
    assert_eq!(
        number(&doc["limits"], "format_name_max"),
        FORMAT_NAME_MAX as u64
    );
    assert_eq!(number(&doc["limits"], "config_max"), CONFIG_MAX as u64);
}

#[test]
fn a_name_at_the_limit_is_a_name_and_one_past_it_is_a_length() {
    let at = "X".repeat(FORMAT_NAME_MAX);
    let past = "X".repeat(FORMAT_NAME_MAX + 1);
    for (format, want) in [
        (at.as_str(), RefusalCode::UnknownFormat),
        (past.as_str(), RefusalCode::FormatNameTooLong),
    ] {
        let got = admit(&Offer {
            format,
            rate_hz: 44_100,
            channels: 2,
            bits: 0,
            config: &[],
        });
        assert_eq!(
            got.map_err(|r| r.code()),
            Err(want),
            "{} bytes",
            format.len()
        );
    }
}

#[test]
fn every_refusal_is_bounded_and_redacted_whatever_it_is_given() {
    let huge_name = "\u{e9}\u{1}=secret ".repeat(512);
    let huge_config = vec![0xA5u8; 4096];
    let refusal = admit(&Offer {
        format: &huge_name,
        rate_hz: u32::MAX,
        channels: u8::MAX,
        bits: u8::MAX,
        config: &huge_config,
    })
    .expect_err("garbage is refused");
    assert_eq!(refusal.code(), RefusalCode::FormatNameTooLong);
    // Redaction is the alphabet and the 32-byte cut, not hiding words: each unit "\u{e9}\u{1}=secret " is eleven bytes
    // and becomes "????secret?", and the echo stops after 32 bytes.
    assert_eq!(refusal.echo().format(), "????secret?????secret?????secret");
    assert!(is_redacted(refusal.echo().format()));
    assert_eq!(
        refusal.echo().config_len,
        4096,
        "the config length is echoed, never its bytes"
    );
    let shown = refusal.to_string();
    assert!(shown.len() <= 160, "{} bytes: {shown}", shown.len());
    assert!(shown.is_ascii(), "{shown}");

    let doc = doc();
    for case in doc["cases"].as_array().expect("cases array") {
        if let Err(got) = run(case) {
            let id = text(case, "id");
            assert!(
                is_redacted(got.echo().format()),
                "{id}: {:?}",
                got.echo().format()
            );
            assert!(got.to_string().len() <= 160, "{id}: {got}");
        }
    }
}

#[test]
fn a_name_is_never_admitted_as_a_codec_its_family_is_not() {
    // The codec follows the family the name states; nothing falls through to Vorbis (or any other default).
    let doc = doc();
    for case in doc["cases"].as_array().expect("cases array") {
        if let Ok(got) = run(case) {
            let name = text(case, "format");
            let family = if name.starts_with("OGG_VORBIS_") {
                Codec::Vorbis
            } else if name.starts_with("MP3_") {
                Codec::Mp3
            } else if name.starts_with("ALAC_") {
                Codec::Alac
            } else if name.starts_with("AAC_") {
                Codec::AacLc
            } else if name == "PCM_S16BE" {
                Codec::PcmS16Be
            } else {
                panic!("{}: admitted a name of no known family", text(case, "id"));
            };
            assert_eq!(got.codec, family, "{}", text(case, "id"));
        }
    }
    for name in [
        "",
        "VORBIS",
        "OGG",
        "OGG_VORBIS",
        "OGG_VORBIS_321",
        "ogg_vorbis_320",
        "MP3",
        "AAC",
        "ALAC",
        "PCM",
    ] {
        let got = admit(&Offer {
            format: name,
            rate_hz: 44_100,
            channels: 2,
            bits: 0,
            config: &[],
        });
        assert_eq!(
            got.map_err(|r| r.code()),
            Err(RefusalCode::UnknownFormat),
            "{name:?} must be refused as unknown, not admitted as a default"
        );
    }
}

#[test]
fn a_downgrade_is_a_refusal_the_lc_twin_is_admitted() {
    // Metamorphic: every case that names a twin differs from it only in the config. The twin is admitted, the
    // case is refused, so a config that is not plain AAC-LC is never decoded as LC.
    let doc = doc();
    let cases = doc["cases"].as_array().expect("cases array");
    let mut pairs = 0;
    for case in cases.iter().filter(|c| c["twin_of"].is_string()) {
        let twin_id = text(case, "twin_of");
        let twin = cases
            .iter()
            .find(|c| text(c, "id") == twin_id)
            .unwrap_or_else(|| panic!("twin {twin_id} is missing"));
        for key in ["format", "rate_hz", "channels", "bits"] {
            assert_eq!(
                case[key],
                twin[key],
                "{}: differs from its twin in {key}",
                text(case, "id")
            );
        }
        assert!(run(twin).is_ok(), "{twin_id}: the twin must be admitted");
        assert!(run(case).is_err(), "{}: must be refused", text(case, "id"));
        pairs += 1;
    }
    assert!(pairs >= 15, "only {pairs} downgrade pairs");
}

#[test]
fn removing_vorbis_from_the_input_changes_no_other_verdict() {
    // Vorbis offers are interleaved before and after every other offer: no verdict may depend on them.
    let doc = doc();
    let cases = doc["cases"].as_array().expect("cases array");
    let vorbis = cases
        .iter()
        .find(|c| text(c, "id") == "ADM-P-OGG_VORBIS_320")
        .expect("the Vorbis case exists");
    for case in cases
        .iter()
        .filter(|c| !text(c, "format").starts_with("OGG_VORBIS_"))
    {
        let alone = run(case);
        let _ = run(vorbis);
        let after = run(case);
        assert_eq!(alone, after, "{}", text(case, "id"));
    }
}
