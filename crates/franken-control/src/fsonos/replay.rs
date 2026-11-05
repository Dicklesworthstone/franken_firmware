//! Replays the hand-written G03 vectors (`tests/vectors/g03_vectors.json`) through the Rust modules.
//!
//! The same file is replayed against an independent Python model (`tests/g03/reference.py`, run by
//! `scripts/e2e/g03`). The expectations were written by hand from `docs/contracts/g03.md`; neither
//! implementation produced them. The wire shapes in them are transcribed from `fsonos-proto` rev
//! `775b08dc` by reading it. No `fsonos` code ran, and nothing here is a capture of a real device.
//!
//! What this covers: the escaper, the SOAP request parser, the argument validation, and the GENA
//! subscription table. What it does not: routing, the ingress policy and the mapping onto N02
//! commands, which `server.rs`'s own tests check and no independent model checks.

use std::net::IpAddr;

use serde_json::{Value, json};

use super::actions::{self, Cmd, Plan};
use super::gena::{GenaConfig, Notification, SubscribeHeaders, SubscriptionTable};
use super::soap::{Fault, Service, SoapCall, parse_call};
use super::state::{EventState, TransportState};
use super::xml::{Escape, Event, XmlLimits, XmlReader, escape};

const VECTORS: &str = include_str!("../../tests/vectors/g03_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vector file is JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` is a string in {value}"))
}

fn service_named(name: &str) -> Service {
    Service::ALL
        .into_iter()
        .find(|s| s.name() == name)
        .unwrap_or_else(|| panic!("no service named {name}"))
}

fn fault_kind(fault: Fault) -> &'static str {
    match fault {
        Fault::TooLarge => "TooLarge",
        Fault::Malformed => "Malformed",
        Fault::UnsupportedXml => "UnsupportedXml",
        Fault::InvalidAction => "InvalidAction",
        Fault::InvalidArgs(_) => "InvalidArgs",
        Fault::ActionFailed(_) => "ActionFailed",
        Fault::NotImplemented => "NotImplemented",
        Fault::OutcomeUnknown => "OutcomeUnknown",
        Fault::Unauthenticated => "Unauthenticated",
    }
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("`{key}` is an array"))
}

#[test]
fn the_vector_file_is_the_one_this_code_was_written_against() {
    let v = vectors();
    assert_eq!(text(&v, "schema"), "ffw.g03.vectors.v1");
    // A guard against an emptied or truncated file making every replay pass for nothing.
    assert!(array(&v, "escape").len() >= 8);
    assert!(array(&v, "soap").len() >= 30);
    assert!(array(&v, "plan").len() >= 50);
    assert!(array(&v["gena"], "scenarios").len() >= 12);

    let limits = XmlLimits::soap_request();
    let file = &v["limits"];
    assert_eq!(file["max_bytes"], limits.max_bytes);
    assert_eq!(file["max_depth"], limits.max_depth);
    assert_eq!(file["max_elements"], limits.max_elements);
    assert_eq!(file["max_attributes"], limits.max_attributes);
    assert_eq!(file["max_name_len"], limits.max_name_len);
    assert_eq!(file["max_value_len"], limits.max_value_len);
    assert_eq!(file["max_args"], super::soap::MAX_ARGS);

    for service in Service::ALL {
        assert_eq!(text(&v["services"], service.name()), service.urn());
    }
    let provisional = GenaConfig::provisional();
    let c = &v["gena"]["config"];
    assert_eq!(c["max_subscriptions"], provisional.max_subscriptions);
    assert_eq!(c["min_timeout_secs"], provisional.min_timeout_secs);
    assert_eq!(c["default_timeout_secs"], provisional.default_timeout_secs);
    assert_eq!(c["max_timeout_secs"], provisional.max_timeout_secs);
    assert_eq!(c["max_callback_len"], provisional.max_callback_len);
}

#[test]
fn the_escape_vectors_hold() {
    for case in array(&vectors(), "escape") {
        let mode = match text(case, "mode") {
            "text" => Escape::Text,
            "attribute" => Escape::Attribute,
            other => panic!("unknown escape mode {other}"),
        };
        assert_eq!(
            escape(text(case, "input"), mode),
            text(case, "output"),
            "{}",
            case["id"]
        );
    }
}

fn body_of(v: &Value, case: &Value) -> Vec<u8> {
    let body = match case.get("wrap") {
        Some(wrap) => text(v, "envelope_template")
            .replace("{action}", text(wrap, "action"))
            .replace("{urn}", text(&v["services"], text(wrap, "service")))
            .replace("{inner}", text(wrap, "inner")),
        None => text(case, "body").to_string(),
    };
    let mut bytes = body.into_bytes();
    if let Some(n) = case.get("pad_to").and_then(Value::as_u64) {
        let n = usize::try_from(n).expect("a size");
        if bytes.len() < n {
            bytes.resize(n, b' ');
        }
    }
    bytes
}

#[test]
fn the_soap_parse_vectors_hold() {
    let v = vectors();
    for case in array(&v, "soap") {
        let body = body_of(&v, case);
        let got = match parse_call(
            case["soap_action"].as_str(),
            &body,
            XmlLimits::soap_request(),
        ) {
            Ok(call) => json!({"call": {
                "service": call.service.name(),
                "action": call.action,
                "args": call.args.iter().map(|(k, val)| json!([k, val])).collect::<Vec<_>>(),
            }}),
            Err(fault) => json!({"fault": fault_kind(fault)}),
        };
        assert_eq!(got, case["expect"], "{}", case["id"]);
    }
}

fn plan_json(result: Result<Plan, Fault>) -> Value {
    match result {
        Ok(Plan::Read(read)) => json!({"read": format!("{read:?}")}),
        Ok(Plan::Ack) => json!({"ack": true}),
        Ok(Plan::Command(cmd)) => match cmd {
            Cmd::SetVolume(n) => json!({"command": "SetVolume", "value": n}),
            Cmd::SetMute(m) => json!({"command": "SetMute", "value": m}),
            Cmd::SetGroupVolume(n) => json!({"command": "SetGroupVolume", "value": n}),
            Cmd::RelativeVolume(d) => json!({"command": "RelativeVolume", "value": d}),
            Cmd::RelativeGroupVolume(d) => json!({"command": "RelativeGroupVolume", "value": d}),
            Cmd::Stop => json!({"command": "Stop"}),
        },
        Err(fault) => json!({"fault": fault_kind(fault)}),
    }
}

#[test]
fn the_plan_vectors_hold() {
    for case in array(&vectors(), "plan") {
        let call = SoapCall {
            service: service_named(text(case, "service")),
            action: text(case, "action").to_string(),
            args: array(case, "args")
                .iter()
                .map(|pair| {
                    (
                        pair[0].as_str().expect("a name").to_string(),
                        pair[1].as_str().expect("a value").to_string(),
                    )
                })
                .collect(),
        };
        assert_eq!(
            plan_json(actions::plan(&call)),
            case["expect"],
            "{}",
            case["id"]
        );
    }
}

fn transport(name: &str) -> TransportState {
    match name {
        "PLAYING" => TransportState::Playing,
        "PAUSED_PLAYBACK" => TransportState::PausedPlayback,
        "STOPPED" => TransportState::Stopped,
        "TRANSITIONING" => TransportState::Transitioning,
        "NO_MEDIA_PRESENT" => TransportState::NoMediaPresent,
        other => panic!("unknown transport state {other}"),
    }
}

fn state_of(base: &Value, overrides: &Value) -> EventState {
    let mut merged = base.as_object().expect("a state object").clone();
    for (key, value) in overrides.as_object().expect("a state override object") {
        merged.insert(key.clone(), value.clone());
    }
    let small = |key: &str| u8::try_from(merged[key].as_u64().expect("a number")).expect("a u8");
    EventState {
        epoch: merged["epoch"].as_u64().expect("an epoch"),
        revision: merged["revision"].as_u64().expect("a revision"),
        volume: merged["volume"]
            .as_u64()
            .map(|v| u8::try_from(v).expect("a u8")),
        mute: merged["mute"].as_bool(),
        group_volume: small("group_volume"),
        group_mute: merged["group_mute"].as_bool().expect("a bool"),
        transport: transport(merged["transport"].as_str().expect("a transport")),
        zone_group_state: merged["zone_group_state"]
            .as_str()
            .expect("a document")
            .to_string(),
    }
}

fn config_of(base: &Value, overrides: Option<&Value>) -> GenaConfig {
    let mut merged = base.as_object().expect("a config object").clone();
    if let Some(extra) = overrides {
        for (key, value) in extra.as_object().expect("a config override object") {
            merged.insert(key.clone(), value.clone());
        }
    }
    let number = |key: &str| merged[key].as_u64().expect("a number");
    GenaConfig {
        max_subscriptions: usize::try_from(number("max_subscriptions")).expect("a count"),
        min_timeout_secs: u32::try_from(number("min_timeout_secs")).expect("seconds"),
        default_timeout_secs: u32::try_from(number("default_timeout_secs")).expect("seconds"),
        max_timeout_secs: u32::try_from(number("max_timeout_secs")).expect("seconds"),
        max_callback_len: usize::try_from(number("max_callback_len")).expect("a length"),
    }
}

/// The variables a `LastChange` document carries, as `Name=value`.
fn last_change_vars(document: &str) -> Vec<String> {
    let mut reader = XmlReader::new(document.as_bytes(), wide_limits()).expect("within bounds");
    let mut out = Vec::new();
    while let Some(event) = reader.next_event().expect("a well formed document") {
        if let Event::Start {
            name, attributes, ..
        } = event
            && name != "InstanceID"
            && let Some((_, val)) = attributes.iter().find(|(k, _)| k == "val")
        {
            out.push(format!("{name}={val}"));
        }
    }
    out
}

fn wide_limits() -> XmlLimits {
    XmlLimits {
        max_bytes: 16 * 1024,
        max_value_len: 8 * 1024,
        ..XmlLimits::soap_request()
    }
}

/// What a `NOTIFY` body says, reduced to the variables, the revision and the epoch.
fn read_body(notification: &Notification) -> (Vec<String>, u64, u64) {
    let mut reader =
        XmlReader::new(notification.body.as_bytes(), wide_limits()).expect("within bounds");
    let mut vars = Vec::new();
    let (mut revision, mut epoch) = (None, None);
    let mut current: Option<String> = None;
    while let Some(event) = reader.next_event().expect("a well formed body") {
        match event {
            Event::Start { name, .. } if name != "e:propertyset" && name != "e:property" => {
                current = Some(name);
            }
            Event::Text(body) => {
                if let Some(name) = current.take() {
                    match name.as_str() {
                        "FrankenStateRevision" => revision = body.parse::<u64>().ok(),
                        "FrankenEpoch" => epoch = body.parse::<u64>().ok(),
                        "LastChange" => vars.extend(last_change_vars(&body)),
                        other => vars.push(format!("{other}={body}")),
                    }
                }
            }
            _ => {}
        }
    }
    (
        vars,
        revision.expect("every body names the revision"),
        epoch.expect("every body names the epoch"),
    )
}

fn initial_json(notification: &Notification) -> Value {
    let (vars, revision, epoch) = read_body(notification);
    json!({"seq": notification.seq, "vars": vars, "revision": revision, "epoch": epoch})
}

fn event_json(notification: &Notification) -> Value {
    let (vars, revision, _) = read_body(notification);
    json!({"sid": notification.sid, "seq": notification.seq, "vars": vars, "revision": revision})
}

fn run_scenario(v: &Value, scenario: &Value) {
    let g = &v["gena"];
    let config = config_of(&g["config"], scenario.get("config"));
    let nonce = u32::try_from(g["nonce"].as_u64().expect("a nonce")).expect("a u32");
    let mut table = SubscriptionTable::new(config, nonce);
    let id = &scenario["id"];

    for (i, step) in array(scenario, "steps").iter().enumerate() {
        let at = step["at_s"]
            .as_u64()
            .map(|s| s * 1_000_000_000)
            .or_else(|| step["at_ns"].as_u64())
            .unwrap_or(0);
        let headers = SubscribeHeaders {
            callback: step["callback"].as_str(),
            nt: step["nt"].as_str(),
            timeout: step["timeout"].as_str(),
        };
        let got = match text(step, "op") {
            "subscribe" => {
                let peer: IpAddr = text(step, "peer").parse().expect("an address");
                let state = state_of(&g["base_state"], &step["state"]);
                match table.subscribe(
                    at,
                    service_named(text(step, "service")),
                    peer,
                    &headers,
                    &state,
                ) {
                    Ok((grant, initial)) => json!({"ok": {
                        "sid": grant.sid,
                        "timeout": grant.timeout_secs,
                        "initial": initial_json(&initial),
                    }}),
                    Err(e) => json!({"err": e.http_status()}),
                }
            }
            "renew" => match table.renew(
                at,
                service_named(text(step, "service")),
                text(step, "sid"),
                &headers,
            ) {
                Ok(grant) => json!({"ok": {"sid": grant.sid, "timeout": grant.timeout_secs}}),
                Err(e) => json!({"err": e.http_status()}),
            },
            "unsubscribe" => {
                match table.unsubscribe(at, service_named(text(step, "service")), text(step, "sid"))
                {
                    Ok(()) => json!({"ok": true}),
                    Err(e) => json!({"err": e.http_status()}),
                }
            }
            "publish" => {
                let state = state_of(&g["base_state"], &step["state"]);
                let events: Vec<Value> = table.publish(at, &state).iter().map(event_json).collect();
                json!({"events": events})
            }
            "expire" => json!({"removed": table.expire(at)}),
            "len" => json!({"len": table.len()}),
            "set_next_seq" => {
                let seq = u32::try_from(step["seq"].as_u64().expect("a number")).expect("a u32");
                table.set_next_seq(seq);
                continue;
            }
            other => panic!("{id} step {i}: unknown op {other}"),
        };
        assert_eq!(got, step["expect"], "{id} step {i}");
    }
}

#[test]
fn the_gena_scenarios_hold() {
    let v = vectors();
    for scenario in array(&v["gena"], "scenarios") {
        run_scenario(&v, scenario);
    }
}
