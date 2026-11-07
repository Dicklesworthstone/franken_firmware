//! SSDP discovery and the device description (G03 / `ffw-xvv`), slice 2: pure, bounded message handling.
//!
//! What a UPnP controller needs before it can speak SOAP to this endpoint: to find it (an `M-SEARCH`
//! answered with the right `ST`/`USN`, and `NOTIFY alive`/`byebye` announcements) and to read what it
//! offers (the device description, with the service list and the control and event paths). This module
//! parses a search datagram and builds those datagrams and that document. **It opens no socket, reads no
//! clock and draws no random number**: the transport owns the multicast group, the timing, and the
//! entropy for the response delay ([`response_delay_ms`] takes it as an argument).
//!
//! # The minimum actually served
//!
//! Only the services this endpoint serves are advertised: [`SERVICES`], that is `RenderingControl`,
//! `GroupRenderingControl`, `AVTransport` and `ZoneGroupTopology`. `ContentDirectory` is a retired
//! legacy catalog and is **not** advertised, so a search for it, or for any device type this endpoint is
//! not, gets no answer at all (UPnP responders stay silent rather than refuse). There is no `SCPDURL`:
//! service description documents are not served, so none is promised.
//!
//! # Bounds and refusals
//!
//! A datagram is refused (the transport drops it silently; the error is for the log) if it is over
//! [`MAX_DATAGRAM`] bytes, not printable ASCII, has a bare `CR` or `LF`, is not terminated by an empty
//! line, carries bytes after it, has an unknown request line, a folded or malformed header, more than
//! [`MAX_HEADERS`] headers, a duplicated `HOST`/`MAN`/`MX`/`ST`, a `MAN` other than `"ssdp:discover"`, or
//! an `MX` that is not a whole number of seconds from 1 to 120 (a value above 5 is answered as 5). A
//! `NOTIFY` or a response from another device is well-formed and simply not a search for this one.
//!
//! Every value that reaches a header is validated first ([`Device::new`]): the id is a lowercase
//! 8-4-4-4-12 UUID, the address is four octets, the port is not zero, so no `CR`/`LF` can be injected.
//! The friendly name only ever reaches the XML document, through the escaper.
//!
//! # What is not claimed
//!
//! Nothing here was run against a real controller or a real network. The message shapes are those of
//! the UPnP Device Architecture 1.0 and the `ZonePlayer:1` device type that controllers of this family
//! search for; whether the `fsonos` client accepts this description is the open gate in
//! `docs/contracts/g03.md` section 11. IPv6 is not supported. Unicast `M-SEARCH` without an `MX` is refused.
//! The addresses in the vectors are from the documentation range and the ids are synthetic.

use thiserror::Error;

use super::soap::Service;
use super::xml::{Escape, escape};

/// The SSDP port.
pub const SSDP_PORT: u16 = 1900;
/// The SSDP IPv4 multicast group (a protocol constant, not site data).
pub const MULTICAST_ADDR: &str = "239.255.255.250";
/// A larger datagram is refused. An SSDP message fits one datagram.
pub const MAX_DATAGRAM: usize = 1500;
/// A longer header line is refused.
pub const MAX_LINE: usize = 512;
/// More headers than this is refused.
pub const MAX_HEADERS: usize = 24;
/// The longest search target accepted.
pub const MAX_TARGET: usize = 160;
/// An `MX` above this is answered as this many seconds.
pub const MAX_MX: u8 = 5;
/// An `MX` above this is refused.
pub const MAX_MX_ACCEPTED: u32 = 120;
/// The smallest `max-age` (seconds) a device may declare.
pub const MIN_MAX_AGE: u32 = 1800;
/// The largest `max-age` (seconds) a device may declare.
pub const MAX_MAX_AGE: u32 = 86_400;
/// The longest friendly name.
pub const MAX_NAME_CHARS: usize = 64;
/// The device type a controller of this family searches for.
pub const DEVICE_TYPE: &str = "urn:schemas-upnp-org:device:ZonePlayer:1";
/// The root-device search target.
pub const ROOT_DEVICE: &str = "upnp:rootdevice";
/// The path of the device description document.
pub const DESCRIPTION_PATH: &str = "/xml/device_description.xml";
/// The content type to serve the description with.
pub const DESCRIPTION_CONTENT_TYPE: &str = "text/xml; charset=\"utf-8\"";
/// The `SERVER` header value.
pub const SERVER: &str = "franken-firmware/0 UPnP/1.0";
/// The services this endpoint serves, and so the only ones it advertises.
pub const SERVICES: [Service; 4] = [
    Service::RenderingControl,
    Service::GroupRenderingControl,
    Service::AvTransport,
    Service::ZoneGroupTopology,
];
/// How many targets a device answers `ssdp:all` with: the root device, its id, its type, and each service.
pub const TARGET_COUNT: usize = 3 + SERVICES.len();

/// Why a datagram or a device configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SsdpError {
    #[error("the datagram is {len} bytes, over the 1500-byte cap")]
    TooLarge { len: usize },
    #[error("the datagram is not printable ASCII")]
    NotPrintableAscii,
    #[error("a line ends with a bare CR or LF")]
    BareLineEnding,
    #[error("the head is not terminated by an empty line")]
    Unterminated,
    #[error("bytes follow the empty line")]
    TrailingBytes,
    #[error("the request line is not one this module recognises")]
    BadRequestLine,
    #[error("a header line is malformed, folded or too long")]
    BadHeader,
    #[error("more than 24 headers")]
    TooManyHeaders,
    #[error("the {name} header appears twice")]
    DuplicateHeader { name: &'static str },
    #[error("the {name} header is missing")]
    MissingHeader { name: &'static str },
    #[error("MAN is not \"ssdp:discover\"")]
    BadMan,
    #[error("MX is not a whole number of seconds from 1 to 120")]
    BadMx,
    #[error("the search target is empty, too long, or has a space or control character")]
    BadTarget,
    #[error("the device id is not a lowercase 8-4-4-4-12 UUID")]
    BadUuid,
    #[error("the port is zero")]
    BadPort,
    #[error("the friendly name is empty, over 64 characters, or has a control character")]
    BadName,
    #[error("max-age is outside 1800 to 86400 seconds")]
    BadMaxAge,
}

impl SsdpError {
    /// A fixed word for the log and for the vectors.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "too_large",
            Self::NotPrintableAscii => "not_printable_ascii",
            Self::BareLineEnding => "bare_line_ending",
            Self::Unterminated => "unterminated",
            Self::TrailingBytes => "trailing_bytes",
            Self::BadRequestLine => "bad_request_line",
            Self::BadHeader => "bad_header",
            Self::TooManyHeaders => "too_many_headers",
            Self::DuplicateHeader { .. } => "duplicate_header",
            Self::MissingHeader { .. } => "missing_header",
            Self::BadMan => "bad_man",
            Self::BadMx => "bad_mx",
            Self::BadTarget => "bad_target",
            Self::BadUuid => "bad_uuid",
            Self::BadPort => "bad_port",
            Self::BadName => "bad_name",
            Self::BadMaxAge => "bad_max_age",
        }
    }
}

/// A valid `M-SEARCH`: the target and the (clamped) number of seconds the answer may be spread over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MSearch {
    pub target: String,
    pub mx: u8,
}

/// A well-formed datagram that is not a search for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Other {
    /// Another device's `NOTIFY`.
    Notify,
    /// A search response (another device's, or ours echoed back).
    Response,
    /// Some other method on `*`.
    Method,
}

/// What a received datagram is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    Search(MSearch),
    Other(Other),
}

fn printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\r' | b'\n')
}

fn bare_line_ending(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| match b {
        b'\r' => bytes.get(i + 1) != Some(&b'\n'),
        b'\n' => i == 0 || bytes.get(i - 1) != Some(&b'\r'),
        _ => false,
    })
}

fn set_once<'a>(
    slot: &mut Option<&'a str>,
    value: &'a str,
    name: &'static str,
) -> Result<(), SsdpError> {
    if slot.is_some() {
        return Err(SsdpError::DuplicateHeader { name });
    }
    *slot = Some(value);
    Ok(())
}

fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 64
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '[' | ']' | '-'))
}

fn valid_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= MAX_TARGET
        && target.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn parse_mx(value: &str) -> Result<u8, SsdpError> {
    if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SsdpError::BadMx);
    }
    let seconds: u32 = value.parse().map_err(|_| SsdpError::BadMx)?;
    if !(1..=MAX_MX_ACCEPTED).contains(&seconds) {
        return Err(SsdpError::BadMx);
    }
    Ok(u8::try_from(seconds.min(u32::from(MAX_MX))).unwrap_or(MAX_MX))
}

/// Parse one received datagram.
///
/// # Errors
/// [`SsdpError`]: the datagram is malformed, over a bound, or an `M-SEARCH` this module will not answer.
pub fn parse_datagram(bytes: &[u8]) -> Result<Datagram, SsdpError> {
    if bytes.len() > MAX_DATAGRAM {
        return Err(SsdpError::TooLarge { len: bytes.len() });
    }
    if !bytes.iter().copied().all(printable) {
        return Err(SsdpError::NotPrintableAscii);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| SsdpError::NotPrintableAscii)?;
    if bare_line_ending(text) {
        return Err(SsdpError::BareLineEnding);
    }
    let end = text.find("\r\n\r\n").ok_or(SsdpError::Unterminated)?;
    if end + 4 != text.len() {
        return Err(SsdpError::TrailingBytes);
    }
    let mut lines = text[..end].split("\r\n");
    let request_line = lines.next().unwrap_or("");
    match request_line {
        "M-SEARCH * HTTP/1.1" => parse_search(lines),
        "NOTIFY * HTTP/1.1" => Ok(Datagram::Other(Other::Notify)),
        line if line.starts_with("HTTP/1.1 ") => Ok(Datagram::Other(Other::Response)),
        line if is_method_on_star(line) => Ok(Datagram::Other(Other::Method)),
        _ => Err(SsdpError::BadRequestLine),
    }
}

fn is_method_on_star(line: &str) -> bool {
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(method), Some("*"), Some("HTTP/1.1" | "HTTP/1.0"), None) => {
            !method.is_empty()
                && method.len() <= 16
                && method.chars().all(|c| c.is_ascii_uppercase() || c == '-')
        }
        _ => false,
    }
}

fn parse_search<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Datagram, SsdpError> {
    let (mut host, mut man, mut mx, mut st) = (None, None, None, None);
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS {
            return Err(SsdpError::TooManyHeaders);
        }
        if line.len() > MAX_LINE || line.starts_with(' ') {
            return Err(SsdpError::BadHeader);
        }
        let (name, value) = line.split_once(':').ok_or(SsdpError::BadHeader)?;
        if name.is_empty() || name.len() > 32 || !name.chars().all(token_char) {
            return Err(SsdpError::BadHeader);
        }
        let value = value.trim_matches(' ');
        match name.to_ascii_lowercase().as_str() {
            "host" => set_once(&mut host, value, "HOST")?,
            "man" => set_once(&mut man, value, "MAN")?,
            "mx" => set_once(&mut mx, value, "MX")?,
            "st" => set_once(&mut st, value, "ST")?,
            _ => {}
        }
    }
    let host = host.ok_or(SsdpError::MissingHeader { name: "HOST" })?;
    if !valid_host(host) {
        return Err(SsdpError::BadHeader);
    }
    let man = man.ok_or(SsdpError::MissingHeader { name: "MAN" })?;
    if man != "\"ssdp:discover\"" {
        return Err(SsdpError::BadMan);
    }
    let mx = parse_mx(mx.ok_or(SsdpError::MissingHeader { name: "MX" })?)?;
    let target = st.ok_or(SsdpError::MissingHeader { name: "ST" })?;
    if !valid_target(target) {
        return Err(SsdpError::BadTarget);
    }
    Ok(Datagram::Search(MSearch {
        target: target.to_string(),
        mx,
    }))
}

/// How long to wait before sending an answer: somewhere in `[0, mx)` seconds, chosen by the caller's
/// entropy (this module draws none). `mx` is clamped to `1..=5`.
#[must_use]
pub fn response_delay_ms(mx: u8, entropy: u32) -> u32 {
    let seconds = u32::from(mx.clamp(1, MAX_MX));
    entropy % (seconds * 1000)
}

/// One advertised target and the `USN` that names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertised {
    pub target: String,
    pub usn: String,
}

fn valid_uuid(uuid: &str) -> bool {
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// The identity this endpoint announces. Every field is validated at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    uuid: String,
    address: [u8; 4],
    port: u16,
    name: String,
    max_age: u32,
}

impl Device {
    /// # Errors
    /// [`SsdpError::BadUuid`], [`SsdpError::BadPort`], [`SsdpError::BadName`], [`SsdpError::BadMaxAge`].
    pub fn new(
        uuid: &str,
        address: [u8; 4],
        port: u16,
        name: &str,
        max_age: u32,
    ) -> Result<Self, SsdpError> {
        if !valid_uuid(uuid) {
            return Err(SsdpError::BadUuid);
        }
        if port == 0 {
            return Err(SsdpError::BadPort);
        }
        if name.is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(SsdpError::BadName);
        }
        if !(MIN_MAX_AGE..=MAX_MAX_AGE).contains(&max_age) {
            return Err(SsdpError::BadMaxAge);
        }
        Ok(Self {
            uuid: uuid.to_string(),
            address,
            port,
            name: name.to_string(),
            max_age,
        })
    }

    fn udn(&self) -> String {
        format!("uuid:{}", self.uuid)
    }

    /// The URL of the description document.
    #[must_use]
    pub fn location(&self) -> String {
        let [a, b, c, d] = self.address;
        format!("http://{a}.{b}.{c}.{d}:{}{DESCRIPTION_PATH}", self.port)
    }

    /// Everything this device answers or announces, root device first, then its id, its type, then each
    /// service in [`SERVICES`] order. This is the whole list; nothing else is ever advertised.
    #[must_use]
    pub fn advertised(&self) -> Vec<Advertised> {
        let udn = self.udn();
        let mut out = vec![
            Advertised {
                target: ROOT_DEVICE.to_string(),
                usn: format!("{udn}::{ROOT_DEVICE}"),
            },
            Advertised {
                target: udn.clone(),
                usn: udn.clone(),
            },
            Advertised {
                target: DEVICE_TYPE.to_string(),
                usn: format!("{udn}::{DEVICE_TYPE}"),
            },
        ];
        out.extend(SERVICES.iter().map(|service| Advertised {
            target: service.urn().to_string(),
            usn: format!("{udn}::{}", service.urn()),
        }));
        out
    }

    /// What this device answers for a search target: `ssdp:all` is everything; an exact match (the id
    /// ignoring case) is that one entry; anything else, including a service or a device this endpoint
    /// does not serve, is nothing.
    #[must_use]
    pub fn answers(&self, target: &str) -> Vec<Advertised> {
        let all = self.advertised();
        if target == "ssdp:all" {
            return all;
        }
        all.into_iter()
            .filter(|entry| {
                entry.target == target
                    || (entry.target.starts_with("uuid:")
                        && entry.target.eq_ignore_ascii_case(target))
            })
            .collect()
    }

    /// The full response datagrams for a search, in the order of [`Device::answers`].
    #[must_use]
    pub fn search_responses(&self, search: &MSearch) -> Vec<String> {
        self.answers(&search.target)
            .iter()
            .map(|entry| {
                format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age={}\r\nEXT:\r\nLOCATION: {}\r\nSERVER: {SERVER}\r\nST: {}\r\nUSN: {}\r\n\r\n",
                    self.max_age,
                    self.location(),
                    entry.target,
                    entry.usn
                )
            })
            .collect()
    }

    /// The `NOTIFY ssdp:alive` datagrams for every advertised target.
    #[must_use]
    pub fn notify_alive(&self) -> Vec<String> {
        self.advertised()
            .iter()
            .map(|entry| {
                format!(
                    "NOTIFY * HTTP/1.1\r\nHOST: {MULTICAST_ADDR}:{SSDP_PORT}\r\nCACHE-CONTROL: max-age={}\r\nLOCATION: {}\r\nNT: {}\r\nNTS: ssdp:alive\r\nSERVER: {SERVER}\r\nUSN: {}\r\n\r\n",
                    self.max_age,
                    self.location(),
                    entry.target,
                    entry.usn
                )
            })
            .collect()
    }

    /// The `NOTIFY ssdp:byebye` datagrams for every advertised target.
    #[must_use]
    pub fn notify_byebye(&self) -> Vec<String> {
        self.advertised()
            .iter()
            .map(|entry| {
                format!(
                    "NOTIFY * HTTP/1.1\r\nHOST: {MULTICAST_ADDR}:{SSDP_PORT}\r\nNT: {}\r\nNTS: ssdp:byebye\r\nUSN: {}\r\n\r\n",
                    entry.target, entry.usn
                )
            })
            .collect()
    }

    /// The device description document: the service list is exactly [`SERVICES`], with the control and
    /// event paths the request handler serves. The friendly name goes through the escaper, and is also the `roomName` a controller
    /// reads (the `fsonos` client reads that element, not `friendlyName`, for a player's room label).
    #[must_use]
    pub fn description_xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\"?>\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><device>",
        );
        out.push_str("<deviceType>");
        out.push_str(DEVICE_TYPE);
        out.push_str("</deviceType><friendlyName>");
        let name = escape(&self.name, Escape::Text);
        out.push_str(&name);
        out.push_str("</friendlyName><roomName>");
        out.push_str(&name);
        out.push_str("</roomName><manufacturer>FrankenFirmware</manufacturer><modelName>franken-speaker</modelName><UDN>");
        out.push_str(&escape(&self.udn(), Escape::Text));
        out.push_str("</UDN><serviceList>");
        for service in SERVICES {
            out.push_str("<service><serviceType>");
            out.push_str(service.urn());
            out.push_str("</serviceType><serviceId>urn:upnp-org:serviceId:");
            out.push_str(service.name());
            out.push_str("</serviceId><controlURL>");
            out.push_str(service.control_path());
            out.push_str("</controlURL><eventSubURL>");
            out.push_str(service.event_path());
            out.push_str("</eventSubURL></service>");
        }
        out.push_str("</serviceList></device></root>");
        out
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::fsonos::xml::{Event, XmlLimits, XmlReader};

    const VECTORS: &str = include_str!("../../tests/vectors/g03_ssdp_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn device() -> Device {
        let d = &vectors()["device"];
        let address = d["address"].as_array().unwrap();
        Device::new(
            d["uuid"].as_str().unwrap(),
            [
                u8::try_from(address[0].as_u64().unwrap()).unwrap(),
                u8::try_from(address[1].as_u64().unwrap()).unwrap(),
                u8::try_from(address[2].as_u64().unwrap()).unwrap(),
                u8::try_from(address[3].as_u64().unwrap()).unwrap(),
            ],
            u16::try_from(d["port"].as_u64().unwrap()).unwrap(),
            d["name"].as_str().unwrap(),
            u32::try_from(d["max_age"].as_u64().unwrap()).unwrap(),
        )
        .unwrap()
    }

    /// `[["NAME", "value"], ...]` with a start line, joined the way the wire form is.
    fn wire(start: &str, headers: &Value) -> String {
        let mut out = format!("{start}\r\n");
        for pair in headers.as_array().unwrap() {
            let pair = pair.as_array().unwrap();
            out.push_str(&format!(
                "{}:{}\r\n",
                pair[0].as_str().unwrap(),
                if pair[1].as_str().unwrap().is_empty() {
                    String::new()
                } else {
                    format!(" {}", pair[1].as_str().unwrap())
                }
            ));
        }
        out.push_str("\r\n");
        out
    }

    fn datagram_text(case: &Value) -> String {
        match case.get("raw") {
            Some(raw) => raw.as_str().unwrap().to_string(),
            None => wire(case["start"].as_str().unwrap(), &case["headers"]),
        }
    }

    #[test]
    fn the_vectors_parse_to_the_expected_search_or_refusal() {
        let v = vectors();
        for case in v["parse"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let got = parse_datagram(datagram_text(case).as_bytes());
            let expect = &case["expect"];
            match (
                got,
                expect.get("search"),
                expect.get("other"),
                expect.get("err"),
            ) {
                (Ok(Datagram::Search(s)), Some(want), None, None) => {
                    assert_eq!(s.target, want["target"].as_str().unwrap(), "{id}");
                    assert_eq!(u64::from(s.mx), want["mx"].as_u64().unwrap(), "{id}");
                }
                (Ok(Datagram::Other(o)), None, Some(want), None) => {
                    let name = match o {
                        Other::Notify => "notify",
                        Other::Response => "response",
                        Other::Method => "method",
                    };
                    assert_eq!(name, want.as_str().unwrap(), "{id}");
                }
                (Err(e), None, None, Some(want)) => {
                    assert_eq!(e.code(), want.as_str().unwrap(), "{id}")
                }
                (got, ..) => panic!("{id}: got {got:?}, vector says {expect}"),
            }
        }
    }

    #[test]
    fn a_search_is_answered_only_for_what_this_device_actually_serves() {
        let v = vectors();
        let d = device();
        for case in v["search"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let got: Vec<(String, String)> = d
                .answers(case["st"].as_str().unwrap())
                .into_iter()
                .map(|a| (a.target, a.usn))
                .collect();
            let want: Vec<(String, String)> = case["expect"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            assert_eq!(got, want, "{id}");
        }
        // the permitted positive and the refusals beside it, by name
        assert_eq!(d.answers("ssdp:all").len(), TARGET_COUNT);
        assert!(
            d.answers("urn:schemas-upnp-org:service:ContentDirectory:1")
                .is_empty()
        );
        assert!(
            d.answers("urn:schemas-upnp-org:device:MediaServer:1")
                .is_empty()
        );
    }

    #[test]
    fn responses_and_notifications_are_the_golden_datagrams() {
        let v = vectors();
        let d = device();
        let search = MSearch {
            target: v["response"]["st"].as_str().unwrap().to_string(),
            mx: 3,
        };
        let responses = d.search_responses(&search);
        assert_eq!(responses.len(), 1);
        assert_eq!(
            responses[0],
            wire("HTTP/1.1 200 OK", &v["response"]["headers"])
        );
        let alive = d.notify_alive();
        let want_alive: Vec<String> = v["notify_alive"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| wire("NOTIFY * HTTP/1.1", &c["headers"]))
            .collect();
        assert_eq!(alive, want_alive);
        let byebye = d.notify_byebye();
        let want_byebye: Vec<String> = v["notify_byebye"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| wire("NOTIFY * HTTP/1.1", &c["headers"]))
            .collect();
        assert_eq!(byebye, want_byebye);
        // a byebye carries neither a location nor a lifetime
        assert!(
            byebye
                .iter()
                .all(|m| !m.contains("LOCATION") && !m.contains("CACHE-CONTROL"))
        );
    }

    #[test]
    fn every_datagram_built_is_within_the_cap_crlf_only_and_parses_as_not_a_search() {
        let d = device();
        let all = d.search_responses(&MSearch {
            target: "ssdp:all".to_string(),
            mx: 5,
        });
        assert_eq!(all.len(), TARGET_COUNT);
        let built: Vec<String> = all
            .into_iter()
            .chain(d.notify_alive())
            .chain(d.notify_byebye())
            .collect();
        for message in &built {
            assert!(message.len() <= MAX_DATAGRAM, "{message}");
            assert!(message.ends_with("\r\n\r\n"));
            assert!(!bare_line_ending(message), "{message}");
            // what we build is well formed to our own reader, and is never mistaken for a search
            match parse_datagram(message.as_bytes()) {
                Ok(Datagram::Other(_)) => {}
                other => panic!("{message:?} parsed as {other:?}"),
            }
        }
    }

    #[test]
    fn a_device_configuration_is_validated_before_it_reaches_a_header_or_a_document() {
        let v = vectors();
        for case in v["device_reject"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let address = case["address"].as_array().unwrap();
            let result = Device::new(
                case["uuid"].as_str().unwrap(),
                [
                    u8::try_from(address[0].as_u64().unwrap()).unwrap(),
                    u8::try_from(address[1].as_u64().unwrap()).unwrap(),
                    u8::try_from(address[2].as_u64().unwrap()).unwrap(),
                    u8::try_from(address[3].as_u64().unwrap()).unwrap(),
                ],
                u16::try_from(case["port"].as_u64().unwrap()).unwrap(),
                case["name"].as_str().unwrap(),
                u32::try_from(case["max_age"].as_u64().unwrap()).unwrap(),
            );
            assert_eq!(
                result.unwrap_err().code(),
                case["err"].as_str().unwrap(),
                "{id}"
            );
        }
        // the permitted configuration beside the refusals: the vectors' device builds
        assert_eq!(device().location(), vectors()["location"].as_str().unwrap());
    }

    #[test]
    fn the_description_is_golden_lists_only_served_services_and_reads_back_through_the_bounded_reader()
     {
        let v = vectors();
        let d = device();
        let doc = d.description_xml();
        assert_eq!(doc, v["description"].as_str().unwrap());
        let mut reader = XmlReader::new(doc.as_bytes(), XmlLimits::soap_request()).unwrap();
        let mut path: Vec<String> = Vec::new();
        let mut service_types = Vec::new();
        let mut control_urls = Vec::new();
        let mut name = String::new();
        let mut room = String::new();
        while let Some(event) = reader.next_event().unwrap() {
            match event {
                Event::Start { name, .. } => path.push(name),
                Event::End { .. } => {
                    path.pop();
                }
                Event::Text(text) => match path.last().map(String::as_str) {
                    Some("serviceType") => service_types.push(text),
                    Some("controlURL") => control_urls.push(text),
                    Some("friendlyName") => name = text,
                    Some("roomName") => room = text,
                    _ => {}
                },
            }
        }
        let want: Vec<String> = SERVICES.iter().map(|s| s.urn().to_string()).collect();
        assert_eq!(service_types, want);
        assert!(!service_types.iter().any(|t| t.contains("ContentDirectory")));
        let paths: Vec<String> = SERVICES
            .iter()
            .map(|s| s.control_path().to_string())
            .collect();
        assert_eq!(control_urls, paths);
        assert_eq!(name, "Test Room");
        // the room label the `fsonos` client reads is the same name, as its own element
        assert_eq!(room, "Test Room");
        // a hostile friendly name cannot break out of its element
        let hostile =
            Device::new(d.uuid.as_str(), [192, 0, 2, 10], 1400, "<x>&\"'</x>", 1800).unwrap();
        let hostile_doc = hostile.description_xml();
        assert!(hostile_doc.contains(&format!(
            "<friendlyName>{}</friendlyName>",
            v["description_hostile"]["friendly_name_xml"].as_str().unwrap()
        )));
        assert!(hostile_doc.contains(&format!(
            "<roomName>{}</roomName>",
            v["description_hostile"]["friendly_name_xml"].as_str().unwrap()
        )));
        assert!(!hostile_doc.contains("<x>"));
        assert!(XmlReader::new(hostile_doc.as_bytes(), XmlLimits::soap_request()).is_ok());
    }

    #[test]
    fn the_response_delay_is_inside_the_clamped_mx_for_every_mx_and_entropy() {
        let v = vectors();
        for case in v["delay"].as_array().unwrap() {
            let mx = u8::try_from(case["mx"].as_u64().unwrap()).unwrap();
            let entropy = u32::try_from(case["entropy"].as_u64().unwrap()).unwrap();
            assert_eq!(
                u64::from(response_delay_ms(mx, entropy)),
                case["expect"].as_u64().unwrap(),
                "{case}"
            );
        }
        for mx in 0..=255u8 {
            let bound = u32::from(mx.clamp(1, MAX_MX)) * 1000;
            for entropy in [0, 1, 999, 1000, 4999, 5000, 65_535, u32::MAX] {
                assert!(response_delay_ms(mx, entropy) < bound, "{mx} {entropy}");
            }
        }
    }

    #[test]
    fn a_truncated_or_corrupted_search_is_refused_and_never_panics() {
        let valid = wire(
            "M-SEARCH * HTTP/1.1",
            &serde_json::json!([
                ["HOST", "239.255.255.250:1900"],
                ["MAN", "\"ssdp:discover\""],
                ["MX", "2"],
                ["ST", "ssdp:all"]
            ]),
        );
        assert!(matches!(
            parse_datagram(valid.as_bytes()),
            Ok(Datagram::Search(_))
        ));
        // every proper prefix is refused (the empty line is what terminates it)
        for len in 0..valid.len() {
            assert!(parse_datagram(&valid.as_bytes()[..len]).is_err(), "{len}");
        }
        // one corrupted byte at a time: it is either refused or still a well-formed search, never a panic
        for index in 0..valid.len() {
            for bad in [0u8, 0x80, b'\n', b'\r', b' ', 0xff] {
                let mut bytes = valid.as_bytes().to_vec();
                bytes[index] = bad;
                let _ = parse_datagram(&bytes);
            }
        }
        // over the cap, by one byte
        let mut big = valid.clone().into_bytes();
        big.resize(MAX_DATAGRAM + 1, b'a');
        assert_eq!(
            parse_datagram(&big),
            Err(SsdpError::TooLarge {
                len: MAX_DATAGRAM + 1
            })
        );
    }
}
