//! SOAP control: parsing a request and building the response or fault (G03 / `ffw-xvv`).
//!
//! The wire shapes are those the `fsonos-proto` controller side builds and parses (rev `775b08dc`):
//! a SOAP 1.1 envelope whose body holds one `<u:Action xmlns:u="<service URN>">` element with flat
//! argument children, a `SOAPACTION: "<service URN>#<Action>"` header, a response element named
//! `<Action>Response`, and a fault whose `detail/UPnPError` carries `errorCode` and `errorDescription`.
//!
//! Parsing is bounded ([`super::xml`]) and strict about shape: exactly one action in the body, flat
//! text arguments, the header and the body agreeing about the service and the action, and the
//! namespaces the envelope and the action element declare being the ones they should be. Nothing a
//! peer sent is ever copied into a fault: the description is a fixed word.

use super::xml::{Escape, Event, XmlError, XmlLimits, XmlReader, escape};

pub const SOAP_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const SOAP_ENCODING_NS: &str = "http://schemas.xmlsoap.org/soap/encoding/";
pub const UPNP_CONTROL_NS: &str = "urn:schemas-upnp-org:control-1-0";
pub const GENA_EVENT_NS: &str = "urn:schemas-upnp-org:event-1-0";
/// Most arguments one action may carry.
pub const MAX_ARGS: usize = 16;

/// A UPnP service this endpoint can name. `ContentDirectory` is here only so that its actions can be
/// refused by name: the legacy content catalog is retired and is not reintroduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    RenderingControl,
    GroupRenderingControl,
    AvTransport,
    ZoneGroupTopology,
    ContentDirectory,
}

impl Service {
    pub const ALL: [Self; 5] = [
        Self::RenderingControl,
        Self::GroupRenderingControl,
        Self::AvTransport,
        Self::ZoneGroupTopology,
        Self::ContentDirectory,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RenderingControl => "RenderingControl",
            Self::GroupRenderingControl => "GroupRenderingControl",
            Self::AvTransport => "AVTransport",
            Self::ZoneGroupTopology => "ZoneGroupTopology",
            Self::ContentDirectory => "ContentDirectory",
        }
    }

    #[must_use]
    pub const fn urn(self) -> &'static str {
        match self {
            Self::RenderingControl => "urn:schemas-upnp-org:service:RenderingControl:1",
            Self::GroupRenderingControl => "urn:schemas-upnp-org:service:GroupRenderingControl:1",
            Self::AvTransport => "urn:schemas-upnp-org:service:AVTransport:1",
            Self::ZoneGroupTopology => "urn:schemas-upnp-org:service:ZoneGroupTopology:1",
            Self::ContentDirectory => "urn:schemas-upnp-org:service:ContentDirectory:1",
        }
    }

    #[must_use]
    pub const fn control_path(self) -> &'static str {
        match self {
            Self::RenderingControl => "/MediaRenderer/RenderingControl/Control",
            Self::GroupRenderingControl => "/MediaRenderer/GroupRenderingControl/Control",
            Self::AvTransport => "/MediaRenderer/AVTransport/Control",
            Self::ZoneGroupTopology => "/ZoneGroupTopology/Control",
            Self::ContentDirectory => "/MediaServer/ContentDirectory/Control",
        }
    }

    #[must_use]
    pub const fn event_path(self) -> &'static str {
        match self {
            Self::RenderingControl => "/MediaRenderer/RenderingControl/Event",
            Self::GroupRenderingControl => "/MediaRenderer/GroupRenderingControl/Event",
            Self::AvTransport => "/MediaRenderer/AVTransport/Event",
            Self::ZoneGroupTopology => "/ZoneGroupTopology/Event",
            Self::ContentDirectory => "/MediaServer/ContentDirectory/Event",
        }
    }

    #[must_use]
    pub fn from_urn(urn: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.urn() == urn)
    }

    #[must_use]
    pub fn from_control_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.control_path() == path)
    }

    #[must_use]
    pub fn from_event_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.event_path() == path)
    }
}

/// Why a request got no success. Each has a status, and where UPnP defines one, an error code. The
/// words are fixed; nothing a peer sent appears in them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Fault {
    /// The request was larger than the bound. HTTP 413, no body.
    #[error("the request is over the size limit")]
    TooLarge,
    /// The request could not be read as a SOAP call. HTTP 400, no body.
    #[error("the request is not a well-formed SOAP call")]
    Malformed,
    /// It used XML this endpoint refuses (a DOCTYPE, a comment, an entity declaration). HTTP 400.
    #[error("the request uses XML this endpoint does not accept")]
    UnsupportedXml,
    /// No such action on that service. UPnP 401.
    #[error("invalid action")]
    InvalidAction,
    /// The arguments were wrong. UPnP 402, with the rule that was broken.
    #[error("invalid arguments: {0}")]
    InvalidArgs(&'static str),
    /// The action was understood and could not be done. UPnP 501, with the reason.
    #[error("action failed: {0}")]
    ActionFailed(&'static str),
    /// A real action of the service that this endpoint does not implement. UPnP 602. Never a success.
    #[error("optional action not implemented")]
    NotImplemented,
    /// A retried command number the control channel no longer remembers (its outcome aged out of the
    /// ledger). Whether it was applied is unknown, and it will **not** be applied now: read the state
    /// and decide. UPnP vendor range, code 801. Never a success and never a re-application.
    #[error("command outcome unknown")]
    OutcomeUnknown,
    /// Tailnet ingress without a valid command authorization. HTTP 401, no body.
    #[error("the request is not authenticated")]
    Unauthenticated,
}

impl Fault {
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::TooLarge => 413,
            Self::Malformed | Self::UnsupportedXml => 400,
            Self::Unauthenticated => 401,
            Self::InvalidAction
            | Self::InvalidArgs(_)
            | Self::ActionFailed(_)
            | Self::NotImplemented
            | Self::OutcomeUnknown => 500,
        }
    }

    /// The UPnP error code, for the faults UPnP defines.
    #[must_use]
    pub const fn upnp_code(self) -> Option<u16> {
        match self {
            Self::InvalidAction => Some(401),
            Self::InvalidArgs(_) => Some(402),
            Self::ActionFailed(_) => Some(501),
            Self::NotImplemented => Some(602),
            Self::OutcomeUnknown => Some(801),
            Self::TooLarge | Self::Malformed | Self::UnsupportedXml | Self::Unauthenticated => None,
        }
    }

    /// `errorDescription`: the standard words, and the reason in brackets where there is one.
    #[must_use]
    pub fn description(self) -> Option<String> {
        match self {
            Self::InvalidAction => Some("Invalid Action".to_string()),
            Self::InvalidArgs(reason) => Some(format!("Invalid Args ({reason})")),
            Self::ActionFailed(reason) => Some(format!("Action Failed ({reason})")),
            Self::NotImplemented => Some("Optional Action Not Implemented".to_string()),
            Self::OutcomeUnknown => Some("Command Outcome Unknown (read the state)".to_string()),
            Self::TooLarge | Self::Malformed | Self::UnsupportedXml | Self::Unauthenticated => None,
        }
    }
}

impl From<XmlError> for Fault {
    fn from(error: XmlError) -> Self {
        match error {
            XmlError::TooLarge { .. } => Self::TooLarge,
            XmlError::Unsupported { .. } => Self::UnsupportedXml,
            _ => Self::Malformed,
        }
    }
}

/// One parsed call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapCall {
    pub service: Service,
    pub action: String,
    /// Arguments in document order, text decoded.
    pub args: Vec<(String, String)>,
}

impl SoapCall {
    /// The argument `name`, if the request carried it.
    #[must_use]
    pub fn arg(&self, name: &str) -> Option<&str> {
        self.args
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn local(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

fn prefix(name: &str) -> Option<&str> {
    name.split_once(':').map(|(prefix, _)| prefix)
}

/// The namespace `element` binds to its own prefix (or the default namespace), if it declares it.
fn declared_namespace<'a>(name: &str, attributes: &'a [(String, String)]) -> Option<&'a str> {
    let wanted = prefix(name).map_or_else(|| "xmlns".to_string(), |p| format!("xmlns:{p}"));
    attributes
        .iter()
        .find(|(k, _)| *k == wanted)
        .map(|(_, v)| v.as_str())
}

/// `"urn:...:service:X:1#Action"` (the quotes are optional on input) into its service and action.
fn parse_soap_action(header: &str) -> Result<(Service, String), Fault> {
    let value = header.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    let (urn, action) = value.split_once('#').ok_or(Fault::Malformed)?;
    let service = Service::from_urn(urn).ok_or(Fault::InvalidAction)?;
    let valid = !action.is_empty()
        && action.len() <= 64
        && action
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid {
        return Err(Fault::Malformed);
    }
    Ok((service, action.to_string()))
}

/// Skip whitespace-only text, which separates elements and means nothing.
fn next_structural(reader: &mut XmlReader<'_>) -> Result<Option<Event>, Fault> {
    loop {
        match reader.next_event()? {
            Some(Event::Text(text)) if text.chars().all(|c| c.is_ascii_whitespace()) => {}
            other => return Ok(other),
        }
    }
}

/// Parse one SOAP call.
///
/// Order: the `SOAPACTION` header (cheap), then the size and shape of the body, then agreement between
/// the two.
pub fn parse_call(
    soap_action: Option<&str>,
    body: &[u8],
    limits: XmlLimits,
) -> Result<SoapCall, Fault> {
    let (service, header_action) = parse_soap_action(soap_action.ok_or(Fault::Malformed)?)?;
    let mut reader = XmlReader::new(body, limits)?;

    // <Envelope xmlns:s="soap">
    let Some(Event::Start {
        name, attributes, ..
    }) = next_structural(&mut reader)?
    else {
        return Err(Fault::Malformed);
    };
    if local(&name) != "Envelope"
        || declared_namespace(&name, &attributes) != Some(SOAP_ENVELOPE_NS)
    {
        return Err(Fault::Malformed);
    }

    // <Body>
    let Some(Event::Start { name, empty, .. }) = next_structural(&mut reader)? else {
        return Err(Fault::Malformed);
    };
    if local(&name) != "Body" || empty {
        return Err(Fault::Malformed);
    }

    // <u:Action xmlns:u="service">
    let Some(Event::Start {
        name,
        attributes,
        empty: action_empty,
    }) = next_structural(&mut reader)?
    else {
        return Err(Fault::Malformed);
    };
    let action = local(&name).to_string();
    if action != header_action || declared_namespace(&name, &attributes) != Some(service.urn()) {
        return Err(Fault::InvalidAction);
    }

    let mut args: Vec<(String, String)> = Vec::new();
    if !action_empty {
        loop {
            match next_structural(&mut reader)? {
                Some(Event::End { .. }) => break,
                Some(Event::Start {
                    name: arg,
                    empty: arg_empty,
                    ..
                }) => {
                    if args.len() >= MAX_ARGS {
                        return Err(Fault::Malformed);
                    }
                    let mut text = String::new();
                    if !arg_empty {
                        loop {
                            match reader.next_event()? {
                                Some(Event::Text(t)) => text.push_str(&t),
                                Some(Event::End { .. }) => break,
                                _ => return Err(Fault::Malformed),
                            }
                        }
                    }
                    let arg = local(&arg).to_string();
                    if args.iter().any(|(k, _)| *k == arg) {
                        return Err(Fault::InvalidArgs("an argument is repeated"));
                    }
                    args.push((arg, text));
                }
                _ => return Err(Fault::Malformed),
            }
        }
    }

    // </Body></Envelope>, and nothing after.
    for _ in 0..2 {
        if !matches!(next_structural(&mut reader)?, Some(Event::End { .. })) {
            return Err(Fault::Malformed);
        }
    }
    if next_structural(&mut reader)?.is_some() {
        return Err(Fault::Malformed);
    }
    Ok(SoapCall {
        service,
        action,
        args,
    })
}

const XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

fn envelope_open() -> String {
    format!(
        "{XML_DECLARATION}<s:Envelope xmlns:s=\"{SOAP_ENVELOPE_NS}\" s:encodingStyle=\"{SOAP_ENCODING_NS}\"><s:Body>"
    )
}

const ENVELOPE_CLOSE: &str = "</s:Body></s:Envelope>";

/// The success response for `action`: `<u:ActionResponse>` with the out-arguments in the order given.
/// Out-argument names are this crate's own constants; the values are escaped.
#[must_use]
pub fn response_envelope(service: Service, action: &str, out_args: &[(&str, String)]) -> String {
    let mut out = envelope_open();
    out.push_str(&format!(
        "<u:{action}Response xmlns:u=\"{}\">",
        service.urn()
    ));
    for (name, value) in out_args {
        out.push_str(&format!("<{name}>{}</{name}>", escape(value, Escape::Text)));
    }
    out.push_str(&format!("</u:{action}Response>"));
    out.push_str(ENVELOPE_CLOSE);
    out
}

/// The fault body, for the faults that have one.
#[must_use]
pub fn fault_envelope(fault: Fault) -> Option<String> {
    let code = fault.upnp_code()?;
    let description = fault.description()?;
    let mut out = envelope_open();
    out.push_str(&format!(
        "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>\
         <UPnPError xmlns=\"{UPNP_CONTROL_NS}\"><errorCode>{code}</errorCode>\
         <errorDescription>{}</errorDescription></UPnPError></detail></s:Fault>",
        escape(&description, Escape::Text)
    ));
    out.push_str(ENVELOPE_CLOSE);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> XmlLimits {
        XmlLimits::soap_request()
    }

    const VOLUME: &str = "\"urn:schemas-upnp-org:service:RenderingControl:1#SetVolume\"";

    fn envelope(action: &str, urn: &str, args: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope \
             xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
             <u:{action} xmlns:u=\"{urn}\">{args}</u:{action}></s:Body></s:Envelope>"
        )
    }

    fn set_volume(args: &str) -> String {
        envelope(
            "SetVolume",
            "urn:schemas-upnp-org:service:RenderingControl:1",
            args,
        )
    }

    fn parse(header: Option<&str>, body: &str) -> Result<SoapCall, Fault> {
        parse_call(header, body.as_bytes(), limits())
    }

    #[test]
    fn a_controller_style_call_parses_with_its_arguments_in_order() {
        let body = set_volume(
            "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>30</DesiredVolume>",
        );
        let call = parse(Some(VOLUME), &body).unwrap();
        assert_eq!(call.service, Service::RenderingControl);
        assert_eq!(call.action, "SetVolume");
        assert_eq!(
            call.args,
            vec![
                ("InstanceID".to_string(), "0".to_string()),
                ("Channel".to_string(), "Master".to_string()),
                ("DesiredVolume".to_string(), "30".to_string())
            ]
        );
        assert_eq!(call.arg("Channel"), Some("Master"));
        assert_eq!(call.arg("Nope"), None);
    }

    #[test]
    fn the_header_quotes_are_optional_and_whitespace_between_elements_is_ignored() {
        // Whitespace inside the action and after the root is fine.
        let body = format!("{}\n", set_volume("\n <InstanceID>0</InstanceID>\n"));
        assert!(
            parse(
                Some("urn:schemas-upnp-org:service:RenderingControl:1#SetVolume"),
                &body
            )
            .is_ok()
        );
    }

    #[test]
    fn whitespace_before_the_xml_declaration_is_refused_as_xml_requires() {
        // The declaration must be the first bytes. Leading whitespace puts a processing instruction in the
        // middle of the document, which this reader does not accept.
        let body = format!("\n  {}", set_volume("<InstanceID>0</InstanceID>"));
        assert_eq!(parse(Some(VOLUME), &body), Err(Fault::UnsupportedXml));
    }

    #[test]
    fn arguments_are_decoded_and_an_empty_argument_is_empty() {
        let body = envelope(
            "SetVolume",
            "urn:schemas-upnp-org:service:RenderingControl:1",
            "<A>a&amp;b&lt;c</A><B/><C></C>",
        );
        let call = parse(Some(VOLUME), &body).unwrap();
        assert_eq!(call.arg("A"), Some("a&b<c"));
        assert_eq!(call.arg("B"), Some(""));
        assert_eq!(call.arg("C"), Some(""));
    }

    #[test]
    fn an_action_with_no_arguments_parses() {
        let body = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                    <u:GetZoneGroupState xmlns:u=\"urn:schemas-upnp-org:service:ZoneGroupTopology:1\"/>\
                    </s:Body></s:Envelope>";
        let call = parse(
            Some("\"urn:schemas-upnp-org:service:ZoneGroupTopology:1#GetZoneGroupState\""),
            body,
        )
        .unwrap();
        assert_eq!(call.action, "GetZoneGroupState");
        assert!(call.args.is_empty());
    }

    #[test]
    fn the_header_must_be_present_well_formed_and_agree_with_the_body() {
        let body = set_volume("<InstanceID>0</InstanceID>");
        assert_eq!(parse(None, &body), Err(Fault::Malformed));
        assert_eq!(parse(Some("nonsense"), &body), Err(Fault::Malformed));
        assert_eq!(
            parse(
                Some("\"urn:schemas-upnp-org:service:Nope:1#SetVolume\""),
                &body
            ),
            Err(Fault::InvalidAction)
        );
        // The header names another action than the body does.
        assert_eq!(
            parse(
                Some("\"urn:schemas-upnp-org:service:RenderingControl:1#SetMute\""),
                &body
            ),
            Err(Fault::InvalidAction)
        );
        // The header names another service than the body's namespace does.
        assert_eq!(
            parse(
                Some("\"urn:schemas-upnp-org:service:AVTransport:1#SetVolume\""),
                &body
            ),
            Err(Fault::InvalidAction)
        );
        // A bad action name in the header.
        assert_eq!(
            parse(
                Some("\"urn:schemas-upnp-org:service:RenderingControl:1#Set Volume\""),
                &body
            ),
            Err(Fault::Malformed)
        );
        assert_eq!(
            parse(
                Some("\"urn:schemas-upnp-org:service:RenderingControl:1#\""),
                &body
            ),
            Err(Fault::Malformed)
        );
    }

    #[test]
    fn the_namespaces_must_be_the_ones_they_claim_to_be() {
        // The envelope element not in the SOAP namespace.
        let bad_envelope = set_volume("").replace(
            "http://schemas.xmlsoap.org/soap/envelope/",
            "http://example.invalid/not-soap",
        );
        assert_eq!(parse(Some(VOLUME), &bad_envelope), Err(Fault::Malformed));
        // The action element declaring another service's namespace.
        let wrong = envelope(
            "SetVolume",
            "urn:schemas-upnp-org:service:AVTransport:1",
            "",
        );
        assert_eq!(parse(Some(VOLUME), &wrong), Err(Fault::InvalidAction));
        // The action element declaring no namespace at all.
        let none = set_volume("").replace(
            " xmlns:u=\"urn:schemas-upnp-org:service:RenderingControl:1\"",
            "",
        );
        assert_eq!(parse(Some(VOLUME), &none), Err(Fault::InvalidAction));
    }

    #[test]
    fn shape_errors_are_refused() {
        let wrap = |inner: &str| {
            format!(
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">{inner}</s:Envelope>"
            )
        };
        let action = "<u:SetVolume xmlns:u=\"urn:schemas-upnp-org:service:RenderingControl:1\">\
                      <InstanceID>0</InstanceID></u:SetVolume>";
        for (what, body) in [
            ("no body", wrap("")),
            (
                "a header element",
                wrap(&format!("<s:Header/><s:Body>{action}</s:Body>")),
            ),
            ("an empty body", wrap("<s:Body/>")),
            (
                "two actions",
                wrap(&format!("<s:Body>{action}{action}</s:Body>")),
            ),
            (
                "a nested argument",
                wrap(
                    "<s:Body><u:SetVolume xmlns:u=\"urn:schemas-upnp-org:service:RenderingControl:1\">\
                      <A><B>1</B></A></u:SetVolume></s:Body>",
                ),
            ),
            (
                "trailing element",
                wrap(&format!("<s:Body>{action}</s:Body><x/>")),
            ),
            ("not an envelope", "<root/>".to_string()),
            ("empty", String::new()),
        ] {
            assert!(parse(Some(VOLUME), &body).is_err(), "{what}");
        }
    }

    #[test]
    fn a_repeated_argument_is_invalid_args_and_too_many_arguments_are_refused() {
        let repeated = set_volume("<A>1</A><A>2</A>");
        assert_eq!(
            parse(Some(VOLUME), &repeated),
            Err(Fault::InvalidArgs("an argument is repeated"))
        );
        let many: String = (0..=MAX_ARGS).map(|i| format!("<A{i}>1</A{i}>")).collect();
        assert_eq!(
            parse(Some(VOLUME), &set_volume(&many)),
            Err(Fault::Malformed)
        );
        let at_limit: String = (0..MAX_ARGS).map(|i| format!("<A{i}>1</A{i}>")).collect();
        assert!(parse(Some(VOLUME), &set_volume(&at_limit)).is_ok());
    }

    #[test]
    fn xml_that_is_too_large_or_dangerous_maps_to_the_right_fault() {
        let huge = set_volume(&"x".repeat(limits().max_bytes));
        assert_eq!(parse(Some(VOLUME), &huge), Err(Fault::TooLarge));
        let doctype = format!(
            "<!DOCTYPE a [<!ENTITY x \"y\">]>{}",
            set_volume("<A>&x;</A>")
        );
        assert_eq!(parse(Some(VOLUME), &doctype), Err(Fault::UnsupportedXml));
        assert_eq!(
            parse_call(Some(VOLUME), &[0xFF, 0xFE], limits()),
            Err(Fault::Malformed)
        );
    }

    #[test]
    fn every_fault_has_a_status_and_the_standard_upnp_code_where_one_exists() {
        let table = [
            (Fault::TooLarge, 413, None),
            (Fault::Malformed, 400, None),
            (Fault::UnsupportedXml, 400, None),
            (Fault::Unauthenticated, 401, None),
            (Fault::InvalidAction, 500, Some(401)),
            (Fault::InvalidArgs("x"), 500, Some(402)),
            (Fault::ActionFailed("x"), 500, Some(501)),
            (Fault::NotImplemented, 500, Some(602)),
            (Fault::OutcomeUnknown, 500, Some(801)),
        ];
        for (fault, status, code) in table {
            assert_eq!(fault.http_status(), status, "{fault:?}");
            assert_eq!(fault.upnp_code(), code, "{fault:?}");
            assert_eq!(fault_envelope(fault).is_some(), code.is_some(), "{fault:?}");
        }
    }

    #[test]
    fn a_fault_envelope_has_the_shape_the_controller_side_reads() {
        let body = fault_envelope(Fault::InvalidArgs("volume above 100")).unwrap();
        assert_eq!(
            body,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
             <s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>\
             <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>402</errorCode>\
             <errorDescription>Invalid Args (volume above 100)</errorDescription></UPnPError>\
             </detail></s:Fault></s:Body></s:Envelope>"
        );
        // And our own reader accepts what we wrote.
        let mut reader = XmlReader::new(body.as_bytes(), limits()).unwrap();
        let mut elements = 0;
        while let Some(event) = reader.next_event().unwrap() {
            if matches!(event, Event::Start { .. }) {
                elements += 1;
            }
        }
        assert_eq!(elements, 9);
    }

    #[test]
    fn a_response_envelope_names_the_action_response_and_escapes_its_values() {
        let body = response_envelope(
            Service::ZoneGroupTopology,
            "GetZoneGroupState",
            &[("ZoneGroupState", "<ZoneGroups a=\"1\"/>".to_string())],
        );
        assert_eq!(
            body,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
             <u:GetZoneGroupStateResponse xmlns:u=\"urn:schemas-upnp-org:service:ZoneGroupTopology:1\">\
             <ZoneGroupState>&lt;ZoneGroups a=\"1\"/&gt;</ZoneGroupState>\
             </u:GetZoneGroupStateResponse></s:Body></s:Envelope>"
        );
    }

    #[test]
    fn the_embedded_document_survives_a_round_trip_through_the_reader() {
        let doc = "<ZoneGroupState><ZoneGroups a=\"x&amp;y\"/></ZoneGroupState>";
        let body = response_envelope(
            Service::ZoneGroupTopology,
            "GetZoneGroupState",
            &[("ZoneGroupState", doc.to_string())],
        );
        let mut reader = XmlReader::new(
            body.as_bytes(),
            XmlLimits {
                max_bytes: 4096,
                ..limits()
            },
        )
        .unwrap();
        let mut texts = Vec::new();
        while let Some(event) = reader.next_event().unwrap() {
            if let Event::Text(t) = event {
                texts.push(t);
            }
        }
        assert_eq!(texts, vec![doc.to_string()]);
    }

    #[test]
    fn a_fault_never_carries_what_the_peer_sent() {
        // Whatever the arguments said, the descriptions are fixed vocabulary.
        let secret = "tok-9f3a1c77e0b2";
        let body = set_volume(&format!("<DesiredVolume>{secret}</DesiredVolume>"));
        let call = parse(Some(VOLUME), &body).unwrap();
        assert_eq!(call.arg("DesiredVolume"), Some(secret));
        for fault in [
            Fault::InvalidAction,
            Fault::InvalidArgs("a volume is a whole number from 0 to 100"),
            Fault::ActionFailed("the group lease is not live"),
            Fault::NotImplemented,
            Fault::OutcomeUnknown,
        ] {
            let text = fault_envelope(fault).unwrap();
            assert!(!text.contains("9f3a1c77e0b2"), "{text}");
        }
    }

    #[test]
    fn the_services_round_trip_through_their_urns_and_paths() {
        for service in Service::ALL {
            assert_eq!(Service::from_urn(service.urn()), Some(service));
            assert_eq!(
                Service::from_control_path(service.control_path()),
                Some(service)
            );
            assert_eq!(
                Service::from_event_path(service.event_path()),
                Some(service)
            );
            assert!(service.urn().ends_with(":1"));
            assert!(service.urn().contains(service.name()));
        }
        assert_eq!(Service::from_urn("urn:x"), None);
        assert_eq!(Service::from_control_path("/nope"), None);
        // The control and event paths are distinct, and none is shared between services.
        let mut paths: Vec<&str> = Service::ALL
            .iter()
            .flat_map(|s| [s.control_path(), s.event_path()])
            .collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), 10);
    }
}
