//! The action matrix and the mapping of SOAP actions to what the endpoint does (G03 / `ffw-xvv`).
//!
//! The bead asks for "an action matrix from actual usage before committing the compatibility surface".
//! [`MATRIX`] is that matrix: every action the `fsonos` controller side sends, with the number of
//! production call sites that send it, measured by `tests/g03/measure_usage.py` and recorded in
//! `tests/g03/usage_matrix.json`. A test compares this table with the recorded measurement.
//!
//! An action is in one of three states, and none of them is ever answered with a fabricated success:
//!
//! * **Implemented**: the endpoint does it (a read of live state, or a command that goes through N02).
//! * **Deferred**: a real action of the service that needs something not built yet (source
//!   arbitration, group membership proposals, a metadata model). It is answered with fault `602`
//!   and the matrix says what it waits for.
//! * An action name the service does not have is fault `401`, and anything on the retired
//!   `ContentDirectory` service is `602`: the legacy content catalog is not reintroduced.
//!
//! [`plan`] validates a parsed call against the action's declared arguments, strictly: every required
//! argument present, no argument that was not declared, and every value in range, before any state is
//! read or any command is built.

use super::soap::{Fault, Service, SoapCall};

/// Whether an action is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Implemented,
    Deferred,
}

/// Who may use an implemented action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Local legacy SOAP and authenticated tailnet commands alike.
    Any,
    /// A relative change. Over plain SOAP, which has no idempotency token, a retry of the same request
    /// is a new command and applies again; only the authenticated route, which names a command id,
    /// is deduplicated. The result is clamped to 0..=100 by the channel.
    Relative,
}

/// One row of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSpec {
    pub service: Service,
    pub name: &'static str,
    /// Production call sites in the consumer crates, from the recorded measurement.
    pub sites: u16,
    pub status: Status,
    pub access: Access,
    /// For a deferred action: what it waits for. For an implemented one: how it is served.
    pub note: &'static str,
}

const fn row(
    service: Service,
    name: &'static str,
    sites: u16,
    status: Status,
    access: Access,
    note: &'static str,
) -> ActionSpec {
    ActionSpec {
        service,
        name,
        sites,
        status,
        access,
        note,
    }
}

use Access::{Any, Relative};
use Service::{AvTransport, GroupRenderingControl, RenderingControl, ZoneGroupTopology};
use Status::{Deferred, Implemented};

const NO_SOURCE: &str = "needs source arbitration, which G01 has not built";
const NO_QUEUE: &str = "the queue belongs to the source layer";
const NO_TONE: &str = "the slim renderer has no tone controls yet";

/// Every action the controller side sends, in descending order of measured use.
pub const MATRIX: &[ActionSpec] = &[
    row(
        ZoneGroupTopology,
        "GetZoneGroupState",
        112,
        Implemented,
        Any,
        "read of the live session",
    ),
    row(
        AvTransport,
        "GetTransportInfo",
        58,
        Implemented,
        Any,
        "state supplied by the owner; the session has no source",
    ),
    row(
        AvTransport,
        "GetMediaInfo",
        51,
        Deferred,
        Any,
        "needs a source and metadata model",
    ),
    row(
        AvTransport,
        "SetAVTransportURI",
        39,
        Deferred,
        Any,
        "also carries group join and leave; needs G01 membership proposals and source arbitration",
    ),
    row(
        RenderingControl,
        "GetVolume",
        30,
        Implemented,
        Any,
        "read of this endpoint's member",
    ),
    row(
        AvTransport,
        "GetPositionInfo",
        26,
        Deferred,
        Any,
        "needs a source and a position model",
    ),
    row(
        RenderingControl,
        "SetVolume",
        22,
        Implemented,
        Any,
        "N02 SetMemberVolume",
    ),
    row(AvTransport, "Play", 21, Deferred, Any, NO_SOURCE),
    row(AvTransport, "AddURIToQueue", 16, Deferred, Any, NO_QUEUE),
    row(AvTransport, "Seek", 11, Deferred, Any, NO_SOURCE),
    row(
        AvTransport,
        "ConfigureSleepTimer",
        10,
        Deferred,
        Any,
        "no sleep timer in the slim endpoint",
    ),
    row(AvTransport, "Pause", 8, Deferred, Any, NO_SOURCE),
    row(
        AvTransport,
        "Stop",
        8,
        Implemented,
        Any,
        "N02 StopGroupPlayback",
    ),
    row(
        AvTransport,
        "GetRemainingSleepTimerDuration",
        7,
        Deferred,
        Any,
        "no sleep timer in the slim endpoint",
    ),
    row(
        RenderingControl,
        "GetMute",
        7,
        Implemented,
        Any,
        "read of this endpoint's member",
    ),
    row(
        AvTransport,
        "RemoveTrackRangeFromQueue",
        5,
        Deferred,
        Any,
        NO_QUEUE,
    ),
    row(
        AvTransport,
        "DelegateGroupCoordinationTo",
        3,
        Deferred,
        Any,
        "a coordinator change is an epoch mint, owned by G01",
    ),
    row(
        GroupRenderingControl,
        "GetGroupVolume",
        3,
        Implemented,
        Any,
        "read of the group master volume",
    ),
    row(
        RenderingControl,
        "SetMute",
        3,
        Implemented,
        Any,
        "N02 SetMemberMute",
    ),
    row(
        GroupRenderingControl,
        "SnapshotGroupVolume",
        2,
        Implemented,
        Any,
        "acknowledged and not needed: the session keeps per-room trim",
    ),
    row(RenderingControl, "GetBass", 2, Deferred, Any, NO_TONE),
    row(RenderingControl, "GetLoudness", 2, Deferred, Any, NO_TONE),
    row(RenderingControl, "GetTreble", 2, Deferred, Any, NO_TONE),
    row(AvTransport, "Next", 1, Deferred, Any, NO_SOURCE),
    row(AvTransport, "Previous", 1, Deferred, Any, NO_SOURCE),
    row(AvTransport, "SetPlayMode", 1, Deferred, Any, NO_QUEUE),
    row(
        GroupRenderingControl,
        "SetGroupVolume",
        1,
        Implemented,
        Any,
        "N02 SetGroupVolume",
    ),
    row(
        GroupRenderingControl,
        "SetRelativeGroupVolume",
        1,
        Implemented,
        Relative,
        "N02 AdjustGroupVolume, clamped; a plain-SOAP retry applies twice",
    ),
    row(
        RenderingControl,
        "RampToVolume",
        1,
        Deferred,
        Any,
        "volume ramps belong to G02's transitions",
    ),
    row(RenderingControl, "SetBass", 1, Deferred, Any, NO_TONE),
    row(RenderingControl, "SetLoudness", 1, Deferred, Any, NO_TONE),
    row(
        RenderingControl,
        "SetRelativeVolume",
        1,
        Implemented,
        Relative,
        "N02 AdjustMemberVolume, clamped; a plain-SOAP retry applies twice",
    ),
    row(RenderingControl, "SetTreble", 1, Deferred, Any, NO_TONE),
    row(
        AvTransport,
        "RemoveAllTracksFromQueue",
        0,
        Deferred,
        Any,
        NO_QUEUE,
    ),
];

/// The matrix row for `service`/`name`, if the controller side sends such an action.
#[must_use]
pub fn lookup(service: Service, name: &str) -> Option<&'static ActionSpec> {
    MATRIX
        .iter()
        .find(|row| row.service == service && row.name == name)
}

/// What a state read returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    Volume,
    Mute,
    GroupVolume,
    TransportInfo,
    ZoneGroupState,
}

/// What a command asks of the group, before it becomes an N02 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    SetVolume(u8),
    SetMute(bool),
    SetGroupVolume(u8),
    RelativeVolume(i8),
    RelativeGroupVolume(i8),
    Stop,
}

impl Cmd {
    /// Relative changes are not repeatable: a retry that is mistaken for a new command applies again.
    #[must_use]
    pub const fn is_relative(&self) -> bool {
        matches!(self, Self::RelativeVolume(_) | Self::RelativeGroupVolume(_))
    }
}

/// What the endpoint does for a validated call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Read(Read),
    Command(Cmd),
    /// Acknowledge and do nothing (`SnapshotGroupVolume`).
    Ack,
}

/// What a command's arguments must be, written once and checked the same way for every action.
struct Shape {
    required: &'static [&'static str],
}

fn check_shape(call: &SoapCall, shape: &Shape) -> Result<(), Fault> {
    for name in shape.required {
        if call.arg(name).is_none() {
            return Err(Fault::InvalidArgs("a required argument is missing"));
        }
    }
    if call
        .args
        .iter()
        .any(|(name, _)| !shape.required.contains(&name.as_str()))
    {
        return Err(Fault::InvalidArgs("an argument this action does not take"));
    }
    Ok(())
}

fn instance_zero(call: &SoapCall) -> Result<(), Fault> {
    match call.arg("InstanceID").map(str::trim) {
        Some("0") => Ok(()),
        _ => Err(Fault::InvalidArgs("InstanceID must be 0")),
    }
}

fn master_channel(call: &SoapCall) -> Result<(), Fault> {
    match call.arg("Channel").map(str::trim) {
        Some("Master") => Ok(()),
        _ => Err(Fault::InvalidArgs("only the Master channel is supported")),
    }
}

const BAD_VOLUME: Fault = Fault::InvalidArgs("a volume is a whole number from 0 to 100");
const BAD_ADJUSTMENT: Fault =
    Fault::InvalidArgs("an adjustment is a non-zero whole number from -100 to 100");

/// A decimal integer: an optional sign and digits, nothing else (no spaces inside, no exponent).
fn whole(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let digits = raw.strip_prefix(['-', '+']).unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.len() > 10 {
        return None;
    }
    raw.parse().ok()
}

fn volume(raw: &str) -> Result<u8, Fault> {
    whole(raw)
        .filter(|v| (0..=100).contains(v))
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(BAD_VOLUME)
}

fn adjustment(raw: &str) -> Result<i8, Fault> {
    whole(raw)
        .filter(|v| *v != 0 && (-100..=100).contains(v))
        .and_then(|v| i8::try_from(v).ok())
        .ok_or(BAD_ADJUSTMENT)
}

fn boolean(raw: &str) -> Result<bool, Fault> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(Fault::InvalidArgs("a mute value is 0, 1, true or false")),
    }
}

fn arg<'a>(call: &'a SoapCall, name: &str) -> &'a str {
    call.arg(name).unwrap_or("")
}

/// Classify and validate `call`. A call for a name the service does not have is `InvalidAction`; for a
/// deferred action or the retired catalog, `NotImplemented`; for bad arguments, `InvalidArgs`.
pub fn plan(call: &SoapCall) -> Result<Plan, Fault> {
    if call.service == Service::ContentDirectory {
        return Err(Fault::NotImplemented);
    }
    let spec = lookup(call.service, &call.action).ok_or(Fault::InvalidAction)?;
    if spec.status == Status::Deferred {
        return Err(Fault::NotImplemented);
    }
    let rendering = Shape {
        required: &["InstanceID", "Channel"],
    };
    match (call.service, call.action.as_str()) {
        (RenderingControl, "GetVolume") => {
            check_shape(call, &rendering)?;
            instance_zero(call)?;
            master_channel(call)?;
            Ok(Plan::Read(Read::Volume))
        }
        (RenderingControl, "GetMute") => {
            check_shape(call, &rendering)?;
            instance_zero(call)?;
            master_channel(call)?;
            Ok(Plan::Read(Read::Mute))
        }
        (RenderingControl, "SetVolume") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID", "Channel", "DesiredVolume"],
                },
            )?;
            instance_zero(call)?;
            master_channel(call)?;
            Ok(Plan::Command(Cmd::SetVolume(volume(arg(
                call,
                "DesiredVolume",
            ))?)))
        }
        (RenderingControl, "SetMute") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID", "Channel", "DesiredMute"],
                },
            )?;
            instance_zero(call)?;
            master_channel(call)?;
            Ok(Plan::Command(Cmd::SetMute(boolean(arg(
                call,
                "DesiredMute",
            ))?)))
        }
        (RenderingControl, "SetRelativeVolume") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID", "Channel", "Adjustment"],
                },
            )?;
            instance_zero(call)?;
            master_channel(call)?;
            Ok(Plan::Command(Cmd::RelativeVolume(adjustment(arg(
                call,
                "Adjustment",
            ))?)))
        }
        (GroupRenderingControl, "GetGroupVolume") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID"],
                },
            )?;
            instance_zero(call)?;
            Ok(Plan::Read(Read::GroupVolume))
        }
        (GroupRenderingControl, "SnapshotGroupVolume") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID"],
                },
            )?;
            instance_zero(call)?;
            Ok(Plan::Ack)
        }
        (GroupRenderingControl, "SetGroupVolume") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID", "DesiredVolume"],
                },
            )?;
            instance_zero(call)?;
            Ok(Plan::Command(Cmd::SetGroupVolume(volume(arg(
                call,
                "DesiredVolume",
            ))?)))
        }
        (GroupRenderingControl, "SetRelativeGroupVolume") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID", "Adjustment"],
                },
            )?;
            instance_zero(call)?;
            Ok(Plan::Command(Cmd::RelativeGroupVolume(adjustment(arg(
                call,
                "Adjustment",
            ))?)))
        }
        (AvTransport, "GetTransportInfo") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID"],
                },
            )?;
            instance_zero(call)?;
            Ok(Plan::Read(Read::TransportInfo))
        }
        (AvTransport, "Stop") => {
            check_shape(
                call,
                &Shape {
                    required: &["InstanceID"],
                },
            )?;
            instance_zero(call)?;
            Ok(Plan::Command(Cmd::Stop))
        }
        (ZoneGroupTopology, "GetZoneGroupState") => {
            check_shape(call, &Shape { required: &[] })?;
            Ok(Plan::Read(Read::ZoneGroupState))
        }
        // A row marked implemented with no arm here is a bug in this file; refuse rather than guess.
        _ => Err(Fault::NotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(service: Service, action: &str, args: &[(&str, &str)]) -> SoapCall {
        SoapCall {
            service,
            action: action.to_string(),
            args: args
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    fn rc(action: &str, args: &[(&str, &str)]) -> SoapCall {
        call(RenderingControl, action, args)
    }

    const MASTER: [(&str, &str); 2] = [("InstanceID", "0"), ("Channel", "Master")];

    #[test]
    fn the_matrix_has_one_row_per_action_and_is_ordered_by_use() {
        let mut seen = std::collections::BTreeSet::new();
        for row in MATRIX {
            assert!(
                seen.insert((row.service.name(), row.name)),
                "{} repeated",
                row.name
            );
            assert!(!row.note.is_empty(), "{}", row.name);
            assert_ne!(
                row.service,
                Service::ContentDirectory,
                "the retired catalog has no rows"
            );
        }
        let sites: Vec<u16> = MATRIX.iter().map(|r| r.sites).collect();
        let mut sorted = sites.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(sites, sorted, "descending order of measured use");
        assert_eq!(MATRIX.len(), 34);
    }

    #[test]
    fn exactly_the_actions_in_scope_are_implemented() {
        let mut implemented: Vec<&str> = MATRIX
            .iter()
            .filter(|r| r.status == Implemented)
            .map(|r| r.name)
            .collect();
        implemented.sort_unstable();
        assert_eq!(
            implemented,
            [
                "GetGroupVolume",
                "GetMute",
                "GetTransportInfo",
                "GetVolume",
                "GetZoneGroupState",
                "SetGroupVolume",
                "SetMute",
                "SetRelativeGroupVolume",
                "SetRelativeVolume",
                "SetVolume",
                "SnapshotGroupVolume",
                "Stop"
            ]
        );
        // Only the two relative actions are relative.
        let relative: Vec<&str> = MATRIX
            .iter()
            .filter(|r| r.access == Relative)
            .map(|r| r.name)
            .collect();
        assert_eq!(relative, ["SetRelativeGroupVolume", "SetRelativeVolume"]);
    }

    #[test]
    fn a_command_is_relative_exactly_when_its_matrix_row_says_so() {
        let cases = [
            (Cmd::SetVolume(1), "SetVolume"),
            (Cmd::SetMute(true), "SetMute"),
            (Cmd::SetGroupVolume(1), "SetGroupVolume"),
            (Cmd::RelativeVolume(1), "SetRelativeVolume"),
            (Cmd::RelativeGroupVolume(1), "SetRelativeGroupVolume"),
            (Cmd::Stop, "Stop"),
        ];
        for (cmd, action) in cases {
            let row = MATRIX.iter().find(|r| r.name == action).expect("a row");
            assert_eq!(cmd.is_relative(), row.access == Relative, "{action}");
        }
    }

    #[test]
    fn every_implemented_action_has_a_plan_for_valid_arguments_and_no_deferred_one_does() {
        for row in MATRIX {
            let probe = call(row.service, row.name, &[]);
            match (row.status, plan(&probe)) {
                (Deferred, r) => assert_eq!(r, Err(Fault::NotImplemented), "{}", row.name),
                // With no arguments an implemented action is refused for its arguments, never as
                // unimplemented or unknown: it has a plan, it just was not given valid input.
                (Implemented, Err(Fault::InvalidArgs(_))) => {}
                (Implemented, Ok(Plan::Read(Read::ZoneGroupState))) => {
                    assert_eq!(row.name, "GetZoneGroupState");
                }
                (Implemented, other) => panic!("{}: {other:?}", row.name),
            }
        }
    }

    #[test]
    fn an_unknown_action_is_invalid_action_and_a_known_deferred_one_is_not_implemented() {
        assert_eq!(
            plan(&rc("NoSuchAction", &MASTER)),
            Err(Fault::InvalidAction)
        );
        assert_eq!(
            plan(&call(
                AvTransport,
                "Play",
                &[("InstanceID", "0"), ("Speed", "1")]
            )),
            Err(Fault::NotImplemented)
        );
        assert_eq!(plan(&rc("GetBass", &MASTER)), Err(Fault::NotImplemented));
        // An action of another service under this service's name is unknown here.
        assert_eq!(
            plan(&call(RenderingControl, "Play", &[])),
            Err(Fault::InvalidAction)
        );
    }

    #[test]
    fn the_retired_content_catalog_is_not_implemented_whatever_the_action() {
        for action in [
            "Browse",
            "Search",
            "GetSearchCapabilities",
            "CreateObject",
            "Anything",
        ] {
            assert_eq!(
                plan(&call(
                    Service::ContentDirectory,
                    action,
                    &[("ObjectID", "0")]
                )),
                Err(Fault::NotImplemented),
                "{action}"
            );
        }
    }

    #[test]
    fn volume_and_mute_calls_plan_to_reads_and_commands() {
        assert_eq!(
            plan(&rc("GetVolume", &MASTER)),
            Ok(Plan::Read(Read::Volume))
        );
        assert_eq!(plan(&rc("GetMute", &MASTER)), Ok(Plan::Read(Read::Mute)));
        let with = |extra: (&'static str, &'static str)| [MASTER[0], MASTER[1], extra];
        assert_eq!(
            plan(&rc("SetVolume", &with(("DesiredVolume", "30")))),
            Ok(Plan::Command(Cmd::SetVolume(30)))
        );
        assert_eq!(
            plan(&rc("SetMute", &with(("DesiredMute", "1")))),
            Ok(Plan::Command(Cmd::SetMute(true)))
        );
        assert_eq!(
            plan(&rc("SetRelativeVolume", &with(("Adjustment", "-5")))),
            Ok(Plan::Command(Cmd::RelativeVolume(-5)))
        );
    }

    #[test]
    fn group_volume_and_transport_calls_plan_correctly() {
        let grc = |action: &str, args: &[(&str, &str)]| call(GroupRenderingControl, action, args);
        assert_eq!(
            plan(&grc("GetGroupVolume", &[("InstanceID", "0")])),
            Ok(Plan::Read(Read::GroupVolume))
        );
        assert_eq!(
            plan(&grc("SnapshotGroupVolume", &[("InstanceID", "0")])),
            Ok(Plan::Ack)
        );
        assert_eq!(
            plan(&grc(
                "SetGroupVolume",
                &[("InstanceID", "0"), ("DesiredVolume", "100")]
            )),
            Ok(Plan::Command(Cmd::SetGroupVolume(100)))
        );
        assert_eq!(
            plan(&grc(
                "SetRelativeGroupVolume",
                &[("InstanceID", "0"), ("Adjustment", "7")]
            )),
            Ok(Plan::Command(Cmd::RelativeGroupVolume(7)))
        );
        assert_eq!(
            plan(&call(
                AvTransport,
                "GetTransportInfo",
                &[("InstanceID", "0")]
            )),
            Ok(Plan::Read(Read::TransportInfo))
        );
        assert_eq!(
            plan(&call(AvTransport, "Stop", &[("InstanceID", "0")])),
            Ok(Plan::Command(Cmd::Stop))
        );
        assert_eq!(
            plan(&call(ZoneGroupTopology, "GetZoneGroupState", &[])),
            Ok(Plan::Read(Read::ZoneGroupState))
        );
    }

    #[test]
    fn volumes_are_whole_numbers_from_0_to_100_and_nothing_is_clamped_or_guessed() {
        let set = |v: &str| {
            plan(&rc(
                "SetVolume",
                &[MASTER[0], MASTER[1], ("DesiredVolume", v)],
            ))
        };
        for ok in ["0", "100", "50", " 7 ", "+5", "007"] {
            assert!(
                matches!(set(ok), Ok(Plan::Command(Cmd::SetVolume(_)))),
                "{ok:?}"
            );
        }
        for bad in [
            "101",
            "-1",
            "1000",
            "5.5",
            "1e2",
            "",
            " ",
            "abc",
            "5 5",
            "0x10",
            "99999999999",
            "٣",
        ] {
            assert_eq!(set(bad), Err(BAD_VOLUME), "{bad:?}");
        }
    }

    #[test]
    fn adjustments_are_nonzero_whole_numbers_within_100() {
        let adj = |v: &str| {
            plan(&rc(
                "SetRelativeVolume",
                &[MASTER[0], MASTER[1], ("Adjustment", v)],
            ))
        };
        for ok in ["1", "-1", "100", "-100", "+3"] {
            assert!(
                matches!(adj(ok), Ok(Plan::Command(Cmd::RelativeVolume(_)))),
                "{ok:?}"
            );
        }
        for bad in ["0", "-0", "101", "-101", "1.5", "", "x"] {
            assert_eq!(adj(bad), Err(BAD_ADJUSTMENT), "{bad:?}");
        }
    }

    #[test]
    fn mute_accepts_the_upnp_booleans_and_nothing_else() {
        let mute = |v: &str| plan(&rc("SetMute", &[MASTER[0], MASTER[1], ("DesiredMute", v)]));
        for (raw, expected) in [
            ("1", true),
            ("true", true),
            ("TRUE", true),
            ("0", false),
            ("False", false),
        ] {
            assert_eq!(
                mute(raw),
                Ok(Plan::Command(Cmd::SetMute(expected))),
                "{raw}"
            );
        }
        for bad in ["2", "yes", "", "on"] {
            assert!(matches!(mute(bad), Err(Fault::InvalidArgs(_))), "{bad:?}");
        }
    }

    #[test]
    fn the_instance_and_the_channel_must_be_the_supported_ones() {
        let get = |instance: &str, channel: &str| {
            plan(&rc(
                "GetVolume",
                &[("InstanceID", instance), ("Channel", channel)],
            ))
        };
        assert_eq!(get("0", "Master"), Ok(Plan::Read(Read::Volume)));
        assert_eq!(get(" 0 ", "Master"), Ok(Plan::Read(Read::Volume)));
        assert_eq!(
            get("1", "Master"),
            Err(Fault::InvalidArgs("InstanceID must be 0"))
        );
        assert_eq!(
            get("", "Master"),
            Err(Fault::InvalidArgs("InstanceID must be 0"))
        );
        assert_eq!(
            get("0", "LF"),
            Err(Fault::InvalidArgs("only the Master channel is supported"))
        );
        assert_eq!(
            get("0", "RF"),
            Err(Fault::InvalidArgs("only the Master channel is supported"))
        );
    }

    #[test]
    fn a_missing_or_extra_argument_is_refused_before_anything_else() {
        assert_eq!(
            plan(&rc("SetVolume", &[MASTER[0], MASTER[1]])),
            Err(Fault::InvalidArgs("a required argument is missing"))
        );
        assert_eq!(
            plan(&rc("GetVolume", &[MASTER[0], MASTER[1], ("Extra", "x")])),
            Err(Fault::InvalidArgs("an argument this action does not take"))
        );
        assert_eq!(
            plan(&call(
                ZoneGroupTopology,
                "GetZoneGroupState",
                &[("Extra", "x")]
            )),
            Err(Fault::InvalidArgs("an argument this action does not take"))
        );
        // Order does not matter.
        assert!(
            plan(&rc(
                "SetVolume",
                &[("DesiredVolume", "5"), MASTER[1], MASTER[0]]
            ))
            .is_ok()
        );
    }

    #[test]
    fn a_peers_text_never_reaches_the_fault() {
        let secret = "tok-9f3a1c77e0b2";
        for c in [
            rc(
                "SetVolume",
                &[MASTER[0], MASTER[1], ("DesiredVolume", secret)],
            ),
            rc("SetMute", &[MASTER[0], MASTER[1], ("DesiredMute", secret)]),
            rc("GetVolume", &[MASTER[0], ("Channel", secret)]),
            rc("GetVolume", &[("InstanceID", secret), MASTER[1]]),
            rc("GetVolume", &[MASTER[0], MASTER[1], (secret, "x")]),
            rc(secret, &MASTER),
        ] {
            let shown = format!("{:?}", plan(&c));
            assert!(!shown.contains("9f3a1c77e0b2"), "{shown}");
        }
    }
}
