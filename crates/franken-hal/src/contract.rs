//! Retained-driver contract records and hardware eligibility (`E04` / `ffw-25l`).
//!
//! A *contract record* describes one retained-driver interface (an `ioctl`, a `write`, a `mmap`, ...)
//! field by field: which interface it is, the command number, direction, payload size, endianness,
//! alignment and field map. Every field is in exactly one of three states:
//!
//! * [`FieldStatus::Known`]: a value plus an [`Anchor`] that points at the evidence (an artifact
//!   digest and section/offset/symbol, a public source reference, or an explicitly labelled
//!   synthetic fixture);
//! * [`FieldStatus::Unknown`]: nothing is established, and an [`ExternalBlocker`] names what is
//!   needed to establish it;
//! * [`FieldStatus::NotApplicable`]: the field genuinely does not exist for this interface, with a
//!   stated reason.
//!
//! [`ContractMatrix::evaluate`] turns a matrix into an [`EligibilityReport`] that lists the exact
//! missing contract. Hardware eligibility needs every field of every record resolved and anchored
//! on a real artifact or public source, and a record for every operation the HAL needs. It never
//! looks at how large or how simple a driver is: an artifact's size is registered metadata and is
//! not an input to the verdict (a test pins that).
//!
//! Offline simulation is a weaker bar: [`SyntheticFixture`](Anchor::SyntheticFixture) anchors let a
//! test exercise the model but can never make a matrix hardware-eligible.
//!
//! Besides the driver's interfaces and the radio duties, a matrix carries the audio path's **channel
//! topology** (how many channels, which transducer each feeds, which sample rates and encoding) and
//! its **amplifier sequences** (what the mute pin, clocks and codec do on a startup, a stop and a
//! fault, in what order and with what minimum delays). Both obey the same known / unknown /
//! not-applicable rule, and a sequence that unmutes before the end of a startup, unmutes on a stop or
//! does not wait for the mute to be acknowledged contradicts the safe-startup policy and is refused.

use franken_board_profile::{BoardProfile, TransducerRole};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Schema string of a serialized [`ContractMatrix`].
pub const CONTRACT_SCHEMA: &str = "ffw.e04.contract_matrix.v1";

// PowerPC `_IOC` command layout. The retained model-16 `audiodev.o` reads the size as
// `rlwinm 5,31,16,19,31` (shift 16, 13 bits), tests the write bit as `cmpwi cmd,0` (bit 31) and the
// read bit as `andis. 0,31,16384` (bit 30). That is NOT the layout of an x86 or Arm Linux host,
// where the same word decodes to a different direction and size. Never use a host `ioctl` number.
pub const IOC_TYPE_SHIFT: u32 = 8;
pub const IOC_SIZE_SHIFT: u32 = 16;
pub const IOC_DIR_SHIFT: u32 = 29;
/// Largest value of the 13-bit size field.
pub const IOC_SIZE_MAX: u16 = 0x1fff;
pub const IOC_DIR_NONE: u8 = 1;
pub const IOC_DIR_READ: u8 = 2;
pub const IOC_DIR_WRITE: u8 = 4;
pub const IOC_DIR_READ_WRITE: u8 = IOC_DIR_READ | IOC_DIR_WRITE;

/// The four parts of a PowerPC `ioctl` command word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoctlParts {
    pub nr: u8,
    pub type_byte: u8,
    pub size: u16,
    pub dir_bits: u8,
}

/// Split a command word using the PowerPC layout.
#[must_use]
pub const fn decode_ppc_ioctl(cmd: u32) -> IoctlParts {
    IoctlParts {
        nr: (cmd & 0xff) as u8,
        type_byte: ((cmd >> IOC_TYPE_SHIFT) & 0xff) as u8,
        size: ((cmd >> IOC_SIZE_SHIFT) & 0x1fff) as u16,
        dir_bits: (cmd >> IOC_DIR_SHIFT) as u8,
    }
}

/// Build a command word using the PowerPC layout.
pub fn encode_ppc_ioctl(
    dir_bits: u8,
    type_byte: u8,
    nr: u8,
    size: u16,
) -> Result<u32, ContractError> {
    if dir_bits > 7 {
        return Err(ContractError::IoctlFieldRange {
            field: "dir_bits",
            value: u32::from(dir_bits),
        });
    }
    if size > IOC_SIZE_MAX {
        return Err(ContractError::IoctlFieldRange {
            field: "size",
            value: u32::from(size),
        });
    }
    Ok((u32::from(dir_bits) << IOC_DIR_SHIFT)
        | (u32::from(size) << IOC_SIZE_SHIFT)
        | (u32::from(type_byte) << IOC_TYPE_SHIFT)
        | u32::from(nr))
}

/// Which way data moves across an `ioctl`, from the caller's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoctlDirection {
    NoData,
    /// Kernel to user.
    Read,
    /// User to kernel.
    Write,
    ReadWrite,
}

impl IoctlDirection {
    /// `None` for the legacy "no direction encoded" value 0 and for the invalid mixes 3, 5 and 7.
    #[must_use]
    pub const fn from_dir_bits(bits: u8) -> Option<Self> {
        match bits {
            IOC_DIR_NONE => Some(Self::NoData),
            IOC_DIR_READ => Some(Self::Read),
            IOC_DIR_WRITE => Some(Self::Write),
            IOC_DIR_READ_WRITE => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Big,
    Little,
}

/// Why a primitive or a field map was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("ioctl field {field} out of range: {value}")]
    IoctlFieldRange { field: &'static str, value: u32 },
    #[error("unsupported integer width {width}")]
    BadWidth { width: usize },
    #[error("offset {offset} is not aligned to {align}")]
    Misaligned { offset: usize, align: usize },
    #[error("{width} byte(s) at offset {offset} exceed a {len}-byte buffer")]
    OutOfBounds {
        offset: usize,
        width: usize,
        len: usize,
    },
    #[error("value {value:#x} does not fit in {width} byte(s)")]
    ValueTooWide { width: usize, value: u64 },
    #[error("payload is {actual} byte(s) but the record says {expected}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("field map: {0:?}")]
    FieldMap(FieldMapProblem),
}

/// What is wrong with a field map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldMapProblem {
    BadAlignment(u8),
    EmptyName,
    DuplicateName(String),
    ZeroWidth(String),
    BadIntegerWidth {
        name: String,
        width: u8,
    },
    Misaligned {
        name: String,
        offset: u16,
        width: u8,
    },
    AlignmentTooSmall {
        name: String,
        width: u8,
        alignment: u8,
    },
    Overlap {
        name: String,
    },
    Gap {
        offset: u16,
    },
    OutOfBounds {
        name: String,
    },
}

fn check_int_width(width: usize) -> Result<(), ContractError> {
    if matches!(width, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(ContractError::BadWidth { width })
    }
}

/// Read an unsigned integer of `width` bytes at a naturally aligned `offset`.
///
/// Checks run in this order: width, alignment, bounds. The buffer is untrusted input, so a short
/// buffer is an error and never a panic.
pub fn read_uint(
    bytes: &[u8],
    offset: usize,
    width: usize,
    endian: Endianness,
) -> Result<u64, ContractError> {
    check_int_width(width)?;
    if offset & (width - 1) != 0 {
        return Err(ContractError::Misaligned {
            offset,
            align: width,
        });
    }
    let out_of_bounds = ContractError::OutOfBounds {
        offset,
        width,
        len: bytes.len(),
    };
    let end = offset.checked_add(width).ok_or(out_of_bounds.clone())?;
    let slice = bytes.get(offset..end).ok_or(out_of_bounds)?;
    let mut value: u64 = 0;
    match endian {
        Endianness::Big => {
            for &b in slice {
                value = (value << 8) | u64::from(b);
            }
        }
        Endianness::Little => {
            for &b in slice.iter().rev() {
                value = (value << 8) | u64::from(b);
            }
        }
    }
    Ok(value)
}

/// Write an unsigned integer of `width` bytes at a naturally aligned `offset`.
pub fn write_uint(
    buf: &mut [u8],
    offset: usize,
    width: usize,
    endian: Endianness,
    value: u64,
) -> Result<(), ContractError> {
    check_int_width(width)?;
    if offset & (width - 1) != 0 {
        return Err(ContractError::Misaligned {
            offset,
            align: width,
        });
    }
    if width < 8 && (value >> (8 * width)) != 0 {
        return Err(ContractError::ValueTooWide { width, value });
    }
    let len = buf.len();
    let out_of_bounds = ContractError::OutOfBounds { offset, width, len };
    let end = offset.checked_add(width).ok_or(out_of_bounds.clone())?;
    let slice = buf.get_mut(offset..end).ok_or(out_of_bounds)?;
    for (i, byte) in slice.iter_mut().enumerate() {
        let shift = match endian {
            Endianness::Big => 8 * (width - 1 - i),
            Endianness::Little => 8 * i,
        };
        *byte = ((value >> shift) & 0xff) as u8;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Unsigned,
    Signed,
    /// Bytes the driver ignores or reserves. Any width, any alignment, never decoded.
    Padding,
}

/// One field of a payload struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub offset: u16,
    pub width: u8,
    pub kind: FieldKind,
}

/// A decoded payload field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue {
    Unsigned(u64),
    Signed(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedField {
    pub name: String,
    pub value: FieldValue,
}

/// Check that `fields` tile a `payload_size`-byte struct exactly, with natural alignment.
///
/// Every byte must belong to exactly one field (use [`FieldKind::Padding`] for reserved bytes);
/// integer widths are 1, 2, 4 or 8, naturally aligned and no wider than `alignment`; names are
/// unique and non-empty. A payload that nothing describes is a gap, never a silent default.
pub fn validate_field_map(
    fields: &[FieldSpec],
    payload_size: u16,
    alignment: u8,
) -> Result<(), ContractError> {
    let problem = |p: FieldMapProblem| Err(ContractError::FieldMap(p));
    if !matches!(alignment, 1 | 2 | 4 | 8) {
        return problem(FieldMapProblem::BadAlignment(alignment));
    }
    let mut names = BTreeSet::new();
    for f in fields {
        if f.name.trim().is_empty() {
            return problem(FieldMapProblem::EmptyName);
        }
        if !names.insert(f.name.as_str()) {
            return problem(FieldMapProblem::DuplicateName(f.name.clone()));
        }
        if f.width == 0 {
            return problem(FieldMapProblem::ZeroWidth(f.name.clone()));
        }
        if f.kind != FieldKind::Padding {
            if !matches!(f.width, 1 | 2 | 4 | 8) {
                return problem(FieldMapProblem::BadIntegerWidth {
                    name: f.name.clone(),
                    width: f.width,
                });
            }
            if f.offset & u16::from(f.width - 1) != 0 {
                return problem(FieldMapProblem::Misaligned {
                    name: f.name.clone(),
                    offset: f.offset,
                    width: f.width,
                });
            }
            if f.width > alignment {
                return problem(FieldMapProblem::AlignmentTooSmall {
                    name: f.name.clone(),
                    width: f.width,
                    alignment,
                });
            }
        }
    }
    let mut sorted: Vec<&FieldSpec> = fields.iter().collect();
    sorted.sort_by_key(|f| f.offset);
    let mut next: u32 = 0;
    for f in sorted {
        let start = u32::from(f.offset);
        if start < next {
            return problem(FieldMapProblem::Overlap {
                name: f.name.clone(),
            });
        }
        if start > next {
            return problem(FieldMapProblem::Gap {
                offset: u16::try_from(next).unwrap_or(u16::MAX),
            });
        }
        let end = start + u32::from(f.width);
        if end > u32::from(payload_size) {
            return problem(FieldMapProblem::OutOfBounds {
                name: f.name.clone(),
            });
        }
        next = end;
    }
    if next < u32::from(payload_size) {
        return problem(FieldMapProblem::Gap {
            offset: u16::try_from(next).unwrap_or(u16::MAX),
        });
    }
    Ok(())
}

/// Decode a payload through a field map. The payload length must equal `payload_size` exactly.
pub fn decode_payload(
    fields: &[FieldSpec],
    payload_size: u16,
    alignment: u8,
    payload: &[u8],
    endian: Endianness,
) -> Result<Vec<DecodedField>, ContractError> {
    validate_field_map(fields, payload_size, alignment)?;
    let expected = usize::from(payload_size);
    if payload.len() != expected {
        return Err(ContractError::LengthMismatch {
            expected,
            actual: payload.len(),
        });
    }
    let mut sorted: Vec<&FieldSpec> = fields.iter().collect();
    sorted.sort_by_key(|f| f.offset);
    let mut out = Vec::new();
    for f in sorted {
        if f.kind == FieldKind::Padding {
            continue;
        }
        let width = usize::from(f.width);
        let raw = read_uint(payload, usize::from(f.offset), width, endian)?;
        let value = if f.kind == FieldKind::Signed {
            let shift = 64 - 8 * width;
            FieldValue::Signed(((raw << shift) as i64) >> shift)
        } else {
            FieldValue::Unsigned(raw)
        };
        out.push(DecodedField {
            name: f.name.clone(),
            value,
        });
    }
    Ok(out)
}

/// What is needed, from outside this repository, to establish an unknown field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalBlocker {
    /// Stable id, `EXT-E04-<NAME>`.
    pub id: String,
    pub needs: String,
}

/// Where the evidence for a known field lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anchor {
    /// A registered artifact (by digest) and a place inside it.
    Artifact {
        sha256: String,
        section: String,
        offset: u32,
        symbol: Option<String>,
    },
    /// A public source document or header.
    Source { reference: String },
    /// A labelled test double. Valid for the offline model, never for hardware.
    SyntheticFixture { label: String },
}

/// One contract field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FieldStatus<T> {
    Known { value: T, anchor: Anchor },
    Unknown { blocker: ExternalBlocker },
    NotApplicable { reason: String },
}

impl<T> FieldStatus<T> {
    pub const fn known(value: T, anchor: Anchor) -> Self {
        Self::Known { value, anchor }
    }

    pub fn unknown(id: &str, needs: &str) -> Self {
        Self::Unknown {
            blocker: ExternalBlocker {
                id: id.to_string(),
                needs: needs.to_string(),
            },
        }
    }

    pub fn not_applicable(reason: &str) -> Self {
        Self::NotApplicable {
            reason: reason.to_string(),
        }
    }

    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Known { value, .. } => Some(value),
            _ => None,
        }
    }

    pub const fn is_not_applicable(&self) -> bool {
        matches!(self, Self::NotApplicable { .. })
    }
}

/// The driver operations the HAL contract needs (design sections 6 and 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HalOperation {
    QueryCapabilities,
    AcquireExclusive,
    PrepareFormat,
    SubmitBlock,
    QueryPosition,
    Start,
    SetGain,
    Drain,
    AbortMute,
    Release,
}

impl HalOperation {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::QueryCapabilities => "query_capabilities",
            Self::AcquireExclusive => "acquire_exclusive",
            Self::PrepareFormat => "prepare_format",
            Self::SubmitBlock => "submit_block",
            Self::QueryPosition => "query_position",
            Self::Start => "start",
            Self::SetGain => "set_gain",
            Self::Drain => "drain",
            Self::AbortMute => "abort_mute",
            Self::Release => "release",
        }
    }
}

/// Every operation a hardware-eligible matrix must cover.
pub const REQUIRED_OPERATIONS: [HalOperation; 10] = [
    HalOperation::QueryCapabilities,
    HalOperation::AcquireExclusive,
    HalOperation::PrepareFormat,
    HalOperation::SubmitBlock,
    HalOperation::QueryPosition,
    HalOperation::Start,
    HalOperation::SetGain,
    HalOperation::Drain,
    HalOperation::AbortMute,
    HalOperation::Release,
];

/// How the driver is reached. The bead requires these to be distinguished, not assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Ioctl,
    Write,
    Read,
    Poll,
    Mmap,
}

/// One retained-driver interface and the HAL operation it backs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceContract {
    /// Unique in the matrix.
    pub id: String,
    /// The operation this interface implements, if it is one the HAL needs.
    pub operation: Option<HalOperation>,
    /// The device node, if known. `None` means not yet mapped.
    pub device: Option<String>,
    pub interface: FieldStatus<InterfaceKind>,
    /// The `ioctl` command number (the low byte of the command word).
    pub selector: FieldStatus<u32>,
    /// The complete command word, including type, size and direction.
    pub full_command: FieldStatus<u32>,
    pub direction: FieldStatus<IoctlDirection>,
    pub payload_size: FieldStatus<u16>,
    pub endianness: FieldStatus<Endianness>,
    pub alignment: FieldStatus<u8>,
    pub field_map: FieldStatus<Vec<FieldSpec>>,
}

/// A radio or Wi-Fi duty whose owner must not be assumed to survive daemon replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadioDutyKind {
    MulticastDelivery,
    UnicastDelivery,
    PowerSave,
    Roam,
    Congestion,
    MeshMembership,
    SchedulerInterference,
}

impl RadioDutyKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MulticastDelivery => "multicast_delivery",
            Self::UnicastDelivery => "unicast_delivery",
            Self::PowerSave => "power_save",
            Self::Roam => "roam",
            Self::Congestion => "congestion",
            Self::MeshMembership => "mesh_membership",
            Self::SchedulerInterference => "scheduler_interference",
        }
    }
}

/// Every radio duty a hardware-eligible matrix must cover.
pub const REQUIRED_RADIO_DUTIES: [RadioDutyKind; 7] = [
    RadioDutyKind::MulticastDelivery,
    RadioDutyKind::UnicastDelivery,
    RadioDutyKind::PowerSave,
    RadioDutyKind::Roam,
    RadioDutyKind::Congestion,
    RadioDutyKind::MeshMembership,
    RadioDutyKind::SchedulerInterference,
];

/// Who performs a duty in the stock system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyOwner {
    KernelDriver,
    /// The stock userspace daemon. A replacement firmware does not inherit this.
    Daemon,
    ChipFirmware,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadioDuty {
    /// Unique in the matrix.
    pub id: String,
    pub duty: RadioDutyKind,
    pub owner: FieldStatus<DutyOwner>,
    pub survives_daemon_replacement: FieldStatus<bool>,
    /// Worst-case added audio scheduling delay this duty can cause, in microseconds.
    pub audio_interference_bound_us: FieldStatus<u32>,
}

/// The sample encodings an audio path may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleEncoding {
    Signed16,
    Signed24,
    Signed32,
}

impl SampleEncoding {
    /// Bytes one sample occupies.
    #[must_use]
    pub const fn bytes(self) -> u8 {
        match self {
            Self::Signed16 => 2,
            Self::Signed24 => 3,
            Self::Signed32 => 4,
        }
    }
}

/// One driver channel and the transducer role it feeds. Roles use the board-profile vocabulary, as
/// [`transducer_role_name`] spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRoute {
    pub index: u8,
    pub role: String,
}

/// Lowest and highest sample rate a topology may list, in hertz.
pub const MIN_RATE_HZ: u32 = 8_000;
pub const MAX_RATE_HZ: u32 = 384_000;

/// The audio path's channel map and rates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyContract {
    /// Unique in the matrix.
    pub id: String,
    pub channel_count: FieldStatus<u8>,
    /// Which transducer each driver channel feeds.
    pub routing: FieldStatus<Vec<ChannelRoute>>,
    /// Supported sample rates, strictly increasing.
    pub sample_rates_hz: FieldStatus<Vec<u32>>,
    pub sample_encoding: FieldStatus<SampleEncoding>,
}

/// One thing a startup, stop or fault sequence does to the amplifier path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmpAction {
    AssertMute,
    EnableClocks,
    ConfigureCodec,
    PrimeSilence,
    DeassertMute,
    DisableClocks,
}

impl AmpAction {
    /// Where this action sits in a startup, or `None` for an action a startup may not contain.
    #[must_use]
    pub const fn startup_rank(self) -> Option<usize> {
        match self {
            Self::AssertMute => Some(0),
            Self::EnableClocks => Some(1),
            Self::ConfigureCodec => Some(2),
            Self::PrimeSilence => Some(3),
            Self::DeassertMute => Some(4),
            Self::DisableClocks => None,
        }
    }
}

/// One step: the action, and the least time that must pass after the previous step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmpStep {
    pub action: AmpAction,
    pub min_delay_us: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmpSequenceKind {
    Startup,
    Shutdown,
    Fault,
}

impl AmpSequenceKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Shutdown => "shutdown",
            Self::Fault => "fault",
        }
    }
}

/// Every sequence a hardware-eligible matrix must cover.
pub const REQUIRED_AMP_SEQUENCES: [AmpSequenceKind; 3] = [
    AmpSequenceKind::Startup,
    AmpSequenceKind::Shutdown,
    AmpSequenceKind::Fault,
];

/// What the amplifier path does on a startup, a stop or a fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmpSequence {
    /// Unique in the matrix.
    pub id: String,
    pub kind: AmpSequenceKind,
    pub steps: FieldStatus<Vec<AmpStep>>,
    /// Whether the sequence waits for the driver to acknowledge the mute. It must: a mute that was
    /// only requested is not a mute.
    pub mute_acknowledgment_required: FieldStatus<bool>,
}

/// The board-profile spelling of a transducer role, for comparing a topology with a profile.
#[must_use]
pub fn transducer_role_name(role: TransducerRole) -> String {
    match role {
        TransducerRole::TweeterLeft => "tweeter_left".to_string(),
        TransducerRole::TweeterRight => "tweeter_right".to_string(),
        TransducerRole::MidLeft => "mid_left".to_string(),
        TransducerRole::MidRight => "mid_right".to_string(),
        TransducerRole::WooferCenter => "woofer_center".to_string(),
        TransducerRole::WooferMono => "woofer_mono".to_string(),
        TransducerRole::TweeterMono => "tweeter_mono".to_string(),
        TransducerRole::SubwooferLfe => "subwoofer_lfe".to_string(),
        TransducerRole::ArrayMidWoofer(n) => format!("array_mid_woofer_{n}"),
        TransducerRole::ArrayTweeter(n) => format!("array_tweeter_{n}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSection {
    pub name: String,
    pub size: u32,
}

/// An evidence artifact, registered by digest so anchors can be checked against it.
///
/// `size_bytes` is descriptive metadata. It is never an input to eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub sha256: String,
    pub size_bytes: u64,
    pub description: String,
    pub sections: Vec<ArtifactSection>,
}

/// The contract matrix for one driver build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractMatrix {
    pub schema: String,
    pub artifacts: Vec<ArtifactRef>,
    pub interfaces: Vec<InterfaceContract>,
    pub radio: Vec<RadioDuty>,
    /// The channel map and rates. A matrix without one is not hardware-eligible.
    #[serde(default)]
    pub topology: Vec<TopologyContract>,
    /// The startup, stop and fault sequences. All three are required.
    #[serde(default)]
    pub amp_sequences: Vec<AmpSequence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractScope {
    AudioOutput,
    RadioCoexistence,
    Topology,
    AmpSequencing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractField {
    /// The record as a whole (missing record, duplicate id, wrong schema).
    Record,
    Interface,
    Selector,
    FullCommand,
    Direction,
    PayloadSize,
    Endianness,
    Alignment,
    FieldMap,
    Owner,
    SurvivesDaemonReplacement,
    AudioInterferenceBound,
    ChannelCount,
    Routing,
    SampleRates,
    SampleEncoding,
    Steps,
    MuteAcknowledgment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MissingReason {
    /// No record exists for a required operation or duty.
    NoRecord,
    /// The field is unknown. The blocker names what would establish it.
    Unknown { blocker: ExternalBlocker },
    /// The field is known only through a synthetic fixture. Blocks hardware, not the offline model.
    SyntheticAnchor { label: String },
    /// An artifact anchor names a digest nothing registered.
    UnregisteredArtifact { sha256: String },
    /// An anchor is malformed or points outside its artifact.
    BadAnchor { detail: String },
    /// The record contradicts itself or the matrix is malformed.
    Inconsistent { detail: String },
}

/// One exact piece of missing contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingContract {
    pub scope: ContractScope,
    /// A record id, or `operation:<name>` / `radio:<name>` when no record exists.
    pub record: String,
    pub field: ContractField,
    pub reason: MissingReason,
}

impl fmt::Display for MissingContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}/{} {:?}: ", self.scope, self.record, self.field)?;
        match &self.reason {
            MissingReason::NoRecord => write!(f, "no record"),
            MissingReason::Unknown { blocker } => {
                write!(f, "unknown, blocked by {} ({})", blocker.id, blocker.needs)
            }
            MissingReason::SyntheticAnchor { label } => write!(f, "synthetic anchor {label}"),
            MissingReason::UnregisteredArtifact { sha256 } => {
                write!(f, "artifact {sha256} is not registered")
            }
            MissingReason::BadAnchor { detail } => write!(f, "bad anchor: {detail}"),
            MissingReason::Inconsistent { detail } => write!(f, "inconsistent: {detail}"),
        }
    }
}

/// The verdict on a matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityReport {
    pub schema: String,
    /// Everything is resolved, though possibly only through synthetic fixtures.
    pub offline_model_ok: bool,
    /// Everything is resolved and anchored on real artifacts or public sources.
    pub hardware_eligible: bool,
    /// Every missing item, in a fixed order: structure, then required operations without a record,
    /// then interface records in matrix order, then required duties without a record, then radio
    /// records in matrix order.
    pub missing: Vec<MissingContract>,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl InterfaceContract {
    /// Contradictions inside one record, as (field, explanation).
    fn consistency_problems(&self) -> Vec<(ContractField, String)> {
        let mut problems = Vec::new();
        let kind = self.interface.value().copied();
        let is_ioctl = kind == Some(InterfaceKind::Ioctl);
        if kind.is_some() && !is_ioctl {
            if !self.selector.is_not_applicable() {
                problems.push((
                    ContractField::Selector,
                    "a non-ioctl interface must mark the selector not applicable".to_string(),
                ));
            }
            if !self.full_command.is_not_applicable() {
                problems.push((
                    ContractField::FullCommand,
                    "a non-ioctl interface must mark the full command not applicable".to_string(),
                ));
            }
        }
        if is_ioctl && self.selector.is_not_applicable() {
            problems.push((
                ContractField::Selector,
                "an ioctl interface cannot mark the selector not applicable".to_string(),
            ));
        }
        if is_ioctl && self.full_command.is_not_applicable() {
            problems.push((
                ContractField::FullCommand,
                "an ioctl interface cannot mark the full command not applicable".to_string(),
            ));
        }
        if let Some(&nr) = self.selector.value()
            && nr > 0xff
        {
            problems.push((
                ContractField::Selector,
                format!("selector {nr:#x} exceeds the 8-bit command number"),
            ));
        }
        if let Some(&cmd) = self.full_command.value() {
            let parts = decode_ppc_ioctl(cmd);
            if let Some(&nr) = self.selector.value()
                && u32::from(parts.nr) != nr
            {
                problems.push((
                    ContractField::FullCommand,
                    format!(
                        "command {cmd:#010x} carries number {:#x} but the selector is {nr:#x}",
                        parts.nr
                    ),
                ));
            }
            match IoctlDirection::from_dir_bits(parts.dir_bits) {
                None => problems.push((
                    ContractField::FullCommand,
                    format!("command {cmd:#010x} encodes no valid direction"),
                )),
                Some(encoded) => {
                    if let Some(&declared) = self.direction.value()
                        && declared != encoded
                    {
                        problems.push((
                            ContractField::Direction,
                            format!(
                                "command {cmd:#010x} encodes {encoded:?} but the record says {declared:?}"
                            ),
                        ));
                    }
                }
            }
            if let Some(&size) = self.payload_size.value()
                && size != parts.size
            {
                problems.push((
                    ContractField::PayloadSize,
                    format!(
                        "command {cmd:#010x} encodes {} byte(s) but the record says {size}",
                        parts.size
                    ),
                ));
            }
        }
        if is_ioctl
            && let Some(&size) = self.payload_size.value()
            && size > IOC_SIZE_MAX
        {
            problems.push((
                ContractField::PayloadSize,
                format!("{size} bytes exceed the 13-bit ioctl size field"),
            ));
        }
        if let (Some(&IoctlDirection::NoData), Some(&size)) =
            (self.direction.value(), self.payload_size.value())
            && size != 0
        {
            problems.push((
                ContractField::PayloadSize,
                format!("a no-data command cannot carry {size} byte(s)"),
            ));
        }
        if let Some(&alignment) = self.alignment.value()
            && !matches!(alignment, 1 | 2 | 4 | 8)
        {
            problems.push((
                ContractField::Alignment,
                format!("alignment {alignment} is not 1, 2, 4 or 8"),
            ));
        }
        if let Some(fields) = self.field_map.value() {
            let size = match &self.payload_size {
                FieldStatus::Known { value, .. } => Some(*value),
                FieldStatus::NotApplicable { .. } => Some(0),
                FieldStatus::Unknown { .. } => None,
            };
            if let (Some(size), Some(&alignment)) = (size, self.alignment.value())
                && matches!(alignment, 1 | 2 | 4 | 8)
                && let Err(e) = validate_field_map(fields, size, alignment)
            {
                problems.push((ContractField::FieldMap, e.to_string()));
            }
        }
        problems
    }
}

impl TopologyContract {
    /// Contradictions inside one record, as (field, explanation), in a fixed order.
    fn consistency_problems(&self) -> Vec<(ContractField, String)> {
        let mut problems = Vec::new();
        let count = self.channel_count.value().copied();
        if count == Some(0) {
            problems.push((
                ContractField::ChannelCount,
                "a driver with no channel".to_string(),
            ));
        }
        if let Some(routing) = self.routing.value() {
            if let Some(n) = count
                && routing.len() != usize::from(n)
            {
                problems.push((
                    ContractField::Routing,
                    format!(
                        "{} route(s) for {n} channel(s): the route count differs from the channel count",
                        routing.len()
                    ),
                ));
            }
            let mut indices: Vec<usize> = routing.iter().map(|r| usize::from(r.index)).collect();
            indices.sort_unstable();
            if indices != (0..routing.len()).collect::<Vec<usize>>() {
                problems.push((
                    ContractField::Routing,
                    "the channel indices are not 0..n-1, once each".to_string(),
                ));
            }
            if routing.iter().any(|r| r.role.trim().is_empty()) {
                problems.push((
                    ContractField::Routing,
                    "a channel feeds no named role".to_string(),
                ));
            }
        }
        if let Some(rates) = self.sample_rates_hz.value() {
            if rates.is_empty() {
                problems.push((ContractField::SampleRates, "no sample rate".to_string()));
            } else if rates
                .iter()
                .any(|r| !(MIN_RATE_HZ..=MAX_RATE_HZ).contains(r))
            {
                problems.push((
                    ContractField::SampleRates,
                    format!("a rate is outside {MIN_RATE_HZ} Hz to {MAX_RATE_HZ} Hz"),
                ));
            } else if rates.windows(2).any(|w| w[1] <= w[0]) {
                problems.push((
                    ContractField::SampleRates,
                    "the rates are not strictly increasing".to_string(),
                ));
            }
        }
        problems
    }
}

impl AmpSequence {
    /// Contradictions inside one sequence: mute first, unmute only at the end of a startup, no
    /// unmute on a stop or a fault, no repeated action, and a mute that is acknowledged.
    fn consistency_problems(&self) -> Vec<(ContractField, String)> {
        let mut problems = Vec::new();
        if let Some(steps) = self.steps.value() {
            let actions: Vec<AmpAction> = steps.iter().map(|s| s.action).collect();
            match actions.first() {
                None => {
                    problems.push((ContractField::Steps, "a sequence with no step".to_string()))
                }
                Some(first) => {
                    if *first != AmpAction::AssertMute {
                        problems.push((
                            ContractField::Steps,
                            "mute must be asserted first".to_string(),
                        ));
                    }
                    let distinct: BTreeSet<AmpAction> = actions.iter().copied().collect();
                    if distinct.len() != actions.len() {
                        problems.push((ContractField::Steps, "an action is repeated".to_string()));
                    }
                    if self.kind == AmpSequenceKind::Startup {
                        if actions.last() != Some(&AmpAction::DeassertMute) {
                            problems.push((
                                ContractField::Steps,
                                "a startup must end by deasserting mute".to_string(),
                            ));
                        }
                        if actions.contains(&AmpAction::DisableClocks) {
                            problems.push((
                                ContractField::Steps,
                                "a startup cannot disable the clocks".to_string(),
                            ));
                        }
                        let ranks: Vec<usize> =
                            actions.iter().filter_map(|a| a.startup_rank()).collect();
                        let mut sorted = ranks.clone();
                        sorted.sort_unstable();
                        if ranks != sorted {
                            problems.push((
                                ContractField::Steps,
                                "the startup steps are out of order".to_string(),
                            ));
                        }
                    } else {
                        if actions.contains(&AmpAction::DeassertMute) {
                            problems
                                .push((ContractField::Steps, "only a startup unmutes".to_string()));
                        }
                        if actions
                            .iter()
                            .any(|a| !matches!(a, AmpAction::AssertMute | AmpAction::DisableClocks))
                        {
                            problems.push((
                                ContractField::Steps,
                                "a stop sequence may only mute and cut the clocks".to_string(),
                            ));
                        }
                    }
                }
            }
        }
        if self.mute_acknowledgment_required.value() == Some(&false) {
            problems.push((
                ContractField::MuteAcknowledgment,
                "mute-requested is not mute-acknowledged".to_string(),
            ));
        }
        problems
    }
}

impl ContractMatrix {
    /// Judge the matrix. Pure and deterministic; reads no artifact and no clock.
    #[must_use]
    pub fn evaluate(&self) -> EligibilityReport {
        let mut missing = Vec::new();
        self.check_structure(&mut missing);
        for op in REQUIRED_OPERATIONS {
            if !self.interfaces.iter().any(|r| r.operation == Some(op)) {
                missing.push(MissingContract {
                    scope: ContractScope::AudioOutput,
                    record: format!("operation:{}", op.name()),
                    field: ContractField::Record,
                    reason: MissingReason::NoRecord,
                });
            }
        }
        for record in &self.interfaces {
            self.check_interface(record, &mut missing);
        }
        for duty in REQUIRED_RADIO_DUTIES {
            if !self.radio.iter().any(|r| r.duty == duty) {
                missing.push(MissingContract {
                    scope: ContractScope::RadioCoexistence,
                    record: format!("radio:{}", duty.name()),
                    field: ContractField::Record,
                    reason: MissingReason::NoRecord,
                });
            }
        }
        for record in &self.radio {
            self.check_radio(record, &mut missing);
        }
        if self.topology.is_empty() {
            missing.push(MissingContract {
                scope: ContractScope::Topology,
                record: "topology:audio_output".to_string(),
                field: ContractField::Record,
                reason: MissingReason::NoRecord,
            });
        }
        for record in &self.topology {
            self.check_topology(record, &mut missing);
        }
        for kind in REQUIRED_AMP_SEQUENCES {
            if !self.amp_sequences.iter().any(|r| r.kind == kind) {
                missing.push(MissingContract {
                    scope: ContractScope::AmpSequencing,
                    record: format!("amp_sequence:{}", kind.name()),
                    field: ContractField::Record,
                    reason: MissingReason::NoRecord,
                });
            }
        }
        for record in &self.amp_sequences {
            self.check_sequence(record, &mut missing);
        }
        let offline_model_ok = missing
            .iter()
            .all(|m| matches!(m.reason, MissingReason::SyntheticAnchor { .. }));
        EligibilityReport {
            schema: CONTRACT_SCHEMA.to_string(),
            offline_model_ok,
            hardware_eligible: missing.is_empty(),
            missing,
        }
    }

    fn check_structure(&self, out: &mut Vec<MissingContract>) {
        let mut inconsistent = |record: &str, detail: String| {
            out.push(MissingContract {
                scope: ContractScope::AudioOutput,
                record: record.to_string(),
                field: ContractField::Record,
                reason: MissingReason::Inconsistent { detail },
            });
        };
        if self.schema != CONTRACT_SCHEMA {
            inconsistent(
                "matrix",
                format!("schema is {:?}, expected {CONTRACT_SCHEMA:?}", self.schema),
            );
        }
        let mut digests = BTreeSet::new();
        for artifact in &self.artifacts {
            if !is_sha256_hex(&artifact.sha256) {
                inconsistent(
                    "matrix",
                    format!(
                        "registered artifact digest {:?} is not 64 lowercase hex characters",
                        artifact.sha256
                    ),
                );
            }
            if !digests.insert(artifact.sha256.as_str()) {
                inconsistent(
                    "matrix",
                    format!("artifact {} is registered twice", artifact.sha256),
                );
            }
        }
        let mut ids = BTreeSet::new();
        let all_ids = self
            .interfaces
            .iter()
            .map(|r| r.id.as_str())
            .chain(self.radio.iter().map(|r| r.id.as_str()))
            .chain(self.topology.iter().map(|r| r.id.as_str()))
            .chain(self.amp_sequences.iter().map(|r| r.id.as_str()));
        for id in all_ids {
            if id.trim().is_empty() {
                inconsistent("matrix", "a record has an empty id".to_string());
            } else if !ids.insert(id) {
                inconsistent(id, "record id is used twice".to_string());
            }
        }
    }

    fn anchor_problem(&self, anchor: &Anchor) -> Option<MissingReason> {
        match anchor {
            Anchor::SyntheticFixture { label } => {
                if label.trim().is_empty() {
                    Some(MissingReason::BadAnchor {
                        detail: "a synthetic anchor has no label".to_string(),
                    })
                } else {
                    Some(MissingReason::SyntheticAnchor {
                        label: label.clone(),
                    })
                }
            }
            Anchor::Source { reference } => {
                if reference.trim().is_empty() {
                    Some(MissingReason::BadAnchor {
                        detail: "a source anchor has no reference".to_string(),
                    })
                } else {
                    None
                }
            }
            Anchor::Artifact {
                sha256,
                section,
                offset,
                symbol,
            } => {
                if !is_sha256_hex(sha256) {
                    return Some(MissingReason::BadAnchor {
                        detail: "artifact digest is not 64 lowercase hex characters".to_string(),
                    });
                }
                let Some(artifact) = self.artifacts.iter().find(|a| a.sha256 == *sha256) else {
                    return Some(MissingReason::UnregisteredArtifact {
                        sha256: sha256.clone(),
                    });
                };
                let Some(found) = artifact.sections.iter().find(|s| s.name == *section) else {
                    return Some(MissingReason::BadAnchor {
                        detail: format!("section {section} is not registered for the artifact"),
                    });
                };
                if *offset >= found.size {
                    return Some(MissingReason::BadAnchor {
                        detail: format!(
                            "offset {offset:#x} is outside section {section} ({:#x} byte(s))",
                            found.size
                        ),
                    });
                }
                if let Some(name) = symbol
                    && name.trim().is_empty()
                {
                    return Some(MissingReason::BadAnchor {
                        detail: "the artifact anchor has an empty symbol name".to_string(),
                    });
                }
                None
            }
        }
    }

    fn check_field<T>(
        &self,
        scope: ContractScope,
        record: &str,
        field: ContractField,
        status: &FieldStatus<T>,
        out: &mut Vec<MissingContract>,
    ) {
        let reason = match status {
            FieldStatus::Known { anchor, .. } => self.anchor_problem(anchor),
            FieldStatus::Unknown { blocker } => {
                if blocker.id.trim().is_empty() || blocker.needs.trim().is_empty() {
                    Some(MissingReason::Inconsistent {
                        detail: "an unknown field has no named external blocker".to_string(),
                    })
                } else {
                    Some(MissingReason::Unknown {
                        blocker: blocker.clone(),
                    })
                }
            }
            FieldStatus::NotApplicable { reason } => {
                if reason.trim().is_empty() {
                    Some(MissingReason::Inconsistent {
                        detail: "a not-applicable field gives no reason".to_string(),
                    })
                } else {
                    None
                }
            }
        };
        if let Some(reason) = reason {
            out.push(MissingContract {
                scope,
                record: record.to_string(),
                field,
                reason,
            });
        }
    }

    fn check_interface(&self, r: &InterfaceContract, out: &mut Vec<MissingContract>) {
        let scope = ContractScope::AudioOutput;
        let id = r.id.as_str();
        self.check_field(scope, id, ContractField::Interface, &r.interface, out);
        self.check_field(scope, id, ContractField::Selector, &r.selector, out);
        self.check_field(scope, id, ContractField::FullCommand, &r.full_command, out);
        self.check_field(scope, id, ContractField::Direction, &r.direction, out);
        self.check_field(scope, id, ContractField::PayloadSize, &r.payload_size, out);
        self.check_field(scope, id, ContractField::Endianness, &r.endianness, out);
        self.check_field(scope, id, ContractField::Alignment, &r.alignment, out);
        self.check_field(scope, id, ContractField::FieldMap, &r.field_map, out);
        for (field, detail) in r.consistency_problems() {
            out.push(MissingContract {
                scope,
                record: id.to_string(),
                field,
                reason: MissingReason::Inconsistent { detail },
            });
        }
    }

    fn check_topology(&self, r: &TopologyContract, out: &mut Vec<MissingContract>) {
        let scope = ContractScope::Topology;
        let id = r.id.as_str();
        self.check_field(
            scope,
            id,
            ContractField::ChannelCount,
            &r.channel_count,
            out,
        );
        self.check_field(scope, id, ContractField::Routing, &r.routing, out);
        self.check_field(
            scope,
            id,
            ContractField::SampleRates,
            &r.sample_rates_hz,
            out,
        );
        self.check_field(
            scope,
            id,
            ContractField::SampleEncoding,
            &r.sample_encoding,
            out,
        );
        for (field, detail) in r.consistency_problems() {
            out.push(MissingContract {
                scope,
                record: id.to_string(),
                field,
                reason: MissingReason::Inconsistent { detail },
            });
        }
    }

    fn check_sequence(&self, r: &AmpSequence, out: &mut Vec<MissingContract>) {
        let scope = ContractScope::AmpSequencing;
        let id = r.id.as_str();
        self.check_field(scope, id, ContractField::Steps, &r.steps, out);
        self.check_field(
            scope,
            id,
            ContractField::MuteAcknowledgment,
            &r.mute_acknowledgment_required,
            out,
        );
        for (field, detail) in r.consistency_problems() {
            out.push(MissingContract {
                scope,
                record: id.to_string(),
                field,
                reason: MissingReason::Inconsistent { detail },
            });
        }
    }

    /// [`evaluate`](Self::evaluate), and then the topology checked against the board profile it is
    /// to run on: a driver that feeds a different number of channels, or a different transducer on a
    /// channel, than the profile says is a contradiction, not an approximation. A topology that is
    /// still unknown contributes nothing here; it is already in the verdict as unknown.
    #[must_use]
    pub fn evaluate_for_profile(&self, profile: &BoardProfile) -> EligibilityReport {
        let mut report = self.evaluate();
        for record in &self.topology {
            let mut disagree = |field: ContractField, detail: String| {
                report.missing.push(MissingContract {
                    scope: ContractScope::Topology,
                    record: record.id.clone(),
                    field,
                    reason: MissingReason::Inconsistent { detail },
                });
            };
            if let Some(&count) = record.channel_count.value()
                && count != profile.hardware_channels
            {
                disagree(
                    ContractField::ChannelCount,
                    format!(
                        "the driver feeds {count} channel(s) but the profile has {}",
                        profile.hardware_channels
                    ),
                );
            }
            if let Some(routes) = record.routing.value() {
                if routes.len() == profile.channel_routing.len() {
                    for route in routes {
                        let wanted = profile
                            .channel_routing
                            .get(usize::from(route.index))
                            .map(|role| transducer_role_name(*role));
                        if wanted.as_deref() != Some(route.role.as_str()) {
                            disagree(
                                ContractField::Routing,
                                format!(
                                    "channel {} feeds {:?} but the profile says {:?}",
                                    route.index,
                                    route.role,
                                    wanted.unwrap_or_default()
                                ),
                            );
                        }
                    }
                } else {
                    disagree(
                        ContractField::Routing,
                        format!(
                            "the driver routes {} channel(s) but the profile routes {}",
                            routes.len(),
                            profile.channel_routing.len()
                        ),
                    );
                }
            }
        }
        report.hardware_eligible = report.missing.is_empty();
        report.offline_model_ok = report
            .missing
            .iter()
            .all(|m| matches!(m.reason, MissingReason::SyntheticAnchor { .. }));
        report
    }

    fn check_radio(&self, r: &RadioDuty, out: &mut Vec<MissingContract>) {
        let scope = ContractScope::RadioCoexistence;
        let id = r.id.as_str();
        self.check_field(scope, id, ContractField::Owner, &r.owner, out);
        self.check_field(
            scope,
            id,
            ContractField::SurvivesDaemonReplacement,
            &r.survives_daemon_replacement,
            out,
        );
        self.check_field(
            scope,
            id,
            ContractField::AudioInterferenceBound,
            &r.audio_interference_bound_us,
            out,
        );
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Test doubles. Nothing here is evidence about a real driver.
    use super::*;

    pub(crate) const FIXTURE_SHA: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    pub(crate) fn artifact() -> ArtifactRef {
        ArtifactRef {
            sha256: FIXTURE_SHA.to_string(),
            size_bytes: 4096,
            description: "unit-test double, not a real driver".to_string(),
            sections: vec![
                ArtifactSection {
                    name: ".text".to_string(),
                    size: 0x1000,
                },
                ArtifactSection {
                    name: ".rodata".to_string(),
                    size: 0x400,
                },
            ],
        }
    }

    pub(crate) fn anchor_artifact() -> Anchor {
        Anchor::Artifact {
            sha256: FIXTURE_SHA.to_string(),
            section: ".text".to_string(),
            offset: 0x10,
            symbol: Some("fixture_symbol".to_string()),
        }
    }

    pub(crate) fn anchor_synthetic() -> Anchor {
        Anchor::SyntheticFixture {
            label: "unit-test".to_string(),
        }
    }

    /// A matrix in which every required operation, duty, topology and sequence has a fully known
    /// record: 10 interface records with 8 fields each, 7 radio records with 3 fields each, one
    /// topology with 4 and three sequences with 2 each, 111 fields. The topology is the two-channel
    /// woofer and tweeter of the labelled `S1` fixture profile.
    pub(crate) fn complete_matrix(anchor: fn() -> Anchor) -> ContractMatrix {
        complete_matrix_for(anchor, &["woofer_mono", "tweeter_mono"])
    }

    /// [`complete_matrix`] whose topology routes the given roles, one per channel in order.
    pub(crate) fn complete_matrix_for(anchor: fn() -> Anchor, roles: &[&str]) -> ContractMatrix {
        let mut interfaces = Vec::new();
        for (i, op) in REQUIRED_OPERATIONS.iter().enumerate() {
            let nr = u8::try_from(i + 1).unwrap();
            let cmd = encode_ppc_ioctl(IOC_DIR_WRITE, 0x7e, nr, 8).unwrap();
            interfaces.push(InterfaceContract {
                id: format!("fixture.{}", op.name()),
                operation: Some(*op),
                device: Some("fixture-dsp".to_string()),
                interface: FieldStatus::known(InterfaceKind::Ioctl, anchor()),
                selector: FieldStatus::known(u32::from(nr), anchor()),
                full_command: FieldStatus::known(cmd, anchor()),
                direction: FieldStatus::known(IoctlDirection::Write, anchor()),
                payload_size: FieldStatus::known(8, anchor()),
                endianness: FieldStatus::known(Endianness::Big, anchor()),
                alignment: FieldStatus::known(4, anchor()),
                field_map: FieldStatus::known(
                    vec![
                        FieldSpec {
                            name: "a".to_string(),
                            offset: 0,
                            width: 4,
                            kind: FieldKind::Unsigned,
                        },
                        FieldSpec {
                            name: "b".to_string(),
                            offset: 4,
                            width: 4,
                            kind: FieldKind::Unsigned,
                        },
                    ],
                    anchor(),
                ),
            });
        }
        let radio = REQUIRED_RADIO_DUTIES
            .iter()
            .map(|duty| RadioDuty {
                id: format!("fixture.radio.{}", duty.name()),
                duty: *duty,
                owner: FieldStatus::known(DutyOwner::KernelDriver, anchor()),
                survives_daemon_replacement: FieldStatus::known(true, anchor()),
                audio_interference_bound_us: FieldStatus::known(250, anchor()),
            })
            .collect();
        let routes = roles
            .iter()
            .enumerate()
            .map(|(i, role)| ChannelRoute {
                index: u8::try_from(i).unwrap(),
                role: (*role).to_string(),
            })
            .collect();
        let topology = vec![TopologyContract {
            id: "fixture.topology".to_string(),
            channel_count: FieldStatus::known(u8::try_from(roles.len()).unwrap(), anchor()),
            routing: FieldStatus::known(routes, anchor()),
            sample_rates_hz: FieldStatus::known(vec![44_100, 48_000], anchor()),
            sample_encoding: FieldStatus::known(SampleEncoding::Signed16, anchor()),
        }];
        let sequence = |kind: AmpSequenceKind, actions: &[AmpAction]| AmpSequence {
            id: format!("fixture.amp.{}", kind.name()),
            kind,
            steps: FieldStatus::known(
                actions
                    .iter()
                    .map(|&action| AmpStep {
                        action,
                        min_delay_us: 0,
                    })
                    .collect(),
                anchor(),
            ),
            mute_acknowledgment_required: FieldStatus::known(true, anchor()),
        };
        let amp_sequences = vec![
            sequence(
                AmpSequenceKind::Startup,
                &[
                    AmpAction::AssertMute,
                    AmpAction::EnableClocks,
                    AmpAction::ConfigureCodec,
                    AmpAction::PrimeSilence,
                    AmpAction::DeassertMute,
                ],
            ),
            sequence(
                AmpSequenceKind::Shutdown,
                &[AmpAction::AssertMute, AmpAction::DisableClocks],
            ),
            sequence(AmpSequenceKind::Fault, &[AmpAction::AssertMute]),
        ];
        ContractMatrix {
            schema: CONTRACT_SCHEMA.to_string(),
            artifacts: vec![artifact()],
            interfaces,
            radio,
            topology,
            amp_sequences,
        }
    }

    pub(crate) fn sequence_mut(
        matrix: &mut ContractMatrix,
        kind: AmpSequenceKind,
    ) -> &mut AmpSequence {
        matrix
            .amp_sequences
            .iter_mut()
            .find(|r| r.kind == kind)
            .unwrap()
    }

    pub(crate) fn interface_mut(
        matrix: &mut ContractMatrix,
        op: HalOperation,
    ) -> &mut InterfaceContract {
        matrix
            .interfaces
            .iter_mut()
            .find(|r| r.operation == Some(op))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    /// The committed matrix for the model-16 `audiodev.o`. Every field is still unknown.
    const REAL_MATRIX_JSON: &str = include_str!("../../../tests/e04/matrix_audiodev_m16.json");

    fn blocker(id: &str, needs: &str) -> ExternalBlocker {
        ExternalBlocker {
            id: id.to_string(),
            needs: needs.to_string(),
        }
    }

    #[test]
    fn ppc_ioctl_layout_golden_vectors() {
        // Hand-computed: dir 4 (write) in bits 29..31, size 4 in bits 16..28, type 0x12, nr 0x34.
        let parts = decode_ppc_ioctl(0x8004_1234);
        assert_eq!(
            parts,
            IoctlParts {
                nr: 0x34,
                type_byte: 0x12,
                size: 4,
                dir_bits: 4
            }
        );
        // The retained driver tests bit 31 as "write" and bit 30 as "read".
        assert_eq!(decode_ppc_ioctl(0x8000_0000).dir_bits, IOC_DIR_WRITE);
        assert_eq!(decode_ppc_ioctl(0x4000_0000).dir_bits, IOC_DIR_READ);
        assert_eq!(decode_ppc_ioctl(0x2000_0000).dir_bits, IOC_DIR_NONE);
        assert_eq!(
            decode_ppc_ioctl(0xffff_ffff),
            IoctlParts {
                nr: 0xff,
                type_byte: 0xff,
                size: 0x1fff,
                dir_bits: 7
            }
        );
        assert_eq!(decode_ppc_ioctl(0).size, 0);
        assert_eq!(encode_ppc_ioctl(4, 0x12, 0x34, 4), Ok(0x8004_1234));
        assert_eq!(encode_ppc_ioctl(2, 0x00, 0x0a, 16), Ok(0x4010_000a));
        assert_eq!(
            encode_ppc_ioctl(8, 0, 0, 0),
            Err(ContractError::IoctlFieldRange {
                field: "dir_bits",
                value: 8
            })
        );
        assert_eq!(
            encode_ppc_ioctl(4, 0, 0, 0x2000),
            Err(ContractError::IoctlFieldRange {
                field: "size",
                value: 0x2000
            })
        );
    }

    #[test]
    fn ppc_ioctl_round_trips_over_a_deterministic_sweep() {
        for dir in 0..=7u8 {
            for type_byte in [0u8, 1, 0x7e, 0xff] {
                for nr in [0u8, 1, 2, 41, 0xff] {
                    for size in [0u16, 1, 16, 0x0fff, 0x1fff] {
                        let cmd = encode_ppc_ioctl(dir, type_byte, nr, size).unwrap();
                        assert_eq!(
                            decode_ppc_ioctl(cmd),
                            IoctlParts {
                                nr,
                                type_byte,
                                size,
                                dir_bits: dir
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn direction_decoding_rejects_legacy_and_invalid_mixes() {
        assert_eq!(
            IoctlDirection::from_dir_bits(1),
            Some(IoctlDirection::NoData)
        );
        assert_eq!(IoctlDirection::from_dir_bits(2), Some(IoctlDirection::Read));
        assert_eq!(
            IoctlDirection::from_dir_bits(4),
            Some(IoctlDirection::Write)
        );
        assert_eq!(
            IoctlDirection::from_dir_bits(6),
            Some(IoctlDirection::ReadWrite)
        );
        for bad in [0u8, 3, 5, 7] {
            assert_eq!(IoctlDirection::from_dir_bits(bad), None, "{bad}");
        }
    }

    #[test]
    fn endian_and_alignment_golden_vectors() {
        let b = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(read_uint(&b, 0, 4, Endianness::Big), Ok(0x0102_0304));
        assert_eq!(read_uint(&b, 0, 4, Endianness::Little), Ok(0x0403_0201));
        assert_eq!(read_uint(&b, 4, 4, Endianness::Big), Ok(0x0506_0708));
        assert_eq!(read_uint(&b, 2, 2, Endianness::Big), Ok(0x0304));
        assert_eq!(read_uint(&b, 2, 2, Endianness::Little), Ok(0x0403));
        assert_eq!(read_uint(&b, 3, 1, Endianness::Big), Ok(0x04));
        assert_eq!(
            read_uint(&b, 0, 8, Endianness::Big),
            Ok(0x0102_0304_0506_0708)
        );
        assert_eq!(
            read_uint(&b, 0, 8, Endianness::Little),
            Ok(0x0807_0605_0403_0201)
        );
        // Alignment is checked before bounds.
        assert_eq!(
            read_uint(&b, 2, 4, Endianness::Big),
            Err(ContractError::Misaligned {
                offset: 2,
                align: 4
            })
        );
        assert_eq!(
            read_uint(&b, 4, 8, Endianness::Big),
            Err(ContractError::Misaligned {
                offset: 4,
                align: 8
            })
        );
        assert_eq!(
            read_uint(&b, 8, 1, Endianness::Big),
            Err(ContractError::OutOfBounds {
                offset: 8,
                width: 1,
                len: 8
            })
        );
        assert_eq!(
            read_uint(&b, 0, 3, Endianness::Big),
            Err(ContractError::BadWidth { width: 3 })
        );
        assert_eq!(
            read_uint(&b, usize::MAX - 3, 4, Endianness::Big),
            Err(ContractError::OutOfBounds {
                offset: usize::MAX - 3,
                width: 4,
                len: 8
            })
        );
    }

    #[test]
    fn write_uint_matches_the_golden_bytes_and_rejects_bad_input() {
        let mut buf = [0u8; 8];
        write_uint(&mut buf, 0, 4, Endianness::Big, 0xaabb_ccdd).unwrap();
        assert_eq!(buf, [0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0]);
        let mut buf = [0u8; 8];
        write_uint(&mut buf, 4, 4, Endianness::Little, 0xaabb_ccdd).unwrap();
        assert_eq!(buf, [0, 0, 0, 0, 0xdd, 0xcc, 0xbb, 0xaa]);
        let mut buf = [0u8; 8];
        assert_eq!(
            write_uint(&mut buf, 0, 1, Endianness::Big, 0x100),
            Err(ContractError::ValueTooWide {
                width: 1,
                value: 0x100
            })
        );
        assert_eq!(
            write_uint(&mut buf, 6, 4, Endianness::Big, 1),
            Err(ContractError::Misaligned {
                offset: 6,
                align: 4
            })
        );
        assert_eq!(buf, [0u8; 8], "a rejected write leaves the buffer alone");
        for endian in [Endianness::Big, Endianness::Little] {
            for width in [1usize, 2, 4, 8] {
                let value = if width == 8 {
                    u64::MAX - 1
                } else {
                    (1u64 << (8 * width)) - 2
                };
                let mut buf = [0u8; 8];
                write_uint(&mut buf, 0, width, endian, value).unwrap();
                assert_eq!(read_uint(&buf, 0, width, endian), Ok(value));
            }
        }
    }

    fn spec(name: &str, offset: u16, width: u8, kind: FieldKind) -> FieldSpec {
        FieldSpec {
            name: name.to_string(),
            offset,
            width,
            kind,
        }
    }

    fn problem(p: FieldMapProblem) -> Result<(), ContractError> {
        Err(ContractError::FieldMap(p))
    }

    #[test]
    fn field_maps_must_tile_the_payload_exactly() {
        let ok = [
            spec("rate", 0, 4, FieldKind::Unsigned),
            spec("gain", 4, 2, FieldKind::Signed),
            spec("reserved", 6, 2, FieldKind::Padding),
        ];
        assert_eq!(validate_field_map(&ok, 8, 4), Ok(()));
        assert_eq!(validate_field_map(&[], 0, 1), Ok(()));
        // Gap in the middle, at the end, and an uncovered payload.
        let gap = [
            spec("a", 0, 4, FieldKind::Unsigned),
            spec("b", 8, 4, FieldKind::Unsigned),
        ];
        assert_eq!(
            validate_field_map(&gap, 12, 4),
            problem(FieldMapProblem::Gap { offset: 4 })
        );
        assert_eq!(
            validate_field_map(&ok[..2], 8, 4),
            problem(FieldMapProblem::Gap { offset: 6 })
        );
        assert_eq!(
            validate_field_map(&[], 4, 4),
            problem(FieldMapProblem::Gap { offset: 0 })
        );
        // Overlap, out of bounds, misaligned, too wide for the record alignment, bad names.
        let overlap = [
            spec("a", 0, 4, FieldKind::Unsigned),
            spec("b", 2, 2, FieldKind::Unsigned),
        ];
        assert_eq!(
            validate_field_map(&overlap, 4, 4),
            problem(FieldMapProblem::Overlap {
                name: "b".to_string()
            })
        );
        assert_eq!(
            validate_field_map(&[spec("a", 0, 4, FieldKind::Unsigned)], 3, 4),
            problem(FieldMapProblem::OutOfBounds {
                name: "a".to_string()
            })
        );
        assert_eq!(
            validate_field_map(&[spec("a", 2, 4, FieldKind::Unsigned)], 8, 4),
            problem(FieldMapProblem::Misaligned {
                name: "a".to_string(),
                offset: 2,
                width: 4
            })
        );
        assert_eq!(
            validate_field_map(&[spec("a", 0, 4, FieldKind::Unsigned)], 4, 2),
            problem(FieldMapProblem::AlignmentTooSmall {
                name: "a".to_string(),
                width: 4,
                alignment: 2
            })
        );
        assert_eq!(
            validate_field_map(&[spec("a", 0, 3, FieldKind::Unsigned)], 3, 4),
            problem(FieldMapProblem::BadIntegerWidth {
                name: "a".to_string(),
                width: 3
            })
        );
        assert_eq!(
            validate_field_map(&[spec("a", 0, 0, FieldKind::Padding)], 0, 4),
            problem(FieldMapProblem::ZeroWidth("a".to_string()))
        );
        assert_eq!(
            validate_field_map(&[spec(" ", 0, 1, FieldKind::Unsigned)], 1, 1),
            problem(FieldMapProblem::EmptyName)
        );
        let dup = [
            spec("a", 0, 1, FieldKind::Unsigned),
            spec("a", 1, 1, FieldKind::Unsigned),
        ];
        assert_eq!(
            validate_field_map(&dup, 2, 1),
            problem(FieldMapProblem::DuplicateName("a".to_string()))
        );
        assert_eq!(
            validate_field_map(&ok, 8, 3),
            problem(FieldMapProblem::BadAlignment(3))
        );
        // Padding may sit at an odd offset and have an odd width.
        let odd = [
            spec("a", 0, 1, FieldKind::Unsigned),
            spec("pad", 1, 3, FieldKind::Padding),
        ];
        assert_eq!(validate_field_map(&odd, 4, 1), Ok(()));
    }

    #[test]
    fn payloads_decode_through_the_map_in_both_byte_orders() {
        let fields = [
            spec("rate", 0, 4, FieldKind::Unsigned),
            spec("gain", 4, 2, FieldKind::Signed),
            spec("reserved", 6, 2, FieldKind::Padding),
        ];
        // rate = 5 and gain = 0xfffe (-2) big-endian; padding is ignored.
        let be = [0, 0, 0, 5, 0xff, 0xfe, 0xaa, 0xbb];
        assert_eq!(
            decode_payload(&fields, 8, 4, &be, Endianness::Big),
            Ok(vec![
                DecodedField {
                    name: "rate".to_string(),
                    value: FieldValue::Unsigned(5)
                },
                DecodedField {
                    name: "gain".to_string(),
                    value: FieldValue::Signed(-2)
                },
            ])
        );
        // The same bytes read little-endian are a different, still well-formed, payload.
        assert_eq!(
            decode_payload(&fields, 8, 4, &be, Endianness::Little),
            Ok(vec![
                DecodedField {
                    name: "rate".to_string(),
                    value: FieldValue::Unsigned(0x0500_0000)
                },
                DecodedField {
                    name: "gain".to_string(),
                    value: FieldValue::Signed(-257)
                },
            ])
        );
        // A short or long payload is rejected, never truncated or padded.
        assert_eq!(
            decode_payload(&fields, 8, 4, &be[..7], Endianness::Big),
            Err(ContractError::LengthMismatch {
                expected: 8,
                actual: 7
            })
        );
        let mut long = be.to_vec();
        long.push(0);
        assert_eq!(
            decode_payload(&fields, 8, 4, &long, Endianness::Big),
            Err(ContractError::LengthMismatch {
                expected: 8,
                actual: 9
            })
        );
        // A broken map is rejected before any byte is read.
        assert_eq!(
            decode_payload(&fields[..2], 8, 4, &be, Endianness::Big),
            problem(FieldMapProblem::Gap { offset: 6 }).map(|()| Vec::new())
        );
    }

    #[test]
    fn a_fully_known_matrix_with_artifact_anchors_is_hardware_eligible() {
        // Unit test of the gate with a constructed matrix. No committed data claims eligibility.
        let report = complete_matrix(anchor_artifact).evaluate();
        assert!(report.missing.is_empty(), "{:?}", report.missing);
        assert!(report.hardware_eligible);
        assert!(report.offline_model_ok);
    }

    #[test]
    fn synthetic_anchors_satisfy_the_offline_model_but_never_hardware() {
        let report = complete_matrix(anchor_synthetic).evaluate();
        assert!(report.offline_model_ok);
        assert!(!report.hardware_eligible);
        // One entry per known field: 10 * 8 interface fields + 7 * 3 radio fields + 4 topology
        // fields + 3 * 2 sequence fields.
        assert_eq!(report.missing.len(), 111);
        assert!(report.missing.iter().all(|m| m.reason
            == MissingReason::SyntheticAnchor {
                label: "unit-test".to_string()
            }));
    }

    #[test]
    fn one_unknown_field_blocks_hardware_and_is_named_exactly() {
        let mut m = complete_matrix(anchor_artifact);
        interface_mut(&mut m, HalOperation::Start).payload_size =
            FieldStatus::unknown("EXT-TEST-SIZE", "decode the start handler");
        let report = m.evaluate();
        assert!(!report.hardware_eligible);
        assert!(!report.offline_model_ok);
        assert_eq!(
            report.missing,
            vec![MissingContract {
                scope: ContractScope::AudioOutput,
                record: "fixture.start".to_string(),
                field: ContractField::PayloadSize,
                reason: MissingReason::Unknown {
                    blocker: blocker("EXT-TEST-SIZE", "decode the start handler")
                },
            }]
        );
    }

    #[test]
    fn a_required_operation_or_duty_without_a_record_is_named() {
        let mut m = complete_matrix(anchor_artifact);
        m.interfaces
            .retain(|r| r.operation != Some(HalOperation::Drain));
        m.radio.retain(|r| r.duty != RadioDutyKind::Roam);
        let report = m.evaluate();
        assert_eq!(
            report.missing,
            vec![
                MissingContract {
                    scope: ContractScope::AudioOutput,
                    record: "operation:drain".to_string(),
                    field: ContractField::Record,
                    reason: MissingReason::NoRecord,
                },
                MissingContract {
                    scope: ContractScope::RadioCoexistence,
                    record: "radio:roam".to_string(),
                    field: ContractField::Record,
                    reason: MissingReason::NoRecord,
                },
            ]
        );
    }

    #[test]
    fn eligibility_never_depends_on_driver_size() {
        let real: ContractMatrix = serde_json::from_str(REAL_MATRIX_JSON).unwrap();
        let baseline = real.evaluate();
        assert!(!baseline.hardware_eligible);
        for size in [0u64, 1, 77_380, u64::MAX] {
            let mut m = real.clone();
            for artifact in &mut m.artifacts {
                artifact.size_bytes = size;
            }
            assert_eq!(m.evaluate(), baseline, "size {size} changed the verdict");
        }
        // Nor does a small or simple-looking artifact rescue unknown fields.
        let mut tiny = complete_matrix(anchor_artifact);
        tiny.artifacts[0].size_bytes = 1;
        interface_mut(&mut tiny, HalOperation::SetGain).alignment =
            FieldStatus::unknown("EXT-TEST", "measure it");
        assert!(!tiny.evaluate().hardware_eligible);
        // And a huge, complete one is eligible only because the fields are known.
        let mut huge = complete_matrix(anchor_artifact);
        huge.artifacts[0].size_bytes = u64::MAX;
        assert!(huge.evaluate().hardware_eligible);
    }

    #[test]
    fn bad_anchors_are_named_and_block_hardware() {
        let cases: Vec<(Anchor, MissingReason)> = vec![
            (
                Anchor::Artifact {
                    sha256: "f".repeat(64),
                    section: ".text".to_string(),
                    offset: 0,
                    symbol: None,
                },
                MissingReason::UnregisteredArtifact {
                    sha256: "f".repeat(64),
                },
            ),
            (
                Anchor::Artifact {
                    sha256: FIXTURE_SHA.to_uppercase(),
                    section: ".text".to_string(),
                    offset: 0,
                    symbol: None,
                },
                MissingReason::BadAnchor {
                    detail: "artifact digest is not 64 lowercase hex characters".to_string(),
                },
            ),
            (
                Anchor::Artifact {
                    sha256: FIXTURE_SHA.to_string(),
                    section: ".text".to_string(),
                    offset: 0x1000,
                    symbol: None,
                },
                MissingReason::BadAnchor {
                    detail: "offset 0x1000 is outside section .text (0x1000 byte(s))".to_string(),
                },
            ),
            (
                Anchor::Artifact {
                    sha256: FIXTURE_SHA.to_string(),
                    section: ".bss".to_string(),
                    offset: 0,
                    symbol: None,
                },
                MissingReason::BadAnchor {
                    detail: "section .bss is not registered for the artifact".to_string(),
                },
            ),
            (
                Anchor::Artifact {
                    sha256: FIXTURE_SHA.to_string(),
                    section: ".text".to_string(),
                    offset: 0,
                    symbol: Some(" ".to_string()),
                },
                MissingReason::BadAnchor {
                    detail: "the artifact anchor has an empty symbol name".to_string(),
                },
            ),
            (
                Anchor::Source {
                    reference: " ".to_string(),
                },
                MissingReason::BadAnchor {
                    detail: "a source anchor has no reference".to_string(),
                },
            ),
        ];
        for (anchor, expected) in cases {
            let mut m = complete_matrix(anchor_artifact);
            interface_mut(&mut m, HalOperation::Start).endianness =
                FieldStatus::known(Endianness::Big, anchor.clone());
            let report = m.evaluate();
            assert!(!report.hardware_eligible, "{anchor:?}");
            assert_eq!(
                report.missing,
                vec![MissingContract {
                    scope: ContractScope::AudioOutput,
                    record: "fixture.start".to_string(),
                    field: ContractField::Endianness,
                    reason: expected,
                }],
                "{anchor:?}"
            );
        }
        // Permitted positive: a public source reference is an acceptable anchor.
        let mut m = complete_matrix(anchor_artifact);
        interface_mut(&mut m, HalOperation::Start).endianness = FieldStatus::known(
            Endianness::Big,
            Anchor::Source {
                reference: "public-doc#section".to_string(),
            },
        );
        assert!(m.evaluate().hardware_eligible);
    }

    #[test]
    fn contradictory_records_are_reported_per_field() {
        let mut m = complete_matrix(anchor_artifact);
        {
            let r = interface_mut(&mut m, HalOperation::Start);
            // Fixture start is selector 6 with command 0x8008_7e06 (write, 8 bytes, type 0x7e).
            r.selector = FieldStatus::known(7, anchor_artifact());
            r.direction = FieldStatus::known(IoctlDirection::Read, anchor_artifact());
            r.payload_size = FieldStatus::known(16, anchor_artifact());
        }
        let report = m.evaluate();
        let fields: Vec<ContractField> = report.missing.iter().map(|x| x.field).collect();
        assert_eq!(
            fields,
            vec![
                ContractField::FullCommand,
                ContractField::Direction,
                ContractField::PayloadSize,
                ContractField::FieldMap,
            ]
        );
        assert!(
            report
                .missing
                .iter()
                .all(|x| matches!(x.reason, MissingReason::Inconsistent { .. }))
        );
        // Permitted positive: the same record, made consistent again, passes.
        let ok = complete_matrix(anchor_artifact);
        assert!(ok.evaluate().hardware_eligible);
    }

    #[test]
    fn non_ioctl_interfaces_must_not_carry_an_ioctl_selector() {
        let mut m = complete_matrix(anchor_artifact);
        {
            let r = interface_mut(&mut m, HalOperation::SubmitBlock);
            r.interface = FieldStatus::known(InterfaceKind::Write, anchor_artifact());
        }
        let report = m.evaluate();
        let fields: Vec<ContractField> = report.missing.iter().map(|x| x.field).collect();
        assert_eq!(
            fields,
            vec![ContractField::Selector, ContractField::FullCommand]
        );
        // Permitted positive: marking both not applicable, with a reason, is accepted.
        {
            let r = interface_mut(&mut m, HalOperation::SubmitBlock);
            r.selector = FieldStatus::not_applicable("write has no command number");
            r.full_command = FieldStatus::not_applicable("write has no command word");
        }
        assert!(m.evaluate().hardware_eligible);
        // An ioctl cannot claim the selector does not apply.
        let r = interface_mut(&mut m, HalOperation::SubmitBlock);
        r.interface = FieldStatus::known(InterfaceKind::Ioctl, anchor_artifact());
        let fields: Vec<ContractField> = m.evaluate().missing.iter().map(|x| x.field).collect();
        assert_eq!(
            fields,
            vec![ContractField::Selector, ContractField::FullCommand]
        );
    }

    #[test]
    fn an_unknown_without_a_named_blocker_or_a_blank_reason_is_not_accepted() {
        let mut m = complete_matrix(anchor_artifact);
        interface_mut(&mut m, HalOperation::Start).alignment = FieldStatus::unknown(" ", "x");
        interface_mut(&mut m, HalOperation::Drain).endianness = FieldStatus::not_applicable("  ");
        let report = m.evaluate();
        assert_eq!(report.missing.len(), 2);
        assert!(
            report
                .missing
                .iter()
                .all(|x| matches!(x.reason, MissingReason::Inconsistent { .. }))
        );
    }

    #[test]
    fn matrix_structure_problems_block_eligibility() {
        let mut m = complete_matrix(anchor_artifact);
        m.schema = "other".to_string();
        let dup = m.interfaces[0].clone();
        m.interfaces.push(dup);
        m.artifacts.push(artifact());
        m.artifacts[0].sha256 = "short".to_string();
        let report = m.evaluate();
        assert!(!report.hardware_eligible);
        let details: Vec<&str> = report
            .missing
            .iter()
            .filter_map(|x| match &x.reason {
                MissingReason::Inconsistent { detail } => Some(detail.as_str()),
                _ => None,
            })
            .collect();
        assert!(details.iter().any(|d| d.contains("schema is")));
        assert!(details.iter().any(|d| d.contains("not 64 lowercase hex")));
        assert!(
            details
                .iter()
                .any(|d| d.contains("record id is used twice"))
        );
    }

    #[test]
    fn serialized_shapes_are_stable() {
        let unknown: FieldStatus<u16> = FieldStatus::unknown("EXT-E04-X", "needs a thing");
        assert_eq!(
            serde_json::to_value(&unknown).unwrap(),
            serde_json::json!({
                "status": "unknown",
                "blocker": {"id": "EXT-E04-X", "needs": "needs a thing"}
            })
        );
        let known = FieldStatus::known(
            4u16,
            Anchor::Artifact {
                sha256: FIXTURE_SHA.to_string(),
                section: ".text".to_string(),
                offset: 16,
                symbol: None,
            },
        );
        assert_eq!(
            serde_json::to_value(&known).unwrap(),
            serde_json::json!({
                "status": "known",
                "value": 4,
                "anchor": {"kind": "artifact", "sha256": FIXTURE_SHA, "section": ".text",
                           "offset": 16, "symbol": null}
            })
        );
        let m = complete_matrix(anchor_artifact);
        let text = serde_json::to_string(&m).unwrap();
        let back: ContractMatrix = serde_json::from_str(&text).unwrap();
        assert_eq!(back, m);
        // A report round-trips too, since it travels inside HalError.
        let report = complete_matrix(anchor_synthetic).evaluate();
        let back: EligibilityReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn the_committed_matrix_lists_the_exact_missing_contract() {
        let real: ContractMatrix = serde_json::from_str(REAL_MATRIX_JSON).unwrap();
        let report = real.evaluate();
        assert!(!report.hardware_eligible);
        assert!(!report.offline_model_ok);
        // 10 operations * 8 fields + 7 duties * 3 fields + 4 topology fields + 3 sequences * 2
        // fields, all unknown, none inferred.
        assert_eq!(report.missing.len(), 111);
        assert!(
            report
                .missing
                .iter()
                .all(|m| matches!(m.reason, MissingReason::Unknown { .. }))
        );
        let mut counts = std::collections::BTreeMap::new();
        for m in &report.missing {
            if let MissingReason::Unknown { blocker } = &m.reason {
                *counts.entry(blocker.id.clone()).or_insert(0usize) += 1;
            }
        }
        // Hand-written: which interface implements each operation (3 fields * 10), the ioctl
        // layout (5 fields * 10), radio ownership (2 fields * 7), live interference bounds (7),
        // the channel map (2), the rates (2), the sequence steps (3) and the mute acknowledgments (3).
        let expected: std::collections::BTreeMap<String, usize> = [
            ("EXT-E04-AMP-SEQUENCE", 3),
            ("EXT-E04-CHANNEL-TOPOLOGY", 2),
            ("EXT-E04-IOCTL-LAYOUT", 50),
            ("EXT-E04-LIVE-QUAL", 7),
            ("EXT-E04-MUTE-ACK", 3),
            ("EXT-E04-OP-MAPPING", 30),
            ("EXT-E04-RADIO-OWNERSHIP", 14),
            ("EXT-E04-RATES", 2),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(counts, expected);
        assert_eq!(
            report.missing[0],
            MissingContract {
                scope: ContractScope::AudioOutput,
                record: "op.query_capabilities".to_string(),
                field: ContractField::Interface,
                reason: MissingReason::Unknown {
                    blocker: blocker(
                        "EXT-E04-OP-MAPPING",
                        "which retained-driver interface implements query_capabilities is not established"
                    )
                },
            }
        );
        // The matrix registers the one artifact the anchors will point into.
        assert_eq!(real.artifacts.len(), 1);
        assert_eq!(
            real.artifacts[0].sha256,
            "14c202fa115ffde39dcdfa5a6505ea1ead9ed41b89429c9dd319b47a61939bd2"
        );
        assert_eq!(real.artifacts[0].size_bytes, 77_380);
    }
    fn only(matrix: &ContractMatrix) -> Vec<(ContractScope, String, ContractField)> {
        matrix
            .evaluate()
            .missing
            .iter()
            .map(|m| (m.scope, m.record.clone(), m.field))
            .collect()
    }

    #[test]
    fn a_topology_is_required_and_a_contradictory_one_is_named_exactly() {
        // Required: with none, the verdict says so.
        let mut m = complete_matrix(anchor_artifact);
        m.topology.clear();
        assert_eq!(
            only(&m),
            vec![(
                ContractScope::Topology,
                "topology:audio_output".to_string(),
                ContractField::Record
            )]
        );
        // Three routes for two channels.
        let mut m = complete_matrix(anchor_artifact);
        m.topology[0].routing = FieldStatus::known(
            vec![
                ChannelRoute {
                    index: 0,
                    role: "woofer_mono".to_string(),
                },
                ChannelRoute {
                    index: 1,
                    role: "tweeter_mono".to_string(),
                },
                ChannelRoute {
                    index: 2,
                    role: "subwoofer_lfe".to_string(),
                },
            ],
            anchor_artifact(),
        );
        assert_eq!(
            only(&m),
            vec![(
                ContractScope::Topology,
                "fixture.topology".to_string(),
                ContractField::Routing
            )]
        );
        // Rates that go down, that are out of range, that are empty, and a channel count of nothing.
        for (rates, expect_problem) in [
            (vec![48_000, 44_100], true),
            (vec![48_000, 48_000], true),
            (vec![7_999], true),
            (vec![384_001], true),
            (Vec::new(), true),
            (vec![8_000, 384_000], false),
        ] {
            let mut m = complete_matrix(anchor_artifact);
            m.topology[0].sample_rates_hz = FieldStatus::known(rates.clone(), anchor_artifact());
            assert_eq!(only(&m).is_empty(), !expect_problem, "rates {rates:?}");
        }
        let mut m = complete_matrix(anchor_artifact);
        m.topology[0].channel_count = FieldStatus::known(0, anchor_artifact());
        assert!(only(&m).contains(&(
            ContractScope::Topology,
            "fixture.topology".to_string(),
            ContractField::ChannelCount
        )));
        // Indices must be 0..n-1 once each, and every channel must feed a named role.
        let mut m = complete_matrix(anchor_artifact);
        m.topology[0].routing = FieldStatus::known(
            vec![
                ChannelRoute {
                    index: 1,
                    role: "woofer_mono".to_string(),
                },
                ChannelRoute {
                    index: 1,
                    role: " ".to_string(),
                },
            ],
            anchor_artifact(),
        );
        assert_eq!(
            only(&m),
            vec![
                (
                    ContractScope::Topology,
                    "fixture.topology".to_string(),
                    ContractField::Routing
                );
                2
            ]
        );
    }

    #[test]
    fn the_amplifier_sequences_are_required_and_must_mute_first_and_unmute_last() {
        let mut m = complete_matrix(anchor_artifact);
        m.amp_sequences.retain(|r| r.kind != AmpSequenceKind::Fault);
        assert_eq!(
            only(&m),
            vec![(
                ContractScope::AmpSequencing,
                "amp_sequence:fault".to_string(),
                ContractField::Record
            )]
        );
        let step = |action| AmpStep {
            action,
            min_delay_us: 0,
        };
        let steps_of = |kind: AmpSequenceKind, actions: &[AmpAction]| {
            let mut m = complete_matrix(anchor_artifact);
            sequence_mut(&mut m, kind).steps = FieldStatus::known(
                actions.iter().map(|&a| step(a)).collect(),
                anchor_artifact(),
            );
            only(&m)
        };
        let id = |kind: AmpSequenceKind| format!("fixture.amp.{}", kind.name());
        let steps_problem =
            |kind: AmpSequenceKind| (ContractScope::AmpSequencing, id(kind), ContractField::Steps);
        // A startup that unmutes in the middle and then configures the codec.
        assert_eq!(
            steps_of(
                AmpSequenceKind::Startup,
                &[
                    AmpAction::AssertMute,
                    AmpAction::DeassertMute,
                    AmpAction::ConfigureCodec
                ]
            ),
            vec![steps_problem(AmpSequenceKind::Startup); 2]
        );
        // A stop that unmutes.
        assert_eq!(
            steps_of(
                AmpSequenceKind::Shutdown,
                &[AmpAction::AssertMute, AmpAction::DeassertMute]
            ),
            vec![steps_problem(AmpSequenceKind::Shutdown); 2]
        );
        // Mute is not first; an action repeats; a startup cuts the clocks; there is no step at all.
        assert!(!steps_of(AmpSequenceKind::Fault, &[AmpAction::DisableClocks]).is_empty());
        assert!(
            !steps_of(
                AmpSequenceKind::Shutdown,
                &[AmpAction::AssertMute, AmpAction::AssertMute]
            )
            .is_empty()
        );
        assert!(
            !steps_of(
                AmpSequenceKind::Startup,
                &[
                    AmpAction::AssertMute,
                    AmpAction::DisableClocks,
                    AmpAction::DeassertMute
                ]
            )
            .is_empty()
        );
        assert!(!steps_of(AmpSequenceKind::Fault, &[]).is_empty());
        // Permitted positives: a minimal startup, a stop that only mutes, a fault that mutes and
        // cuts the clocks.
        assert!(
            steps_of(
                AmpSequenceKind::Startup,
                &[AmpAction::AssertMute, AmpAction::DeassertMute]
            )
            .is_empty()
        );
        assert!(steps_of(AmpSequenceKind::Shutdown, &[AmpAction::AssertMute]).is_empty());
        assert!(
            steps_of(
                AmpSequenceKind::Fault,
                &[AmpAction::AssertMute, AmpAction::DisableClocks]
            )
            .is_empty()
        );
        // A mute that need not be acknowledged is not a mute.
        let mut m = complete_matrix(anchor_artifact);
        sequence_mut(&mut m, AmpSequenceKind::Fault).mute_acknowledgment_required =
            FieldStatus::known(false, anchor_artifact());
        assert_eq!(
            only(&m),
            vec![(
                ContractScope::AmpSequencing,
                id(AmpSequenceKind::Fault),
                ContractField::MuteAcknowledgment
            )]
        );
    }

    #[test]
    fn a_topology_is_checked_against_the_board_profile_it_will_run_on() {
        let catalog = franken_board_profile::synthetic_test_fixture_catalog();
        let s1 = catalog.iter().find(|p| p.model_number == "S1").unwrap();
        let s5 = catalog.iter().find(|p| p.model_number == "S5").unwrap();
        let roles = |p: &BoardProfile| -> Vec<String> {
            p.channel_routing
                .iter()
                .map(|r| transducer_role_name(*r))
                .collect()
        };
        let names = roles(s1);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        // The topology built from the profile's own roles agrees with it.
        let matrix = complete_matrix_for(anchor_artifact, &refs);
        let report = matrix.evaluate_for_profile(s1);
        assert!(report.hardware_eligible, "{:?}", report.missing);
        // The same driver on a five-channel board contradicts the profile twice over: the count, and
        // the number of routes.
        let report = matrix.evaluate_for_profile(s5);
        assert!(!report.hardware_eligible);
        let fields: Vec<ContractField> = report.missing.iter().map(|m| m.field).collect();
        assert_eq!(
            fields,
            vec![ContractField::ChannelCount, ContractField::Routing]
        );
        assert!(
            report
                .missing
                .iter()
                .all(|m| matches!(m.reason, MissingReason::Inconsistent { .. })
                    && m.scope == ContractScope::Topology)
        );
        // Right count, wrong transducer on one channel.
        let mut swapped = refs.clone();
        swapped.swap(0, 1);
        let report = complete_matrix_for(anchor_artifact, &swapped).evaluate_for_profile(s1);
        assert_eq!(report.missing.len(), 2, "{:?}", report.missing);
        assert!(
            report
                .missing
                .iter()
                .all(|m| m.field == ContractField::Routing)
        );
        // A topology that is still unknown says nothing about the profile: it is already unknown.
        let real: ContractMatrix = serde_json::from_str(REAL_MATRIX_JSON).unwrap();
        assert_eq!(
            real.evaluate_for_profile(s5).missing,
            real.evaluate().missing
        );
        // Synthetic anchors still pass the offline bar and never the hardware one.
        let report = complete_matrix_for(anchor_synthetic, &refs).evaluate_for_profile(s1);
        assert!(report.offline_model_ok && !report.hardware_eligible);
    }

    #[test]
    fn role_names_follow_the_board_profile_vocabulary() {
        assert_eq!(
            transducer_role_name(TransducerRole::WooferMono),
            "woofer_mono"
        );
        assert_eq!(
            transducer_role_name(TransducerRole::SubwooferLfe),
            "subwoofer_lfe"
        );
        assert_eq!(
            transducer_role_name(TransducerRole::ArrayTweeter(3)),
            "array_tweeter_3"
        );
        // The profile crate serializes a plain role in the same spelling.
        let json = serde_json::to_value(TransducerRole::TweeterLeft).unwrap();
        assert_eq!(json, serde_json::json!("tweeter_left"));
        assert_eq!(SampleEncoding::Signed24.bytes(), 3);
    }
}
