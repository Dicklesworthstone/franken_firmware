//! Admission of negotiated source formats (`S02` / `ffw-6dh`).
//!
//! A pure function from what a session negotiated to what this build will decode. It runs before any
//! decoder is built, allocates nothing, and every refusal is a stable code, so an unsupported format fails
//! explicitly instead of being decoded as something else.
//!
//! The table is the mandatory decoder set derived from the pinned clients (`tests/s02/negotiated.json`:
//! librespot v0.8.0 `d36f9f1907e8`, shairport-sync 5.6.2 `0a34fbda8372`), and the checks mirror what the
//! pinned decoder library (Symphonia v0.6.1 `ee35874b571a`) itself accepts, so admission never lets through
//! what the decoder would refuse and never refuses what the ledger requires. The verdicts the tests hold it
//! to are hand-written in `tests/s02/admission.json`; nothing in that file is computed by this code.
//!
//! Check order, one refusal per offer, the first that applies:
//!
//! 1. the format name is at most [`FORMAT_NAME_MAX`] bytes (`FORMAT_NAME_TOO_LONG`);
//! 2. the name is looked up exactly, in the pin's spelling. A name the pin enumerates but never requests is
//!    `NOT_REQUESTED_BY_PIN`; multichannel AAC is `BLOCKED_MULTICHANNEL` (never downmixed); AAC-ELD, AAC-LD
//!    and HE-AAC names are `UNSUPPORTED_PROFILE`; Opus is `NOT_A_SOURCE_FORMAT` (internal transport only);
//!    anything else is `UNKNOWN_FORMAT`;
//! 3. the rate is one of the row's (`RATE_NOT_NEGOTIATED`), 4. the channel count is the row's
//!    (`CHANNELS_NOT_NEGOTIATED`), 5. the declared sample width is the row's (`BITS_MISMATCH`; lossy rows
//!    declare 0);
//! 6. the config is at most [`CONFIG_MAX`] bytes (`CONFIG_TOO_LARGE`);
//! 7. the config has the shape the codec needs: none for Vorbis, MP3 and PCM (`CONFIG_UNEXPECTED`), the
//!    24-byte ALAC cookie, the AAC `AudioSpecificConfig`. Absent is `CONFIG_MISSING`, malformed is
//!    `CONFIG_INVALID`, a profile or coding mode this build does not decode is `UNSUPPORTED_PROFILE`, and a
//!    config that disagrees with the offer is `CONFIG_MISMATCH`.
//!
//! What this does not claim: that anything decodes, how fast, or in how much memory. `needs_bridge` is true
//! only at 44 100 Hz; the rate bridge itself is not part of this function.

use core::fmt;

/// Longest format name accepted; longer names are refused before any comparison.
pub const FORMAT_NAME_MAX: usize = 32;
/// Largest config (ALAC cookie or AAC `AudioSpecificConfig`) inspected; larger is refused.
pub const CONFIG_MAX: usize = 64;

const ALAC_COOKIE_LEN: usize = 24;
/// The pinned decoder refuses a cookie frame length above 16 x 4096.
const ALAC_MAX_FRAME_LENGTH: u32 = 4096 * 16;
const BRIDGE_RATE_HZ: u32 = 44_100;
/// MPEG-4 audio object type 2: AAC-LC. Type 31 is the escape code (AAC-ELD is 39), 5 is SBR, 29 is PS, 23 is LD.
const AAC_LC_OBJECT_TYPE: u16 = 2;
/// Sampling frequency table of ISO 14496-3; indices 13 and 14 are reserved and 15 is the explicit-rate escape.
const ASC_SAMPLE_RATES: [u32; 13] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
    7_350,
];

/// A negotiated format as the session layer states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer<'a> {
    /// The pin's format name, exactly as spelled there (for example `OGG_VORBIS_320`, `ALAC_44100_S16_2`).
    pub format: &'a str,
    pub rate_hz: u32,
    pub channels: u8,
    /// Declared sample width. Lossy rows (Vorbis, MP3, AAC) declare 0; ALAC and PCM declare their width.
    pub bits: u8,
    /// The ALAC magic cookie or the AAC `AudioSpecificConfig`; empty for Vorbis, MP3 and PCM (Vorbis headers
    /// travel inside the Ogg stream).
    pub config: &'a [u8],
}

/// What this build will decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Vorbis,
    Mp3,
    Alac,
    AacLc,
    PcmS16Be,
}

impl Codec {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match *self {
            Self::Vorbis => "Vorbis",
            Self::Mp3 => "Mp3",
            Self::Alac => "Alac",
            Self::AacLc => "AacLc",
            Self::PcmS16Be => "PcmS16Be",
        }
    }
}

/// An admitted offer: the codec and the parameters it was admitted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub codec: Codec,
    pub rate_hz: u32,
    pub channels: u8,
    pub bits: u8,
    /// True only at 44 100 Hz: the output must go through the exact rate bridge before the renderer.
    pub needs_bridge: bool,
}

/// Why an offer was refused. The strings are stable and shared with `tests/s02/admission.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    FormatNameTooLong,
    UnknownFormat,
    NotRequestedByPin,
    BlockedMultichannel,
    UnsupportedProfile,
    NotASourceFormat,
    RateNotNegotiated,
    ChannelsNotNegotiated,
    BitsMismatch,
    ConfigMissing,
    ConfigUnexpected,
    ConfigTooLarge,
    ConfigInvalid,
    ConfigMismatch,
}

impl RefusalCode {
    /// Every code, so a test can hold each one to at least one case.
    pub const ALL: [Self; 14] = [
        Self::FormatNameTooLong,
        Self::UnknownFormat,
        Self::NotRequestedByPin,
        Self::BlockedMultichannel,
        Self::UnsupportedProfile,
        Self::NotASourceFormat,
        Self::RateNotNegotiated,
        Self::ChannelsNotNegotiated,
        Self::BitsMismatch,
        Self::ConfigMissing,
        Self::ConfigUnexpected,
        Self::ConfigTooLarge,
        Self::ConfigInvalid,
        Self::ConfigMismatch,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match *self {
            Self::FormatNameTooLong => "FORMAT_NAME_TOO_LONG",
            Self::UnknownFormat => "UNKNOWN_FORMAT",
            Self::NotRequestedByPin => "NOT_REQUESTED_BY_PIN",
            Self::BlockedMultichannel => "BLOCKED_MULTICHANNEL",
            Self::UnsupportedProfile => "UNSUPPORTED_PROFILE",
            Self::NotASourceFormat => "NOT_A_SOURCE_FORMAT",
            Self::RateNotNegotiated => "RATE_NOT_NEGOTIATED",
            Self::ChannelsNotNegotiated => "CHANNELS_NOT_NEGOTIATED",
            Self::BitsMismatch => "BITS_MISMATCH",
            Self::ConfigMissing => "CONFIG_MISSING",
            Self::ConfigUnexpected => "CONFIG_UNEXPECTED",
            Self::ConfigTooLarge => "CONFIG_TOO_LARGE",
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::ConfigMismatch => "CONFIG_MISMATCH",
        }
    }
}

/// A bounded, redacted echo of a refused offer: the name cut to [`FORMAT_NAME_MAX`] bytes with every byte
/// outside `A-Z a-z 0-9 _ . -` replaced by `?`, the numbers, and the config length (never its bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    name: [u8; FORMAT_NAME_MAX],
    name_len: u8,
    pub rate_hz: u32,
    pub channels: u8,
    pub bits: u8,
    pub config_len: usize,
}

impl Echo {
    fn of(offer: &Offer<'_>) -> Self {
        let mut name = [0u8; FORMAT_NAME_MAX];
        let mut name_len = 0u8;
        for (slot, &byte) in name.iter_mut().zip(offer.format.as_bytes()) {
            *slot = if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-') {
                byte
            } else {
                b'?'
            };
            name_len += 1;
        }
        Self {
            name,
            name_len,
            rate_hz: offer.rate_hz,
            channels: offer.channels,
            bits: offer.bits,
            config_len: offer.config.len(),
        }
    }

    /// The sanitised, truncated format name.
    #[must_use]
    pub fn format(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len)]).unwrap_or("")
    }
}

/// A refused offer: a stable code and a bounded, redacted echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    code: RefusalCode,
    echo: Echo,
}

impl Refusal {
    #[must_use]
    pub const fn code(&self) -> RefusalCode {
        self.code
    }

    #[must_use]
    pub const fn echo(&self) -> &Echo {
        &self.echo
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: format={} rate_hz={} channels={} bits={} config_len={}",
            self.code.as_str(),
            self.echo.format(),
            self.echo.rate_hz,
            self.echo.channels,
            self.echo.bits,
            self.echo.config_len
        )
    }
}

impl core::error::Error for Refusal {}

/// What a name admits to: the codec and the exact parameters negotiated for it.
#[derive(Debug, Clone, Copy)]
struct Row {
    codec: Codec,
    rates: &'static [u32],
    channels: u8,
    bits: u8,
}

#[derive(Debug, Clone, Copy)]
enum Verdict {
    Admit(Row),
    Refuse(RefusalCode),
}

struct Entry {
    name: &'static str,
    verdict: Verdict,
}

const R44: &[u32] = &[44_100];
const R48: &[u32] = &[48_000];

const VORBIS: Verdict = Verdict::Admit(Row {
    codec: Codec::Vorbis,
    rates: R44,
    channels: 2,
    bits: 0,
});
const MP3: Verdict = Verdict::Admit(Row {
    codec: Codec::Mp3,
    rates: R44,
    channels: 2,
    bits: 0,
});
const ALAC_44: Verdict = Verdict::Admit(Row {
    codec: Codec::Alac,
    rates: R44,
    channels: 2,
    bits: 16,
});
const ALAC_48: Verdict = Verdict::Admit(Row {
    codec: Codec::Alac,
    rates: R48,
    channels: 2,
    bits: 24,
});
const AAC_44: Verdict = Verdict::Admit(Row {
    codec: Codec::AacLc,
    rates: R44,
    channels: 2,
    bits: 0,
});
const AAC_48: Verdict = Verdict::Admit(Row {
    codec: Codec::AacLc,
    rates: R48,
    channels: 2,
    bits: 0,
});
const PCM: Verdict = Verdict::Admit(Row {
    codec: Codec::PcmS16Be,
    rates: R44,
    channels: 2,
    bits: 16,
});
const NOT_REQUESTED: Verdict = Verdict::Refuse(RefusalCode::NotRequestedByPin);
const BLOCKED: Verdict = Verdict::Refuse(RefusalCode::BlockedMultichannel);

/// The ledger, by exact name. Mandatory rows are admitted; the rest of what the pins enumerate is refused
/// with the reason the ledger gives.
#[rustfmt::skip]
static TABLE: &[Entry] = &[
    // spotify.ogg_vorbis (player.rs:1010-1037)
    Entry { name: "OGG_VORBIS_96", verdict: VORBIS },
    Entry { name: "OGG_VORBIS_160", verdict: VORBIS },
    Entry { name: "OGG_VORBIS_320", verdict: VORBIS },
    // spotify.mp3 (player.rs:1010-1037)
    Entry { name: "MP3_96", verdict: MP3 },
    Entry { name: "MP3_160", verdict: MP3 },
    Entry { name: "MP3_256", verdict: MP3 },
    Entry { name: "MP3_320", verdict: MP3 },
    // airplay.alac_* (player.h:154-155)
    Entry { name: "ALAC_44100_S16_2", verdict: ALAC_44 },
    Entry { name: "ALAC_48000_S24_2", verdict: ALAC_48 },
    // airplay.aac_lc_stereo (player.h:156-157)
    Entry { name: "AAC_44100_F24_2", verdict: AAC_44 },
    Entry { name: "AAC_48000_F24_2", verdict: AAC_48 },
    // airplay.pcm_s16be (player.c:1099)
    Entry { name: "PCM_S16BE", verdict: PCM },
    // airplay.aac_lc_multichannel: blocked, never downmixed (player.h:158-159)
    Entry { name: "AAC_48000_F24_5P1", verdict: BLOCKED },
    Entry { name: "AAC_48000_F24_7P1", verdict: BLOCKED },
    // enumerated by the Spotify client but absent from every preference list (player.rs:931-951)
    Entry { name: "MP3_160_ENC", verdict: NOT_REQUESTED },
    Entry { name: "AAC_24", verdict: NOT_REQUESTED },
    Entry { name: "AAC_48", verdict: NOT_REQUESTED },
    Entry { name: "AAC_160", verdict: NOT_REQUESTED },
    Entry { name: "AAC_320", verdict: NOT_REQUESTED },
    Entry { name: "MP4_128", verdict: NOT_REQUESTED },
    Entry { name: "XHE_AAC_12", verdict: NOT_REQUESTED },
    Entry { name: "XHE_AAC_16", verdict: NOT_REQUESTED },
    Entry { name: "XHE_AAC_24", verdict: NOT_REQUESTED },
    Entry { name: "FLAC_FLAC", verdict: NOT_REQUESTED },
    Entry { name: "FLAC_FLAC_24BIT", verdict: NOT_REQUESTED },
];

/// A name the pins do not list. The families this build knowingly does not decode get their own reason; the
/// rest is unknown. Nothing here is ever admitted, and none is treated as a default codec.
fn classify_unlisted(name: &str) -> RefusalCode {
    if ["AAC_ELD", "AAC_LD", "HE_AAC", "HEAAC"]
        .iter()
        .any(|prefix| name.starts_with(*prefix))
    {
        RefusalCode::UnsupportedProfile
    } else if name.starts_with("OPUS") {
        RefusalCode::NotASourceFormat
    } else {
        RefusalCode::UnknownFormat
    }
}

fn refuse(offer: &Offer<'_>, code: RefusalCode) -> Refusal {
    Refusal {
        code,
        echo: Echo::of(offer),
    }
}

/// Admit a negotiated format, or refuse it with a stable code. See the module documentation for the order.
pub fn admit(offer: &Offer<'_>) -> Result<Admitted, Refusal> {
    if offer.format.len() > FORMAT_NAME_MAX {
        return Err(refuse(offer, RefusalCode::FormatNameTooLong));
    }
    let row = match TABLE.iter().find(|entry| entry.name == offer.format) {
        Some(Entry {
            verdict: Verdict::Admit(row),
            ..
        }) => *row,
        Some(Entry {
            verdict: Verdict::Refuse(code),
            ..
        }) => return Err(refuse(offer, *code)),
        None => return Err(refuse(offer, classify_unlisted(offer.format))),
    };
    if !row.rates.contains(&offer.rate_hz) {
        return Err(refuse(offer, RefusalCode::RateNotNegotiated));
    }
    if offer.channels != row.channels {
        return Err(refuse(offer, RefusalCode::ChannelsNotNegotiated));
    }
    if offer.bits != row.bits {
        return Err(refuse(offer, RefusalCode::BitsMismatch));
    }
    if let Err(code) = check_config(row.codec, offer) {
        return Err(refuse(offer, code));
    }
    Ok(Admitted {
        codec: row.codec,
        rate_hz: offer.rate_hz,
        channels: offer.channels,
        bits: offer.bits,
        needs_bridge: offer.rate_hz == BRIDGE_RATE_HZ,
    })
}

fn check_config(codec: Codec, offer: &Offer<'_>) -> Result<(), RefusalCode> {
    if offer.config.len() > CONFIG_MAX {
        return Err(RefusalCode::ConfigTooLarge);
    }
    match codec {
        Codec::Vorbis | Codec::Mp3 | Codec::PcmS16Be => {
            if offer.config.is_empty() {
                Ok(())
            } else {
                Err(RefusalCode::ConfigUnexpected)
            }
        }
        Codec::Alac => check_alac_cookie(offer),
        Codec::AacLc => check_aac_config(offer),
    }
}

/// The 24-byte ALAC magic cookie, big-endian: frame length (0..4), compatible version (4), bit depth (5),
/// channels (9), sample rate (20..24). The 48-byte form with channel-layout info is not in the pins and is
/// refused as invalid.
fn check_alac_cookie(offer: &Offer<'_>) -> Result<(), RefusalCode> {
    let cookie = offer.config;
    if cookie.is_empty() {
        return Err(RefusalCode::ConfigMissing);
    }
    if cookie.len() != ALAC_COOKIE_LEN {
        return Err(RefusalCode::ConfigInvalid);
    }
    if cookie[4] != 0 {
        return Err(RefusalCode::UnsupportedProfile);
    }
    let frame_length = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
    if frame_length == 0 || frame_length > ALAC_MAX_FRAME_LENGTH {
        return Err(RefusalCode::ConfigInvalid);
    }
    let sample_rate = u32::from_be_bytes([cookie[20], cookie[21], cookie[22], cookie[23]]);
    if cookie[5] != offer.bits || cookie[9] != offer.channels || sample_rate != offer.rate_hz {
        return Err(RefusalCode::ConfigMismatch);
    }
    Ok(())
}

/// The AAC `AudioSpecificConfig`, read from its first 16 bits: object type (5), frequency index (4),
/// channel configuration (4), frame-length flag, core-coder flag, extension flag. Anything but plain
/// AAC-LC is refused, never decoded as LC: AAC-ELD (escape type 31), HE-AAC and PS (types 5 and 29),
/// AAC-LD (23), 960-sample frames and a program config are `UNSUPPORTED_PROFILE`, and so is backward-
/// compatible SBR signalled after the base config (sync `0x2b7`), which the pinned reader does not look for.
fn check_aac_config(offer: &Offer<'_>) -> Result<(), RefusalCode> {
    let config = offer.config;
    if config.is_empty() {
        return Err(RefusalCode::ConfigMissing);
    }
    if config.len() < 2 {
        return Err(RefusalCode::ConfigInvalid);
    }
    let head = u16::from_be_bytes([config[0], config[1]]);
    if head >> 11 != AAC_LC_OBJECT_TYPE {
        return Err(RefusalCode::UnsupportedProfile);
    }
    let Some(&rate_hz) = ASC_SAMPLE_RATES.get(usize::from((head >> 7) & 0xF)) else {
        return Err(RefusalCode::ConfigInvalid);
    };
    let channels = match (head >> 3) & 0xF {
        0 => return Err(RefusalCode::UnsupportedProfile),
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        6 => 6,
        7 => 8,
        _ => return Err(RefusalCode::ConfigInvalid),
    };
    if (head >> 2) & 1 != 0 {
        return Err(RefusalCode::UnsupportedProfile);
    }
    if head & 0b11 != 0 {
        return Err(RefusalCode::ConfigInvalid);
    }
    match config.len() {
        2 => {}
        3 => return Err(RefusalCode::ConfigInvalid),
        _ => {
            return Err(if config[2] == 0x56 && config[3] >> 5 == 0b111 {
                RefusalCode::UnsupportedProfile
            } else {
                RefusalCode::ConfigInvalid
            });
        }
    }
    if rate_hz != offer.rate_hz || channels != offer.channels {
        return Err(RefusalCode::ConfigMismatch);
    }
    Ok(())
}
