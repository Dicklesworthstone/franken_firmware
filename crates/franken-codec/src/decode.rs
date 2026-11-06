//! Real decoders for the negotiated source formats (`S02` / `ffw-6dh`).
//!
//! Two adapters over Symphonia 0.6.1, which is the pure-Rust decoder library E06 pinned (`ee35874b571a`, with the `mp3` feature added by this slice
//! because the pinned Spotify client requests MP3):
//!
//! * [`ContainerDecoder`] for formats that arrive as a container: Ogg Vorbis and MP3. Gapless trimming is on (librespot enables it), a seek uses
//!   `SeekMode::Accurate`, resets the decoder, decodes the preroll and discards frames up to the requested one (librespot's
//!   `symphonia_decoder.rs:206,215`), and a position past the end saturates to the duration.
//! * [`PacketDecoder`] for AirPlay audio that arrives as raw packets with out-of-band configuration: ALAC (24-byte magic cookie) and AAC-LC
//!   (`AudioSpecificConfig`). PCM S16BE needs no codec: [`decode_pcm_s16be`].
//!
//! Output is always interleaved `f32` at the stream's NATIVE rate. A block carries its [`PcmFormat`]; the 44.1 -> 48 kHz join is the rate
//! bridge ([`crate::rate_bridge`]), never an implicit step here. A mid-stream change of rate or channel count is reported on the first block
//! of the new format (`format_changed`), and for MP3 (whose decoder only reports a generic decode error for it) the frame header is read here
//! so the change is explicit instead of silently dropped.
//!
//! Everything is bounded by [`Caps`]. Unsupported material is refused with a named [`CodecError`] before decoding starts: multichannel AAC
//! (a BLOCKED requirement, not a deletion), HE-AAC, AAC-ELD, AAC-LD, 960-sample frames and every ALAC depth other than 16 and 24.

use std::io::Cursor;

use symphonia::core::codecs::CodecParameters;
use symphonia::core::codecs::audio::well_known::{
    CODEC_ID_AAC, CODEC_ID_ALAC, CODEC_ID_MP3, CODEC_ID_VORBIS,
};
use symphonia::core::codecs::audio::{
    AudioCodecId, AudioCodecParameters, AudioDecoder, AudioDecoderOptions,
};
use symphonia::core::common::Limit;
use symphonia::core::errors::{Error as SymError, SeekErrorKind};
use symphonia::core::formats::probe::Hint;
use symphonia::core::formats::{FormatOptions, FormatReader, SeekMode, SeekTo, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::core::meta::MetadataOptions;
use symphonia::core::packet::Packet;
use symphonia::core::units::{Duration, Timestamp};

/// The mandatory decode set, by codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceCodec {
    /// Ogg Vorbis (Spotify `OGG_VORBIS_96/160/320`).
    OggVorbis,
    /// MPEG-1/2 Layer III (Spotify `MP3_96/160/256/320`).
    Mp3,
    /// Apple Lossless, raw packets plus a 24-byte cookie (AirPlay).
    Alac,
    /// AAC-LC, raw packets plus an `AudioSpecificConfig` (AirPlay).
    AacLc,
    /// Big-endian signed 16-bit PCM (AirPlay).
    PcmS16Be,
}

impl SourceCodec {
    /// A short stable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OggVorbis => "ogg_vorbis",
            Self::Mp3 => "mp3",
            Self::Alac => "alac",
            Self::AacLc => "aac_lc",
            Self::PcmS16Be => "pcm_s16be",
        }
    }

    const fn hint_extension(self) -> Option<&'static str> {
        match self {
            Self::OggVorbis => Some("ogg"),
            Self::Mp3 => Some("mp3"),
            _ => None,
        }
    }

    /// Frames to seek back before the requested frame so the decoder state is primed when the requested frame is reached: two Vorbis blocks
    /// of up to 4096 frames, three MP3 frames (the bit reservoir reaches back at most two).
    #[must_use]
    pub const fn seek_preroll_frames(self) -> u64 {
        match self {
            Self::OggVorbis => 8192,
            Self::Mp3 => 3 * 1152,
            _ => 0,
        }
    }
}

/// Resource caps. Every cap is checked before the thing it bounds is allocated or returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Largest container accepted at [`ContainerDecoder::open`].
    pub max_input_bytes: usize,
    /// Most frames one decoded block may hold (Vorbis blocks are at most 4096, MP3 1152, AAC 1024, ALAC `frameLength`).
    pub max_block_frames: usize,
    /// Most channels a block may carry.
    pub max_channels: usize,
    /// Largest raw packet accepted by [`PacketDecoder::decode`].
    pub max_packet_bytes: usize,
    /// Most packets in a row that fail to decode before the stream is declared malformed.
    pub max_consecutive_decode_errors: u32,
    /// Most packets in a row that produce no frames before the stream is declared malformed.
    pub max_packets_without_output: u32,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_block_frames: 16_384,
            max_channels: 2,
            max_packet_bytes: 64 * 1024,
            max_consecutive_decode_errors: 8,
            max_packets_without_output: 256,
        }
    }
}

/// Everything this layer refuses or fails on, by name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Valid but not in the supported set.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// The bytes are not a valid stream.
    #[error("malformed stream: {0}")]
    Malformed(&'static str),
    /// A Symphonia resource limit was reached.
    #[error("limit reached: {0}")]
    Limit(&'static str),
    /// The container is larger than [`Caps::max_input_bytes`].
    #[error("input of {len} bytes exceeds the cap of {cap} bytes")]
    InputTooLarge {
        /// Bytes offered.
        len: usize,
        /// The cap.
        cap: usize,
    },
    /// A raw packet is larger than [`Caps::max_packet_bytes`].
    #[error("packet of {len} bytes exceeds the cap of {cap} bytes")]
    PacketTooLarge {
        /// Bytes offered.
        len: usize,
        /// The cap.
        cap: usize,
    },
    /// A decoded block is longer than [`Caps::max_block_frames`].
    #[error("block of {frames} frames exceeds the cap of {cap} frames")]
    BlockTooLarge {
        /// Frames decoded.
        frames: usize,
        /// The cap.
        cap: usize,
    },
    /// More channels than [`Caps::max_channels`].
    #[error("{channels} channels exceed the cap of {cap}")]
    TooManyChannels {
        /// Channels in the stream.
        channels: usize,
        /// The cap.
        cap: usize,
    },
    /// The container holds a different codec from the one that was negotiated.
    #[error("the stream holds {found} but {expected} was negotiated")]
    WrongCodec {
        /// The negotiated codec.
        expected: &'static str,
        /// What the container holds.
        found: &'static str,
    },
    /// The container has no audio track.
    #[error("no audio track")]
    NoAudioTrack,
    /// A seek could not be done.
    #[error("seek: {0}")]
    Seek(&'static str),
    /// An I/O error from the byte source.
    #[error("i/o: {0}")]
    Io(String),
}

fn map_err(error: SymError) -> CodecError {
    match error {
        SymError::IoError(err) => CodecError::Io(err.to_string()),
        SymError::DecodeError(message) => CodecError::Malformed(message),
        SymError::SeekError(kind) => CodecError::Seek(match kind {
            SeekErrorKind::Unseekable => "the stream is not seekable",
            SeekErrorKind::ForwardOnly => "the stream can only seek forward",
            SeekErrorKind::OutOfRange => "the position is out of range",
            SeekErrorKind::InvalidTrack => "invalid track",
            _ => "seek refused",
        }),
        SymError::Unsupported(feature) => CodecError::Unsupported(feature),
        SymError::LimitError(what) => CodecError::Limit(what),
        SymError::ResetRequired => CodecError::Malformed("the decoder needs a reset"),
        _ => CodecError::Malformed("unclassified decoder error"),
    }
}

/// The signal format of a decoded block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcmFormat {
    /// Native sample rate.
    pub rate_hz: u32,
    /// Interleaved channels.
    pub channels: u8,
}

/// One decoded block (the samples are in the caller's buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockInfo {
    /// Format of this block.
    pub format: PcmFormat,
    /// Frames in this block.
    pub frames: usize,
    /// Stream position, in frames, of the first frame of this block (after gapless trimming).
    pub position: i64,
    /// True on the first block whose format differs from the block before it.
    pub format_changed: bool,
}

/// What [`ContainerDecoder::next_block`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// A block was decoded into the caller's buffer.
    Block(BlockInfo),
    /// The stream ended (cleanly, or truncated: see [`ContainerDecoder::truncated`]).
    End,
}

/// Counters kept while decoding. Operation and byte counts, not a CPU, heap or stack measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Packets handed to the decoder.
    pub packets: u64,
    /// Blocks returned.
    pub blocks: u64,
    /// Frames returned.
    pub frames: u64,
    /// Packet bytes handed to the decoder.
    pub bytes_in: u64,
    /// Packets that failed to decode and were dropped.
    pub decode_errors: u64,
    /// Packets that decoded to zero frames (decoder priming, trimmed packets).
    pub empty_packets: u64,
    /// Largest block returned, in frames.
    pub max_block_frames: usize,
    /// Largest capacity the caller's sample buffer reached, in samples.
    pub max_out_capacity_samples: usize,
}

/// Result of [`ContainerDecoder::seek`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeekInfo {
    /// The frame the caller asked for.
    pub requested: u64,
    /// The frame that will come first: `requested`, saturated to the track length.
    pub target: u64,
    /// True when `requested` was past the end.
    pub saturated: bool,
    /// The timestamp the demuxer landed on (at or before `target` minus the preroll).
    pub landed: i64,
}

enum PacketFailure {
    Decode(&'static str),
    Fatal(CodecError),
}

fn found_name(id: AudioCodecId) -> &'static str {
    if id == CODEC_ID_VORBIS {
        "vorbis"
    } else if id == CODEC_ID_MP3 {
        "mp3"
    } else if id == CODEC_ID_AAC {
        "aac"
    } else if id == CODEC_ID_ALAC {
        "alac"
    } else {
        "another codec"
    }
}

fn make_decoder(
    params: &AudioCodecParameters,
    opts: &AudioDecoderOptions,
) -> Result<Box<dyn AudioDecoder>, CodecError> {
    symphonia::default::get_codecs()
        .make_audio_decoder(params, opts)
        .map_err(map_err)
}

/// Decode one packet into `out`. Nothing here borrows the decoder past the call.
fn decode_packet(
    decoder: &mut dyn AudioDecoder,
    packet: &Packet,
    out: &mut Vec<f32>,
    caps: &Caps,
) -> Result<(PcmFormat, usize), PacketFailure> {
    let buf = match decoder.decode(packet) {
        Ok(buf) => buf,
        Err(SymError::DecodeError(message)) => return Err(PacketFailure::Decode(message)),
        Err(other) => return Err(PacketFailure::Fatal(map_err(other))),
    };
    let frames = buf.frames();
    if frames == 0 {
        out.clear();
        return Ok((
            PcmFormat {
                rate_hz: 0,
                channels: 0,
            },
            0,
        ));
    }
    let spec = buf.spec();
    let rate_hz = spec.rate();
    let channels = spec.channels().count();
    if channels == 0 || channels > caps.max_channels {
        return Err(PacketFailure::Fatal(CodecError::TooManyChannels {
            channels,
            cap: caps.max_channels,
        }));
    }
    if frames > caps.max_block_frames {
        return Err(PacketFailure::Fatal(CodecError::BlockTooLarge {
            frames,
            cap: caps.max_block_frames,
        }));
    }
    let channels = u8::try_from(channels).map_err(|_| {
        PacketFailure::Fatal(CodecError::TooManyChannels {
            channels,
            cap: caps.max_channels,
        })
    })?;
    buf.copy_to_vec_interleaved::<f32>(out);
    Ok((PcmFormat { rate_hz, channels }, frames))
}

fn first_audio_track(
    reader: &dyn FormatReader,
) -> Result<(u32, AudioCodecParameters, Option<u64>), CodecError> {
    let track = reader
        .first_track_known_codec(TrackType::Audio)
        .ok_or(CodecError::NoAudioTrack)?;
    match &track.codec_params {
        Some(CodecParameters::Audio(params)) => Ok((track.id, params.clone(), track.num_frames)),
        _ => Err(CodecError::NoAudioTrack),
    }
}

/// Sample rate and channel count from an MPEG audio Layer III frame header, or `None` if the four bytes are not one.
fn mp3_header_format(data: &[u8]) -> Option<(u32, u8)> {
    if data.len() < 4 || data[0] != 0xFF || (data[1] & 0xE0) != 0xE0 {
        return None;
    }
    let version = (data[1] >> 3) & 0x03;
    let layer = (data[1] >> 1) & 0x03;
    let rate_index = usize::from((data[2] >> 2) & 0x03);
    if layer != 1 || rate_index == 3 {
        return None;
    }
    let rates: [u32; 3] = match version {
        3 => [44_100, 48_000, 32_000],
        2 => [22_050, 24_000, 16_000],
        0 => [11_025, 12_000, 8_000],
        _ => return None,
    };
    let channels = if (data[3] >> 6) == 3 { 1 } else { 2 };
    Some((rates[rate_index], channels))
}

/// A decoder for a container: Ogg Vorbis or MP3.
pub struct ContainerDecoder {
    codec: SourceCodec,
    caps: Caps,
    reader: Box<dyn FormatReader>,
    decoder: Box<dyn AudioDecoder>,
    params: AudioCodecParameters,
    opts: AudioDecoderOptions,
    track_id: u32,
    num_frames: Option<u64>,
    format: Option<PcmFormat>,
    mp3_stream: Option<(u32, u8)>,
    ignore_end_trim: bool,
    skip_until: Option<u64>,
    truncated: bool,
    consecutive_errors: u32,
    stats: DecodeStats,
}

impl ContainerDecoder {
    /// Open a complete in-memory container.
    ///
    /// # Errors
    ///
    /// [`CodecError::InputTooLarge`], [`CodecError::NoAudioTrack`], [`CodecError::WrongCodec`] (for example an AAC-in-ADTS stream offered as
    /// MP3), [`CodecError::TooManyChannels`], or whatever Symphonia reports for a stream it cannot parse.
    pub fn open(codec: SourceCodec, bytes: Vec<u8>, caps: Caps) -> Result<Self, CodecError> {
        let expected = match codec {
            SourceCodec::OggVorbis => CODEC_ID_VORBIS,
            SourceCodec::Mp3 => CODEC_ID_MP3,
            _ => {
                return Err(CodecError::Unsupported(
                    "this codec arrives as raw packets, not as a container",
                ));
            }
        };
        if bytes.len() > caps.max_input_bytes {
            return Err(CodecError::InputTooLarge {
                len: bytes.len(),
                cap: caps.max_input_bytes,
            });
        }
        let mut hint = Hint::new();
        if let Some(extension) = codec.hint_extension() {
            hint.with_extension(extension);
        }
        let source = MediaSourceStream::new(
            Box::new(Cursor::new(bytes)),
            MediaSourceStreamOptions::default(),
        );
        let meta_opts = MetadataOptions::default()
            .limit_tag_bytes(Limit::Maximum(16 * 1024))
            .limit_visual_bytes(Limit::Maximum(0));
        let reader = symphonia::default::get_probe()
            .probe(&hint, source, FormatOptions::default(), meta_opts)
            .map_err(map_err)?;
        let (track_id, params, num_frames) = first_audio_track(&*reader)?;
        if params.codec != expected {
            return Err(CodecError::WrongCodec {
                expected: codec.name(),
                found: found_name(params.codec),
            });
        }
        if let Some(channels) = params.channels.as_ref().map(|c| c.count())
            && channels > caps.max_channels
        {
            return Err(CodecError::TooManyChannels {
                channels,
                cap: caps.max_channels,
            });
        }
        let opts = AudioDecoderOptions::default().gapless(true);
        let decoder = make_decoder(&params, &opts)?;
        Ok(Self {
            codec,
            caps,
            reader,
            decoder,
            params,
            opts,
            track_id,
            num_frames,
            format: None,
            mp3_stream: None,
            ignore_end_trim: false,
            skip_until: None,
            truncated: false,
            consecutive_errors: 0,
            stats: DecodeStats::default(),
        })
    }

    /// The codec this decoder was opened for.
    #[must_use]
    pub const fn codec(&self) -> SourceCodec {
        self.codec
    }

    /// Format of the most recent block, if any block was returned yet.
    #[must_use]
    pub const fn format(&self) -> Option<PcmFormat> {
        self.format
    }

    /// Track length in frames, excluding gapless delay and padding, when the container states it.
    #[must_use]
    pub const fn track_frames(&self) -> Option<u64> {
        self.num_frames
    }

    /// True once the byte source ended in the middle of a structure (the stream was cut short).
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Counters since open.
    #[must_use]
    pub const fn stats(&self) -> DecodeStats {
        self.stats
    }

    fn rebuild_after_reset(&mut self) -> Result<(), CodecError> {
        let (track_id, params, num_frames) = first_audio_track(&*self.reader)?;
        if params.codec != self.params.codec {
            return Err(CodecError::WrongCodec {
                expected: self.codec.name(),
                found: found_name(params.codec),
            });
        }
        self.decoder = make_decoder(&params, &self.opts)?;
        self.params = params;
        self.track_id = track_id;
        self.num_frames = num_frames;
        self.skip_until = None;
        Ok(())
    }

    /// Decode the next block into `out` (replaced). Packets that decode to nothing are consumed silently.
    ///
    /// # Errors
    ///
    /// Any [`CodecError`]; after an error the decoder may be asked for the next block, but a caller should treat the stream as damaged.
    pub fn next_block(&mut self, out: &mut Vec<f32>) -> Result<Step, CodecError> {
        out.clear();
        let mut idle: u32 = 0;
        loop {
            if idle > self.caps.max_packets_without_output {
                return Err(CodecError::Malformed(
                    "too many packets in a row produced no audio",
                ));
            }
            let mut packet = match self.reader.next_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) => return Ok(Step::End),
                Err(SymError::ResetRequired) => {
                    self.rebuild_after_reset()?;
                    continue;
                }
                Err(SymError::IoError(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.truncated = true;
                    return Ok(Step::End);
                }
                Err(other) => return Err(map_err(other)),
            };
            if packet.track_id != self.track_id {
                continue;
            }
            self.stats.packets += 1;
            self.stats.bytes_in += packet.data.len() as u64;
            if self.codec == SourceCodec::Mp3 {
                if let Some(now) = mp3_header_format(&packet.data) {
                    match self.mp3_stream {
                        Some(before) if before != now => {
                            // The MPEG decoder reports this only as a generic decode error and would drop every following frame.
                            // Start a fresh decoder at the new format instead, and let the block's `format_changed` say so.
                            self.decoder = make_decoder(&self.params, &self.opts)?;
                            self.mp3_stream = Some(now);
                            // The first stream's Xing/LAME tag fixed the track length that the reader trims every later packet
                            // against; frames of the new stream are past that length and would all be trimmed away.
                            self.ignore_end_trim = true;
                        }
                        Some(_) => {}
                        None => self.mp3_stream = Some(now),
                    }
                }
                if self.ignore_end_trim {
                    packet.trim_end = Duration::ZERO;
                }
            }
            let (format, frames) = match decode_packet(&mut *self.decoder, &packet, out, &self.caps)
            {
                Ok(decoded) => decoded,
                Err(PacketFailure::Fatal(error)) => return Err(error),
                Err(PacketFailure::Decode(message)) => {
                    self.stats.decode_errors += 1;
                    if self.skip_until.is_none() {
                        self.consecutive_errors += 1;
                        if self.consecutive_errors > self.caps.max_consecutive_decode_errors {
                            return Err(CodecError::Malformed(message));
                        }
                    }
                    idle += 1;
                    continue;
                }
            };
            self.consecutive_errors = 0;
            if frames == 0 {
                self.stats.empty_packets += 1;
                idle += 1;
                continue;
            }
            let channels = usize::from(format.channels);
            let mut position = packet.pts.get() + packet.trim_start.get() as i64;
            let mut frames = frames;
            if let Some(target) = self.skip_until {
                let target = target as i64;
                if position + frames as i64 <= target {
                    out.clear();
                    idle += 1;
                    continue;
                }
                if position > target {
                    return Err(CodecError::Seek(
                        "the first decoded frame is after the requested frame",
                    ));
                }
                let drop = (target - position) as usize;
                out.drain(..drop * channels);
                frames -= drop;
                position = target;
                self.skip_until = None;
            }
            let format_changed = self.format.is_some_and(|before| before != format);
            self.format = Some(format);
            self.stats.blocks += 1;
            self.stats.frames += frames as u64;
            self.stats.max_block_frames = self.stats.max_block_frames.max(frames);
            self.stats.max_out_capacity_samples =
                self.stats.max_out_capacity_samples.max(out.capacity());
            return Ok(Step::Block(BlockInfo {
                format,
                frames,
                position,
                format_changed,
            }));
        }
    }

    /// Seek so the next block starts exactly at frame `target_frame` (saturated to the track length).
    ///
    /// The demuxer is seeked [`SourceCodec::seek_preroll_frames`] earlier, the decoder is reset, and the frames before the target are decoded
    /// and discarded, so the output from the target on equals what continuous decoding produces.
    ///
    /// # Errors
    ///
    /// [`CodecError::Seek`] when the demuxer refuses.
    pub fn seek(&mut self, target_frame: u64) -> Result<SeekInfo, CodecError> {
        let (target, saturated) = match self.num_frames {
            Some(total) if target_frame > total => (total, true),
            _ => (target_frame, false),
        };
        let want = target.saturating_sub(self.codec.seek_preroll_frames());
        let want_ts = i64::try_from(want).map_err(|_| CodecError::Seek("the target is too far"))?;
        let landed = self
            .reader
            .seek(
                SeekMode::Accurate,
                SeekTo::Timestamp {
                    ts: Timestamp::new(want_ts),
                    track_id: self.track_id,
                },
            )
            .map_err(map_err)?;
        self.decoder.reset();
        self.skip_until = Some(target);
        self.consecutive_errors = 0;
        Ok(SeekInfo {
            requested: target_frame,
            target,
            saturated,
            landed: landed.actual_ts.get(),
        })
    }
}

/// What the 24-byte ALAC magic cookie says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlacConfig {
    /// `frameLength`: frames per packet.
    pub frame_length: u32,
    /// 16 or 24.
    pub bit_depth: u8,
    /// 1 or 2.
    pub channels: u8,
    /// Sample rate.
    pub sample_rate: u32,
}

/// Parse and validate a raw 24-byte ALAC magic cookie (the form AirPlay carries).
///
/// # Errors
///
/// [`CodecError::Unsupported`] for any cookie that is not exactly 24 bytes, a version above 0, a depth other than 16 or 24, or a channel
/// count outside `1..=caps.max_channels`; [`CodecError::BlockTooLarge`] for a `frameLength` above `caps.max_block_frames`.
pub fn parse_alac_cookie(cookie: &[u8], caps: &Caps) -> Result<AlacConfig, CodecError> {
    if cookie.len() != 24 {
        return Err(CodecError::Unsupported(
            "alac: the magic cookie must be exactly 24 bytes",
        ));
    }
    let frame_length = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
    let compatible_version = cookie[4];
    let bit_depth = cookie[5];
    let channels = cookie[9];
    let sample_rate = u32::from_be_bytes([cookie[20], cookie[21], cookie[22], cookie[23]]);
    if compatible_version != 0 {
        return Err(CodecError::Unsupported("alac: compatible version is not 0"));
    }
    if bit_depth != 16 && bit_depth != 24 {
        return Err(CodecError::Unsupported(
            "alac: only 16 and 24 bit are negotiated",
        ));
    }
    if channels == 0 || usize::from(channels) > caps.max_channels {
        return Err(CodecError::Unsupported(
            "alac: channel count outside the supported range",
        ));
    }
    if frame_length == 0 || frame_length as usize > caps.max_block_frames {
        return Err(CodecError::BlockTooLarge {
            frames: frame_length as usize,
            cap: caps.max_block_frames,
        });
    }
    if sample_rate == 0 {
        return Err(CodecError::Unsupported("alac: sample rate is 0"));
    }
    Ok(AlacConfig {
        frame_length,
        bit_depth,
        channels,
        sample_rate,
    })
}

/// What an AAC `AudioSpecificConfig` says, once it is known to be plain AAC-LC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AacConfig {
    /// Sample rate from the frequency index.
    pub sample_rate: u32,
    /// 1 or 2.
    pub channels: u8,
}

/// Parse an `AudioSpecificConfig`, accepting only AAC-LC with 1024-sample frames and one or two channels.
///
/// # Errors
///
/// [`CodecError::Unsupported`] naming the refused feature. Multichannel is named as the BLOCKED requirement `airplay.aac_lc_multichannel`:
/// it is refused here, before any decoding, and is never downmixed.
pub fn parse_aac_asc(asc: &[u8], caps: &Caps) -> Result<AacConfig, CodecError> {
    if asc.len() < 2 {
        return Err(CodecError::Malformed(
            "aac: the AudioSpecificConfig is shorter than 2 bytes",
        ));
    }
    let object_type = asc[0] >> 3;
    let frequency_index = ((asc[0] & 0x07) << 1) | (asc[1] >> 7);
    let channel_config = (asc[1] >> 3) & 0x0F;
    let frame_length_flag = (asc[1] >> 2) & 0x01;
    match object_type {
        2 => {}
        5 | 29 => {
            return Err(CodecError::Unsupported(
                "aac: HE-AAC (SBR/PS) is not supported",
            ));
        }
        23 => return Err(CodecError::Unsupported("aac: AAC-LD is not supported")),
        31 => {
            // Escape: the object type is 32 plus the next six bits. AAC-ELD (what AirPlay 2 realtime uses) is 39 and has no decoder here.
            let extended = 32 + (((asc[0] & 0x07) << 3) | (asc[1] >> 5));
            return Err(CodecError::Unsupported(if extended == 39 {
                "aac: AAC-ELD is not supported"
            } else {
                "aac: only the LC object type is supported"
            }));
        }
        _ => {
            return Err(CodecError::Unsupported(
                "aac: only the LC object type is supported",
            ));
        }
    }
    if frame_length_flag != 0 {
        return Err(CodecError::Unsupported(
            "aac: 960-sample frames are not supported",
        ));
    }
    const RATES: [u32; 13] = [
        96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025,
        8_000, 7_350,
    ];
    let Some(&sample_rate) = RATES.get(usize::from(frequency_index)) else {
        return Err(CodecError::Unsupported(
            "aac: the frequency index is not a table entry",
        ));
    };
    let channels = match channel_config {
        1 | 2 => channel_config,
        0 => {
            return Err(CodecError::Unsupported(
                "aac: a program config element is not supported",
            ));
        }
        _ => {
            return Err(CodecError::Unsupported(
                "aac: multichannel (BLOCKED: airplay.aac_lc_multichannel, refused before decoding, never downmixed)",
            ));
        }
    };
    if usize::from(channels) > caps.max_channels {
        return Err(CodecError::TooManyChannels {
            channels: usize::from(channels),
            cap: caps.max_channels,
        });
    }
    Ok(AacConfig {
        sample_rate,
        channels,
    })
}

/// A decoder for raw packets with out-of-band configuration: ALAC and AAC-LC.
pub struct PacketDecoder {
    codec: SourceCodec,
    caps: Caps,
    decoder: Box<dyn AudioDecoder>,
    format: PcmFormat,
    nominal_frames: u64,
    next_position: i64,
    stats: DecodeStats,
}

impl PacketDecoder {
    /// An ALAC decoder from the raw 24-byte magic cookie.
    ///
    /// # Errors
    ///
    /// See [`parse_alac_cookie`]; or whatever Symphonia reports when it builds the decoder.
    pub fn alac(cookie: &[u8], caps: Caps) -> Result<Self, CodecError> {
        let config = parse_alac_cookie(cookie, &caps)?;
        let mut params = AudioCodecParameters::new();
        params
            .for_codec(CODEC_ID_ALAC)
            .with_extra_data(cookie.to_vec().into_boxed_slice());
        Self::build(
            SourceCodec::Alac,
            &params,
            PcmFormat {
                rate_hz: config.sample_rate,
                channels: config.channels,
            },
            u64::from(config.frame_length),
            caps,
        )
    }

    /// An AAC-LC decoder from the `AudioSpecificConfig`.
    ///
    /// # Errors
    ///
    /// See [`parse_aac_asc`]; or whatever Symphonia reports when it builds the decoder.
    pub fn aac_lc(asc: &[u8], caps: Caps) -> Result<Self, CodecError> {
        let config = parse_aac_asc(asc, &caps)?;
        let mut params = AudioCodecParameters::new();
        params
            .for_codec(CODEC_ID_AAC)
            .with_sample_rate(config.sample_rate)
            .with_extra_data(asc.to_vec().into_boxed_slice());
        Self::build(
            SourceCodec::AacLc,
            &params,
            PcmFormat {
                rate_hz: config.sample_rate,
                channels: config.channels,
            },
            1024,
            caps,
        )
    }

    fn build(
        codec: SourceCodec,
        params: &AudioCodecParameters,
        format: PcmFormat,
        nominal_frames: u64,
        caps: Caps,
    ) -> Result<Self, CodecError> {
        let opts = AudioDecoderOptions::default();
        let decoder = make_decoder(params, &opts)?;
        Ok(Self {
            codec,
            caps,
            decoder,
            format,
            nominal_frames,
            next_position: 0,
            stats: DecodeStats::default(),
        })
    }

    /// The codec this decoder was built for.
    #[must_use]
    pub const fn codec(&self) -> SourceCodec {
        self.codec
    }

    /// The format the configuration states; every decoded block must match it.
    #[must_use]
    pub const fn format(&self) -> PcmFormat {
        self.format
    }

    /// Counters since construction.
    #[must_use]
    pub const fn stats(&self) -> DecodeStats {
        self.stats
    }

    /// Drop decoder history (after a flush, a seek, or lost packets) and restart positions at 0.
    pub fn reset(&mut self) {
        self.decoder.reset();
        self.next_position = 0;
    }

    /// Decode one packet into `out` (replaced).
    ///
    /// # Errors
    ///
    /// [`CodecError::PacketTooLarge`], [`CodecError::Malformed`] for an empty packet, a decode failure, or output whose format differs from the
    /// configuration; [`CodecError::BlockTooLarge`] / [`CodecError::TooManyChannels`] from the caps.
    pub fn decode(&mut self, data: &[u8], out: &mut Vec<f32>) -> Result<BlockInfo, CodecError> {
        out.clear();
        if data.is_empty() {
            return Err(CodecError::Malformed("empty packet"));
        }
        if data.len() > self.caps.max_packet_bytes {
            return Err(CodecError::PacketTooLarge {
                len: data.len(),
                cap: self.caps.max_packet_bytes,
            });
        }
        let packet = Packet::new(
            0,
            Timestamp::new(self.next_position),
            Duration::new(self.nominal_frames),
            data.to_vec(),
        );
        self.stats.packets += 1;
        self.stats.bytes_in += data.len() as u64;
        let (format, frames) = match decode_packet(&mut *self.decoder, &packet, out, &self.caps) {
            Ok(decoded) => decoded,
            Err(PacketFailure::Fatal(error)) => return Err(error),
            Err(PacketFailure::Decode(message)) => {
                self.stats.decode_errors += 1;
                return Err(CodecError::Malformed(message));
            }
        };
        if frames == 0 {
            self.stats.empty_packets += 1;
            return Err(CodecError::Malformed("the packet decoded to no frames"));
        }
        if format != self.format {
            out.clear();
            return Err(CodecError::Malformed(
                "the decoded format differs from the configured format",
            ));
        }
        let position = self.next_position;
        self.next_position += frames as i64;
        self.stats.blocks += 1;
        self.stats.frames += frames as u64;
        self.stats.max_block_frames = self.stats.max_block_frames.max(frames);
        self.stats.max_out_capacity_samples =
            self.stats.max_out_capacity_samples.max(out.capacity());
        Ok(BlockInfo {
            format,
            frames,
            position,
            format_changed: false,
        })
    }
}

/// Big-endian signed 16-bit PCM to interleaved `f32` (exact). `out` is replaced. Returns the frames.
///
/// # Errors
///
/// [`CodecError::TooManyChannels`] for a count outside `1..=2`; [`CodecError::Malformed`] when the bytes are not a whole number of frames.
pub fn decode_pcm_s16be(
    bytes: &[u8],
    channels: usize,
    out: &mut Vec<f32>,
) -> Result<usize, CodecError> {
    if channels == 0 || channels > 2 {
        return Err(CodecError::TooManyChannels { channels, cap: 2 });
    }
    let frame_bytes = 2 * channels;
    // A leftover byte is refused here, never dropped: the tail of `as_chunks` must be empty before any sample is read.
    let (samples, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() || !bytes.len().is_multiple_of(frame_bytes) {
        return Err(CodecError::Malformed("pcm: the bytes end inside a frame"));
    }
    out.clear();
    out.extend(
        samples
            .iter()
            .map(|&pair| f32::from(i16::from_be_bytes(pair)) / 32_768.0),
    );
    Ok(bytes.len() / frame_bytes)
}

/// A full-scale `f32` sample to 16 bits: round half away from zero, clamp.
#[must_use]
pub fn f32_to_s16(x: f32) -> i16 {
    let v = (x * 32_768.0).round();
    if v >= 32_767.0 {
        i16::MAX
    } else if v <= -32_768.0 {
        i16::MIN
    } else {
        v as i16
    }
}
