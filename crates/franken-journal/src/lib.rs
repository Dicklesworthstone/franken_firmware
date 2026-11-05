//! Minimal persistent state and calibration custody (`U01` / `ffw-mgb`): a small, versioned, crash-consistent
//! journal.
//!
//! The specification is `docs/contracts/u01.md`; `tests/u01/reference.py` is an independent implementation of it that
//! writes the vectors this crate replays, byte for byte: the media after each scripted scenario, the media after every
//! power cut, and the result of opening each hostile image.
//!
//! The journal runs over the [`Storage`] trait: two erase segments, programming that can only clear bits, a volatile
//! write cache and an explicit `sync`. It has no filesystem, flash driver or allocator policy of its own. A commit is
//! write, then sync, then publish: the in-memory state changes only after the medium has acknowledged the sync, and a
//! failure of either step poisons the journal until it is reopened, because the outcome on the medium is then unknown.
//! Recovery returns exactly the old or exactly the new state of any interrupted commit, never a mixture.
//!
//! Five namespaces are kept apart, so a settings reset, a pairing reset and calibration custody are separate operations:
//! settings (coalesced and rate-limited), credentials (versioned, revocable, tombstoned), calibration, records and
//! monotone high-water marks. Persistence is not encryption and not hardware-backed custody; physical rollback of the
//! medium is out of scope. Errors never carry a key or a value.

#![forbid(unsafe_code)]

pub mod codec;
mod journal;
pub mod state;
pub mod storage;

pub use journal::{Commit, Journal, Phase, Recovery, Source};
pub use state::{Credential, Namespace, Op, State};
pub use storage::{MemStorage, Storage, StorageFault};

use std::fmt;

/// Bounds for one namespace: the longest key and value, and how many entries it may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsLimits {
    pub key_max: usize,
    pub value_max: usize,
    pub entries: usize,
}

/// Every bound of a journal. A configuration that cannot hold its own worst case in one segment is refused by
/// [`Limits::validate`] before any medium is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub segment_bytes: usize,
    pub max_txn_payload: usize,
    pub settings: NsLimits,
    pub calibration: NsLimits,
    pub records: NsLimits,
    /// `entries` bounds live AND revoked identities: a tombstone keeps its slot.
    pub credentials: NsLimits,
    pub marks: NsLimits,
    pub min_flush_interval_ticks: u64,
    /// The wear budget: the journal refuses to compact into a segment generation above this.
    pub max_segment_gen: u32,
}

const fn ns_limits(key_max: usize, value_max: usize, entries: usize) -> NsLimits {
    NsLimits {
        key_max,
        value_max,
        entries,
    }
}

impl Limits {
    /// The device configuration: 8 KiB segments.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            segment_bytes: 8192,
            max_txn_payload: 1024,
            settings: ns_limits(16, 32, 16),
            calibration: ns_limits(32, 256, 4),
            records: ns_limits(32, 256, 4),
            credentials: ns_limits(32, 128, 16),
            marks: ns_limits(16, 8, 8),
            min_flush_interval_ticks: 1000,
            max_segment_gen: 200_000,
        }
    }

    /// The small configuration the vectors and the fault tests use: 512-byte segments.
    #[must_use]
    pub const fn tiny() -> Self {
        Self {
            segment_bytes: 512,
            max_txn_payload: 128,
            settings: ns_limits(8, 16, 2),
            calibration: ns_limits(8, 32, 1),
            records: ns_limits(8, 32, 1),
            credentials: ns_limits(8, 16, 3),
            marks: ns_limits(8, 8, 1),
            min_flush_interval_ticks: 10,
            max_segment_gen: 1_000,
        }
    }

    #[must_use]
    pub const fn ns(&self, ns: Namespace) -> &NsLimits {
        match ns {
            Namespace::Settings => &self.settings,
            Namespace::Credentials => &self.credentials,
            Namespace::Calibration => &self.calibration,
            Namespace::Records => &self.records,
            Namespace::Marks => &self.marks,
        }
    }

    /// The largest snapshot payload any state within these limits can produce.
    #[must_use]
    pub fn worst_snapshot_payload(&self) -> usize {
        let blob = |l: &NsLimits| l.entries * (1 + 1 + 1 + l.key_max + 2 + l.value_max);
        2 + blob(&self.settings)
            + blob(&self.calibration)
            + blob(&self.records)
            + self.credentials.entries
                * (1 + 1 + self.credentials.key_max + 8 + 2 + self.credentials.value_max)
            + self.marks.entries * (1 + 1 + self.marks.key_max + 8)
    }

    /// Refuse a configuration that cannot hold its worst-case snapshot plus one maximal transaction in one segment.
    ///
    /// # Errors
    /// [`JournalError::BadConfig`] when a bound is inconsistent.
    pub fn validate(&self) -> Result<(), JournalError> {
        let need = codec::SEG_HEADER
            + codec::FRAME_HEADER
            + self.worst_snapshot_payload()
            + codec::FRAME_HEADER
            + self.max_txn_payload;
        if need > self.segment_bytes
            || self.max_segment_gen < 2
            || self.max_txn_payload > usize::from(u16::MAX)
        {
            return Err(JournalError::BadConfig);
        }
        for ns in [
            Namespace::Settings,
            Namespace::Calibration,
            Namespace::Records,
        ] {
            let l = self.ns(ns);
            if self.max_txn_payload < 2 + 3 + l.key_max + 2 + l.value_max {
                return Err(JournalError::BadConfig);
            }
        }
        Ok(())
    }
}

/// A rejected operation or a refused recovery. [`JournalError::code`] is the stable name. Neither `Display` nor `Debug`
/// can carry a key or a value: the variants hold only counters and fault names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    InvalidKey,
    ValueTooLong,
    BadOp,
    NotFound,
    NamespaceFull,
    BadVersion,
    /// A replacement must carry a strictly higher version than `current`.
    NotNewer {
        current: u64,
    },
    /// The identity was revoked at `tombstone`; only a strictly higher version is admitted.
    Revoked {
        tombstone: u64,
    },
    AlreadyRevoked,
    MarkRegressed {
        current: u64,
    },
    Malformed,
    TxnTooLarge,
    RateLimited {
        retry_after: u64,
    },
    /// A storage operation failed earlier: reopen the journal to learn what is on the medium.
    Poisoned,
    WearExhausted,
    Storage(StorageFault),
    UnsupportedVersion(u8),
    BadConfig,
}

impl JournalError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidKey => "invalid_key",
            Self::ValueTooLong => "value_too_long",
            Self::BadOp => "bad_op",
            Self::NotFound => "not_found",
            Self::NamespaceFull => "namespace_full",
            Self::BadVersion => "bad_version",
            Self::NotNewer { .. } => "not_newer",
            Self::Revoked { .. } => "revoked",
            Self::AlreadyRevoked => "already_revoked",
            Self::MarkRegressed { .. } => "mark_regressed",
            Self::Malformed => "malformed",
            Self::TxnTooLarge => "txn_too_large",
            Self::RateLimited { .. } => "rate_limited",
            Self::Poisoned => "poisoned",
            Self::WearExhausted => "wear_exhausted",
            Self::Storage(_) => "storage",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::BadConfig => "bad_config",
        }
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for JournalError {}
