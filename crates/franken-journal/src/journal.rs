//! The journal: the publication state machine, the bounded scanner, recovery and the named operations.
//!
//! Layout: two segments. A segment is a 16-byte header, then frames. The first frame of a valid segment is a snapshot of
//! the whole state; later frames are transactions. A commit appends one frame (program, sync, publish). When the active
//! segment is full the new state is written as the first frame of the other segment (compaction) and that publishes it,
//! so nothing is ever overwritten in place and no step needs an erase except a compaction's target. Recovery picks the
//! valid segment with the highest generation and replays its frames until the first one that does not check out.

use crate::codec::{
    ERASED, FORMAT_VERSION, FRAME_HEADER, FRAME_MAGIC, HeaderParse, KIND_SNAPSHOT, KIND_TXN,
    LEGACY_VERSION, MAX_SEQ, SEG_HEADER, crc32, decode_ops, encode_frame, encode_ops,
    encode_segment_header, parse_frame_header, parse_segment_header,
};
use crate::state::{Credential, Namespace, Op, State, apply_op};
use crate::storage::{Storage, StorageFault};
use crate::{JournalError, Limits};
use std::collections::BTreeMap;

/// Where a commit got to. After a failure it names the last step that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    /// Validated and encoded; nothing written.
    Staged,
    /// The frame (or the new segment) was programmed; not yet synced.
    Written,
    /// The sync was acknowledged; the medium holds the new state.
    Synced,
    /// The in-memory state was replaced.
    Published,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Commit {
    /// Nothing changed, so nothing was written.
    Noop,
    Appended,
    Compacted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Both segments erased: a fresh medium was formatted.
    Blank,
    /// Neither segment holds a valid state although the medium is not blank: it was formatted empty and the caller is
    /// told, so it can raise an alarm instead of carrying on as if nothing were lost.
    Unrecoverable,
    Segment,
}

/// What opening found and what it did about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub source: Source,
    pub generation: u32,
    pub frames: u32,
    pub tail_dirty: bool,
    pub migrated_from: Option<u8>,
    pub retired_stale: bool,
    pub compacted: bool,
}

struct SegmentScan {
    generation: u32,
    version: u8,
    state: State,
    end: usize,
    next_seq: u32,
    frames: u32,
    tail_dirty: bool,
}

enum Scan {
    Blank,
    Invalid,
    Unsupported { generation: u32, version: u8 },
    Valid(Box<SegmentScan>),
}

const CHUNK: usize = 64;

pub struct Journal<S: Storage> {
    storage: S,
    lim: Limits,
    worst_snapshot: usize,
    state: State,
    active: usize,
    generation: u32,
    next_seq: u32,
    write_off: usize,
    poisoned: bool,
    phase: Phase,
    pending_retire: Option<usize>,
    staged: BTreeMap<Vec<u8>, Vec<u8>>,
    last_flush: Option<u64>,
    frames_written: u64,
    compactions: u64,
    bytes_programmed: u64,
}

impl<S: Storage> Journal<S> {
    /// Open the journal on `storage`: scan both segments, recover, and repair what recovery leaves behind (a dirty tail
    /// or an old schema is rewritten into the other segment; a stale valid segment is retired).
    ///
    /// # Errors
    /// [`JournalError::BadConfig`] for limits that cannot work, [`JournalError::UnsupportedVersion`] if the newest
    /// segment is written by a schema this code does not know (it is never formatted over), or a storage fault.
    pub fn open(storage: S, lim: Limits) -> Result<(Self, Recovery), JournalError> {
        lim.validate()?;
        if storage.segment_bytes() != lim.segment_bytes {
            return Err(JournalError::BadConfig);
        }
        let worst_snapshot = lim.worst_snapshot_payload();
        let mut j = Self {
            storage,
            lim,
            worst_snapshot,
            state: State::default(),
            active: 0,
            generation: 0,
            next_seq: 1,
            write_off: SEG_HEADER,
            poisoned: false,
            phase: Phase::Idle,
            pending_retire: None,
            staged: BTreeMap::new(),
            last_flush: None,
            frames_written: 0,
            compactions: 0,
            bytes_programmed: 0,
        };
        let scans = [
            j.scan(0).map_err(JournalError::Storage)?,
            j.scan(1).map_err(JournalError::Storage)?,
        ];
        let mut best: Option<usize> = None;
        for (i, scan) in scans.iter().enumerate() {
            if let Scan::Valid(found) = scan {
                let better = match best {
                    Some(b) => match &scans[b] {
                        Scan::Valid(current) => found.generation > current.generation,
                        _ => true,
                    },
                    None => true,
                };
                if better {
                    best = Some(i);
                }
            }
        }
        for scan in &scans {
            if let Scan::Unsupported {
                generation,
                version,
            } = scan
            {
                let newer = match best {
                    Some(b) => match &scans[b] {
                        Scan::Valid(current) => *generation > current.generation,
                        _ => true,
                    },
                    None => true,
                };
                if newer {
                    return Err(JournalError::UnsupportedVersion(*version));
                }
            }
        }
        let Some(index) = best else {
            let blank = scans.iter().all(|s| matches!(s, Scan::Blank));
            j.format()?;
            let rec = Recovery {
                source: if blank {
                    Source::Blank
                } else {
                    Source::Unrecoverable
                },
                generation: j.generation,
                frames: 0,
                tail_dirty: false,
                migrated_from: None,
                retired_stale: false,
                compacted: true,
            };
            return Ok((j, rec));
        };
        let Scan::Valid(found) = &scans[index] else {
            return Err(JournalError::Malformed);
        };
        j.active = index;
        j.generation = found.generation;
        j.state = found.state.clone();
        j.next_seq = found.next_seq;
        j.write_off = found.end;
        let mut rec = Recovery {
            source: Source::Segment,
            generation: found.generation,
            frames: found.frames,
            tail_dirty: found.tail_dirty,
            migrated_from: None,
            retired_stale: false,
            compacted: false,
        };
        let stale = 1 - index;
        if matches!(scans[stale], Scan::Valid(_) | Scan::Unsupported { .. }) {
            j.pending_retire = Some(stale);
        }
        if found.tail_dirty || found.version != FORMAT_VERSION {
            if found.version != FORMAT_VERSION {
                rec.migrated_from = Some(found.version);
            }
            let snapshot = j.state.clone();
            j.compact(&snapshot)?;
            rec.compacted = true;
        }
        if j.pending_retire.is_some() {
            j.retire()?;
            rec.retired_stale = true;
        }
        Ok((j, rec))
    }

    // ---- reading the medium

    fn region_blank(&self, base: usize, len: usize) -> Result<bool, StorageFault> {
        let mut buf = [0u8; CHUNK];
        let mut done = 0;
        while done < len {
            let n = CHUNK.min(len - done);
            self.storage.read(base + done, &mut buf[..n])?;
            if buf[..n].iter().any(|&b| b != ERASED) {
                return Ok(false);
            }
            done += n;
        }
        Ok(true)
    }

    /// Bounded scan of one segment: it reads only what the segment's own structure says is there, at most one frame
    /// header per `FRAME_HEADER` bytes of the segment.
    fn scan(&self, index: usize) -> Result<Scan, StorageFault> {
        let seg = self.lim.segment_bytes;
        let base = index * seg;
        let mut head = [0u8; SEG_HEADER];
        self.storage.read(base, &mut head)?;
        let header = match parse_segment_header(&head) {
            HeaderParse::Blank => return Ok(Scan::Blank),
            HeaderParse::Invalid => return Ok(Scan::Invalid),
            HeaderParse::Ok(h) => h,
        };
        if header.version != LEGACY_VERSION && header.version != FORMAT_VERSION {
            return Ok(Scan::Unsupported {
                generation: header.generation,
                version: header.version,
            });
        }
        let mut state = State::default();
        let mut off = SEG_HEADER;
        let mut seq = header.first_seq;
        let mut frames: u32 = 0;
        for _ in 0..seg / FRAME_HEADER {
            if off + FRAME_HEADER > seg {
                break;
            }
            let mut fh = [0u8; FRAME_HEADER];
            self.storage.read(base + off, &mut fh)?;
            if fh[0] != FRAME_MAGIC {
                break; // erased (the end of the log) or garbage
            }
            let f = parse_frame_header(&fh);
            let snapshot = f.kind == KIND_SNAPSHOT;
            let cap = if snapshot {
                self.worst_snapshot
            } else {
                self.lim.max_txn_payload
            };
            if (f.kind != KIND_TXN && !snapshot)
                || f.length > cap
                || off + FRAME_HEADER + f.length > seg
                || f.seq != seq
            {
                break;
            }
            if (frames == 0) != snapshot {
                break;
            }
            let mut payload = vec![0u8; f.length]; // the length was bounded above, before this allocation
            self.storage.read(base + off + FRAME_HEADER, &mut payload)?;
            if crc32(&[&fh[..8], &payload[..]]) != f.crc {
                break;
            }
            let Ok(ops) = decode_ops(&self.lim, &payload, header.version, snapshot) else {
                break;
            };
            let mut trial = state.clone();
            if ops
                .iter()
                .any(|op| apply_op(&self.lim, &mut trial, op, snapshot).is_err())
            {
                break;
            }
            let Some(next) = seq.checked_add(1) else {
                break;
            };
            state = trial;
            off += FRAME_HEADER + f.length;
            seq = next;
            frames += 1;
        }
        if frames == 0 {
            return Ok(Scan::Invalid);
        }
        let tail_dirty = off < seg && !self.region_blank(base + off, seg - off)?;
        Ok(Scan::Valid(Box::new(SegmentScan {
            generation: header.generation,
            version: header.version,
            state,
            end: off,
            next_seq: seq,
            frames,
            tail_dirty,
        })))
    }

    // ---- low-level steps; a storage fault poisons the journal until it is reopened

    fn io<T>(&mut self, result: Result<T, StorageFault>) -> Result<T, JournalError> {
        result.map_err(|fault| {
            self.poisoned = true;
            JournalError::Storage(fault)
        })
    }

    fn do_program(&mut self, offset: usize, data: &[u8]) -> Result<(), JournalError> {
        let result = self.storage.program(offset, data);
        self.io(result)
    }

    fn do_erase(&mut self, segment: usize) -> Result<(), JournalError> {
        let result = self.storage.erase(segment);
        self.io(result)
    }

    fn do_sync(&mut self) -> Result<(), JournalError> {
        let result = self.storage.sync();
        self.io(result)
    }

    fn segment_blank(&mut self, index: usize) -> Result<bool, JournalError> {
        let seg = self.lim.segment_bytes;
        let result = self.region_blank(index * seg, seg);
        self.io(result)
    }

    fn format(&mut self) -> Result<(), JournalError> {
        for index in 0..2 {
            if !self.segment_blank(index)? {
                self.do_erase(index)?;
            }
        }
        self.active = 0;
        self.generation = 0;
        self.next_seq = 1;
        self.write_segment(0, 1, &State::default())?;
        self.generation = 1;
        self.active = 0;
        self.state = State::default();
        Ok(())
    }

    fn write_segment(
        &mut self,
        index: usize,
        generation: u32,
        state: &State,
    ) -> Result<(), JournalError> {
        let base = index * self.lim.segment_bytes;
        let frame = encode_frame(KIND_SNAPSHOT, self.next_seq, &state.canonical_bytes()?)?;
        let header = encode_segment_header(FORMAT_VERSION, generation, self.next_seq);
        self.do_program(base, &header)?;
        self.do_program(base + SEG_HEADER, &frame)?;
        self.phase = Phase::Written;
        self.do_sync()?;
        self.phase = Phase::Synced;
        self.bytes_programmed += (SEG_HEADER + frame.len()) as u64;
        self.write_off = SEG_HEADER + frame.len();
        self.next_seq += 1;
        Ok(())
    }

    /// Write `new_state` as the first frame of the other segment, sync, then publish it. The old segment stays valid until
    /// the deferred retire, so a cut anywhere before the sync recovers the old state.
    fn compact(&mut self, new_state: &State) -> Result<(), JournalError> {
        if self.generation >= self.lim.max_segment_gen || self.next_seq == MAX_SEQ {
            return Err(JournalError::WearExhausted);
        }
        let target = 1 - self.active;
        if !self.segment_blank(target)? {
            self.do_erase(target)?;
        }
        let (old_active, old_off, old_seq) = (self.active, self.write_off, self.next_seq);
        if let Err(err) = self.write_segment(target, self.generation + 1, new_state) {
            self.write_off = old_off;
            self.next_seq = old_seq;
            return Err(err);
        }
        self.active = target;
        self.generation += 1;
        self.state = new_state.clone();
        self.pending_retire = Some(old_active);
        self.compactions += 1;
        Ok(())
    }

    /// Clear the stale segment's magic (programming only clears bits), so damage to the current segment can never fall
    /// back to a state that predates a revocation.
    fn retire(&mut self) -> Result<(), JournalError> {
        let Some(index) = self.pending_retire else {
            return Ok(());
        };
        let base = index * self.lim.segment_bytes;
        self.do_program(base, &[0, 0])?;
        self.do_sync()?;
        self.pending_retire = None;
        Ok(())
    }

    // ---- the publication state machine

    /// Validate, write, sync, publish. A storage fault leaves the journal poisoned and the published state unchanged;
    /// reopen it to learn which of old and new is on the medium.
    ///
    /// # Errors
    /// The first rule an operation breaks (nothing is written), [`JournalError::TxnTooLarge`],
    /// [`JournalError::WearExhausted`] when a compaction is needed and the wear budget is spent,
    /// [`JournalError::Poisoned`] after an earlier fault, or the storage fault itself.
    pub fn commit(&mut self, ops: &[Op]) -> Result<Commit, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        self.phase = Phase::Idle;
        if self.pending_retire.is_some() {
            self.retire()?;
        }
        let mut trial = self.state.clone();
        for op in ops {
            apply_op(&self.lim, &mut trial, op, false)?;
        }
        if trial == self.state {
            return Ok(Commit::Noop);
        }
        self.phase = Phase::Staged;
        let payload = encode_ops(ops)?;
        if payload.len() > self.lim.max_txn_payload {
            return Err(JournalError::TxnTooLarge);
        }
        let frame = encode_frame(KIND_TXN, self.next_seq, &payload)?;
        if self.next_seq < MAX_SEQ && self.write_off + frame.len() <= self.lim.segment_bytes {
            let offset = self.active * self.lim.segment_bytes + self.write_off;
            self.do_program(offset, &frame)?;
            self.phase = Phase::Written;
            self.do_sync()?;
            self.phase = Phase::Synced;
            self.bytes_programmed += frame.len() as u64;
            self.write_off += frame.len();
            self.next_seq += 1;
            self.state = trial;
            self.frames_written += 1;
            self.phase = Phase::Published;
            return Ok(Commit::Appended);
        }
        self.compact(&trial)?;
        self.phase = Phase::Published;
        Ok(Commit::Compacted)
    }

    // ---- the named operations: each is one transaction

    /// # Errors
    /// As [`Journal::commit`].
    pub fn put(&mut self, ns: Namespace, key: &[u8], value: &[u8]) -> Result<Commit, JournalError> {
        self.commit(&[Op::Put {
            ns,
            key: key.to_vec(),
            value: value.to_vec(),
        }])
    }

    /// # Errors
    /// As [`Journal::commit`].
    pub fn delete(&mut self, ns: Namespace, key: &[u8]) -> Result<Commit, JournalError> {
        self.commit(&[Op::Delete {
            ns,
            key: key.to_vec(),
        }])
    }

    /// Forget every setting (and anything staged). Calibration, credentials, records and marks are untouched.
    ///
    /// # Errors
    /// As [`Journal::commit`].
    pub fn reset_settings(&mut self) -> Result<Commit, JournalError> {
        self.staged.clear();
        self.commit(&[Op::Reset {
            ns: Namespace::Settings,
        }])
    }

    /// Forget calibration. Its own operation: nothing else clears it.
    ///
    /// # Errors
    /// As [`Journal::commit`].
    pub fn clear_calibration(&mut self) -> Result<Commit, JournalError> {
        self.commit(&[Op::Reset {
            ns: Namespace::Calibration,
        }])
    }

    /// Admit `id` at `version`, or replace it with a strictly higher one.
    ///
    /// # Errors
    /// [`JournalError::Revoked`] / [`JournalError::NotNewer`] and the rest of [`Journal::commit`].
    pub fn install(
        &mut self,
        id: &[u8],
        version: u64,
        secret: &[u8],
    ) -> Result<Commit, JournalError> {
        self.commit(&[Op::Install {
            id: id.to_vec(),
            version,
            secret: secret.to_vec(),
        }])
    }

    /// # Errors
    /// [`JournalError::AlreadyRevoked`], [`JournalError::NotFound`] and the rest of [`Journal::commit`].
    pub fn revoke(&mut self, id: &[u8]) -> Result<Commit, JournalError> {
        self.commit(&[Op::Revoke { id: id.to_vec() }])
    }

    /// Revoke every live identity (each keeps a tombstone). Settings, calibration, records and marks are untouched.
    ///
    /// # Errors
    /// As [`Journal::commit`].
    pub fn reset_pairing(&mut self) -> Result<Commit, JournalError> {
        self.commit(&[Op::ResetPairing])
    }

    /// Raise a high-water mark; it never goes down.
    ///
    /// # Errors
    /// [`JournalError::MarkRegressed`] and the rest of [`Journal::commit`].
    pub fn raise_mark(&mut self, key: &[u8], value: u64) -> Result<Commit, JournalError> {
        self.commit(&[Op::Raise {
            key: key.to_vec(),
            value,
        }])
    }

    /// Record a settings change in memory only. Any number of these between flushes costs no writes.
    ///
    /// # Errors
    /// [`JournalError::InvalidKey`], [`JournalError::ValueTooLong`], [`JournalError::NamespaceFull`].
    pub fn stage_setting(&mut self, key: &[u8], value: &[u8]) -> Result<(), JournalError> {
        crate::state::check_key(&self.lim, Namespace::Settings, key)?;
        crate::state::check_value(&self.lim, Namespace::Settings, value)?;
        let mut count = self.state.settings.len();
        for staged in self.staged.keys() {
            if !self.state.settings.contains_key(staged) {
                count += 1;
            }
        }
        if !self.state.settings.contains_key(key) && !self.staged.contains_key(key) {
            count += 1;
        }
        if count > self.lim.settings.entries {
            return Err(JournalError::NamespaceFull);
        }
        self.staged.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    /// Commit the staged settings as one transaction, if the flush interval has passed since the last flush.
    ///
    /// # Errors
    /// [`JournalError::RateLimited`] (nothing is written) and the rest of [`Journal::commit`].
    pub fn flush_settings(&mut self, now: u64) -> Result<Commit, JournalError> {
        if self.staged.is_empty() {
            return Ok(Commit::Noop);
        }
        if let Some(last) = self.last_flush {
            let due = last.saturating_add(self.lim.min_flush_interval_ticks);
            if now < due {
                return Err(JournalError::RateLimited {
                    retry_after: due - now,
                });
            }
        }
        let ops: Vec<Op> = self
            .staged
            .iter()
            .map(|(key, value)| Op::Put {
                ns: Namespace::Settings,
                key: key.clone(),
                value: value.clone(),
            })
            .collect();
        let outcome = self.commit(&ops)?;
        self.staged.clear();
        self.last_flush = Some(now);
        Ok(outcome)
    }

    // ---- reading

    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    #[must_use]
    pub fn staged(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.staged
    }

    #[must_use]
    pub fn credential(&self, id: &[u8]) -> Option<&Credential> {
        self.state.credentials.get(id)
    }

    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    #[must_use]
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    #[must_use]
    pub fn compactions(&self) -> u64 {
        self.compactions
    }

    #[must_use]
    pub fn bytes_programmed(&self) -> u64 {
        self.bytes_programmed
    }

    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }
}
