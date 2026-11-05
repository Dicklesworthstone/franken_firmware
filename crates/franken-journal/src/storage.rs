//! The storage the journal runs over, and an in-memory fake that can fail at any byte.
//!
//! The model is a flash-like medium of two erase segments with a volatile write cache. Programming can only clear bits,
//! so a byte that is not erased can only be programmed to a value whose set bits are a subset of what is there. Reads see
//! the cache. `sync` makes everything issued before it durable. On a power cut the medium keeps the durable bytes plus a
//! byte-budgeted prefix of the operations issued since the last sync, in issue order (or in reverse order, to model a
//! device that persists out of order), the last of them possibly torn.

use crate::codec::ERASED;
use std::fmt;

/// A storage failure. These carry no data from the medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFault {
    Io,
    OutOfRange,
    /// A program would need to set a bit that is clear: the target was not erased.
    BitsCannotRise,
    PowerCut,
    SyncFailed,
}

impl StorageFault {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::OutOfRange => "out_of_range",
            Self::BitsCannotRise => "bits_cannot_rise",
            Self::PowerCut => "power_cut",
            Self::SyncFailed => "sync_failed",
        }
    }
}

impl fmt::Display for StorageFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Two erase segments of `segment_bytes()` each, addressed as one range of `2 * segment_bytes()` bytes.
pub trait Storage {
    fn segment_bytes(&self) -> usize;

    /// # Errors
    /// [`StorageFault::OutOfRange`], or a fault of the medium.
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault>;

    /// Program `data` at `offset`. Only 1 to 0 transitions are possible.
    ///
    /// # Errors
    /// [`StorageFault::BitsCannotRise`] if a bit would have to be set, [`StorageFault::OutOfRange`], or a medium fault.
    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault>;

    /// Erase one segment to all ones.
    ///
    /// # Errors
    /// [`StorageFault::OutOfRange`] for a segment other than 0 or 1, or a medium fault.
    fn erase(&mut self, segment: usize) -> Result<(), StorageFault>;

    /// Make everything issued so far durable.
    ///
    /// # Errors
    /// [`StorageFault::SyncFailed`]: the outcome on the medium is then unknown.
    fn sync(&mut self) -> Result<(), StorageFault>;
}

/// A borrowed storage is a storage, so a test can open a journal on `&mut medium`, drop it, and reuse the medium
/// (including after an open that failed).
impl<T: Storage + ?Sized> Storage for &mut T {
    fn segment_bytes(&self) -> usize {
        (**self).segment_bytes()
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        (**self).read(offset, out)
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        (**self).program(offset, data)
    }

    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        (**self).erase(segment)
    }

    fn sync(&mut self) -> Result<(), StorageFault> {
        (**self).sync()
    }
}

#[derive(Debug, Clone)]
enum Pending {
    Program { offset: usize, data: Vec<u8> },
    Erase { base: usize },
}

/// The in-memory medium with fault injection. All plan fields are public so a test states exactly what it injects.
#[derive(Debug, Clone)]
pub struct MemStorage {
    segment: usize,
    media: Vec<u8>,
    view: Vec<u8>,
    pending: Vec<Pending>,
    ops_done: usize,
    pending_before: Vec<usize>,
    /// Power is cut when the operation with this index is about to start.
    pub cut_after_ops: Option<usize>,
    /// Bytes of the unsynced operations that reach the medium at the cut.
    pub cut_budget: usize,
    /// Apply the unsynced operations newest first at the cut.
    pub cut_reverse: bool,
    /// The program or erase with this index fails with [`StorageFault::Io`] and has no effect.
    pub fail_op_at: Option<usize>,
    /// The sync with this index fails and cuts power.
    pub sync_fail_at: Option<usize>,
    /// Whether a failed sync nevertheless made the unsynced operations durable.
    pub sync_fail_persists: bool,
    dead: bool,
}

impl MemStorage {
    #[must_use]
    pub fn new(segment_bytes: usize) -> Self {
        Self {
            segment: segment_bytes,
            media: vec![ERASED; 2 * segment_bytes],
            view: vec![ERASED; 2 * segment_bytes],
            pending: Vec::new(),
            ops_done: 0,
            pending_before: Vec::new(),
            cut_after_ops: None,
            cut_budget: 0,
            cut_reverse: false,
            fail_op_at: None,
            sync_fail_at: None,
            sync_fail_persists: false,
            dead: false,
        }
    }

    /// A medium holding `image` (both segments) as if it had always been there.
    ///
    /// # Panics
    /// If the image is not exactly two segments.
    #[must_use]
    pub fn from_image(segment_bytes: usize, image: &[u8]) -> Self {
        assert_eq!(
            image.len(),
            2 * segment_bytes,
            "an image is exactly two segments"
        );
        let mut me = Self::new(segment_bytes);
        me.media.copy_from_slice(image);
        me.view.copy_from_slice(image);
        me
    }

    /// The durable bytes.
    #[must_use]
    pub fn durable(&self) -> &[u8] {
        &self.media
    }

    /// Storage operations (program, erase, sync) completed so far.
    #[must_use]
    pub const fn ops_done(&self) -> usize {
        self.ops_done
    }

    /// Bytes pending before each operation that was attempted, in order.
    #[must_use]
    pub fn pending_before(&self) -> &[usize] {
        &self.pending_before
    }

    #[must_use]
    pub const fn is_dead(&self) -> bool {
        self.dead
    }

    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending
            .iter()
            .map(|p| match p {
                Pending::Program { data, .. } => data.len(),
                Pending::Erase { .. } => self.segment,
            })
            .sum()
    }

    fn begin(&mut self, is_sync: bool) -> Result<(), StorageFault> {
        if self.dead {
            return Err(StorageFault::PowerCut);
        }
        let pending = self.pending_bytes();
        self.pending_before.push(pending);
        if self.cut_after_ops == Some(self.ops_done) {
            self.power_cut(self.cut_budget, self.cut_reverse);
            return Err(StorageFault::PowerCut);
        }
        if !is_sync && self.fail_op_at == Some(self.ops_done) {
            self.ops_done += 1;
            return Err(StorageFault::Io);
        }
        Ok(())
    }

    /// Cut the power: keep the durable bytes plus `budget` bytes of the pending operations (newest first if `reverse`).
    pub fn power_cut(&mut self, budget: usize, reverse: bool) {
        let mut pending = std::mem::take(&mut self.pending);
        if reverse {
            pending.reverse();
        }
        let mut left = budget;
        for op in pending {
            match op {
                Pending::Program { offset, data } => {
                    let take = data.len().min(left);
                    for (i, byte) in data.iter().take(take).enumerate() {
                        self.media[offset + i] &= *byte;
                    }
                    left -= take;
                }
                Pending::Erase { base } => {
                    let take = self.segment.min(left);
                    for byte in &mut self.media[base..base + take] {
                        *byte = ERASED;
                    }
                    left -= take;
                }
            }
        }
        self.view.clone_from(&self.media);
        self.dead = true;
    }

    /// Power returns: only the durable bytes remain and the fault plan is cleared.
    pub fn restart(&mut self) {
        self.view.clone_from(&self.media);
        self.pending.clear();
        self.dead = false;
        self.cut_after_ops = None;
        self.fail_op_at = None;
        self.sync_fail_at = None;
    }
}

impl Storage for MemStorage {
    fn segment_bytes(&self) -> usize {
        self.segment
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        if self.dead {
            return Err(StorageFault::PowerCut);
        }
        let end = offset
            .checked_add(out.len())
            .ok_or(StorageFault::OutOfRange)?;
        if end > self.view.len() {
            return Err(StorageFault::OutOfRange);
        }
        out.copy_from_slice(&self.view[offset..end]);
        Ok(())
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        self.begin(false)?;
        let end = offset
            .checked_add(data.len())
            .ok_or(StorageFault::OutOfRange)?;
        if end > self.view.len() {
            return Err(StorageFault::OutOfRange);
        }
        for (i, byte) in data.iter().enumerate() {
            if *byte & !self.view[offset + i] != 0 {
                return Err(StorageFault::BitsCannotRise);
            }
        }
        for (i, byte) in data.iter().enumerate() {
            self.view[offset + i] &= *byte;
        }
        self.pending.push(Pending::Program {
            offset,
            data: data.to_vec(),
        });
        self.ops_done += 1;
        Ok(())
    }

    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        self.begin(false)?;
        if segment > 1 {
            return Err(StorageFault::OutOfRange);
        }
        let base = segment * self.segment;
        for byte in &mut self.view[base..base + self.segment] {
            *byte = ERASED;
        }
        self.pending.push(Pending::Erase { base });
        self.ops_done += 1;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), StorageFault> {
        self.begin(true)?;
        if self.sync_fail_at == Some(self.ops_done) {
            self.ops_done += 1;
            if self.sync_fail_persists {
                self.media.clone_from(&self.view);
            }
            self.pending.clear();
            self.view.clone_from(&self.media);
            self.dead = true;
            return Err(StorageFault::SyncFailed);
        }
        self.media.clone_from(&self.view);
        self.pending.clear();
        self.ops_done += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programming_can_only_clear_bits_and_an_erase_restores_them() {
        let mut m = MemStorage::new(16);
        m.program(0, &[0xF0]).unwrap();
        m.program(0, &[0x30]).unwrap(); // clears two more bits: fine
        assert_eq!(m.program(0, &[0xF0]), Err(StorageFault::BitsCannotRise));
        m.erase(0).unwrap();
        m.program(0, &[0xF0]).unwrap();
    }

    #[test]
    fn a_cut_keeps_the_durable_bytes_plus_a_budgeted_prefix_of_what_was_not_synced() {
        let mut m = MemStorage::new(16);
        m.program(0, &[1, 2, 3, 4]).unwrap();
        m.sync().unwrap();
        m.program(8, &[5, 6, 7, 8]).unwrap();
        m.power_cut(2, false);
        assert_eq!(&m.durable()[0..4], &[1, 2, 3, 4]);
        assert_eq!(&m.durable()[8..12], &[5, 6, ERASED, ERASED]);
        m.restart();
        let mut out = [0u8; 4];
        m.read(8, &mut out).unwrap();
        assert_eq!(out, [5, 6, ERASED, ERASED]);
    }

    #[test]
    fn unsynced_writes_are_visible_to_reads_but_not_durable() {
        let mut m = MemStorage::new(16);
        m.program(0, &[9]).unwrap();
        let mut out = [0u8; 1];
        m.read(0, &mut out).unwrap();
        assert_eq!(out[0], 9);
        assert_eq!(m.durable()[0], ERASED);
    }

    #[test]
    fn a_failed_sync_can_leave_the_data_or_not_and_kills_the_power() {
        for persists in [false, true] {
            let mut m = MemStorage::new(16);
            m.program(0, &[7]).unwrap();
            m.sync_fail_at = Some(1);
            m.sync_fail_persists = persists;
            assert_eq!(m.sync(), Err(StorageFault::SyncFailed));
            assert_eq!(m.durable()[0], if persists { 7 } else { ERASED });
            assert_eq!(m.program(1, &[1]), Err(StorageFault::PowerCut));
        }
    }

    #[test]
    fn an_io_failure_has_no_effect_on_the_view() {
        let mut m = MemStorage::new(16);
        m.fail_op_at = Some(0);
        assert_eq!(m.program(0, &[1]), Err(StorageFault::Io));
        let mut out = [0u8; 1];
        m.read(0, &mut out).unwrap();
        assert_eq!(out[0], ERASED);
    }
}
