//! Owner-held buffer slots (`P04` / `ffw-0bh`).
//!
//! The one rule: **storage the kernel may still read is never freed or reused.**
//!
//! * The [`SlotTable`] owns every slot's storage. A slot returns to `Free` only when the table is
//!   told the device acknowledged it (a completion, a flush acknowledgment, or a reset
//!   acknowledgment). Nothing a caller holds can do that.
//! * A submit token is inert data (a slot number and a generation). It owns nothing and has no
//!   `Drop`, so forgetting it, dropping it or never polling for it cannot return storage.
//! * Dropping the table itself is the dangerous case: a plain drop would free memory the kernel may
//!   still be reading. So `Drop for SlotTable` keeps the storage of every slot that is not `Free`
//!   alive for the rest of the process (a deliberate, counted leak), and a [`LeakLedger`] caps how
//!   much of that the process will accept: once the cap is reached, new tables are refused.
//!
//! The kernel is modelled safely: it holds a [`KernelView`], a `Weak` reference that does **not**
//! keep storage alive, the way a raw pointer handed to a driver does not. If the owner ever freed
//! storage the kernel was using, the view would fail to upgrade and the fake device would record a
//! use-after-free.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

/// Most slots a table can have.
pub const MAX_SLOTS: usize = 64;
/// Largest block a slot can hold, in bytes.
pub const MAX_BLOCK_BYTES: usize = 1 << 20;
/// Slots the process will agree to leak before it refuses new tables.
pub const DEFAULT_LEAK_CAP_SLOTS: usize = 256;

/// The backing store of one slot.
#[derive(Debug)]
pub struct StorageCell {
    bytes: Mutex<Vec<u8>>,
}

impl StorageCell {
    fn new() -> Self {
        Self {
            bytes: Mutex::new(Vec::new()),
        }
    }

    fn set(&self, data: &[u8]) {
        let mut guard = self.bytes.lock().unwrap_or_else(PoisonError::into_inner);
        guard.clear();
        guard.extend_from_slice(data);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// What the kernel sees when it reads a slot it was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelRead {
    /// The storage is still there; here is what it holds.
    Alive(Vec<u8>),
    /// The owner freed it. A real kernel would be reading freed memory.
    Freed,
}

/// The kernel's non-owning reference to a slot. It does not keep the storage alive.
#[derive(Debug, Clone)]
pub struct KernelView {
    cell: Weak<StorageCell>,
}

impl KernelView {
    /// Read the slot as the kernel would.
    #[must_use]
    pub fn read(&self) -> KernelRead {
        match self.cell.upgrade() {
            Some(cell) => KernelRead::Alive(cell.snapshot()),
            None => KernelRead::Freed,
        }
    }
}

/// Counts the storage deliberately leaked because the kernel might still use it, and caps it.
#[derive(Debug)]
pub struct LeakLedger {
    cap_slots: usize,
    leaked_slots: AtomicUsize,
    leaked_bytes: AtomicUsize,
}

impl LeakLedger {
    #[must_use]
    pub const fn new(cap_slots: usize) -> Self {
        Self {
            cap_slots,
            leaked_slots: AtomicUsize::new(0),
            leaked_bytes: AtomicUsize::new(0),
        }
    }

    /// The process-wide ledger used outside tests.
    #[must_use]
    pub fn process() -> Arc<Self> {
        static PROCESS: OnceLock<Arc<LeakLedger>> = OnceLock::new();
        Arc::clone(PROCESS.get_or_init(|| Arc::new(Self::new(DEFAULT_LEAK_CAP_SLOTS))))
    }

    #[must_use]
    pub const fn cap_slots(&self) -> usize {
        self.cap_slots
    }

    #[must_use]
    pub fn leaked_slots(&self) -> usize {
        self.leaked_slots.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn leaked_bytes(&self) -> usize {
        self.leaked_bytes.load(Ordering::Relaxed)
    }

    /// Whether the process has already leaked as much as it will accept.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.leaked_slots() >= self.cap_slots
    }

    fn record(&self, slots: usize, bytes: usize) {
        self.leaked_slots.fetch_add(slots, Ordering::Relaxed);
        self.leaked_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotState {
    Free,
    /// The device may be reading it. Only an acknowledgment from the device changes this.
    KernelOwned,
    /// A completion was lost or the device misbehaved. Not reusable until a reset is acknowledged.
    Quarantined,
}

/// Where a submit token's slot stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenState {
    InFlight,
    Quarantined,
    /// Completed, or the slot has since been reused for a later submit.
    Settled,
}

/// Why a completion report was refused. The slot is left exactly as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CompletionProblem {
    #[error("slot number is out of range")]
    OutOfRange,
    /// A duplicate (the slot is free) or a report for a quarantined slot.
    #[error("slot is not kernel-owned (it is {0:?})")]
    NotKernelOwned(SlotState),
    #[error("stale generation: slot is at {expected}, report says {got}")]
    StaleGeneration { expected: u32, got: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlotError {
    #[error("slot count {0} is out of range")]
    BadSlotCount(usize),
    #[error("block size {0} is out of range")]
    BadBlockSize(usize),
    #[error("quarantine cap {cap} is out of range for {depth} slot(s)")]
    BadQuarantineCap { cap: usize, depth: usize },
    #[error("the process leak budget is exhausted")]
    LeakBudgetExhausted,
    #[error("no free slot")]
    NoFreeSlot,
    #[error("{len} byte(s) do not fit a {block}-byte block")]
    TooLarge { len: usize, block: usize },
}

#[derive(Debug)]
struct Slot {
    cell: Arc<StorageCell>,
    state: SlotState,
    generation: u32,
}

/// All the storage a session hands to a device, owned in one place.
#[derive(Debug)]
pub struct SlotTable {
    slots: Vec<Slot>,
    block_bytes: usize,
    quarantine_cap: usize,
    ledger: Arc<LeakLedger>,
}

impl SlotTable {
    /// A table of `depth` slots of `block_bytes` each. `quarantine_cap` is how many slots may be
    /// quarantined before the session treats the device as unusable.
    pub fn new(
        depth: usize,
        block_bytes: usize,
        quarantine_cap: usize,
        ledger: Arc<LeakLedger>,
    ) -> Result<Self, SlotError> {
        if depth == 0 || depth > MAX_SLOTS {
            return Err(SlotError::BadSlotCount(depth));
        }
        if block_bytes == 0 || block_bytes > MAX_BLOCK_BYTES {
            return Err(SlotError::BadBlockSize(block_bytes));
        }
        if quarantine_cap == 0 || quarantine_cap > depth {
            return Err(SlotError::BadQuarantineCap {
                cap: quarantine_cap,
                depth,
            });
        }
        if ledger.exhausted() {
            return Err(SlotError::LeakBudgetExhausted);
        }
        let slots = (0..depth)
            .map(|_| Slot {
                cell: Arc::new(StorageCell::new()),
                state: SlotState::Free,
                generation: 0,
            })
            .collect();
        Ok(Self {
            slots,
            block_bytes,
            quarantine_cap,
            ledger,
        })
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub const fn block_bytes(&self) -> usize {
        self.block_bytes
    }

    #[must_use]
    pub fn count(&self, wanted: SlotState) -> usize {
        self.slots.iter().filter(|s| s.state == wanted).count()
    }

    #[must_use]
    pub fn states(&self) -> Vec<SlotState> {
        self.slots.iter().map(|s| s.state).collect()
    }

    /// True once more slots are quarantined than the cap allows.
    #[must_use]
    pub fn quarantine_over_cap(&self) -> bool {
        self.count(SlotState::Quarantined) > self.quarantine_cap
    }

    /// Where the use of a slot named by a token stands.
    #[must_use]
    pub fn token_state(&self, slot: u16, generation: u32) -> TokenState {
        match self.slots.get(usize::from(slot)) {
            Some(s) if s.generation == generation && s.state == SlotState::KernelOwned => {
                TokenState::InFlight
            }
            Some(s) if s.generation == generation && s.state == SlotState::Quarantined => {
                TokenState::Quarantined
            }
            _ => TokenState::Settled,
        }
    }

    /// Fill the lowest free slot with `data` and hand it to the kernel. The storage is written
    /// before the slot becomes kernel-owned; there is no way to write a slot after that.
    pub fn acquire_free(&mut self, data: &[u8]) -> Result<(u16, u32, KernelView), SlotError> {
        if data.len() > self.block_bytes {
            return Err(SlotError::TooLarge {
                len: data.len(),
                block: self.block_bytes,
            });
        }
        let Some(index) = self.slots.iter().position(|s| s.state == SlotState::Free) else {
            return Err(SlotError::NoFreeSlot);
        };
        let slot = &mut self.slots[index];
        slot.cell.set(data);
        slot.generation = slot.generation.wrapping_add(1);
        slot.state = SlotState::KernelOwned;
        let view = KernelView {
            cell: Arc::downgrade(&slot.cell),
        };
        // `index` is below MAX_SLOTS (64), so it always fits.
        Ok((
            u16::try_from(index).unwrap_or(u16::MAX),
            slot.generation,
            view,
        ))
    }

    /// The device took none of it: the slot goes straight back to `Free`.
    pub fn release_unaccepted(&mut self, slot: u16, generation: u32) -> bool {
        match self.slots.get_mut(usize::from(slot)) {
            Some(s) if s.state == SlotState::KernelOwned && s.generation == generation => {
                s.state = SlotState::Free;
                true
            }
            _ => false,
        }
    }

    /// The device reports it finished with a slot.
    pub fn complete(&mut self, slot: u16, generation: u32) -> Result<(), CompletionProblem> {
        let Some(s) = self.slots.get_mut(usize::from(slot)) else {
            return Err(CompletionProblem::OutOfRange);
        };
        if s.state != SlotState::KernelOwned {
            return Err(CompletionProblem::NotKernelOwned(s.state));
        }
        if s.generation != generation {
            return Err(CompletionProblem::StaleGeneration {
                expected: s.generation,
                got: generation,
            });
        }
        s.state = SlotState::Free;
        Ok(())
    }

    /// We cannot tell whether the kernel kept this slot (a submit failed with an error).
    pub fn quarantine_slot(&mut self, slot: u16) {
        if let Some(s) = self.slots.get_mut(usize::from(slot))
            && s.state == SlotState::KernelOwned
        {
            s.state = SlotState::Quarantined;
        }
    }

    /// Everything the kernel may still hold becomes quarantined. Returns how many.
    pub fn quarantine_all_in_flight(&mut self) -> usize {
        let mut moved = 0;
        for s in &mut self.slots {
            if s.state == SlotState::KernelOwned {
                s.state = SlotState::Quarantined;
                moved += 1;
            }
        }
        moved
    }

    /// The device acknowledged a flush: what it held is released. Quarantined slots stay put.
    pub fn free_in_flight_after_flush_ack(&mut self) -> usize {
        let mut freed = 0;
        for s in &mut self.slots {
            if s.state == SlotState::KernelOwned {
                s.state = SlotState::Free;
                freed += 1;
            }
        }
        freed
    }

    /// The device acknowledged a full reset: nothing it held is in use any more.
    pub fn release_all_after_reset_ack(&mut self) -> usize {
        let mut freed = 0;
        for s in &mut self.slots {
            if s.state != SlotState::Free {
                s.state = SlotState::Free;
                freed += 1;
            }
        }
        freed
    }
}

impl Drop for SlotTable {
    /// Destroying the table must not free storage the kernel may still be reading. Every slot that
    /// is not `Free` keeps its storage for the life of the process, and the ledger counts it.
    fn drop(&mut self) {
        let mut slots = 0usize;
        let mut bytes = 0usize;
        for slot in &self.slots {
            if slot.state != SlotState::Free {
                let keep = Arc::clone(&slot.cell);
                bytes += keep.snapshot().len();
                slots += 1;
                std::mem::forget(keep);
            }
        }
        if slots > 0 {
            self.ledger.record(slots, bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(depth: usize) -> (SlotTable, Arc<LeakLedger>) {
        let ledger = Arc::new(LeakLedger::new(8));
        let t = SlotTable::new(depth, 16, depth.min(2), Arc::clone(&ledger)).unwrap();
        (t, ledger)
    }

    #[test]
    fn the_weak_view_really_does_detect_a_free() {
        // Control for every use-after-free assertion below: if the owner dropped the last strong
        // reference, the kernel's view must report it. Otherwise "never freed" would prove nothing.
        let cell = Arc::new(StorageCell::new());
        cell.set(&[1, 2, 3]);
        let view = KernelView {
            cell: Arc::downgrade(&cell),
        };
        assert_eq!(view.read(), KernelRead::Alive(vec![1, 2, 3]));
        drop(cell);
        assert_eq!(view.read(), KernelRead::Freed);
    }

    #[test]
    fn construction_is_bounded() {
        let ledger = Arc::new(LeakLedger::new(8));
        let new = |d, b, q| SlotTable::new(d, b, q, Arc::clone(&ledger));
        assert_eq!(new(0, 16, 1).unwrap_err(), SlotError::BadSlotCount(0));
        assert_eq!(new(65, 16, 1).unwrap_err(), SlotError::BadSlotCount(65));
        assert_eq!(new(4, 0, 1).unwrap_err(), SlotError::BadBlockSize(0));
        assert_eq!(
            new(4, MAX_BLOCK_BYTES + 1, 1).unwrap_err(),
            SlotError::BadBlockSize(MAX_BLOCK_BYTES + 1)
        );
        assert_eq!(
            new(4, 16, 0).unwrap_err(),
            SlotError::BadQuarantineCap { cap: 0, depth: 4 }
        );
        assert_eq!(
            new(4, 16, 5).unwrap_err(),
            SlotError::BadQuarantineCap { cap: 5, depth: 4 }
        );
        // Permitted positive: the largest legal table builds.
        assert!(new(MAX_SLOTS, MAX_BLOCK_BYTES, MAX_SLOTS).is_ok());
    }

    #[test]
    fn a_slot_is_kernel_owned_until_the_device_acknowledges_it() {
        let (mut t, _) = table(2);
        let (slot, generation, view) = t.acquire_free(&[9, 9]).unwrap();
        assert_eq!((slot, generation), (0, 1));
        assert_eq!(t.states(), vec![SlotState::KernelOwned, SlotState::Free]);
        assert_eq!(t.token_state(slot, generation), TokenState::InFlight);
        // The second submit takes the other slot, never the in-flight one.
        let (slot2, _, _) = t.acquire_free(&[8]).unwrap();
        assert_eq!(slot2, 1);
        assert_eq!(t.acquire_free(&[7]).unwrap_err(), SlotError::NoFreeSlot);
        assert_eq!(view.read(), KernelRead::Alive(vec![9, 9]));
        // The completion frees it, and only then can it be reused (with a new generation).
        assert_eq!(t.complete(slot, generation), Ok(()));
        assert_eq!(t.token_state(slot, generation), TokenState::Settled);
        let (again, g2, _) = t.acquire_free(&[5]).unwrap();
        assert_eq!((again, g2), (0, 2));
    }

    #[test]
    fn bad_completions_change_nothing() {
        let (mut t, _) = table(2);
        let (slot, generation, _view) = t.acquire_free(&[1]).unwrap();
        let before = t.states();
        assert_eq!(t.complete(9, 1), Err(CompletionProblem::OutOfRange));
        assert_eq!(
            t.complete(1, 1),
            Err(CompletionProblem::NotKernelOwned(SlotState::Free))
        );
        assert_eq!(
            t.complete(slot, generation + 1),
            Err(CompletionProblem::StaleGeneration {
                expected: 1,
                got: 2
            })
        );
        assert_eq!(
            t.states(),
            before,
            "a refused completion must not move any slot"
        );
        // Permitted positive: the right completion is accepted, and a duplicate of it is not.
        assert_eq!(t.complete(slot, generation), Ok(()));
        assert_eq!(
            t.complete(slot, generation),
            Err(CompletionProblem::NotKernelOwned(SlotState::Free))
        );
    }

    #[test]
    fn a_stale_completion_cannot_free_the_new_occupant() {
        let (mut t, _) = table(1);
        let (slot, g1, _) = t.acquire_free(&[1]).unwrap();
        assert_eq!(t.complete(slot, g1), Ok(()));
        let (slot, g2, view) = t.acquire_free(&[2]).unwrap();
        assert_eq!(g2, g1 + 1);
        // A late duplicate of the first completion arrives while the slot holds the second use.
        assert_eq!(
            t.complete(slot, g1),
            Err(CompletionProblem::StaleGeneration {
                expected: g2,
                got: g1
            })
        );
        assert_eq!(t.states(), vec![SlotState::KernelOwned]);
        assert_eq!(view.read(), KernelRead::Alive(vec![2]));
    }

    #[test]
    fn quarantine_is_not_released_by_a_flush_only_by_a_reset() {
        let (mut t, _) = table(3);
        t.acquire_free(&[1]).unwrap();
        t.acquire_free(&[2]).unwrap();
        assert_eq!(t.quarantine_all_in_flight(), 2);
        assert_eq!(t.count(SlotState::Quarantined), 2);
        // A flush acknowledgment frees what was merely in flight, never what was quarantined.
        assert_eq!(t.free_in_flight_after_flush_ack(), 0);
        assert_eq!(t.count(SlotState::Quarantined), 2);
        assert_eq!(t.release_all_after_reset_ack(), 2);
        assert_eq!(t.count(SlotState::Free), 3);
    }

    #[test]
    fn the_quarantine_cap_is_reported() {
        let (mut t, _) = table(4); // cap 2
        for _ in 0..3 {
            t.acquire_free(&[1]).unwrap();
        }
        t.quarantine_all_in_flight();
        assert!(t.quarantine_over_cap(), "3 quarantined with a cap of 2");
        t.release_all_after_reset_ack();
        assert!(!t.quarantine_over_cap());
    }

    #[test]
    fn dropping_the_table_keeps_what_the_kernel_may_still_read() {
        let (mut t, ledger) = table(3);
        // Take all three slots first, so each keeps its own storage (a free slot is reused lowest
        // first): 0 stays in flight, 1 is completed, 2 is quarantined.
        let (_, _, in_flight) = t.acquire_free(&[7; 4]).unwrap();
        let (s1, g1, done) = t.acquire_free(&[6; 2]).unwrap();
        let (s2, _, quarantined) = t.acquire_free(&[5; 8]).unwrap();
        assert_eq!((s1, s2), (1, 2));
        t.complete(s1, g1).unwrap();
        t.quarantine_slot(s2);
        assert_eq!(
            t.states(),
            vec![
                SlotState::KernelOwned,
                SlotState::Free,
                SlotState::Quarantined
            ]
        );
        drop(t);
        // Kernel-owned and quarantined storage survives the table.
        assert_eq!(in_flight.read(), KernelRead::Alive(vec![7; 4]));
        assert_eq!(quarantined.read(), KernelRead::Alive(vec![5; 8]));
        // A slot that was properly completed is freed with the table, so nothing leaks needlessly.
        assert_eq!(done.read(), KernelRead::Freed);
        assert_eq!(ledger.leaked_slots(), 2);
        assert_eq!(ledger.leaked_bytes(), 4 + 8);
    }

    #[test]
    fn a_clean_table_leaks_nothing() {
        let (mut t, ledger) = table(2);
        let (s, g, view) = t.acquire_free(&[1]).unwrap();
        t.complete(s, g).unwrap();
        drop(t);
        assert_eq!(view.read(), KernelRead::Freed);
        assert_eq!(ledger.leaked_slots(), 0);
    }

    #[test]
    fn the_leak_budget_bounds_how_many_tables_are_admitted() {
        let ledger = Arc::new(LeakLedger::new(2));
        for round in 0..2 {
            let mut t = SlotTable::new(2, 8, 2, Arc::clone(&ledger)).unwrap();
            t.acquire_free(&[1]).unwrap();
            drop(t); // leaks one slot each time
            assert_eq!(ledger.leaked_slots(), round + 1);
        }
        assert!(ledger.exhausted());
        assert_eq!(
            SlotTable::new(2, 8, 2, Arc::clone(&ledger)).unwrap_err(),
            SlotError::LeakBudgetExhausted
        );
    }

    #[test]
    fn an_unaccepted_submit_returns_the_slot_but_a_stale_release_does_not() {
        let (mut t, _) = table(1);
        let (s, g, _) = t.acquire_free(&[1]).unwrap();
        assert!(!t.release_unaccepted(s, g + 1), "wrong generation");
        assert_eq!(t.states(), vec![SlotState::KernelOwned]);
        assert!(t.release_unaccepted(s, g));
        assert_eq!(t.states(), vec![SlotState::Free]);
        assert!(!t.release_unaccepted(s, g), "already free");
    }

    #[test]
    fn oversized_data_is_refused_without_touching_a_slot() {
        let (mut t, _) = table(1);
        assert_eq!(
            t.acquire_free(&[0; 17]).unwrap_err(),
            SlotError::TooLarge { len: 17, block: 16 }
        );
        assert_eq!(t.states(), vec![SlotState::Free]);
    }

    #[test]
    fn the_shared_process_ledger_is_one_ledger() {
        assert!(Arc::ptr_eq(&LeakLedger::process(), &LeakLedger::process()));
        assert_eq!(LeakLedger::process().cap_slots(), DEFAULT_LEAK_CAP_SLOTS);
    }
}
