//! The bounded outcome ledger (N02 / `ffw-ugf`): the memory behind "one logical effect per command".
//!
//! Once a command has a terminal outcome, the ledger remembers it under `(peer, seq)`, together with
//! the request body it answered. A retry of that command is then answered from here, with the same
//! outcome, and is never applied again. That is what makes a lost acknowledgement harmless: the
//! client asks again and is told what happened.
//!
//! The memory is bounded in two ways, by entry count and by age, and **forgetting is explicit**.
//! When an entry is evicted for either reason, the peer's *floor* is raised to at least that entry's
//! `seq`. A request whose `seq` is at or below its peer's floor and is no longer remembered gets
//! [`Lookup::OutOfWindow`]: the channel no longer knows whether it was applied and will not apply it
//! again. This is deliberately not "exactly once forever". It is a stronger and more honest promise:
//! a command is applied at most once, and whether it was applied can always be answered while it is
//! remembered and is reported as unknown afterwards.
//!
//! **Why the floor is sound.** An applied command stays in the ledger until it is evicted, and at
//! eviction the floor rises to at least its `seq`. So a `seq` that is above the floor and not in the
//! ledger has never been recorded. The floor is conservative in one direction only: after an eviction
//! it can also cover `seq` values that were never seen (an out-of-order arrival below an evicted
//! entry). Those are reported unknown rather than guessed at.
//!
//! The floor table has one entry per authenticated peer, and the authority bounds how many distinct
//! identities exist, so it is bounded too. Time is injected and treated as non-decreasing: a clock
//! reading earlier than one already seen is raised to it, so a clock fault cannot make entries live
//! longer or shorter than their retention.

use std::collections::{BTreeMap, VecDeque};

use super::peer::PeerId;

/// A ledger that cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("a ledger needs room for at least one entry")]
    ZeroCapacity,
    #[error("a ledger needs a retention of at least one nanosecond")]
    ZeroRetention,
}

struct Entry<B, O> {
    body: B,
    outcome: O,
    recorded_ns: u64,
    /// When the sender first acknowledged this outcome, if it has. Acknowledging changes nothing else:
    /// not the retention, not the eviction order, not the floor.
    acked_ns: Option<u64>,
}

/// What marking an entry acknowledged did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marked {
    /// The first acknowledgement. The entry was `age_ns` old.
    First { age_ns: u64 },
    /// It had been acknowledged before; nothing changed.
    Already,
    /// There is no such entry (never recorded, or forgotten).
    Absent,
}

/// What the ledger knows about a `(peer, seq)`.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a, B, O> {
    /// A recorded outcome, with the body it answered.
    Settled { body: &'a B, outcome: &'a O },
    /// No longer remembered, and at or below the peer's floor: whether it was applied is unknown.
    OutOfWindow { floor: u64 },
    /// Never recorded.
    Unseen,
}

/// One thing a step did to the ledger, kept only while a step is open so it can be undone exactly.
enum Undo<B, O> {
    /// An entry the step recorded.
    Inserted((PeerId, u64)),
    /// An entry the step evicted to make room (or because it had aged out), with the peer's floor as it was.
    Evicted {
        key: (PeerId, u64),
        entry: Entry<B, O>,
        floor_before: Option<u64>,
    },
}

/// Outcomes by `(peer, seq)`, bounded by count and age.
pub struct OutcomeLedger<B, O> {
    entries: BTreeMap<(PeerId, u64), Entry<B, O>>,
    order: VecDeque<(PeerId, u64)>,
    floors: BTreeMap<PeerId, u64>,
    capacity: usize,
    retention_ns: u64,
    clock_ns: u64,
    /// What the open step has done so far, if a step is open ([`OutcomeLedger::begin`]).
    undo: Option<Vec<Undo<B, O>>>,
}

impl<B, O> OutcomeLedger<B, O> {
    /// A ledger holding at most `capacity` entries, each for at most `retention_ns`.
    pub fn new(capacity: usize, retention_ns: u64) -> Result<Self, LedgerError> {
        if capacity == 0 {
            return Err(LedgerError::ZeroCapacity);
        }
        if retention_ns == 0 {
            return Err(LedgerError::ZeroRetention);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            floors: BTreeMap::new(),
            capacity,
            retention_ns,
            clock_ns: 0,
            undo: None,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The peer's floor, if anything of theirs has ever been evicted.
    #[must_use]
    pub fn floor(&self, peer: &PeerId) -> Option<u64> {
        self.floors.get(peer).copied()
    }

    /// How many peers have a floor. Bounded by the number of authenticated identities.
    #[must_use]
    pub fn tracked_peers(&self) -> usize {
        self.floors.len()
    }

    fn advance_clock(&mut self, now_ns: u64) {
        self.clock_ns = self.clock_ns.max(now_ns);
    }

    fn evict_oldest(&mut self) {
        let Some(key) = self.order.pop_front() else {
            return;
        };
        if let Some(entry) = self.entries.remove(&key) {
            let (peer, seq) = key.clone();
            let floor_before = self.floors.get(&peer).copied();
            let floor = self.floors.entry(peer).or_insert(seq);
            *floor = (*floor).max(seq);
            if let Some(undo) = self.undo.as_mut() {
                undo.push(Undo::Evicted {
                    key,
                    entry,
                    floor_before,
                });
            }
        }
    }

    /// Evict every entry whose age has reached the retention. Eviction is oldest first, and entries
    /// are recorded in time order, so this stops at the first one that is still young.
    pub fn expire(&mut self, now_ns: u64) {
        self.advance_clock(now_ns);
        while let Some(key) = self.order.front() {
            let Some(entry) = self.entries.get(key) else {
                self.order.pop_front();
                continue;
            };
            if self.clock_ns.saturating_sub(entry.recorded_ns) < self.retention_ns {
                break;
            }
            self.evict_oldest();
        }
    }

    /// What the ledger knows about `(peer, seq)`.
    #[must_use]
    pub fn lookup(&self, peer: &PeerId, seq: u64) -> Lookup<'_, B, O> {
        if let Some(entry) = self.entries.get(&(peer.clone(), seq)) {
            return Lookup::Settled {
                body: &entry.body,
                outcome: &entry.outcome,
            };
        }
        match self.floors.get(peer) {
            Some(&floor) if seq <= floor => Lookup::OutOfWindow { floor },
            _ => Lookup::Unseen,
        }
    }

    /// Record a terminal outcome. Returns `false`, changing nothing, if `(peer, seq)` already has
    /// one: a terminal outcome is never overwritten. At capacity the oldest entry is evicted first.
    #[must_use = "a false result means the outcome was not recorded"]
    pub fn record(&mut self, peer: PeerId, seq: u64, body: B, outcome: O, now_ns: u64) -> bool {
        self.expire(now_ns);
        let key = (peer, seq);
        if self.entries.contains_key(&key) {
            return false;
        }
        while self.entries.len() >= self.capacity {
            let before = self.entries.len();
            self.evict_oldest();
            // The two structures always agree, so every pass either evicts or consumes a stale key.
            // If they ever did not, give up rather than spin: a bounded ledger must not loop forever.
            if self.entries.len() == before && self.order.is_empty() {
                return false;
            }
        }
        if let Some(undo) = self.undo.as_mut() {
            undo.push(Undo::Inserted(key.clone()));
        }
        self.order.push_back(key.clone());
        self.entries.insert(
            key,
            Entry {
                body,
                outcome,
                recorded_ns: self.clock_ns,
                acked_ns: None,
            },
        );
        true
    }

    /// Note that the sender acknowledged `(peer, seq)`. Entries past their retention are forgotten first,
    /// so a forgotten entry is `Absent`. Only the flag is set; nothing about how long the entry lives.
    pub fn mark_acked(&mut self, peer: &PeerId, seq: u64, now_ns: u64) -> Marked {
        self.expire(now_ns);
        let clock_ns = self.clock_ns;
        match self.entries.get_mut(&(peer.clone(), seq)) {
            None => Marked::Absent,
            Some(entry) if entry.acked_ns.is_some() => Marked::Already,
            Some(entry) => {
                entry.acked_ns = Some(clock_ns);
                Marked::First {
                    age_ns: clock_ns.saturating_sub(entry.recorded_ns),
                }
            }
        }
    }

    /// How many remembered outcomes nobody has acknowledged.
    #[must_use]
    pub fn unacked(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.acked_ns.is_none())
            .count()
    }

    /// Open a step: from now until [`OutcomeLedger::commit`] or [`OutcomeLedger::rollback`], everything `record` does
    /// (the entries it adds, and the older ones it evicts, with the floors that raises) is kept so it can be undone.
    /// Expiry by age before the step is not part of it; do that first.
    pub fn begin(&mut self) {
        self.undo = Some(Vec::new());
    }

    /// The open step stands. What it recorded and evicted is final.
    pub fn commit(&mut self) {
        self.undo = None;
    }

    /// Undo the open step exactly: its entries are gone (`Unseen` again, no floor raised), and every entry it evicted
    /// is back, in its place in the eviction order, with the peer's floor as it was. Without an open step this does
    /// nothing.
    ///
    /// This is for an owner that has *not delivered* a step's outcomes because it could not make the step durable and
    /// has rolled the step's effect back: until it does this, a retry would be answered with a result the client was
    /// never given, and the older outcomes the step pushed out would answer `OutOfWindow` for no reason.
    pub fn rollback(&mut self) {
        let Some(mut undo) = self.undo.take() else {
            return;
        };
        while let Some(done) = undo.pop() {
            match done {
                Undo::Inserted(key) => {
                    self.entries.remove(&key);
                    if let Some(position) = self.order.iter().rposition(|queued| *queued == key) {
                        let _ = self.order.remove(position);
                    }
                }
                Undo::Evicted {
                    key,
                    entry,
                    floor_before,
                } => {
                    match floor_before {
                        Some(floor) => {
                            self.floors.insert(key.0.clone(), floor);
                        }
                        None => {
                            self.floors.remove(&key.0);
                        }
                    }
                    self.order.push_front(key.clone());
                    self.entries.insert(key, entry);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Ledger = OutcomeLedger<&'static str, u32>;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn ledger(capacity: usize, retention_ns: u64) -> Ledger {
        Ledger::new(capacity, retention_ns).unwrap()
    }

    fn settled(l: &Ledger, peer: &PeerId, seq: u64) -> Option<(&'static str, u32)> {
        match l.lookup(peer, seq) {
            Lookup::Settled { body, outcome } => Some((*body, *outcome)),
            _ => None,
        }
    }

    #[test]
    fn a_ledger_needs_room_and_a_retention() {
        assert_eq!(Ledger::new(0, 10).err(), Some(LedgerError::ZeroCapacity));
        assert_eq!(Ledger::new(1, 0).err(), Some(LedgerError::ZeroRetention));
        assert!(Ledger::new(1, 1).is_ok());
    }

    #[test]
    fn a_recorded_outcome_is_returned_with_the_body_it_answered() {
        let mut l = ledger(8, 1_000);
        let a = id("a");
        assert_eq!(l.lookup(&a, 1), Lookup::Unseen);
        assert!(l.record(a.clone(), 1, "vol+5", 42, 0));
        assert_eq!(settled(&l, &a, 1), Some(("vol+5", 42)));
        assert_eq!(l.lookup(&a, 2), Lookup::Unseen);
        assert_eq!(
            l.lookup(&id("b"), 1),
            Lookup::Unseen,
            "a different peer has its own numbers"
        );
        assert_eq!((l.len(), l.is_empty()), (1, false));
    }

    #[test]
    fn a_terminal_outcome_is_never_overwritten() {
        let mut l = ledger(8, 1_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "first", 1, 0));
        assert!(!l.record(a.clone(), 1, "second", 2, 5));
        assert_eq!(settled(&l, &a, 1), Some(("first", 1)));
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn at_capacity_the_oldest_is_evicted_and_becomes_explicitly_unknown() {
        let mut l = ledger(3, 1_000_000);
        let a = id("a");
        for seq in 1..=4 {
            assert!(l.record(a.clone(), seq, "c", seq as u32, seq));
        }
        assert_eq!(l.len(), 3);
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
        for seq in 2..=4 {
            assert_eq!(settled(&l, &a, seq), Some(("c", seq as u32)), "seq {seq}");
        }
        assert_eq!(l.floor(&a), Some(1));
        // The next number was never recorded and is above the floor.
        assert_eq!(l.lookup(&a, 5), Lookup::Unseen);
    }

    #[test]
    fn an_entry_expires_exactly_when_its_age_reaches_the_retention() {
        let mut l = ledger(8, 100);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "c", 1, 0));
        l.expire(99);
        assert!(
            settled(&l, &a, 1).is_some(),
            "age 99 is still within retention"
        );
        l.expire(100);
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
        assert!(l.is_empty());
    }

    #[test]
    fn expiry_removes_only_the_old_and_raises_the_floor_to_the_newest_removed() {
        let mut l = ledger(8, 100);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "c", 1, 0));
        assert!(l.record(a.clone(), 2, "c", 2, 50));
        assert!(l.record(a.clone(), 3, "c", 3, 90));
        // At t = 150 the ages are 150, 100 and 60: the first two have reached the retention of 100.
        l.expire(150);
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 2 });
        assert_eq!(l.lookup(&a, 2), Lookup::OutOfWindow { floor: 2 });
        assert!(settled(&l, &a, 3).is_some());
        assert_eq!(l.floor(&a), Some(2));
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn a_recorded_command_never_reads_as_unseen_afterwards() {
        // The property the floor exists for, over a deterministic mixed schedule of records,
        // expiries and clock readings (a small linear congruential generator, fixed seed).
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        let peers = [id("a"), id("b"), id("c")];
        let mut l = ledger(7, 400);
        let mut recorded: Vec<(usize, u64)> = Vec::new();
        let mut clock = 0u64;
        let mut next_seq = [1u64, 1, 1];
        for _ in 0..2_000 {
            clock += next() % 60;
            match next() % 4 {
                0 | 1 => {
                    // Mostly in order, sometimes a gap, sometimes a late low number.
                    let p = (next() % 3) as usize;
                    let seq = match next() % 8 {
                        0 => next_seq[p].saturating_sub(1 + next() % 5).max(1),
                        1 => next_seq[p] + next() % 4,
                        _ => next_seq[p],
                    };
                    if matches!(l.lookup(&peers[p], seq), Lookup::Unseen)
                        && l.record(peers[p].clone(), seq, "c", 0, clock)
                    {
                        recorded.push((p, seq));
                    }
                    next_seq[p] = next_seq[p].max(seq + 1);
                }
                2 => l.expire(clock),
                _ => {}
            }
            assert!(l.len() <= 7, "the ledger outgrew its capacity");
            assert!(l.tracked_peers() <= peers.len());
            for &(p, seq) in &recorded {
                assert!(
                    !matches!(l.lookup(&peers[p], seq), Lookup::Unseen),
                    "peer {p} seq {seq} was recorded and now reads as never seen"
                );
            }
        }
        assert!(
            recorded.len() > 100,
            "the schedule must actually record things"
        );
    }

    #[test]
    fn the_floor_also_covers_a_number_that_was_never_seen_below_an_evicted_one() {
        // Out-of-order arrival: 9 is recorded before 7. 9 is evicted first (oldest), so the floor is
        // 9 and the never-seen 8 reads as unknown, while the still-remembered 7 stays answerable.
        let mut l = ledger(2, 1_000_000);
        let a = id("a");
        assert!(l.record(a.clone(), 9, "c", 9, 0));
        assert!(l.record(a.clone(), 7, "c", 7, 1));
        assert!(l.record(a.clone(), 10, "c", 10, 2)); // evicts 9
        assert_eq!(l.floor(&a), Some(9));
        assert!(settled(&l, &a, 7).is_some());
        assert_eq!(l.lookup(&a, 8), Lookup::OutOfWindow { floor: 9 });
        assert_eq!(l.lookup(&a, 9), Lookup::OutOfWindow { floor: 9 });
        assert_eq!(l.lookup(&a, 11), Lookup::Unseen);
    }

    #[test]
    fn floors_are_per_peer() {
        let mut l = ledger(2, 1_000_000);
        let (a, b) = (id("a"), id("b"));
        assert!(l.record(a.clone(), 1, "c", 1, 0));
        assert!(l.record(a.clone(), 2, "c", 2, 1));
        assert!(l.record(a.clone(), 3, "c", 3, 2)); // evicts a:1
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
        assert_eq!(l.floor(&b), None);
        assert_eq!(
            l.lookup(&b, 1),
            Lookup::Unseen,
            "b is unaffected by a's floor"
        );
    }

    #[test]
    fn memory_stays_bounded_over_a_long_run() {
        let mut l = ledger(8, 1_000_000_000);
        let a = id("a");
        for seq in 1..=10_000u64 {
            assert!(l.record(a.clone(), seq, "c", 0, seq));
            assert!(l.len() <= 8);
        }
        assert_eq!(l.len(), 8);
        assert_eq!(l.floor(&a), Some(10_000 - 8));
        assert_eq!(l.tracked_peers(), 1);
    }

    #[test]
    fn a_clock_that_runs_backwards_cannot_extend_or_shorten_retention() {
        let mut l = ledger(8, 100);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "c", 1, 1_000));
        // A reading from the past does not rewind the ledger's notion of now.
        l.expire(0);
        assert!(settled(&l, &a, 1).is_some());
        // An entry recorded "at" an earlier time is stamped with the newest time seen, so it still
        // lives for the full retention from then.
        assert!(l.record(a.clone(), 2, "c", 2, 500));
        l.expire(1_099);
        assert!(settled(&l, &a, 2).is_some());
        l.expire(1_100);
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 2 });
        assert_eq!(l.lookup(&a, 2), Lookup::OutOfWindow { floor: 2 });
    }

    #[test]
    fn marking_acknowledged_is_first_once_then_already_and_absent_when_unknown() {
        let mut l = ledger(8, 1_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 100));
        assert_eq!(l.unacked(), 1);
        assert_eq!(l.mark_acked(&a, 1, 130), Marked::First { age_ns: 30 });
        assert_eq!(l.unacked(), 0);
        assert_eq!(l.mark_acked(&a, 1, 140), Marked::Already);
        assert_eq!(l.mark_acked(&a, 2, 140), Marked::Absent);
        assert_eq!(l.mark_acked(&id("b"), 1, 140), Marked::Absent);
    }

    #[test]
    fn an_acknowledged_entry_is_remembered_exactly_as_long_as_an_unacknowledged_one() {
        let mut l = ledger(8, 1_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 0));
        assert!(l.record(a.clone(), 2, "y", 2, 0));
        assert_eq!(l.mark_acked(&a, 1, 10), Marked::First { age_ns: 10 });
        l.expire(999);
        assert_eq!(settled(&l, &a, 1), Some(("x", 1)));
        assert_eq!(settled(&l, &a, 2), Some(("y", 2)));
        l.expire(1_000);
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 2 });
        assert_eq!(l.lookup(&a, 2), Lookup::OutOfWindow { floor: 2 });
        assert_eq!(l.unacked(), 0);
    }

    #[test]
    fn marking_a_forgotten_entry_is_absent_even_at_the_instant_it_expires() {
        let mut l = ledger(8, 1_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 0));
        assert_eq!(l.mark_acked(&a, 1, 1_000), Marked::Absent);
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
    }

    #[test]
    fn eviction_for_capacity_forgets_the_unacknowledged_count_with_the_entry() {
        let mut l = ledger(2, 1_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 0));
        assert!(l.record(a.clone(), 2, "y", 2, 0));
        assert_eq!(l.unacked(), 2);
        assert!(l.record(a.clone(), 3, "z", 3, 0));
        assert_eq!(l.len(), 2);
        assert_eq!(l.unacked(), 2, "the evicted entry no longer counts");
    }

    #[test]
    fn a_rolled_back_step_is_unseen_again_and_raises_no_floor() {
        let mut l = ledger(8, 1_000_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 0));
        l.begin();
        assert!(l.record(a.clone(), 2, "y", 2, 0));
        assert_eq!(settled(&l, &a, 2), Some(("y", 2)));
        l.rollback();
        // Not eviction: no floor, so a retry is a first application, and the number can be recorded afresh.
        assert_eq!(l.lookup(&a, 2), Lookup::Unseen);
        assert_eq!(l.floor(&a), None);
        assert_eq!(
            settled(&l, &a, 1),
            Some(("x", 1)),
            "what was recorded before the step is untouched"
        );
        assert!(l.record(a.clone(), 2, "again", 3, 0));
        assert_eq!(settled(&l, &a, 2), Some(("again", 3)));
        // With no open step there is nothing to undo.
        l.rollback();
        assert_eq!(settled(&l, &a, 2), Some(("again", 3)));
    }

    #[test]
    fn a_rolled_back_step_gives_back_what_it_evicted_with_the_floor_and_the_order() {
        // Full at capacity 3 with two peers. The step records two outcomes and so evicts the two oldest.
        let mut l = ledger(3, 1_000_000);
        let (a, b) = (id("a"), id("b"));
        assert!(l.record(a.clone(), 1, "a1", 1, 0));
        assert!(l.record(b.clone(), 1, "b1", 2, 0));
        assert!(l.record(a.clone(), 2, "a2", 3, 0));
        l.begin();
        assert!(l.record(b.clone(), 2, "b2", 4, 0));
        assert!(l.record(a.clone(), 3, "a3", 5, 0));
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
        assert_eq!(l.lookup(&b, 1), Lookup::OutOfWindow { floor: 1 });
        l.rollback();
        // Every previously settled outcome answers as it did, and no floor was left behind.
        assert_eq!(settled(&l, &a, 1), Some(("a1", 1)));
        assert_eq!(settled(&l, &b, 1), Some(("b1", 2)));
        assert_eq!(settled(&l, &a, 2), Some(("a2", 3)));
        assert_eq!((l.floor(&a), l.floor(&b)), (None, None));
        assert_eq!(l.lookup(&b, 2), Lookup::Unseen);
        assert_eq!(l.lookup(&a, 3), Lookup::Unseen);
        assert_eq!(l.len(), 3);
        // The eviction order is as it was: the next record evicts a1 first, then b1.
        assert!(l.record(b.clone(), 3, "b3", 6, 0));
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
        assert_eq!(settled(&l, &b, 1), Some(("b1", 2)));
        assert!(l.record(a.clone(), 4, "a4", 7, 0));
        assert_eq!(l.lookup(&b, 1), Lookup::OutOfWindow { floor: 1 });
    }

    #[test]
    fn a_committed_step_is_final() {
        let mut l = ledger(2, 1_000_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 0));
        assert!(l.record(a.clone(), 2, "y", 2, 0));
        l.begin();
        assert!(l.record(a.clone(), 3, "z", 3, 0));
        l.commit();
        l.rollback();
        assert_eq!(l.lookup(&a, 1), Lookup::OutOfWindow { floor: 1 });
        assert_eq!(settled(&l, &a, 3), Some(("z", 3)));
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn a_floor_that_was_already_there_is_restored_to_its_old_value() {
        let mut l = ledger(2, 1_000_000);
        let a = id("a");
        assert!(l.record(a.clone(), 1, "x", 1, 0));
        assert!(l.record(a.clone(), 2, "y", 2, 0));
        assert!(l.record(a.clone(), 3, "z", 3, 0));
        assert_eq!(l.floor(&a), Some(1));
        l.begin();
        assert!(l.record(a.clone(), 4, "w", 4, 0));
        assert_eq!(l.floor(&a), Some(2));
        l.rollback();
        assert_eq!(l.floor(&a), Some(1));
        assert_eq!(settled(&l, &a, 2), Some(("y", 2)));
        assert_eq!(l.lookup(&a, 4), Lookup::Unseen);
    }
}
