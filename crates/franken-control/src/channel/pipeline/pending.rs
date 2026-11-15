//! Consuming-owner durable control step: no live-session borrow survives a poll.

use super::*;
use franken_journal::{Journal, JournalError, Namespace, Op, OwnedCommit, PollStorage};
use std::task::{Context, Poll};

/// Terminal failure retains every withheld outcome and any local silence applied.
#[derive(Debug)]
pub enum PendingStepFailure {
    Storage(StoreFailed),
    FenceChanged {
        withheld: Vec<Settlement>,
        applied: Vec<Settlement>,
    },
}

/// Terminal ownership and outcome of one durable control step.
pub type FinishedDurableStep<A, S> = (
    ControlChannel<A>,
    Journal<S>,
    Result<Vec<Settlement>, PendingStepFailure>,
);

enum Stage {
    Commands,
    Floor,
    Effect,
    Exhaustion,
    HighWater,
    Publish,
    Done,
}

/// Owns both channel and journal until terminal extraction. Ingress cannot
/// mutate the ledger's open transaction while this value owns the channel.
/// The caller independently services rendering/local stop and passes the newest
/// monotone stop generation plus live session on every poll. The generation
/// must saturate, never wrap; MAX permanently refuses further publication.
#[must_use = "poll to completion then recover channel and journal with finish"]
pub struct PendingDurableStep<A: PeerAuthority, S: Storage> {
    channel: ControlChannel<A>,
    journal: Option<Journal<S>>,
    commit: Option<OwnedCommit<S>>,
    staged: UnifiedGroupSession,
    original: UnifiedGroupSession,
    stop_generation: u64,
    cancelled: bool,
    before: Option<ChannelStats>,
    remaining: usize,
    floor: u64,
    item: Option<Queued>,
    prepared: Option<PreparedEffect>,
    next_floor: Option<SeqFloors>,
    settled: Vec<Settlement>,
    applied_items: Vec<Queued>,
    admitted_items: Vec<Queued>,
    stage: Stage,
    result: Option<Result<Vec<Settlement>, PendingStepFailure>>,
}

impl<A: PeerAuthority, S: Storage> PendingDurableStep<A, S> {
    pub(crate) fn channel(&self) -> &ControlChannel<A> {
        &self.channel
    }
}

impl<A: PeerAuthority, S: PollStorage> PendingDurableStep<A, S> {
    pub fn new(
        mut channel: ControlChannel<A>,
        journal: Journal<S>,
        now_ns: u64,
        live: &UnifiedGroupSession,
        stop_generation: u64,
    ) -> Self {
        if journal.is_poisoned() {
            channel.latch_durability("owner_storage_poisoned");
        }
        let before = (channel.durability == Durability::Healthy && channel.has_work())
            .then(|| channel.begin_step(now_ns, live));
        // Capture the bounded admission set, including commands that expiry or
        // cancellation may remove before a later incarnation fence is noticed.
        let admitted_items = channel
            .priority
            .iter()
            .chain(channel.ordinary.iter())
            .cloned()
            .collect();
        let floor = *channel
            .revision_floor
            .get_or_insert(live.state_revision.max(channel.restored_high_water));
        let mut settled = Vec::new();
        if before.is_some() {
            channel.expire_pending(now_ns, live.state_revision, &mut settled);
        }
        let remaining = channel.config.max_per_step;
        Self {
            channel,
            journal: Some(journal),
            commit: None,
            staged: live.clone(),
            original: live.clone(),
            stop_generation,
            cancelled: stop_generation == u64::MAX,
            before,
            remaining,
            floor,
            item: None,
            prepared: None,
            next_floor: None,
            settled,
            applied_items: Vec::new(),
            admitted_items,
            stage: Stage::Commands,
            result: None,
        }
    }

    /// Request cancellation without discarding an accepted storage operation.
    /// Keep polling until it settles; `finish` refuses to surrender an in-flight journal.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    fn settle_item(&mut self, outcome: Outcome, now_ns: u64) {
        let item = self.item.take().expect("current command retained");
        if matches!(
            outcome,
            Outcome::Committed { .. } | Outcome::AlreadySilent { .. }
        ) {
            self.applied_items.push(item.clone());
            if ControlChannel::<A>::silences_locally(&item) {
                self.channel.silenced.push(item.clone());
            }
        }
        self.channel.settle(
            item.request.body().clone(),
            outcome,
            Settled {
                now_ns,
                accepted_ns: item.accepted_ns,
                revision: self.staged.state_revision,
            },
            &mut self.settled,
        );
        self.prepared = None;
    }

    fn start_write(&mut self, ops: Vec<Op>) {
        let journal = self
            .journal
            .take()
            .expect("no simultaneous journal transaction");
        self.commit = Some(journal.into_commit(ops));
    }

    fn fail(&mut self, now_ns: u64, live: &mut UnifiedGroupSession, storage: Option<JournalError>) {
        if self.item.is_some() {
            self.settle_item(Outcome::Refused(Refusal::InternalFault), now_ns);
        }
        if let Some(before) = self.before.take() {
            let code = storage
                .as_ref()
                .map_or("pending_fence_changed", JournalError::code);
            self.channel
                .rollback_step(before, now_ns, live, &self.settled, code);
            // A cancelled transaction may already have advanced durable highwater.
            // Reopening is required before new non-silencing commands are admitted.
            self.channel.latch_durability(code);
        }
        let same_incarnation = live.group_id == self.original.group_id
            && live.current_epoch == self.original.current_epoch
            && live.coordinator_id == self.original.coordinator_id
            && live.members.len() == self.original.members.len()
            && self.original.members.iter().all(|(id, prior)| {
                live.members.get(id).is_some_and(|current| {
                    current.member_id == prior.member_id
                        && current.profile_id == prior.profile_id
                        && current.role == prior.role
                        && current.legacy_sw_gen_hint == prior.legacy_sw_gen_hint
                })
            });
        let applied = if same_incarnation {
            self.channel.apply_silencing_live(now_ns, live)
        } else {
            // LocalUser deliberately bypasses ordinary remote epoch checks.
            // That privilege belongs to the admitted incarnation, never a
            // replacement group with a coincidentally reused member label.
            self.channel.silenced.clear();
            self.channel.priority.clear();
            self.channel.ordinary.clear();
            // Rollback restores ledger entries as pending/unseen. Replace each
            // original admitted peer+sequence with an explicit terminal refusal
            // so neither the remaining queue nor a replay can cross this fence.
            self.settled.clear();
            for item in std::mem::take(&mut self.admitted_items) {
                self.channel.settle(
                    item.request.body().clone(),
                    Outcome::Refused(Refusal::AuthorityExpired),
                    Settled {
                        now_ns,
                        accepted_ns: item.accepted_ns,
                        revision: live.state_revision,
                    },
                    &mut self.settled,
                );
            }
            self.channel.emit_facts(now_ns, live);
            Vec::new()
        };
        let withheld = std::mem::take(&mut self.settled)
            .into_iter()
            .filter(|s| !applied.iter().any(|a| a.peer == s.peer && a.seq == s.seq))
            .collect();
        self.result = Some(Err(match storage {
            Some(cause) => PendingStepFailure::Storage(StoreFailed {
                cause,
                withheld,
                applied,
            }),
            None => PendingStepFailure::FenceChanged { withheld, applied },
        }));
        self.stage = Stage::Done;
    }

    /// One bounded command/transaction-progress turn. Backend polling may take
    /// reactor locks; this is not a hard real-time execution guarantee.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        now_ns: u64,
        live: &mut UnifiedGroupSession,
        stop_generation: u64,
    ) -> Poll<()> {
        if matches!(self.stage, Stage::Done) {
            return Poll::Ready(());
        }
        self.cancelled |= stop_generation != self.stop_generation || live != &self.original;
        if let Some(commit) = self.commit.as_mut() {
            match commit.poll_commit(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.journal = Some(self.commit.take().unwrap().into_journal());
                    if let Err(error) = result {
                        if matches!(self.stage, Stage::Floor)
                            && !self.journal.as_ref().unwrap().is_poisoned()
                        {
                            // Validation/capacity refusal wrote nothing. Match
                            // the synchronous floor store: refuse this command,
                            // preserve health, and continue unrelated work.
                            self.channel.last_internal_fault = None;
                            self.channel.store_cause = Some(StoreCause::Reservation(error.code()));
                            self.next_floor = None;
                            self.settle_item(Outcome::Refused(Refusal::InternalFault), now_ns);
                            self.stage = Stage::Commands;
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        self.fail(now_ns, live, Some(error));
                        return Poll::Ready(());
                    }
                    if matches!(self.stage, Stage::Floor) {
                        self.channel.seq_floors =
                            self.next_floor.take().expect("acknowledged floor");
                        self.stage = Stage::Effect;
                    }
                }
            }
        }
        if self.cancelled {
            self.fail(now_ns, live, None);
            return Poll::Ready(());
        }
        if self.before.is_none() {
            self.result = Some(Ok(self.channel.step(now_ns, live)));
            self.stage = Stage::Done;
            return Poll::Ready(());
        }
        match self.stage {
            Stage::Commands => {
                if self.remaining == 0 {
                    self.stage = Stage::Exhaustion;
                } else if let Some(item) = self
                    .channel
                    .pop_priority()
                    .or_else(|| self.channel.ordinary.pop_front())
                {
                    self.remaining -= 1;
                    let prepared = self.channel.prepare_effect(
                        &item,
                        now_ns,
                        self.floor,
                        &mut self.staged,
                        &mut self.settled,
                    );
                    self.item = Some(item);
                    match prepared {
                        Err(outcome) => self.settle_item(outcome, now_ns),
                        Ok(prepared) => {
                            self.prepared = Some(prepared);
                            let body = self.item.as_ref().unwrap().request.body();
                            if body.command().is_relative()
                                && !self.channel.unstable_retry.contains(body.peer())
                            {
                                if let Some(next) =
                                    self.channel.seq_floors.raised(body.peer(), body.seq())
                                {
                                    let packed = next.encode();
                                    self.next_floor = Some(next);
                                    self.start_write(vec![Op::Put {
                                        ns: Namespace::Records,
                                        key: SEQ_FLOORS_KEY.to_vec(),
                                        value: packed,
                                    }]);
                                    self.stage = Stage::Floor;
                                } else {
                                    self.channel.last_internal_fault = None;
                                    self.channel.store_cause = Some(StoreCause::Reservation(
                                        if self.channel.seq_floors.is_refusing() {
                                            "floors_unreadable"
                                        } else {
                                            "floors_full"
                                        },
                                    ));
                                    self.settle_item(
                                        Outcome::Refused(Refusal::InternalFault),
                                        now_ns,
                                    );
                                }
                            } else {
                                self.stage = Stage::Effect;
                            }
                        }
                    }
                } else {
                    self.stage = Stage::Exhaustion;
                }
            }
            Stage::Effect => {
                let prepared = self.prepared.take().unwrap();
                let outcome = self.channel.apply_prepared(
                    self.item.as_ref().unwrap(),
                    now_ns,
                    &mut self.staged,
                    prepared,
                );
                self.settle_item(outcome, now_ns);
                self.stage = Stage::Commands;
            }
            Stage::Exhaustion => {
                if self.channel.session_sequence_exhausted(&self.staged)
                    && !self
                        .journal
                        .as_ref()
                        .unwrap()
                        .state()
                        .marks
                        .get(persist::EXHAUSTED_KEY)
                        .is_some_and(|mark| *mark != 0)
                {
                    self.start_write(vec![Op::Raise {
                        key: persist::EXHAUSTED_KEY.to_vec(),
                        value: 1,
                    }]);
                }
                self.stage = Stage::HighWater;
            }
            Stage::HighWater => {
                let mark = self.channel.high_water(&self.staged);
                if !(mark == REFUSING_FLOOR && self.staged.state_revision != u64::MAX)
                    && self
                        .journal
                        .as_ref()
                        .unwrap()
                        .state()
                        .marks
                        .get(HIGH_WATER_KEY)
                        != Some(&mark)
                {
                    self.start_write(vec![Op::Raise {
                        key: HIGH_WATER_KEY.to_vec(),
                        value: mark,
                    }]);
                }
                self.stage = Stage::Publish;
            }
            Stage::Publish => {
                if self.applied_items.iter().any(|item| {
                    !self.channel.authority.is_current(&item.auth)
                        || now_ns.saturating_sub(item.accepted_ns)
                            >= self.channel.config.pending_ttl_ns
                        || self
                            .channel
                            .lease_refusal(
                                item.request.body().command(),
                                item.auth.role,
                                live,
                                now_ns,
                            )
                            .is_some()
                }) {
                    self.fail(now_ns, live, None);
                    return Poll::Ready(());
                }
                *live = self.staged.clone();
                self.channel.commit_step(now_ns, live);
                self.before = None;
                self.result = Some(Ok(std::mem::take(&mut self.settled)));
                self.stage = Stage::Done;
                return Poll::Ready(());
            }
            Stage::Floor => unreachable!("floor stage always owns a commit"),
            Stage::Done => return Poll::Ready(()),
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Terminal extraction returns channel and storage even when the step failed.
    /// Calling before completion returns this entire pending owner unchanged.
    #[expect(
        clippy::result_large_err,
        reason = "return pending custody without adding a recovery-path allocation"
    )]
    pub fn finish(mut self) -> Result<FinishedDurableStep<A, S>, Self> {
        if self.commit.is_some() || self.result.is_none() {
            return Err(self);
        }
        let journal = self.journal.take().expect("completed journal retained");
        let result = self.result.take().unwrap();
        Ok((self.channel, journal, result))
    }
}
