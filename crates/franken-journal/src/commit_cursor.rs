//! One commit ordering shared by blocking and pollable storage.

use super::*;
use crate::storage::{PollStorage, StorageOperation};
use std::task::{Context, Poll};

#[derive(Clone, Copy)]
enum Step {
    RetireProgram,
    RetireSync,
    Prepare,
    ScanTarget,
    Erase,
    Header,
    Frame,
    Sync,
    Publish,
    Done,
}

/// A resumable, exclusively borrowed transaction. Each call issues at most
/// one storage operation. Validation/encoding uses the existing allocator and
/// validates the supplied operation slice; callers must bound that slice.
/// This is not allocation-failure admission or a per-poll CPU deadline.
///
/// Dropping after a write may have started poisons the journal. Recovery must
/// first quiesce any backend operation, then reopen the medium. Cancellation
/// never rolls back a potentially durable write or publishes staged memory.
pub struct CommitCursor<'a, S: Storage> {
    journal: &'a mut Journal<S>,
    ops: &'a [Op],
    step: Step,
    trial: Option<State>,
    frame: Vec<u8>,
    header: [u8; SEG_HEADER],
    scan: [u8; CHUNK],
    scan_offset: usize,
    target: usize,
    compacting: bool,
    uncertain: bool,
    poll_driver: Option<bool>,
    result: Option<Result<Commit, JournalError>>,
}

impl<'a, S: Storage> CommitCursor<'a, S> {
    pub(super) fn new(journal: &'a mut Journal<S>, ops: &'a [Op]) -> Result<Self, JournalError> {
        if journal.poisoned {
            return Err(JournalError::Poisoned);
        }
        journal.phase = Phase::Idle;
        let step = if journal.pending_retire.is_some() {
            Step::RetireProgram
        } else {
            Step::Prepare
        };
        Ok(Self {
            journal,
            ops,
            step,
            trial: None,
            frame: Vec::new(),
            header: [0; SEG_HEADER],
            scan: [0; CHUNK],
            scan_offset: 0,
            target: 0,
            compacting: false,
            uncertain: false,
            poll_driver: None,
            result: None,
        })
    }

    /// Published state remains available while this transaction is pending.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.journal.state
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.journal.phase
    }

    /// Perform at most one **blocking** storage operation. `None` means that
    /// another step is required, not that the storage operation was asynchronous.
    /// Mixing this driver with `poll_commit` returns `BadOp` without touching storage.
    pub fn advance(&mut self) -> Option<Result<Commit, JournalError>> {
        if self.poll_driver == Some(true) {
            return Some(Err(JournalError::BadOp));
        }
        self.poll_driver = Some(false);
        match self.drive(|storage, operation| Poll::Ready(operation.execute(storage))) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        }
    }

    fn finish(
        &mut self,
        result: Result<Commit, JournalError>,
    ) -> Poll<Result<Commit, JournalError>> {
        self.step = Step::Done;
        self.result = Some(result.clone());
        Poll::Ready(result)
    }

    fn prepare(&mut self) -> Result<Option<Commit>, JournalError> {
        let journal = &mut self.journal;
        let mut trial = journal.state.clone();
        for op in self.ops {
            apply_op(&journal.lim, &mut trial, op, false)?;
        }
        if trial == journal.state {
            return Ok(Some(Commit::Noop));
        }
        journal.phase = Phase::Staged;
        let payload = encode_ops(self.ops)?;
        if payload.len() > journal.lim.max_txn_payload {
            return Err(JournalError::TxnTooLarge);
        }
        self.frame = encode_frame(KIND_TXN, journal.next_seq, &payload)?;
        if journal.next_seq < MAX_SEQ
            && journal.write_off + self.frame.len() <= journal.lim.segment_bytes
        {
            self.target = journal.active;
            self.step = Step::Frame;
        } else {
            if journal.generation >= journal.lim.max_segment_gen || journal.next_seq == MAX_SEQ {
                return Err(JournalError::WearExhausted);
            }
            self.compacting = true;
            self.target = 1 - journal.active;
            self.frame = encode_frame(KIND_SNAPSHOT, journal.next_seq, &trial.canonical_bytes()?)?;
            self.header =
                encode_segment_header(FORMAT_VERSION, journal.generation + 1, journal.next_seq);
            self.step = Step::ScanTarget;
        }
        self.trial = Some(trial);
        Ok(None)
    }

    fn drive(
        &mut self,
        mut execute: impl FnMut(&mut S, StorageOperation<'_>) -> Poll<Result<(), StorageFault>>,
    ) -> Poll<Result<Commit, JournalError>> {
        if let Some(result) = &self.result {
            return Poll::Ready(result.clone());
        }
        if matches!(self.step, Step::Prepare) {
            match self.prepare() {
                Ok(Some(commit)) => return self.finish(Ok(commit)),
                Err(error) => return self.finish(Err(error)),
                Ok(None) => {}
            }
        }
        if matches!(self.step, Step::Publish) {
            let journal = &mut self.journal;
            let trial = self
                .trial
                .take()
                .expect("prepared transaction owns its staged state");
            let commit = if self.compacting {
                journal.pending_retire = Some(journal.active);
                journal.active = self.target;
                journal.generation += 1;
                journal.write_off = SEG_HEADER + self.frame.len();
                journal.bytes_programmed += (SEG_HEADER + self.frame.len()) as u64;
                journal.compactions += 1;
                Commit::Compacted
            } else {
                journal.write_off += self.frame.len();
                journal.bytes_programmed += self.frame.len() as u64;
                journal.frames_written += 1;
                Commit::Appended
            };
            journal.next_seq += 1;
            journal.state = trial;
            journal.phase = Phase::Published;
            self.uncertain = false;
            return self.finish(Ok(commit));
        }
        let base = self.target * self.journal.lim.segment_bytes;
        let operation = match self.step {
            Step::RetireProgram => StorageOperation::Program {
                offset: self.journal.pending_retire.expect("retire target")
                    * self.journal.lim.segment_bytes,
                data: &[0, 0],
            },
            Step::RetireSync | Step::Sync => StorageOperation::Sync,
            Step::ScanTarget => {
                let count = CHUNK.min(self.journal.lim.segment_bytes - self.scan_offset);
                StorageOperation::Read {
                    offset: base + self.scan_offset,
                    out: &mut self.scan[..count],
                }
            }
            Step::Erase => StorageOperation::Erase {
                segment: self.target,
            },
            Step::Header => StorageOperation::Program {
                offset: base,
                data: &self.header,
            },
            Step::Frame => StorageOperation::Program {
                offset: base
                    + if self.compacting {
                        SEG_HEADER
                    } else {
                        self.journal.write_off
                    },
                data: &self.frame,
            },
            Step::Prepare | Step::Publish | Step::Done => {
                unreachable!("non-I/O steps handled above")
            }
        };
        if !matches!(self.step, Step::ScanTarget) {
            // Pending may mean that the backend already submitted the mutation.
            self.uncertain = true;
        }
        match execute(&mut self.journal.storage, operation) {
            Poll::Pending => {
                // Even a submitted read owns backend resources until it settles.
                self.uncertain = true;
                return Poll::Pending;
            }
            Poll::Ready(Err(fault)) => {
                self.journal.poisoned = true;
                return self.finish(Err(JournalError::Storage(fault)));
            }
            Poll::Ready(Ok(())) => {}
        }
        self.step = match self.step {
            Step::RetireProgram => Step::RetireSync,
            Step::RetireSync => {
                self.journal.pending_retire = None;
                self.uncertain = false;
                Step::Prepare
            }
            Step::ScanTarget => {
                self.uncertain = false;
                let count = CHUNK.min(self.journal.lim.segment_bytes - self.scan_offset);
                if self.scan[..count].iter().any(|&byte| byte != ERASED) {
                    Step::Erase
                } else {
                    self.scan_offset += count;
                    if self.scan_offset == self.journal.lim.segment_bytes {
                        Step::Header
                    } else {
                        Step::ScanTarget
                    }
                }
            }
            Step::Erase => Step::Header,
            Step::Header => Step::Frame,
            Step::Frame => {
                self.journal.phase = Phase::Written;
                Step::Sync
            }
            Step::Sync => {
                self.journal.phase = Phase::Synced;
                Step::Publish
            }
            Step::Prepare | Step::Publish | Step::Done => {
                unreachable!("non-I/O steps handled above")
            }
        };
        Poll::Pending
    }
}

impl<S: PollStorage> CommitCursor<'_, S> {
    /// Poll one operation. Successful intermediate steps schedule another poll;
    /// actual backend suspension relies on the backend's registered waker.
    /// Mixing this driver with `advance` returns `BadOp` without touching storage.
    pub fn poll_commit(&mut self, cx: &mut Context<'_>) -> Poll<Result<Commit, JournalError>> {
        if self.poll_driver == Some(false) {
            return Poll::Ready(Err(JournalError::BadOp));
        }
        self.poll_driver = Some(true);
        let mut backend_pending = false;
        let result = self.drive(|storage, operation| {
            let result = storage.poll_operation(cx, operation);
            backend_pending = result.is_pending();
            result
        });
        if result.is_pending() && !backend_pending {
            cx.waker().wake_by_ref();
        }
        result
    }
}

impl<S: Storage> Drop for CommitCursor<'_, S> {
    fn drop(&mut self) {
        if self.uncertain {
            self.journal.poisoned = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemStorage;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Wake, Waker};

    // A deterministic pending-operation model; real file persistence is tested
    // separately using the speaker's actual FileMedium implementation.
    struct PausingStorage {
        inner: MemStorage,
        pause: bool,
        completions: usize,
    }
    impl Storage for PausingStorage {
        fn segment_bytes(&self) -> usize {
            self.inner.segment_bytes()
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
            self.inner.read(offset, out)
        }
        fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
            self.inner.program(offset, data)
        }
        fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
            self.inner.erase(segment)
        }
        fn sync(&mut self) -> Result<(), StorageFault> {
            self.inner.sync()
        }
    }
    impl PollStorage for PausingStorage {
        fn poll_operation(
            &mut self,
            cx: &mut Context<'_>,
            operation: StorageOperation<'_>,
        ) -> Poll<Result<(), StorageFault>> {
            if self.pause {
                self.pause = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.pause = true;
                self.completions += 1;
                Poll::Ready(operation.execute(&mut self.inner))
            }
        }
    }
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    enum SubmittedMutation {
        Program { offset: usize, bytes: Vec<u8> },
        Erase { segment: usize },
        Sync,
    }

    // Model of submitted, backend-owned work, not a real asynchronous backend.
    // Recovery reads are refused until the outstanding mutation is quiesced.
    struct SubmittedStorage {
        inner: MemStorage,
        pending: Option<SubmittedMutation>,
        wake: Option<Waker>,
    }

    impl SubmittedStorage {
        fn quiesce(&mut self) -> Result<(), StorageFault> {
            let result = match self.pending.take() {
                Some(SubmittedMutation::Program { offset, bytes }) => {
                    self.inner.program(offset, &bytes)
                }
                Some(SubmittedMutation::Erase { segment }) => self.inner.erase(segment),
                Some(SubmittedMutation::Sync) => self.inner.sync(),
                None => Ok(()),
            };
            if let Some(waker) = self.wake.take() {
                waker.wake();
            }
            result
        }
    }

    impl Storage for SubmittedStorage {
        fn segment_bytes(&self) -> usize {
            self.inner.segment_bytes()
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
            if self.pending.is_some() {
                return Err(StorageFault::Io);
            }
            self.inner.read(offset, out)
        }
        fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
            if self.pending.is_some() {
                return Err(StorageFault::Io);
            }
            self.inner.program(offset, data)
        }
        fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
            if self.pending.is_some() {
                return Err(StorageFault::Io);
            }
            self.inner.erase(segment)
        }
        fn sync(&mut self) -> Result<(), StorageFault> {
            if self.pending.is_some() {
                return Err(StorageFault::Io);
            }
            self.inner.sync()
        }
    }

    impl PollStorage for SubmittedStorage {
        fn poll_operation(
            &mut self,
            cx: &mut Context<'_>,
            operation: StorageOperation<'_>,
        ) -> Poll<Result<(), StorageFault>> {
            if self.pending.is_some() {
                return Poll::Ready(self.quiesce());
            }
            self.pending = Some(match operation {
                StorageOperation::Program { offset, data } => SubmittedMutation::Program {
                    offset,
                    bytes: data.to_vec(),
                },
                StorageOperation::Erase { segment } => SubmittedMutation::Erase { segment },
                StorageOperation::Sync => SubmittedMutation::Sync,
                StorageOperation::Read { offset, out } => {
                    return Poll::Ready(self.inner.read(offset, out));
                }
            });
            self.wake = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    #[test]
    fn cursor_cancel_submitted_work_requires_quiescence_before_durable_recovery() {
        for cancel_sync in [false, true] {
            let lim = Limits::tiny();
            let storage = SubmittedStorage {
                inner: MemStorage::new(lim.segment_bytes),
                pending: None,
                wake: None,
            };
            let (mut journal, _) = Journal::open(storage, lim.clone()).unwrap();
            journal.raise_mark(b"floor", 3).unwrap();
            let old = journal.state().clone();
            let ops = mark(9);
            let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&wakes));
            let mut cx = Context::from_waker(&waker);
            {
                let mut cursor = journal.begin_commit(&ops).unwrap();
                assert!(cursor.poll_commit(&mut cx).is_pending()); // submitted owned program
                if cancel_sync {
                    assert!(cursor.poll_commit(&mut cx).is_pending()); // completed program
                    assert!(cursor.poll_commit(&mut cx).is_pending()); // submitted sync
                }
                assert_eq!(cursor.state(), &old);
            }
            assert!(journal.is_poisoned());
            assert_eq!(
                journal.raise_mark(b"floor", 10),
                Err(JournalError::Poisoned)
            );
            assert_eq!(journal.state(), &old);
            let mut storage = journal.into_storage();
            assert!(
                storage.pending.is_some(),
                "cursor drop must not discard backend-owned mutation"
            );
            assert!(
                Journal::open(&mut storage, lim.clone()).is_err(),
                "recovery cannot race outstanding I/O"
            );
            storage.quiesce().unwrap();
            assert!(storage.pending.is_none());
            assert!(storage.wake.is_none());
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            storage.inner.power_cut(0, false);
            storage.inner.restart();
            let (reopened, _) = Journal::open(storage, lim).unwrap();
            let expected = if cancel_sync { 9 } else { 3 };
            assert_eq!(
                reopened.state().marks.get(b"floor".as_slice()),
                Some(&expected)
            );
        }
    }

    #[test]
    fn cursor_poll_driver_wakes_and_resumes_without_duplicate_writes() {
        let lim = Limits::tiny();
        let storage = PausingStorage {
            inner: MemStorage::new(lim.segment_bytes),
            pause: true,
            completions: 0,
        };
        let (mut journal, _) = Journal::open(storage, lim).unwrap();
        let old = journal.state().clone();
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let ops = mark(9);
        {
            let mut cursor = journal.begin_commit(&ops).unwrap();
            assert!(cursor.poll_commit(&mut cx).is_pending());
            assert_eq!(cursor.advance(), Some(Err(JournalError::BadOp)));
            assert_eq!(cursor.state(), &old);
            for _ in 0..3 {
                assert!(cursor.poll_commit(&mut cx).is_pending());
            }
            assert_eq!(
                cursor.poll_commit(&mut cx),
                Poll::Ready(Ok(Commit::Appended))
            );
        }
        assert_eq!(journal.storage().completions, 2);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 4);
        assert_eq!(journal.state().marks.get(b"floor".as_slice()), Some(&9));
    }

    fn mark(value: u64) -> [Op; 1] {
        [Op::Raise {
            key: b"floor".to_vec(),
            value,
        }]
    }

    #[test]
    fn cursor_publishes_only_after_sync_and_explicit_publication_step() {
        let lim = Limits::tiny();
        let (mut journal, _) = Journal::open(MemStorage::new(lim.segment_bytes), lim).unwrap();
        let old = journal.state().clone();
        let ops = mark(9);
        let mut cursor = journal.begin_commit(&ops).unwrap();
        assert_eq!(cursor.advance(), None);
        assert_eq!(cursor.phase(), Phase::Written);
        assert_eq!(cursor.state(), &old);
        assert_eq!(cursor.advance(), None);
        assert_eq!(cursor.phase(), Phase::Synced);
        assert_eq!(cursor.state(), &old);
        assert_eq!(cursor.advance(), Some(Ok(Commit::Appended)));
        assert_ne!(cursor.state(), &old);
        assert_eq!(cursor.advance(), Some(Ok(Commit::Appended)));
    }

    #[test]
    fn cursor_cancel_before_io_is_clean_but_after_write_requires_recovery() {
        let lim = Limits::tiny();
        for advances in 0..=2 {
            let (mut journal, _) =
                Journal::open(MemStorage::new(lim.segment_bytes), lim.clone()).unwrap();
            journal.raise_mark(b"floor", 3).unwrap();
            let old = journal.state().clone();
            let ops = mark(9);
            {
                let mut cursor = journal.begin_commit(&ops).unwrap();
                for _ in 0..advances {
                    assert_eq!(cursor.advance(), None);
                }
            }
            assert_eq!(journal.state(), &old);
            assert_eq!(journal.is_poisoned(), advances != 0);
            let mut storage = journal.into_storage();
            storage.power_cut(0, false);
            storage.restart();
            let (reopened, _) = Journal::open(storage, lim.clone()).unwrap();
            let expected = if advances == 2 { 9 } else { 3 };
            assert_eq!(
                reopened.state().marks.get(b"floor".as_slice()),
                Some(&expected)
            );
        }
    }

    #[test]
    fn cursor_storage_failures_never_publish_staged_mark() {
        let lim = Limits::tiny();
        for sync_failure in [false, true] {
            for persists in [false, true] {
                let (mut journal, _) =
                    Journal::open(MemStorage::new(lim.segment_bytes), lim.clone()).unwrap();
                journal.raise_mark(b"floor", 3).unwrap();
                let old = journal.state().clone();
                let start = journal.storage().ops_done();
                if sync_failure {
                    journal.storage_mut().sync_fail_at = Some(start + 1);
                    journal.storage_mut().sync_fail_persists = persists;
                } else {
                    journal.storage_mut().fail_op_at = Some(start);
                }
                let ops = mark(9);
                let result = {
                    let mut cursor = journal.begin_commit(&ops).unwrap();
                    loop {
                        if let Some(result) = cursor.advance() {
                            break result;
                        }
                    }
                };
                assert!(matches!(result, Err(JournalError::Storage(_))));
                assert_eq!(journal.state(), &old);
                assert!(journal.is_poisoned());
                let mut storage = journal.into_storage();
                storage.restart();
                let (reopened, _) = Journal::open(storage, lim.clone()).unwrap();
                let expected = if sync_failure && persists { 9 } else { 3 };
                assert_eq!(
                    reopened.state().marks.get(b"floor".as_slice()),
                    Some(&expected)
                );
            }
        }
    }

    #[test]
    fn cursor_pending_does_not_repeat_or_advance_a_storage_operation() {
        let lim = Limits::tiny();
        let (mut journal, _) = Journal::open(MemStorage::new(lim.segment_bytes), lim).unwrap();
        let old = journal.state().clone();
        let ops = mark(9);
        let mut cursor = journal.begin_commit(&ops).unwrap();
        for _ in 0..8 {
            assert!(
                cursor
                    .drive(|_, operation| {
                        assert!(matches!(operation, StorageOperation::Program { .. }));
                        Poll::Pending
                    })
                    .is_pending()
            );
            assert_eq!(cursor.phase(), Phase::Staged);
            assert_eq!(cursor.state(), &old);
        }
        assert_eq!(cursor.advance(), None);
        assert_eq!(cursor.phase(), Phase::Written);
        for _ in 0..8 {
            assert!(
                cursor
                    .drive(|_, operation| {
                        assert!(matches!(operation, StorageOperation::Sync));
                        Poll::Pending
                    })
                    .is_pending()
            );
            assert_eq!(cursor.state(), &old);
        }
        assert_eq!(cursor.advance(), None);
        assert_eq!(cursor.advance(), Some(Ok(Commit::Appended)));
    }
}
