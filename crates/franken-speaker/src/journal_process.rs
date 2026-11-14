//! Isolated regular-file journal I/O. Startup/recovery and explicit teardown
//! run outside the control loop. Polling uses a nonblocking reactor socket;
//! the child exclusively owns FileMedium. This is not a device flash backend.
//! Keep WorkerCustody until reaped, including every cancellation/error path.
//! There is deliberately no blocking destructor or implicit reaper thread.
//! Socket calls are nonblocking and retries are bounded. Reactor registration
//! still takes runtime locks and kernel calls; no hard per-poll latency or
//! render-deadline guarantee is claimed under contention.

use asupersync::runtime::io_driver::IoRegistration;
use asupersync::runtime::reactor::Interest;
use franken_journal::{Journal, Limits, PollStorage, Storage, StorageFault, StorageOperation};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const MAX_SEGMENT: usize = 16_384;
const HEADER: usize = 17;
const ACK: usize = 9;
const PROGRAM: u8 = 1;
const ERASE: u8 = 2;
const SYNC: u8 = 3;
const CLOSE: u8 = 4;

/// Explicit child ownership; dropping this value does NOT establish quiescence.
#[must_use = "retain custody until try_reap or shutdown_off_loop confirms exit"]
pub struct WorkerCustody {
    child: Child,
}
impl WorkerCustody {
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn try_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    /// Off-control-loop fallback: kill this owned child and poll reap until the
    /// deadline. A timeout retains custody for a later retry; never blocks in wait().
    pub fn shutdown_off_loop(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("invalid shutdown deadline"))?;
        if let Some(status) = self.child.try_wait()? {
            return Ok(status);
        }
        if let Err(error) = self.child.kill() {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            return Err(error);
        }
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "journal child not reaped",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Failed startup retains any child already spawned, rather than losing its PID.
pub struct SpawnFailure {
    pub error: io::Error,
    pub custody: Option<WorkerCustody>,
}
impl std::fmt::Debug for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnFailure")
            .field("kind", &self.error.kind())
            .field("has_custody", &self.custody.is_some())
            .finish()
    }
}

fn profile(limits: &Limits) -> Option<&'static str> {
    if *limits == Limits::tiny() {
        Some("tiny")
    } else if *limits == Limits::standard() {
        Some("standard")
    } else if *limits == Limits::fleet_control_development() {
        Some("fleet")
    } else {
        None
    }
}

fn read_before(socket: &mut StdStream, mut out: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !out.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "worker startup deadline"))?;
        socket.set_read_timeout(Some(remaining))?;
        match socket.read(out) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "worker startup ended",
                ));
            }
            Ok(n) => out = &mut out[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if Instant::now() > deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "worker startup deadline",
        ));
    }
    Ok(())
}

/// One in-flight operation, bounded wire storage and a read-only medium mirror.
/// The mirror changes only on successful, sequence-matched child ACKs.
pub struct ProcessStorage {
    socket: StdStream,
    registration: Option<IoRegistration>,
    mirror: Vec<u8>,
    segment: usize,
    tx: Vec<u8>,
    tx_len: usize,
    sent: usize,
    ack: [u8; ACK],
    received: usize,
    sequence: u64,
    pending: bool,
    closed: bool,
    fault: Option<StorageFault>,
}

impl ProcessStorage {
    /// Blocking startup only: spawn, recover in child, receive the bounded
    /// mirror under one five-second post-spawn deadline. Process creation itself
    /// is an OS startup call, not a bounded control-loop operation.
    /// No child is lost on failure.
    pub fn spawn_off_loop(
        executable: &Path,
        path: &Path,
        limits: &Limits,
    ) -> Result<(Self, WorkerCustody), SpawnFailure> {
        let no_child = |error| SpawnFailure {
            error,
            custody: None,
        };
        let name = profile(limits)
            .ok_or_else(|| no_child(io::Error::other("unsupported journal profile")))?;
        let (mut parent, child_socket) = StdStream::pair().map_err(no_child)?;
        let stdin: OwnedFd = child_socket.try_clone().map_err(no_child)?.into();
        let stdout: OwnedFd = child_socket.into();
        let child = Command::new(executable)
            .arg(path)
            .arg(name)
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::null())
            .spawn()
            .map_err(no_child)?;
        let custody = WorkerCustody { child };
        let result = (|| {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut hello = [0u8; 8];
            read_before(&mut parent, &mut hello, deadline)?;
            if &hello[..4] != b"FJW1"
                || u32::from_be_bytes(hello[4..].try_into().unwrap()) as usize
                    != limits.segment_bytes
            {
                return Err(io::Error::other("invalid journal worker greeting"));
            }
            // Profiles were checked before allocation; at most 32 KiB mirror.
            let mut mirror = vec![0; 2 * limits.segment_bytes];
            read_before(&mut parent, &mut mirror, deadline)?;
            parent.set_read_timeout(None)?;
            parent.set_nonblocking(true)?;
            Ok(Self {
                socket: parent,
                registration: None,
                mirror,
                segment: limits.segment_bytes,
                tx: vec![0; HEADER + MAX_SEGMENT],
                tx_len: 0,
                sent: 0,
                ack: [0; ACK],
                received: 0,
                sequence: 0,
                pending: false,
                closed: false,
                fault: None,
            })
        })();
        match result {
            Ok(storage) => Ok((storage, custody)),
            Err(error) => Err(SpawnFailure {
                error,
                custody: Some(custody),
            }),
        }
    }

    fn queue(&mut self, kind: u8, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        if self.pending || self.closed || data.len() > self.segment {
            return Err(StorageFault::Io);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(StorageFault::Io)?;
        self.tx[0] = kind;
        self.tx[1..9].copy_from_slice(&self.sequence.to_be_bytes());
        self.tx[9..13].copy_from_slice(
            &u32::try_from(offset)
                .map_err(|_| StorageFault::OutOfRange)?
                .to_be_bytes(),
        );
        self.tx[13..17].copy_from_slice(&(data.len() as u32).to_be_bytes());
        self.tx[HEADER..HEADER + data.len()].copy_from_slice(data);
        self.tx_len = HEADER + data.len();
        self.sent = 0;
        self.received = 0;
        self.pending = true;
        Ok(())
    }

    fn fail(&mut self) -> Poll<Result<(), StorageFault>> {
        self.fault = Some(StorageFault::Io);
        Poll::Ready(Err(StorageFault::Io))
    }

    fn arm_current(&mut self, cx: &Context<'_>, interest: Interest) -> Result<(), StorageFault> {
        // Always bind a new wait to the runtime polling us now. A registration
        // from an idle previous runtime cannot deliver this runtime's wake.
        self.registration = None;
        let Some(current) = asupersync::cx::Cx::current() else {
            return Err(StorageFault::Io);
        };
        let Ok(mut registration) = current.register_io(&self.socket, interest) else {
            return Err(StorageFault::Io);
        };
        if !matches!(registration.rearm(interest, cx.waker()), Ok(true)) {
            return Err(StorageFault::Io);
        }
        self.registration = Some(registration);
        Ok(())
    }

    fn poll_socket(&mut self, cx: &Context<'_>, write: bool) -> Poll<Result<usize, StorageFault>> {
        for attempt in 0..2 {
            let result = if write {
                self.socket.write(&self.tx[self.sent..self.tx_len])
            } else {
                self.socket.read(&mut self.ack[self.received..])
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if attempt == 1 {
                        return Poll::Pending;
                    }
                    let interest = if write {
                        Interest::WRITABLE
                    } else {
                        Interest::READABLE
                    };
                    if let Err(error) = self.arm_current(cx, interest) {
                        return Poll::Ready(Err(error));
                    }
                    // Retry once after installing the real waker. Any readiness
                    // consumed by register_io's initial noop is observed here;
                    // later readiness wakes us. No registration self-wake loop.
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Ok(0) | Err(_) => return Poll::Ready(Err(StorageFault::Io)),
                Ok(n) => return Poll::Ready(Ok(n)),
            }
        }
        unreachable!("second WouldBlock returns Pending")
    }

    fn pump(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StorageFault>> {
        if let Some(fault) = self.fault {
            return Poll::Ready(Err(fault));
        }
        if self.sent < self.tx_len {
            match self.poll_socket(cx, true) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return self.fail(),
                Poll::Ready(Ok(n)) => self.sent += n,
            }
            if self.sent < self.tx_len {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        match self.poll_socket(cx, false) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return self.fail(),
            Poll::Ready(Ok(n)) => self.received += n,
        }
        if self.received < ACK {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.ack[0] != 0 || self.ack[1..] != self.sequence.to_be_bytes() {
            return self.fail();
        }
        let offset = u32::from_be_bytes(self.tx[9..13].try_into().unwrap()) as usize;
        match self.tx[0] {
            PROGRAM => self.mirror[offset..offset + self.tx_len - HEADER]
                .copy_from_slice(&self.tx[HEADER..self.tx_len]),
            ERASE => self.mirror[offset * self.segment..(offset + 1) * self.segment].fill(0xff),
            CLOSE => self.closed = true,
            _ => {}
        }
        self.pending = false;
        Poll::Ready(Ok(()))
    }

    /// Drain accepted work, sync and close the child's FileMedium. Success
    /// proves file custody released, not process reaped: retain WorkerCustody.
    pub fn poll_quiesce(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StorageFault>> {
        if let Some(fault) = self.fault {
            return Poll::Ready(Err(fault));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.pending {
            match self.pump(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Err(error) = self.queue(CLOSE, 0, &[]) {
            return Poll::Ready(Err(error));
        }
        self.pump(cx)
    }
}

impl Storage for ProcessStorage {
    fn segment_bytes(&self) -> usize {
        self.segment
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        if self.closed || self.pending || self.fault.is_some() {
            return Err(StorageFault::Io);
        }
        let end = offset
            .checked_add(out.len())
            .ok_or(StorageFault::OutOfRange)?;
        let bytes = self
            .mirror
            .get(offset..end)
            .ok_or(StorageFault::OutOfRange)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    // Refuse accidental blocking compatibility commits on the control caller.
    fn program(&mut self, _: usize, _: &[u8]) -> Result<(), StorageFault> {
        Err(StorageFault::Io)
    }
    fn erase(&mut self, _: usize) -> Result<(), StorageFault> {
        Err(StorageFault::Io)
    }
    fn sync(&mut self) -> Result<(), StorageFault> {
        Err(StorageFault::Io)
    }
}

impl PollStorage for ProcessStorage {
    fn poll_operation(
        &mut self,
        cx: &mut Context<'_>,
        operation: StorageOperation<'_>,
    ) -> Poll<Result<(), StorageFault>> {
        if let Some(fault) = self.fault {
            return Poll::Ready(Err(fault));
        }
        if self.closed {
            return Poll::Ready(Err(StorageFault::Io));
        }
        let (kind, offset, bytes) = match operation {
            StorageOperation::Read { offset, out } => return Poll::Ready(self.read(offset, out)),
            StorageOperation::Program { offset, data } => {
                if offset
                    .checked_add(data.len())
                    .is_none_or(|end| end > self.mirror.len())
                    || data.len() > self.segment
                {
                    return Poll::Ready(Err(StorageFault::OutOfRange));
                }
                (PROGRAM, offset, data)
            }
            StorageOperation::Erase { segment } => {
                if segment > 1 {
                    return Poll::Ready(Err(StorageFault::OutOfRange));
                }
                (ERASE, segment, &[][..])
            }
            StorageOperation::Sync => (SYNC, 0, &[][..]),
        };
        if self.pending {
            if self.tx[0] != kind
                || u32::from_be_bytes(self.tx[9..13].try_into().unwrap()) as usize != offset
                || &self.tx[HEADER..self.tx_len] != bytes
            {
                return self.fail();
            }
        } else if let Err(error) = self.queue(kind, offset, bytes) {
            return Poll::Ready(Err(error));
        }
        self.pump(cx)
    }
}

/// Worker executable entry point. All regular-file calls occur in this child.
pub fn run_worker(path: &Path, name: &str) -> io::Result<()> {
    let limits = match name {
        "tiny" => Limits::tiny(),
        "standard" => Limits::standard(),
        "fleet" => Limits::fleet_control_development(),
        _ => return Err(io::Error::other("unsupported profile")),
    };
    let file = crate::file_medium::FileMedium::open_existing(path, &limits)
        .map_err(|_| io::Error::other("medium refused"))?;
    let (journal, _) =
        Journal::open(file, limits.clone()).map_err(|_| io::Error::other("recovery refused"))?;
    let mut file = journal.into_storage();
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    output.write_all(b"FJW1")?;
    output.write_all(&(limits.segment_bytes as u32).to_be_bytes())?;
    let mut mirror = vec![0; 2 * limits.segment_bytes];
    file.read(0, &mut mirror)
        .map_err(|_| io::Error::other("snapshot refused"))?;
    output.write_all(&mirror)?;
    output.flush()?;
    let mut data = vec![0; limits.segment_bytes];
    let mut previous = 0u64;
    loop {
        let mut header = [0u8; HEADER];
        input.read_exact(&mut header)?;
        let sequence = u64::from_be_bytes(header[1..9].try_into().unwrap());
        let offset = u32::from_be_bytes(header[9..13].try_into().unwrap()) as usize;
        let len = u32::from_be_bytes(header[13..17].try_into().unwrap()) as usize;
        if previous.checked_add(1) != Some(sequence) || len > data.len() {
            return Err(io::Error::other("invalid request"));
        }
        input.read_exact(&mut data[..len])?;
        let result = match header[0] {
            PROGRAM => file.program(offset, &data[..len]),
            ERASE if len == 0 => file.erase(offset),
            SYNC | CLOSE if len == 0 && offset == 0 => file.sync(),
            _ => Err(StorageFault::Io),
        };
        let mut ack = [0u8; ACK];
        ack[0] = u8::from(result.is_err());
        ack[1..].copy_from_slice(&sequence.to_be_bytes());
        if header[0] == CLOSE {
            drop(file);
            output.write_all(&ack)?;
            output.flush()?;
            return Ok(());
        }
        output.write_all(&ack)?;
        output.flush()?;
        if result.is_err() {
            return Err(io::Error::other("storage operation failed"));
        }
        previous = sequence;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Transport-contract unit tests; real worker/file coverage is in the
    // journal_process integration test binary.
    fn connected() -> (ProcessStorage, StdStream) {
        let (parent, peer) = StdStream::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        (
            ProcessStorage {
                socket: parent,
                registration: None,
                mirror: vec![0xff; 1024],
                segment: 512,
                tx: vec![0; HEADER + MAX_SEGMENT],
                tx_len: 0,
                sent: 0,
                ack: [0; ACK],
                received: 0,
                sequence: 0,
                pending: false,
                closed: false,
                fault: None,
            },
            peer,
        )
    }

    #[test]
    fn operation_mismatch_latches_failure_without_mutating_mirror() {
        let (mut storage, _peer) = connected();
        storage.queue(PROGRAM, 0, &[0]).unwrap();
        let before = storage.mirror.clone();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            storage.poll_operation(&mut cx, StorageOperation::Sync),
            Poll::Ready(Err(StorageFault::Io))
        );
        assert_eq!(storage.mirror, before);
        assert_eq!(
            storage.poll_quiesce(&mut cx),
            Poll::Ready(Err(StorageFault::Io))
        );
    }

    #[test]
    fn missing_runtime_reactor_refuses_wait_without_starting_fallback() {
        let (mut storage, _peer) = connected();
        storage.queue(SYNC, 0, &[]).unwrap();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(storage.pump(&mut cx), Poll::Ready(Err(StorageFault::Io)));
        assert!(storage.registration.is_none());
    }

    #[test]
    fn only_successful_matching_ack_changes_mirror() {
        for (status, sequence, accepted) in [(0, 1u64, true), (0, 2, false), (1, 1, false)] {
            let (mut storage, mut peer) = connected();
            storage.queue(PROGRAM, 0, &[0]).unwrap();
            let mut ack = [0; ACK];
            ack[0] = status;
            ack[1..].copy_from_slice(&sequence.to_be_bytes());
            peer.write_all(&ack).unwrap();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let result = storage.pump(&mut cx);
            assert_eq!(
                result,
                Poll::Ready(if accepted {
                    Ok(())
                } else {
                    Err(StorageFault::Io)
                })
            );
            assert_eq!(storage.mirror[0], if accepted { 0 } else { 0xff });
        }
    }

    #[test]
    fn startup_deadline_refuses_expired_budget_before_read() {
        let (mut socket, _peer) = StdStream::pair().unwrap();
        let mut byte = [0];
        let deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(
            read_before(&mut socket, &mut byte, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn close_ack_revokes_cached_mirror_reads() {
        let (mut storage, mut peer) = connected();
        let mut byte = [0];
        assert_eq!(storage.read(0, &mut byte), Ok(()));
        assert_eq!(byte, [0xff]);
        storage.queue(CLOSE, 0, &[]).unwrap();
        let mut ack = [0; ACK];
        ack[1..].copy_from_slice(&1u64.to_be_bytes());
        peer.write_all(&ack).unwrap();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(storage.pump(&mut cx), Poll::Ready(Ok(())));
        byte[0] = 0x42;
        assert_eq!(storage.read(0, &mut byte), Err(StorageFault::Io));
        assert_eq!(byte, [0x42], "refusal must not reveal stale mirrored bytes");
        assert!(Journal::open(storage, Limits::tiny()).is_err());
    }
}
