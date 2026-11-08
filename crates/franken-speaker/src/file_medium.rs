//! A regular-file [`Storage`] for the Virtual House control owner (`N02` / `ffw-ugf`): the restart evidence of a durable control
//! plane can cross a PROCESS boundary instead of living in RAM ([`RamMedium`](franken_control::channel::pipeline::RamMedium)).
//!
//! This is a prototype medium for the harness, not a device medium: no block or character device, no flash, and no claim about a
//! power cut. A process kill keeps every byte already handed to the operating system, synced or not, so a killed owner proves a
//! restart, not `sync_all`. A device owner will have flash behind the same trait; this file is its stand-in, written as one module
//! whose only imports are `Limits`, `Storage` and `StorageFault`, so it can move into the journal crate as a file move.
//!
//! # The file
//!
//! A fixed [`FILE_HEADER_BYTES`]-byte header, then the two journal segments exactly as `Storage` presents them (address 0 of the
//! medium is byte [`FILE_HEADER_BYTES`] of the file). The header is a magic, the format, the segment size, the data length and a
//! CRC-32 over the rest. The file is exactly `FILE_HEADER_BYTES + 2 * segment_bytes` long. A blank medium is all `0xFF` after the
//! header, so a fresh file opens as a blank journal.
//!
//! # What it refuses, and what it never does
//!
//! * [`FileMedium::create_new`] is the only way a file comes into being, and it is `O_EXCL`: an existing path (a file, a directory,
//!   a symlink, even a dangling one) is [`FileError::AlreadyExists`] and is left exactly as it was.
//! * [`FileMedium::open_existing`] never creates, truncates, resizes or formats. A path that is not a regular file (a symlink, a
//!   directory, a device, a socket), a file with another hard link, a file of the wrong length, and a file without this header or
//!   with another geometry are refused by name, and the bytes are not touched. A foreign file is never adopted.
//! * Both take an exclusive advisory lock on the open file ([`std::fs::File::try_lock`]). A second opener, in this process or
//!   another, gets [`FileError::Locked`] while the first lives; the lock goes with the process, so a killed owner releases it.
//!   This is what makes the read-then-write of [`Storage::program`] safe against a second journal on the same file. It is advisory:
//!   it does not stop a program that does not ask.
//! * Offsets are checked before any byte is written ([`StorageFault::OutOfRange`]); a program that would need a bit to rise is
//!   [`StorageFault::BitsCannotRise`] before the first byte is written.
//! * **First failure latches.** After the first write-side or sync failure, or a real read I/O error (the medium is then not to be
//!   trusted), every later call returns that fault. A caller's mistake (`OutOfRange`, `BitsCannotRise`) touches nothing and does not
//!   latch. The journal poisons itself on a failed write or sync; this keeps the file layer from contradicting it (a retried
//!   `fsync` can report success after the data of a failed one was dropped).
//!
//! # What it does not close
//!
//! The check that a path is a regular file and the open that follows are two system calls: the handle's `(device, inode)` is compared
//! with the path's afterwards, which narrows a swap to nothing a cooperating directory owner would do, but it is not an atomic open.
//! The directory the file lives in belongs to the owner. A failed `create_new` leaves any file it made (nothing here deletes).
//! A partial image is refused on reopen; a failure after the complete image was written, such as a directory-sync failure, may
//! leave a valid image. Reopening that image does not establish that the failed creation became durable.
//!
//! Errors carry no path and no bytes, only a stable [`FileError::code`].

use franken_control::channel::pipeline::{Limits, Storage, StorageFault};
use std::cell::Cell;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;

/// The first eight bytes of the file.
pub const FILE_MAGIC: [u8; 8] = *b"FFWJFILE";
/// The file format this code writes and the only one it opens.
pub const FILE_FORMAT: u8 = 1;
/// Bytes before the first journal segment.
pub const FILE_HEADER_BYTES: usize = 32;
/// The largest segment a file may be created with or opened at (1 MiB), so neither call can be made to size a huge file.
pub const MAX_FILE_SEGMENT_BYTES: usize = 1 << 20;
/// An erased byte, as the journal's medium model has it.
const ERASED: u8 = 0xFF;

/// Why a file was not created or opened. These carry no path and no data; [`FileError::code`] is the stable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// The limits are not a valid journal configuration, or the segment is larger than [`MAX_FILE_SEGMENT_BYTES`].
    BadGeometry,
    /// `create_new`: something already exists at the path. It was not touched.
    AlreadyExists,
    /// Nothing exists at the path (or in its directory).
    NotFound,
    /// The operating system refused access to the path.
    Denied,
    /// Not a regular file (a symlink, directory, device or socket).
    NotRegularFile,
    /// The file has more than one hard link, so it is not this owner's alone.
    NotExclusive,
    /// The handle opened is not the file the path named a moment before.
    Replaced,
    /// The file is not exactly `FILE_HEADER_BYTES + 2 * segment_bytes` long.
    WrongLength,
    /// The header is not this format: wrong magic, format, reserved bytes or checksum.
    BadHeader,
    /// The header is well formed but names another segment size than the limits do.
    GeometryMismatch,
    /// Another open handle holds the file.
    Locked,
    /// Any other operating-system failure.
    Io,
}

impl FileError {
    pub const ALL: [Self; 12] = [
        Self::BadGeometry,
        Self::AlreadyExists,
        Self::NotFound,
        Self::Denied,
        Self::NotRegularFile,
        Self::NotExclusive,
        Self::Replaced,
        Self::WrongLength,
        Self::BadHeader,
        Self::GeometryMismatch,
        Self::Locked,
        Self::Io,
    ];

    /// The stable name, safe to log.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadGeometry => "bad_geometry",
            Self::AlreadyExists => "already_exists",
            Self::NotFound => "not_found",
            Self::Denied => "denied",
            Self::NotRegularFile => "not_regular_file",
            Self::NotExclusive => "not_exclusive",
            Self::Replaced => "replaced",
            Self::WrongLength => "wrong_length",
            Self::BadHeader => "bad_header",
            Self::GeometryMismatch => "geometry_mismatch",
            Self::Locked => "locked",
            Self::Io => "io",
        }
    }
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for FileError {}

/// The journal's two-segment medium on one regular file. See the module documentation for what it refuses and promises.
#[derive(Debug)]
pub struct FileMedium {
    file: File,
    segment: usize,
    /// The first failure; every later call returns it.
    fault: Cell<Option<StorageFault>>,
}

/// CRC-32 (IEEE 802.3, reflected: the one zlib and Ethernet use) over `bytes`, bit by bit; the header is 28 bytes and is checked once
/// per open.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn segment_for(limits: &Limits) -> Result<usize, FileError> {
    limits.validate().map_err(|_| FileError::BadGeometry)?;
    if limits.segment_bytes > MAX_FILE_SEGMENT_BYTES {
        return Err(FileError::BadGeometry);
    }
    Ok(limits.segment_bytes)
}

const fn file_len(segment: usize) -> u64 {
    (FILE_HEADER_BYTES + 2 * segment) as u64
}

fn encode_header(segment: usize) -> [u8; FILE_HEADER_BYTES] {
    let mut head = [0u8; FILE_HEADER_BYTES];
    head[..8].copy_from_slice(&FILE_MAGIC);
    head[8] = FILE_FORMAT;
    head[12..16].copy_from_slice(&(segment as u32).to_be_bytes());
    head[16..24].copy_from_slice(&((2 * segment) as u64).to_be_bytes());
    let crc = crc32(&head[..28]);
    head[28..32].copy_from_slice(&crc.to_be_bytes());
    head
}

fn check_header(head: &[u8; FILE_HEADER_BYTES], segment: usize) -> Result<(), FileError> {
    let stored = u32::from_be_bytes([head[28], head[29], head[30], head[31]]);
    let well_formed = head[..8] == FILE_MAGIC
        && head[8] == FILE_FORMAT
        && head[9..12] == [0, 0, 0]
        && head[24..28] == [0, 0, 0, 0]
        && stored == crc32(&head[..28]);
    if !well_formed {
        return Err(FileError::BadHeader);
    }
    let named_segment = u32::from_be_bytes([head[12], head[13], head[14], head[15]]);
    let named_data = u64::from_be_bytes([
        head[16], head[17], head[18], head[19], head[20], head[21], head[22], head[23],
    ]);
    if named_segment as usize != segment || named_data != (2 * segment) as u64 {
        return Err(FileError::GeometryMismatch);
    }
    Ok(())
}

fn path_error(error: &std::io::Error) -> FileError {
    match error.kind() {
        ErrorKind::AlreadyExists => FileError::AlreadyExists,
        ErrorKind::NotFound => FileError::NotFound,
        ErrorKind::PermissionDenied => FileError::Denied,
        _ => FileError::Io,
    }
}

fn lock(file: &File) -> Result<(), FileError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(FileError::Locked),
        Err(TryLockError::Error(_)) => Err(FileError::Io),
    }
}

/// Make the directory entry of a new file durable: open the directory and `fsync` it.
fn sync_directory_of(path: &Path) -> Result<(), FileError> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| FileError::Io)
}

impl FileMedium {
    /// Create the file, explicitly and only if nothing exists at `path`: `create_new`, mode 0600, the handle locked, the header and
    /// two erased segments written, the file and its directory synced. The medium is blank, so a journal opened on it formats an
    /// empty state.
    ///
    /// # Errors
    /// [`FileError::BadGeometry`] before anything is touched; [`FileError::AlreadyExists`] if `path` exists in any form (it is not
    /// opened or changed); [`FileError::Denied`], [`FileError::NotFound`] (a missing directory) or [`FileError::Io`]. A failure after
    /// the file was made leaves it in place. A complete image may reopen even if the final sync failed; reopening is not proof
    /// that creation became durable.
    pub fn create_new(path: &Path, limits: &Limits) -> Result<Self, FileError> {
        let segment = segment_for(limits)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| path_error(&error))?;
        lock(&file)?;
        let mut image = encode_header(segment).to_vec();
        image.resize(FILE_HEADER_BYTES + 2 * segment, ERASED);
        file.write_all_at(&image, 0).map_err(|_| FileError::Io)?;
        file.sync_all().map_err(|_| FileError::Io)?;
        sync_directory_of(path)?;
        Ok(Self {
            file,
            segment,
            fault: Cell::new(None),
        })
    }

    /// Open a file made by [`FileMedium::create_new`], for read and write, without creating, truncating or changing anything.
    ///
    /// # Errors
    /// [`FileError::BadGeometry`]; [`FileError::NotFound`] / [`FileError::Denied`]; [`FileError::NotRegularFile`] for a symlink, a
    /// directory or a special file; [`FileError::NotExclusive`] for a file with another hard link; [`FileError::Replaced`] if the
    /// handle is not the file the path named; [`FileError::Locked`] while another handle holds it; [`FileError::WrongLength`];
    /// [`FileError::BadHeader`]; [`FileError::GeometryMismatch`]. Every refusal leaves the file's bytes as they were.
    pub fn open_existing(path: &Path, limits: &Limits) -> Result<Self, FileError> {
        let segment = segment_for(limits)?;
        let named = std::fs::symlink_metadata(path).map_err(|error| path_error(&error))?;
        if !named.file_type().is_file() {
            return Err(FileError::NotRegularFile);
        }
        if named.nlink() != 1 {
            return Err(FileError::NotExclusive);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| path_error(&error))?;
        lock(&file)?;
        let opened = file.metadata().map_err(|_| FileError::Io)?;
        if !opened.file_type().is_file()
            || opened.dev() != named.dev()
            || opened.ino() != named.ino()
        {
            return Err(FileError::Replaced);
        }
        if opened.nlink() != 1 {
            return Err(FileError::NotExclusive);
        }
        if opened.len() != file_len(segment) {
            return Err(FileError::WrongLength);
        }
        let mut head = [0u8; FILE_HEADER_BYTES];
        file.read_exact_at(&mut head, 0)
            .map_err(|_| FileError::Io)?;
        check_header(&head, segment)?;
        Ok(Self {
            file,
            segment,
            fault: Cell::new(None),
        })
    }

    /// The first failure this handle saw, if any: from then on every call returns it.
    #[must_use]
    pub fn fault(&self) -> Option<StorageFault> {
        self.fault.get()
    }

    fn latched(&self) -> Result<(), StorageFault> {
        self.fault.get().map_or(Ok(()), Err)
    }

    /// Record `fault` unless an earlier one is already recorded, and return the one that is.
    fn fail(&self, fault: StorageFault) -> StorageFault {
        if self.fault.get().is_none() {
            self.fault.set(Some(fault));
        }
        self.fault.get().unwrap_or(fault)
    }

    fn in_range(&self, offset: usize, len: usize) -> bool {
        offset
            .checked_add(len)
            .is_some_and(|end| end <= 2 * self.segment)
    }

    /// The position in the file of byte `offset` of the medium.
    fn at(offset: usize) -> u64 {
        (FILE_HEADER_BYTES + offset) as u64
    }
}

impl Storage for FileMedium {
    fn segment_bytes(&self) -> usize {
        self.segment
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        self.latched()?;
        if !self.in_range(offset, out.len()) {
            return Err(StorageFault::OutOfRange);
        }
        self.file
            .read_exact_at(out, Self::at(offset))
            .map_err(|_| self.fail(StorageFault::Io))
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        self.latched()?;
        if !self.in_range(offset, data.len()) {
            return Err(StorageFault::OutOfRange);
        }
        let mut have = vec![0u8; data.len()];
        self.read(offset, &mut have)?;
        if data.iter().zip(&have).any(|(want, now)| want & !now != 0) {
            return Err(StorageFault::BitsCannotRise);
        }
        self.file
            .write_all_at(data, Self::at(offset))
            .map_err(|_| self.fail(StorageFault::Io))
    }

    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        self.latched()?;
        if segment > 1 {
            return Err(StorageFault::OutOfRange);
        }
        let blank = vec![ERASED; self.segment];
        self.file
            .write_all_at(&blank, Self::at(segment * self.segment))
            .map_err(|_| self.fail(StorageFault::Io))
    }

    fn sync(&mut self) -> Result<(), StorageFault> {
        self.latched()?;
        self.file
            .sync_all()
            .map_err(|_| self.fail(StorageFault::SyncFailed))
    }
}

/// Which storage call a [`FaultingMedium`] fails: the `n`-th (counting from 1) `program` or `sync` issued after it was armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAt {
    /// The `n`-th `program` fails with [`StorageFault::Io`] and has no effect on the medium.
    Program(usize),
    /// The `n`-th `sync` fails with [`StorageFault::SyncFailed`]. The bytes already written stay in the file (a failed `fsync`
    /// does not undo a write), so what the file holds afterwards is, as the journal assumes, unknown.
    Sync(usize),
}

impl FailAt {
    /// `program:N` or `sync:N` with `N >= 1`; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (kind, count) = text.split_once(':')?;
        let n: usize = count.parse().ok().filter(|n| *n >= 1)?;
        match kind {
            "program" => Some(Self::Program(n)),
            "sync" => Some(Self::Sync(n)),
            _ => None,
        }
    }
}

/// A medium that passes every call through to `M` and, once armed, fails exactly one chosen call. It is for the harness: it lets a
/// test make the commit of a chosen step fail on a REAL file medium in a real process. With no plan, or before it is armed, it is
/// `M`. The `armed` flag is shared so the owner can arm it after the boot (the journal's own writes while it opens are not counted).
#[derive(Debug)]
pub struct FaultingMedium<M: Storage> {
    inner: M,
    plan: Option<FailAt>,
    armed: Rc<Cell<bool>>,
    programs: usize,
    syncs: usize,
}

impl<M: Storage> FaultingMedium<M> {
    #[must_use]
    pub fn new(inner: M, plan: Option<FailAt>, armed: Rc<Cell<bool>>) -> Self {
        Self {
            inner,
            plan,
            armed,
            programs: 0,
            syncs: 0,
        }
    }
}

impl<M: Storage> Storage for FaultingMedium<M> {
    fn segment_bytes(&self) -> usize {
        self.inner.segment_bytes()
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        self.inner.read(offset, out)
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageFault> {
        if self.armed.get() {
            self.programs += 1;
            if self.plan == Some(FailAt::Program(self.programs)) {
                return Err(StorageFault::Io);
            }
        }
        self.inner.program(offset, data)
    }

    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        self.inner.erase(segment)
    }

    fn sync(&mut self) -> Result<(), StorageFault> {
        if self.armed.get() {
            self.syncs += 1;
            if self.plan == Some(FailAt::Sync(self.syncs)) {
                return Err(StorageFault::SyncFailed);
            }
        }
        self.inner.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static DIRS: AtomicU32 = AtomicU32::new(0);

    /// A fresh directory this test binary alone owns: a direct child of the temp directory named with the process id and a
    /// counter, made with `create_dir` (which refuses a path that exists), so a passing test removes only what it made and a
    /// failing one keeps its files for inspection.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            Self::in_directory(&std::env::temp_dir())
        }

        fn in_directory(parent: &Path) -> Self {
            let n = DIRS.fetch_add(1, Ordering::SeqCst);
            let dir = parent.join(format!("ffw-file-medium-{}-{n}", std::process::id()));
            fs::create_dir(&dir).expect("a fresh scratch directory");
            Self { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "file_medium tests: a test failed; keeping {}",
                    self.dir.display()
                );
                return;
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn bytes_of(path: &Path) -> Vec<u8> {
        fs::read(path).expect("the file reads")
    }

    fn fresh(scratch: &Scratch, name: &str, lim: &Limits) -> PathBuf {
        let path = scratch.path(name);
        drop(FileMedium::create_new(&path, lim).expect("a new file"));
        path
    }

    /// `sockaddr_un.sun_path`: 108 bytes on Linux, 104 on macOS and the BSDs. `bind` takes a spelling one byte shorter than this (the
    /// terminating NUL needs the last byte). The limit is on the path as it is SPELLED, not on where it resolves, so an absolute
    /// spelling under a long `TMPDIR` can be over it while a relative spelling of the same place is not.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SUN_PATH_BYTES: usize = 108;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const SUN_PATH_BYTES: usize = 104;

    /// Why a fixture socket could not be bound, by name, so a failing test says which.
    #[derive(Debug, PartialEq, Eq)]
    enum SocketPathError {
        /// The spelling is `len` bytes and `bind` takes at most `limit`; nothing was asked of the operating system.
        TooLong { len: usize, limit: usize },
        /// `bind` refused for another reason.
        Refused(ErrorKind),
    }

    /// Bind a Unix socket at `path`. A spelling over the limit is the named error `TooLong`, checked before `bind` is asked, instead of
    /// an `expect` panic that reads as a failure of whatever the test was about.
    fn bind_socket(path: &Path) -> Result<UnixListener, SocketPathError> {
        let len = path.as_os_str().len();
        let limit = SUN_PATH_BYTES - 1;
        if len > limit {
            return Err(SocketPathError::TooLong { len, limit });
        }
        UnixListener::bind(path).map_err(|error| SocketPathError::Refused(error.kind()))
    }

    #[test]
    fn the_checksum_is_the_standard_crc32() {
        // the published check value of CRC-32/ISO-HDLC
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_new_file_is_the_header_and_two_erased_segments() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let created = FileMedium::create_new(&path, &lim).expect("create");
        assert_eq!(created.segment_bytes(), 512);
        assert_eq!(created.fault(), None);
        drop(created);
        let bytes = bytes_of(&path);
        assert_eq!(bytes.len(), FILE_HEADER_BYTES + 1024);
        assert_eq!(&bytes[..8], b"FFWJFILE");
        assert_eq!(&bytes[..FILE_HEADER_BYTES], &encode_header(512)[..]);
        assert!(bytes[FILE_HEADER_BYTES..].iter().all(|b| *b == ERASED));
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let storage = FileMedium::open_existing(&path, &lim).expect("the new file opens");
        assert_eq!(storage.segment_bytes(), 512);
    }

    #[test]
    fn what_was_programmed_and_synced_is_there_after_the_file_is_reopened() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let mut first = FileMedium::create_new(&path, &lim).expect("create");
        assert_eq!(first.program(100, &[0x12, 0x34]), Ok(()));
        assert_eq!(first.program(512, &[0xAB]), Ok(()));
        assert_eq!(first.sync(), Ok(()));
        drop(first);
        let second = FileMedium::open_existing(&path, &lim).expect("reopen");
        let mut got = [0u8; 2];
        second.read(100, &mut got).expect("read");
        assert_eq!(got, [0x12, 0x34]);
        let mut one = [0u8; 1];
        second.read(512, &mut one).expect("read");
        assert_eq!(one, [0xAB]);
        second.read(99, &mut one).expect("read");
        assert_eq!(one, [ERASED], "the byte before is still erased");
    }

    #[test]
    fn create_new_refuses_every_existing_path_and_leaves_it_exactly_as_it_was() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let foreign = scratch.path("foreign.bin");
        fs::write(&foreign, b"not a journal at all").expect("write");
        assert_eq!(
            FileMedium::create_new(&foreign, &lim).err(),
            Some(FileError::AlreadyExists)
        );
        assert_eq!(bytes_of(&foreign), b"not a journal at all");

        let directory = scratch.path("d");
        fs::create_dir(&directory).expect("directory");
        assert_eq!(
            FileMedium::create_new(&directory, &lim).err(),
            Some(FileError::AlreadyExists)
        );

        let nowhere = scratch.path("nowhere");
        let dangling = scratch.path("dangling");
        std::os::unix::fs::symlink(&nowhere, &dangling).expect("symlink");
        assert_eq!(
            FileMedium::create_new(&dangling, &lim).err(),
            Some(FileError::AlreadyExists)
        );
        assert!(
            !nowhere.exists(),
            "create_new must not create through a symlink"
        );

        let existing = fresh(&scratch, "existing.img", &lim);
        let image = bytes_of(&existing);
        assert_eq!(
            FileMedium::create_new(&existing, &lim).err(),
            Some(FileError::AlreadyExists)
        );
        assert_eq!(bytes_of(&existing), image);

        // the permitted case: a path with nothing at it, in a directory that exists
        FileMedium::create_new(&scratch.path("fresh.img"), &lim).expect("a fresh path works");
        assert_eq!(
            FileMedium::create_new(&scratch.path("no-such-dir").join("x.img"), &lim).err(),
            Some(FileError::NotFound)
        );
    }

    #[test]
    fn a_geometry_the_journal_cannot_use_or_a_file_cannot_bound_is_refused_before_anything_is_made()
    {
        let scratch = Scratch::new();
        let mut broken = Limits::tiny();
        broken.max_txn_payload = 100_000;
        assert_eq!(
            FileMedium::create_new(&scratch.path("a.img"), &broken).err(),
            Some(FileError::BadGeometry)
        );
        assert!(!scratch.path("a.img").exists());
        let mut huge = Limits::standard();
        huge.segment_bytes = MAX_FILE_SEGMENT_BYTES + 1;
        assert_eq!(
            FileMedium::create_new(&scratch.path("b.img"), &huge).err(),
            Some(FileError::BadGeometry)
        );
        assert!(!scratch.path("b.img").exists());
        let lim = Limits::standard();
        let path = fresh(&scratch, "c.img", &lim);
        assert_eq!(bytes_of(&path).len(), FILE_HEADER_BYTES + 2 * 8192);
        assert_eq!(
            FileMedium::open_existing(&path, &broken).err(),
            Some(FileError::BadGeometry)
        );
        FileMedium::open_existing(&path, &lim).expect("the permitted geometry opens");
    }

    #[test]
    fn a_file_that_is_not_this_format_is_refused_by_name_and_never_changed() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let good_path = fresh(&scratch, "good.img", &lim);
        let good = bytes_of(&good_path);
        assert_eq!(good.len(), FILE_HEADER_BYTES + 1024);

        let mut cases: Vec<(String, Vec<u8>, FileError)> = vec![
            ("empty".to_string(), Vec::new(), FileError::WrongLength),
            (
                "header only".to_string(),
                good[..FILE_HEADER_BYTES].to_vec(),
                FileError::WrongLength,
            ),
            (
                "one byte short".to_string(),
                good[..good.len() - 1].to_vec(),
                FileError::WrongLength,
            ),
            (
                "one byte long".to_string(),
                [good.clone(), vec![ERASED]].concat(),
                FileError::WrongLength,
            ),
            (
                "a foreign file of the right length".to_string(),
                vec![0x5A; good.len()],
                FileError::BadHeader,
            ),
            (
                "zeros of the right length".to_string(),
                vec![0; good.len()],
                FileError::BadHeader,
            ),
        ];
        for (index, _) in good[..FILE_HEADER_BYTES].iter().enumerate() {
            let mut flipped = good.clone();
            flipped[index] ^= 0x01;
            cases.push((
                format!("header byte {index} flipped"),
                flipped,
                FileError::BadHeader,
            ));
        }
        // a well-formed header (checksum and all) for another segment size, on a file of this size
        let mut other = good.clone();
        other[..FILE_HEADER_BYTES].copy_from_slice(&encode_header(256));
        cases.push((
            "a header for another geometry".to_string(),
            other,
            FileError::GeometryMismatch,
        ));

        for (n, (label, bytes, want)) in cases.iter().enumerate() {
            let path = scratch.path(&format!("case-{n}.img"));
            fs::write(&path, bytes).expect("write the case");
            assert_eq!(
                FileMedium::open_existing(&path, &lim).err(),
                Some(*want),
                "{label}"
            );
            assert_eq!(
                &bytes_of(&path),
                bytes,
                "{label}: a refusal changed the file"
            );
        }
        // other limits make the good file the wrong length, and the good file is still good
        assert_eq!(
            FileMedium::open_existing(&good_path, &Limits::standard()).err(),
            Some(FileError::WrongLength)
        );
        assert_eq!(bytes_of(&good_path), good);
        FileMedium::open_existing(&good_path, &lim).expect("the intact file opens");
    }

    #[test]
    fn what_is_not_a_regular_file_with_one_link_is_refused_and_untouched() {
        // AF_UNIX bounds the spelling passed to bind, even when the absolute
        // worker TMPDIR is long. A fresh relative fixture needs no cwd change.
        let scratch = Scratch::in_directory(Path::new("."));
        let lim = Limits::tiny();
        assert_eq!(
            FileMedium::open_existing(&scratch.path("missing"), &lim).err(),
            Some(FileError::NotFound)
        );

        let directory = scratch.path("d");
        fs::create_dir(&directory).expect("directory");
        assert_eq!(
            FileMedium::open_existing(&directory, &lim).err(),
            Some(FileError::NotRegularFile)
        );

        let target = fresh(&scratch, "target.img", &lim);
        let image = bytes_of(&target);
        let link = scratch.path("link.img");
        std::os::unix::fs::symlink(
            fs::canonicalize(&target).expect("the target resolves"),
            &link,
        )
        .expect("symlink");
        assert_eq!(bytes_of(&link), image, "the link must reach the real image");
        assert_eq!(
            FileMedium::open_existing(&link, &lim).err(),
            Some(FileError::NotRegularFile)
        );

        let socket_path = scratch.path("s");
        let _listener = bind_socket(&socket_path).expect("a socket file");
        assert_eq!(
            FileMedium::open_existing(&socket_path, &lim).err(),
            Some(FileError::NotRegularFile)
        );

        let alias = scratch.path("alias.img");
        fs::hard_link(&target, &alias).expect("hard link");
        assert_eq!(
            FileMedium::open_existing(&target, &lim).err(),
            Some(FileError::NotExclusive)
        );
        assert_eq!(
            FileMedium::open_existing(&alias, &lim).err(),
            Some(FileError::NotExclusive)
        );

        assert_eq!(bytes_of(&target), image);
        // paired: an ordinary file with one link opens
        let plain = fresh(&scratch, "plain.img", &lim);
        FileMedium::open_existing(&plain, &lim).expect("a regular file with one link opens");
    }

    #[test]
    fn a_socket_spelling_binds_up_to_the_sun_path_limit_and_past_it_is_a_named_error_not_a_panic() {
        let limit = SUN_PATH_BYTES - 1;

        // A fresh relative scratch has a short spelling whatever the absolute working directory or TMPDIR is, so a fixture socket
        // fits. Fill the spelling to exactly the limit, and it binds.
        let scratch = Scratch::in_directory(Path::new("."));
        let room = limit - scratch.dir.as_os_str().len() - 1; // minus the separator
        let at_limit = scratch.path(&"s".repeat(room));
        assert_eq!(at_limit.as_os_str().len(), limit);
        let listener = bind_socket(&at_limit).expect("a spelling of exactly the limit binds");
        assert!(at_limit.exists(), "the socket file was made");
        drop(listener);

        // One byte more is a named error and nothing is made. `bind` itself returns an error for it too (it does not panic), so the
        // limit used above is the platform's and not only this helper's assumption.
        let past = scratch.path(&"t".repeat(room + 1));
        assert_eq!(past.as_os_str().len(), limit + 1);
        let refused = SocketPathError::TooLong {
            len: limit + 1,
            limit,
        };
        assert_eq!(bind_socket(&past).err(), Some(refused));
        assert!(UnixListener::bind(&past).is_err());
        assert!(!past.exists(), "a refused spelling makes no file");

        // The failure seen on a worker: an absolute fixture path under a base as long as `sun_path` is over the limit, and says so by
        // name. Nothing is created: the spelling is judged before the operating system is asked.
        let deep = Path::new("/").join("x".repeat(SUN_PATH_BYTES)).join("s");
        assert_eq!(
            bind_socket(&deep).err(),
            Some(SocketPathError::TooLong {
                len: deep.as_os_str().len(),
                limit,
            })
        );
    }

    #[test]
    fn a_second_open_is_refused_while_the_first_lives_and_allowed_after() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let created = FileMedium::create_new(&path, &lim).expect("create");
        assert_eq!(
            FileMedium::open_existing(&path, &lim).err(),
            Some(FileError::Locked)
        );
        drop(created);
        let first = FileMedium::open_existing(&path, &lim).expect("after the creator is gone");
        assert_eq!(
            FileMedium::open_existing(&path, &lim).err(),
            Some(FileError::Locked)
        );
        assert_eq!(first.fault(), None);
        drop(first);
        FileMedium::open_existing(&path, &lim).expect("after the first is gone");
    }

    #[test]
    fn a_file_the_owner_cannot_write_is_denied_and_unchanged() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = fresh(&scratch, "j.img", &lim);
        let image = bytes_of(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("chmod");
        if OpenOptions::new().write(true).open(&path).is_ok() {
            // a process that may write a 0400 file (root) cannot show a refusal; say so instead of passing silently
            eprintln!("FILE_MEDIUM_TEST_NOT_RUN denied: this process can write a 0400 file");
        } else {
            assert_eq!(
                FileMedium::open_existing(&path, &lim).err(),
                Some(FileError::Denied)
            );
        }
        assert_eq!(bytes_of(&path), image);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod back");
        FileMedium::open_existing(&path, &lim).expect("the owner's file opens again");
    }

    #[test]
    fn offsets_are_checked_before_any_write_and_programming_only_clears_bits() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let mut storage = FileMedium::create_new(&path, &lim).expect("create");
        let blank = bytes_of(&path);
        let end = 1024;

        assert_eq!(
            storage.program(end - 1, &[0x00, 0x00]),
            Err(StorageFault::OutOfRange)
        );
        assert_eq!(
            storage.program(usize::MAX, &[0x00]),
            Err(StorageFault::OutOfRange)
        );
        let mut two = [0u8; 2];
        assert_eq!(
            storage.read(end - 1, &mut two),
            Err(StorageFault::OutOfRange)
        );
        assert_eq!(storage.erase(2), Err(StorageFault::OutOfRange));
        assert_eq!(bytes_of(&path), blank, "a refused call wrote nothing");
        assert_eq!(storage.fault(), None, "a caller's error does not latch");
        assert_eq!(
            storage.program(end, &[]),
            Ok(()),
            "an empty write at the end is in range"
        );

        assert_eq!(storage.program(end - 1, &[0x0F]), Ok(()));
        assert_eq!(storage.program(0, &[0xF0]), Ok(()));
        // 0x0F would need the low nibble to rise from 0 (0x0F & !0xF0 = 0x0F): refused before a byte is written
        assert_eq!(
            storage.program(0, &[0x0F]),
            Err(StorageFault::BitsCannotRise)
        );
        assert_eq!(storage.fault(), None, "a refused program does not latch");
        let mut one = [0u8; 1];
        storage.read(0, &mut one).expect("read");
        assert_eq!(one, [0xF0]);
        assert_eq!(
            storage.program(0, &[0x30]),
            Ok(()),
            "0x30 only clears bits of 0xF0"
        );
        storage.read(0, &mut one).expect("read");
        assert_eq!(one, [0x30]);

        // a rise in the LAST byte of a multi-byte program leaves the first byte unwritten
        assert_eq!(storage.program(10, &[0xAA, 0xAA]), Ok(()));
        assert_eq!(
            storage.program(10, &[0x00, 0xFF]),
            Err(StorageFault::BitsCannotRise)
        );
        storage.read(10, &mut two).expect("read");
        assert_eq!(two, [0xAA, 0xAA]);

        // erase restores one segment to ones and leaves the other alone
        assert_eq!(storage.erase(0), Ok(()));
        let mut first = vec![0u8; 512];
        storage.read(0, &mut first).expect("read");
        assert!(first.iter().all(|b| *b == ERASED));
        storage.read(end - 1, &mut one).expect("read");
        assert_eq!(one, [0x0F]);
        assert_eq!(storage.sync(), Ok(()));
        assert_eq!(storage.fault(), None);
    }

    #[test]
    fn the_first_failure_latches_and_every_later_call_returns_it() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = fresh(&scratch, "j.img", &lim);
        let image = bytes_of(&path);

        // a real I/O failure: a handle opened read-only cannot write
        let read_only = File::open(&path).expect("a read-only handle");
        let mut storage = FileMedium {
            file: read_only,
            segment: 512,
            fault: Cell::new(None),
        };
        let mut buf = [0u8; 4];
        assert_eq!(
            storage.read(0, &mut buf),
            Ok(()),
            "reads work before the failure"
        );
        assert_eq!(storage.program(0, &[0x00]), Err(StorageFault::Io));
        assert_eq!(storage.fault(), Some(StorageFault::Io));
        assert_eq!(
            storage.read(0, &mut buf),
            Err(StorageFault::Io),
            "latched, though the read itself would work"
        );
        assert_eq!(storage.program(0, &[0xFF]), Err(StorageFault::Io));
        assert_eq!(storage.erase(0), Err(StorageFault::Io));
        assert_eq!(storage.sync(), Err(StorageFault::Io));
        assert_eq!(bytes_of(&path), image, "nothing reached the file");

        // the first fault is the one kept: a sync failure after an I/O failure does not replace it
        assert_eq!(storage.fail(StorageFault::SyncFailed), StorageFault::Io);
        drop(storage);

        // a sync failure latches as itself and answers every operation
        let mut healthy = FileMedium::open_existing(&path, &lim).expect("open");
        assert_eq!(
            healthy.fail(StorageFault::SyncFailed),
            StorageFault::SyncFailed
        );
        assert_eq!(healthy.read(0, &mut buf), Err(StorageFault::SyncFailed));
        assert_eq!(healthy.program(0, &[0x00]), Err(StorageFault::SyncFailed));
        assert_eq!(healthy.erase(1), Err(StorageFault::SyncFailed));
        assert_eq!(healthy.sync(), Err(StorageFault::SyncFailed));
        assert_eq!(bytes_of(&path), image);
        drop(healthy);

        // paired: a handle that has not failed does all of it
        let mut again = FileMedium::open_existing(&path, &lim)
            .expect("reopen after the failed handles are gone");
        assert_eq!(again.program(0, &[0x7F]), Ok(()));
        assert_eq!(again.sync(), Ok(()));
        assert_eq!(again.fault(), None);
    }

    #[test]
    fn error_codes_are_unique_snake_case_names_that_carry_no_data() {
        let mut seen = std::collections::BTreeSet::new();
        for error in FileError::ALL {
            let code = error.code();
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code}"
            );
            assert!(seen.insert(code), "{code} appears twice");
            assert_eq!(error.to_string(), code);
        }
        assert_eq!(seen.len(), FileError::ALL.len());
    }

    #[test]
    fn a_fail_plan_is_program_or_sync_and_a_count_of_at_least_one() {
        assert_eq!(FailAt::parse("program:3"), Some(FailAt::Program(3)));
        assert_eq!(FailAt::parse("sync:1"), Some(FailAt::Sync(1)));
        for refused in [
            "program:0",
            "sync:0",
            "program:x",
            "sync:-1",
            "erase:1",
            "program",
            ":1",
            "",
        ] {
            assert_eq!(FailAt::parse(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_faulting_medium_fails_exactly_the_chosen_program_after_it_is_armed_and_the_failed_one_has_no_effect()
     {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let armed = Rc::new(Cell::new(false));
        let mut medium = FaultingMedium::new(
            FileMedium::create_new(&path, &lim).expect("create"),
            Some(FailAt::Program(2)),
            Rc::clone(&armed),
        );
        let mut one = [0u8; 1];
        // before it is armed nothing is counted and nothing fails
        assert_eq!(medium.program(0, &[0xF0]), Ok(()));
        assert_eq!(medium.program(1, &[0xF0]), Ok(()));
        armed.set(true);
        // the first armed program passes; the second fails with no effect; the third passes (only that one call is chosen)
        assert_eq!(medium.program(2, &[0xF0]), Ok(()));
        assert_eq!(medium.program(3, &[0xF0]), Err(StorageFault::Io));
        medium.read(3, &mut one).expect("read");
        assert_eq!(one, [ERASED], "the failed program wrote nothing");
        assert_eq!(medium.program(3, &[0xF0]), Ok(()));
        medium.read(3, &mut one).expect("read");
        assert_eq!(one, [0xF0]);
        // the file layer underneath was never told: it is not latched
        drop(medium);
        FileMedium::open_existing(&path, &lim).expect("the file is intact and reopens");
    }

    #[test]
    fn a_faulting_medium_fails_exactly_the_chosen_sync_and_what_was_written_stays_in_the_file() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let armed = Rc::new(Cell::new(true));
        let mut medium = FaultingMedium::new(
            FileMedium::create_new(&path, &lim).expect("create"),
            Some(FailAt::Sync(2)),
            Rc::clone(&armed),
        );
        assert_eq!(medium.program(0, &[0x11]), Ok(()));
        assert_eq!(medium.sync(), Ok(()));
        assert_eq!(medium.program(1, &[0x22]), Ok(()));
        assert_eq!(medium.sync(), Err(StorageFault::SyncFailed));
        assert_eq!(medium.sync(), Ok(()), "only the second sync was chosen");
        drop(medium);
        let reopened = FileMedium::open_existing(&path, &lim).expect("reopen");
        let mut two = [0u8; 2];
        reopened.read(0, &mut two).expect("read");
        assert_eq!(two, [0x11, 0x22], "a failed sync does not undo a write");
    }

    #[test]
    fn a_faulting_medium_with_no_plan_is_the_medium_it_wraps() {
        let scratch = Scratch::new();
        let lim = Limits::tiny();
        let path = scratch.path("j.img");
        let mut medium = FaultingMedium::new(
            FileMedium::create_new(&path, &lim).expect("create"),
            None,
            Rc::new(Cell::new(true)),
        );
        assert_eq!(medium.segment_bytes(), 512);
        for n in 0..8 {
            assert_eq!(medium.program(n, &[0x0F]), Ok(()));
            assert_eq!(medium.sync(), Ok(()));
        }
        assert_eq!(medium.erase(1), Ok(()));
        assert_eq!(medium.program(2000, &[0]), Err(StorageFault::OutOfRange));
    }
}
