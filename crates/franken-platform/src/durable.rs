//! Durable-file ABI core for the legacy big-endian kernels (`P06` / `ffw-2nw`, slice A1). Contract: `docs/contracts/p06.md`.
//!
//! `franken_journal::Storage` (`read`/`program`/`erase`/`sync`) has no backing on the legacy images, and E03 marks "filesystem sync and
//! atomic rename (write, `fsync`, rename over an existing file, read back, old name gone)" **Required**. This module is the pure half of a
//! file-backed answer: the numbers the two admitted ABIs disagree on, the 64-bit file offset on a 32-bit ABI, and the decoders that turn a
//! raw return into a typed result. It issues no call and holds no state; the syscall numbers, the `KernelOps` methods and the leaf's
//! wrappers (the only `unsafe`) are `P02`'s and are not part of this slice. **It claims a bounded POSIX-file semantic, not raw flash and not
//! a generic filesystem.**
//!
//! Why the numbers are here and not borrowed. `O_CREAT` is `0x40` on PowerPC and `0x100` on MIPS; `O_EXCL`, `O_APPEND`, `O_DIRECTORY` and
//! `O_NOFOLLOW` move too, `O_LARGEFILE` on one ABI is `O_DIRECTORY` on the other, and eight file errnos differ (`ELOOP` on MIPS is `EMSGSIZE`
//! on PowerPC). A library that drops its `x86_64`/`aarch64` `compile_error!` and rebuilds would pass on a laptop and misread MIPS.
//!
//! Kernel-generation facts the numbers rest on (primary sources in `docs/contracts/p06.md`, "Slice A1"):
//! * `O_CLOEXEC` exists from **2.6.23**. Before that the kernel does not validate open flags, so the bit is **silently ignored** and the
//!   descriptor is *not* close-on-exec. [`CLOEXEC_HONORED_SINCE`] and [`cloexec_is_honored`] say so; nothing here can detect it from a result.
//! * `O_DSYNC` is a separate flag from **2.6.33**, and `O_SYNC` changes value then. This module uses the 2.6.33 numbers. On an older kernel
//!   `O_DSYNC` is the old `O_SYNC` bit (a full sync: stronger, never weaker) and the extra bit of the new `O_SYNC` is unassigned there, so the
//!   same argument works on both generations.
//! * `fsync` reports a writeback error **once** (`test_and_clear_bit` of `AS_EIO`/`AS_ENOSPC`), so a second `fsync` after a failure can return
//!   `0` over data that never reached the medium. [`DurableError::SyncFailed`] is therefore final: never retry it into a success.
//!
//! What is deliberately not here:
//! * **No thread-local `errno`.** A failure arrives in-band as `-errno` (see [`crate::abi`]).
//! * **No directory-`fsync` claim.** The E03 sequence does not include syncing the containing directory after the rename, so the judge does
//!   not either, and nothing here says a rename is durable.
//! * **No emulation.** `O_CLOEXEC` is not rebuilt with a later `fcntl` on a kernel that ignores it (`P02` contract, "The seam").

use thiserror::Error;

use crate::abi::{Abi, O_CLOEXEC, SysError};

/// A kernel release as `(major, minor, patch)`.
pub type KernelRelease = (u32, u32, u32);

/// The first release in which `open(O_CLOEXEC)` sets close-on-exec. On an earlier one the flag is ignored without an error.
pub const CLOEXEC_HONORED_SINCE: KernelRelease = (2, 6, 23);

/// The first release with a separate `O_DSYNC` and the two-bit `O_SYNC` that this module's numbers use.
pub const DSYNC_SINCE: KernelRelease = (2, 6, 33);

const fn at_least(release: KernelRelease, since: KernelRelease) -> bool {
    if release.0 != since.0 {
        return release.0 > since.0;
    }
    if release.1 != since.1 {
        return release.1 > since.1;
    }
    release.2 >= since.2
}

/// Whether a kernel of this release makes a descriptor close-on-exec when `O_CLOEXEC` is passed.
#[must_use]
pub const fn cloexec_is_honored(release: KernelRelease) -> bool {
    at_least(release, CLOEXEC_HONORED_SINCE)
}

/// Whether a kernel of this release has the separate `O_DSYNC` this module's `O_DSYNC` and `O_SYNC` numbers are written for.
#[must_use]
pub const fn dsync_is_native(release: KernelRelease) -> bool {
    at_least(release, DSYNC_SINCE)
}

// ------------------------------------------------------------------------------------------------------------ errors

/// A file errno, by name, with a number per ABI. The first sixteen are the same on both ABIs; the last eight are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileErrno {
    Perm,
    NoEnt,
    Io,
    BadF,
    NoMem,
    Acces,
    Busy,
    Exist,
    XDev,
    NotDir,
    IsDir,
    NFile,
    MFile,
    FBig,
    NoSpc,
    RoFs,
    Deadlk,
    NameTooLong,
    NoLck,
    NotEmpty,
    Loop,
    Overflow,
    Stale,
    DQuot,
}

impl FileErrno {
    pub const ALL: [Self; 24] = [
        Self::Perm,
        Self::NoEnt,
        Self::Io,
        Self::BadF,
        Self::NoMem,
        Self::Acces,
        Self::Busy,
        Self::Exist,
        Self::XDev,
        Self::NotDir,
        Self::IsDir,
        Self::NFile,
        Self::MFile,
        Self::FBig,
        Self::NoSpc,
        Self::RoFs,
        Self::Deadlk,
        Self::NameTooLong,
        Self::NoLck,
        Self::NotEmpty,
        Self::Loop,
        Self::Overflow,
        Self::Stale,
        Self::DQuot,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Perm => "EPERM",
            Self::NoEnt => "ENOENT",
            Self::Io => "EIO",
            Self::BadF => "EBADF",
            Self::NoMem => "ENOMEM",
            Self::Acces => "EACCES",
            Self::Busy => "EBUSY",
            Self::Exist => "EEXIST",
            Self::XDev => "EXDEV",
            Self::NotDir => "ENOTDIR",
            Self::IsDir => "EISDIR",
            Self::NFile => "ENFILE",
            Self::MFile => "EMFILE",
            Self::FBig => "EFBIG",
            Self::NoSpc => "ENOSPC",
            Self::RoFs => "EROFS",
            Self::Deadlk => "EDEADLK",
            Self::NameTooLong => "ENAMETOOLONG",
            Self::NoLck => "ENOLCK",
            Self::NotEmpty => "ENOTEMPTY",
            Self::Loop => "ELOOP",
            Self::Overflow => "EOVERFLOW",
            Self::Stale => "ESTALE",
            Self::DQuot => "EDQUOT",
        }
    }

    /// This error's number on `abi`.
    #[must_use]
    pub const fn number(self, abi: Abi) -> i32 {
        match (self, abi) {
            (Self::Perm, _) => 1,
            (Self::NoEnt, _) => 2,
            (Self::Io, _) => 5,
            (Self::BadF, _) => 9,
            (Self::NoMem, _) => 12,
            (Self::Acces, _) => 13,
            (Self::Busy, _) => 16,
            (Self::Exist, _) => 17,
            (Self::XDev, _) => 18,
            (Self::NotDir, _) => 20,
            (Self::IsDir, _) => 21,
            (Self::NFile, _) => 23,
            (Self::MFile, _) => 24,
            (Self::FBig, _) => 27,
            (Self::NoSpc, _) => 28,
            (Self::RoFs, _) => 30,
            (Self::Deadlk, Abi::PowerPc32) => 35,
            (Self::Deadlk, Abi::Mips32) => 45,
            (Self::NameTooLong, Abi::PowerPc32) => 36,
            (Self::NameTooLong, Abi::Mips32) => 78,
            (Self::NoLck, Abi::PowerPc32) => 37,
            (Self::NoLck, Abi::Mips32) => 46,
            (Self::NotEmpty, Abi::PowerPc32) => 39,
            (Self::NotEmpty, Abi::Mips32) => 93,
            (Self::Loop, Abi::PowerPc32) => 40,
            (Self::Loop, Abi::Mips32) => 90,
            (Self::Overflow, Abi::PowerPc32) => 75,
            (Self::Overflow, Abi::Mips32) => 79,
            (Self::Stale, Abi::PowerPc32) => 116,
            (Self::Stale, Abi::Mips32) => 151,
            (Self::DQuot, Abi::PowerPc32) => 122,
            (Self::DQuot, Abi::Mips32) => 1133,
        }
    }

    /// Which file error `errno` is **on this ABI**, or `None` if it is none of the twenty-four (it may still be another errno).
    #[must_use]
    pub fn of(abi: Abi, errno: i32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.number(abi) == errno)
    }
}

/// Why an open request was not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FlagsError {
    /// `O_TRUNC`, `O_APPEND` or a sync flag on a read-only open: the kernel's effect is unspecified or meaningless.
    #[error("a write flag (truncate, append or sync) was asked for on a read-only open")]
    WriteFlagOnReadOnly,
    /// `O_DIRECTORY` is for opening a directory to sync it; combining it with create, truncate, append, sync or write access is not.
    #[error(
        "a directory open must be read-only and carry no create, truncate, append or sync flag"
    )]
    DirectoryWithFileFlag,
}

/// Why a kernel answer is not believed, or a request was not built. Nothing here is a capability verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DurableError {
    /// `ENOSYS`, `EINTR`, `EAGAIN`, `EINVAL` or a return that is not an errno at all (see [`SysError`]). Never `SysError::Errno`.
    #[error("{0}")]
    Sys(SysError),
    /// An errno this layer names, in this ABI's numbering.
    #[error("{}", .0.name())]
    File(FileErrno),
    /// An errno that is none of the twenty-four. Kept as the kernel numbered it and never reinterpreted.
    #[error("errno {0}")]
    Unknown(i32),
    /// `fsync` failed with `EIO`, `ENOSPC` or `EDQUOT`. The kernel reports such an error once, so **the data may not be on the medium and a
    /// later `fsync` that returns 0 proves nothing**. Final.
    #[error("fsync failed with {}; durability is unknown and a retry cannot establish it", .0.name())]
    SyncFailed(FileErrno),
    /// `fsync` on a file with no sync operation (a special file): `EINVAL` from `fsync` means this, not a bad argument.
    #[error("the file has no sync operation")]
    NotSyncable,
    /// A `write` returned `0` for a request of at least one byte.
    #[error("write made no progress on a request of {requested} bytes")]
    NoProgress { requested: usize },
    /// A `write` reported more bytes than were requested.
    #[error("write reported {reported} bytes for a request of {requested}")]
    OverReported { reported: usize, requested: usize },
    /// A call that returns only `0` returned this.
    #[error("the call returned {raw}, which it never does")]
    UnexpectedResult { raw: usize },
    /// `open` returned a descriptor that does not fit an `int`.
    #[error("descriptor {raw} does not fit an int")]
    DescriptorRange { raw: usize },
    /// A file offset below zero.
    #[error("a negative file offset")]
    OffsetNegative,
    /// A file offset above what a 32-bit `off_t` carries.
    #[error("the offset does not fit a 32-bit off_t")]
    OffsetTooLarge,
    /// An open request that was not built.
    #[error("{0}")]
    Flags(FlagsError),
}

impl DurableError {
    /// Classify a decoded kernel error: a numbered errno becomes a [`FileErrno`] or [`DurableError::Unknown`]; every other [`SysError`] stays.
    #[must_use]
    pub fn classify(abi: Abi, error: SysError) -> Self {
        match error {
            SysError::Errno(errno) => {
                FileErrno::of(abi, errno).map_or(Self::Unknown(errno), Self::File)
            }
            other => Self::Sys(other),
        }
    }

    /// Whether a retry could turn this into a success. Only an interruption can; a sync failure never can.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Sys(SysError::Interrupted))
    }
}

// ------------------------------------------------------------------------------------------------------- open flags

/// `O_RDONLY`, `O_WRONLY`, `O_RDWR`: the same on both ABIs.
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
/// `O_TRUNC`: `0o1000` on both ABIs.
pub const O_TRUNC: u32 = 0x200;

/// The open flags whose numbers the two ABIs disagree on, plus `O_TRUNC`'s neighbours that a durable open uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFlag {
    Creat,
    Excl,
    Append,
    Dsync,
    Sync,
    Directory,
    NoFollow,
    LargeFile,
}

impl OpenFlag {
    pub const ALL: [Self; 8] = [
        Self::Creat,
        Self::Excl,
        Self::Append,
        Self::Dsync,
        Self::Sync,
        Self::Directory,
        Self::NoFollow,
        Self::LargeFile,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Creat => "O_CREAT",
            Self::Excl => "O_EXCL",
            Self::Append => "O_APPEND",
            Self::Dsync => "O_DSYNC",
            Self::Sync => "O_SYNC",
            Self::Directory => "O_DIRECTORY",
            Self::NoFollow => "O_NOFOLLOW",
            Self::LargeFile => "O_LARGEFILE",
        }
    }

    /// This flag's value on `abi`, in the 2.6.33 numbering (see the module header for older kernels).
    #[must_use]
    pub const fn value(self, abi: Abi) -> u32 {
        match (self, abi) {
            (Self::Creat, Abi::PowerPc32) => 0x40,
            (Self::Creat, Abi::Mips32) => 0x100,
            (Self::Excl, Abi::PowerPc32) => 0x80,
            (Self::Excl, Abi::Mips32) => 0x400,
            (Self::Append, Abi::PowerPc32) => 0x400,
            (Self::Append, Abi::Mips32) => 0x8,
            (Self::Dsync, Abi::PowerPc32) => 0x1000,
            (Self::Dsync, Abi::Mips32) => 0x10,
            (Self::Sync, Abi::PowerPc32) => 0x10_1000,
            (Self::Sync, Abi::Mips32) => 0x4010,
            (Self::Directory, Abi::PowerPc32) => 0x4000,
            (Self::Directory, Abi::Mips32) => 0x1_0000,
            (Self::NoFollow, Abi::PowerPc32) => 0x8000,
            (Self::NoFollow, Abi::Mips32) => 0x2_0000,
            (Self::LargeFile, Abi::PowerPc32) => 0x1_0000,
            (Self::LargeFile, Abi::Mips32) => 0x2000,
        }
    }
}

/// How a file is opened for access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// Whether and how the open creates the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Create {
    /// The file must already exist.
    Never,
    /// `O_CREAT`: create it if it is missing.
    IfMissing,
    /// `O_CREAT | O_EXCL`: create it and fail with `EEXIST` if it is there.
    MustBeNew,
}

/// Whether a write waits for the medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    None,
    /// `O_DSYNC`: data (and what is needed to read it back) before a write returns.
    Data,
    /// `O_SYNC`: data and metadata before a write returns.
    Full,
}

/// An `open` request. Nothing is on by default; [`OpenRequest::flags`] turns it into the argument or refuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenRequest {
    pub access: Access,
    pub create: Create,
    pub truncate: bool,
    pub append: bool,
    pub sync: SyncMode,
    pub directory: bool,
    pub no_follow: bool,
    pub nonblock: bool,
    pub cloexec: bool,
    pub large_file: bool,
}

impl OpenRequest {
    /// A request for `access` with every other option off.
    #[must_use]
    pub const fn new(access: Access) -> Self {
        Self {
            access,
            create: Create::Never,
            truncate: false,
            append: false,
            sync: SyncMode::None,
            directory: false,
            no_follow: false,
            nonblock: false,
            cloexec: false,
            large_file: false,
        }
    }

    /// Whether a positioned write (`pwrite64`) to a file opened like this lands where the offset says. **Linux appends regardless of the
    /// offset on an `O_APPEND` descriptor**, so a random-access store such as `Storage::program` must not open with `append`.
    #[must_use]
    pub const fn allows_positioned_write(&self) -> bool {
        !self.append
    }

    /// The `flags` argument of `open` on `abi`, or why the request is refused.
    ///
    /// # Errors
    /// [`DurableError::Flags`].
    pub fn flags(&self, abi: Abi) -> Result<u32, DurableError> {
        let read_only = matches!(self.access, Access::ReadOnly);
        if read_only && (self.truncate || self.append || !matches!(self.sync, SyncMode::None)) {
            return Err(DurableError::Flags(FlagsError::WriteFlagOnReadOnly));
        }
        if self.directory
            && (!read_only
                || self.truncate
                || self.append
                || !matches!(self.create, Create::Never)
                || !matches!(self.sync, SyncMode::None))
        {
            return Err(DurableError::Flags(FlagsError::DirectoryWithFileFlag));
        }
        let mut value = match self.access {
            Access::ReadOnly => O_RDONLY,
            Access::WriteOnly => O_WRONLY,
            Access::ReadWrite => O_RDWR,
        };
        match self.create {
            Create::Never => {}
            Create::IfMissing => value |= OpenFlag::Creat.value(abi),
            Create::MustBeNew => value |= OpenFlag::Creat.value(abi) | OpenFlag::Excl.value(abi),
        }
        if self.truncate {
            value |= O_TRUNC;
        }
        if self.append {
            value |= OpenFlag::Append.value(abi);
        }
        match self.sync {
            SyncMode::None => {}
            SyncMode::Data => value |= OpenFlag::Dsync.value(abi),
            SyncMode::Full => value |= OpenFlag::Sync.value(abi),
        }
        if self.directory {
            value |= OpenFlag::Directory.value(abi);
        }
        if self.no_follow {
            value |= OpenFlag::NoFollow.value(abi);
        }
        if self.nonblock {
            value |= abi.o_nonblock();
        }
        if self.cloexec {
            value |= O_CLOEXEC;
        }
        if self.large_file {
            value |= OpenFlag::LargeFile.value(abi);
        }
        Ok(value)
    }
}

// ----------------------------------------------------------------------------------------------------- decoders

/// Decode the return of `open`: a descriptor, or why not.
///
/// # Errors
/// [`DurableError::Sys`], [`DurableError::File`], [`DurableError::Unknown`] or [`DurableError::DescriptorRange`].
pub fn decode_open(abi: Abi, raw: isize) -> Result<i32, DurableError> {
    let fd = abi
        .decode(raw)
        .map_err(|error| DurableError::classify(abi, error))?;
    i32::try_from(fd).map_err(|_| DurableError::DescriptorRange { raw: fd })
}

/// What one `write` achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteProgress {
    /// Every requested byte was written.
    Full,
    /// Some, not all: neither success nor a fault. The caller writes the rest from `written`.
    Partial { written: usize },
}

/// Decode the return of a `write` of `requested` bytes.
///
/// # Errors
/// [`DurableError::NoProgress`] for `0` on a nonempty request, [`DurableError::OverReported`] for more than was asked, or a classified kernel
/// error (`ENOSPC`, `EDQUOT`, `EIO`, `EFBIG`, `EINTR` before any byte...).
pub fn decode_write(abi: Abi, raw: isize, requested: usize) -> Result<WriteProgress, DurableError> {
    let written = abi
        .decode(raw)
        .map_err(|error| DurableError::classify(abi, error))?;
    if written > requested {
        return Err(DurableError::OverReported {
            reported: written,
            requested,
        });
    }
    if written == requested {
        return Ok(WriteProgress::Full);
    }
    if written == 0 {
        return Err(DurableError::NoProgress { requested });
    }
    Ok(WriteProgress::Partial { written })
}

/// Decode a call that returns `0` or an error: `rename`, `unlink`, `fdatasync`, `ftruncate`, `close`.
///
/// # Errors
/// A classified kernel error, or [`DurableError::UnexpectedResult`] for a positive return.
pub fn decode_unit(abi: Abi, raw: isize) -> Result<(), DurableError> {
    match abi.decode(raw) {
        Ok(0) => Ok(()),
        Ok(other) => Err(DurableError::UnexpectedResult { raw: other }),
        Err(error) => Err(DurableError::classify(abi, error)),
    }
}

/// Decode the return of `fsync`. As [`decode_unit`], except that `EINVAL` means "no sync operation" and `EIO`, `ENOSPC` and `EDQUOT` are
/// [`DurableError::SyncFailed`], which is final.
///
/// # Errors
/// As [`decode_unit`], plus [`DurableError::NotSyncable`] and [`DurableError::SyncFailed`].
pub fn decode_fsync(abi: Abi, raw: isize) -> Result<(), DurableError> {
    match decode_unit(abi, raw) {
        Err(DurableError::Sys(SysError::Invalid)) => Err(DurableError::NotSyncable),
        Err(DurableError::File(kind @ (FileErrno::Io | FileErrno::NoSpc | FileErrno::DQuot))) => {
            Err(DurableError::SyncFailed(kind))
        }
        other => other,
    }
}

// ----------------------------------------------------------------------------------------------- 64-bit offsets

/// A file offset (`loff_t`, a signed 64-bit value) as the two 32-bit words a 32-bit big-endian ABI passes it in: high word first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOffset {
    hi: u32,
    lo: u32,
}

impl FileOffset {
    /// An offset of at least zero. A negative value is refused, never wrapped.
    ///
    /// # Errors
    /// [`DurableError::OffsetNegative`].
    pub fn new(offset: i64) -> Result<Self, DurableError> {
        let unsigned = u64::try_from(offset).map_err(|_| DurableError::OffsetNegative)?;
        Ok(Self {
            hi: u32::try_from(unsigned >> 32).map_err(|_| DurableError::OffsetNegative)?,
            lo: u32::try_from(unsigned & 0xffff_ffff).map_err(|_| DurableError::OffsetNegative)?,
        })
    }

    /// The high and low words, high first.
    #[must_use]
    pub const fn words(self) -> (u32, u32) {
        (self.hi, self.lo)
    }

    /// The value.
    #[must_use]
    pub fn value(self) -> i64 {
        (i64::from(self.hi) << 32) | i64::from(self.lo)
    }

    /// The three argument words that follow `(fd, buf, count)` in `pread64` and `pwrite64` on both ABIs: a **pad word of zero** (a 64-bit
    /// argument starts on an even register pair, so the fourth slot is skipped), then the high word, then the low word. Both calls therefore
    /// take **six** argument slots, which is one more than the leaf's five-argument trampoline carries.
    #[must_use]
    pub const fn positioned_tail(self) -> [u32; 3] {
        [0, self.hi, self.lo]
    }

    /// The value as a 32-bit `off_t`, for an interface that has no 64-bit form. An offset past `i32::MAX` is refused, never truncated.
    ///
    /// # Errors
    /// [`DurableError::OffsetTooLarge`].
    pub fn to_i32(self) -> Result<i32, DurableError> {
        i32::try_from(self.value()).map_err(|_| DurableError::OffsetTooLarge)
    }

    /// Read the `loff_t` that `_llseek` stores through its result pointer: eight big-endian bytes, high word first.
    ///
    /// # Errors
    /// [`DurableError::OffsetNegative`] when the sign bit is set.
    pub fn from_llseek_result(bytes: [u8; 8]) -> Result<Self, DurableError> {
        let hi = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let lo = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if hi > 0x7fff_ffff {
            return Err(DurableError::OffsetNegative);
        }
        Ok(Self { hi, lo })
    }
}

// ------------------------------------------------------------------------------------- the E03 replace sequence

/// One observed step of the E03 "replace a file" sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The whole write, after the caller's own loop over [`WriteProgress::Partial`]: `written` of `requested` bytes.
    Write { requested: usize, written: usize },
    /// The raw return of `fsync` on the new file.
    Fsync { raw: isize },
    /// The raw return of `rename` of the new name over the old one.
    Rename { raw: isize },
    /// Whether reading the target back gave the bytes written.
    ReadBack { matches: bool },
    /// The raw return of opening or stat-ing the **old** name: it must be `-ENOENT`.
    OldNameGone { raw: isize },
}

impl Step {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Write { .. } => "write",
            Self::Fsync { .. } => "fsync",
            Self::Rename { .. } => "rename",
            Self::ReadBack { .. } => "read_back",
            Self::OldNameGone { .. } => "old_name_gone",
        }
    }
}

/// The order E03 observes: write, `fsync`, rename over an existing file, read back, old name gone.
pub const SEQUENCE: [&str; 5] = ["write", "fsync", "rename", "read_back", "old_name_gone"];

/// Why a sequence is not a pass. The first causal step is named; nothing after it is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SequenceError {
    #[error("the sequence ended before {expected}")]
    Missing { expected: &'static str },
    #[error("step {index} should be {expected}")]
    OutOfOrder {
        index: usize,
        expected: &'static str,
    },
    #[error("step {index} is past the end of the sequence")]
    Extra { index: usize },
    #[error("the write stopped at {written} of {requested} bytes")]
    ShortWrite { requested: usize, written: usize },
    #[error("{step} failed: {error}")]
    Failed {
        index: usize,
        step: &'static str,
        error: DurableError,
    },
    #[error("the target read back different bytes")]
    ReadBackDiffers,
    #[error("the old name still opens")]
    OldNameStillThere,
}

/// Judge an observed replace sequence against the E03 order. `fsync` must come **before** the rename: a rename of unsynced data is the
/// failure this sequence exists to rule out.
///
/// # Errors
/// [`SequenceError`] naming the first step that is missing, misplaced, failed or wrong.
pub fn judge_replace_sequence(abi: Abi, steps: &[Step]) -> Result<(), SequenceError> {
    for (index, expected) in SEQUENCE.into_iter().enumerate() {
        let step = steps
            .get(index)
            .ok_or(SequenceError::Missing { expected })?;
        if step.name() != expected {
            return Err(SequenceError::OutOfOrder { index, expected });
        }
        let failed = |error| SequenceError::Failed {
            index,
            step: expected,
            error,
        };
        match *step {
            Step::Write { requested, written } => {
                if written > requested {
                    return Err(failed(DurableError::OverReported {
                        reported: written,
                        requested,
                    }));
                }
                if written < requested {
                    return Err(SequenceError::ShortWrite { requested, written });
                }
            }
            Step::Fsync { raw } => decode_fsync(abi, raw).map_err(failed)?,
            Step::Rename { raw } => decode_unit(abi, raw).map_err(failed)?,
            Step::ReadBack { matches } => {
                if !matches {
                    return Err(SequenceError::ReadBackDiffers);
                }
            }
            Step::OldNameGone { raw } => match abi.decode(raw) {
                Ok(_) => return Err(SequenceError::OldNameStillThere),
                Err(error) => match DurableError::classify(abi, error) {
                    DurableError::File(FileErrno::NoEnt) => {}
                    other => return Err(failed(other)),
                },
            },
        }
    }
    if steps.len() > SEQUENCE.len() {
        return Err(SequenceError::Extra {
            index: SEQUENCE.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    /// Written by hand from the kernel headers and the libc crate's musl b32 files; replayed here and read again, independently, by
    /// `tests/p06/test_durable.py`. Nothing in it was produced by this module.
    const VECTORS: &str = include_str!("../tests/vectors/p06_durable_abi.json");
    /// This file's own text, for the source test at the end.
    const SOURCE: &str = include_str!("durable.rs");
    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("the vector file parses")
    }

    fn abi_named(name: &str) -> Abi {
        match name {
            "powerpc32" => Abi::PowerPc32,
            "mips32" => Abi::Mips32,
            other => panic!("unknown ABI {other}"),
        }
    }

    fn key(abi: Abi) -> &'static str {
        match abi {
            Abi::PowerPc32 => "powerpc32",
            Abi::Mips32 => "mips32",
        }
    }

    fn num(value: &Value, field: &str) -> i64 {
        value[field]
            .as_i64()
            .unwrap_or_else(|| panic!("{field} is not a number in {value}"))
    }

    fn text<'a>(value: &'a Value, field: &str) -> &'a str {
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is not a string in {value}"))
    }

    fn cases<'a>(v: &'a Value, group: &str) -> &'a Vec<Value> {
        v[group]
            .as_array()
            .unwrap_or_else(|| panic!("{group} is not a list"))
    }

    fn error_name(error: &DurableError) -> String {
        match error {
            DurableError::Sys(SysError::Interrupted) => "interrupted".to_string(),
            DurableError::Sys(SysError::Absent) => "absent".to_string(),
            DurableError::Sys(SysError::WouldBlock) => "would_block".to_string(),
            DurableError::Sys(SysError::Invalid) => "invalid".to_string(),
            DurableError::Sys(SysError::Errno(errno)) => format!("sys_errno:{errno}"),
            DurableError::Sys(SysError::Malformed(_)) => "malformed".to_string(),
            DurableError::File(kind) => kind.name().to_string(),
            DurableError::Unknown(errno) => format!("unknown:{errno}"),
            DurableError::SyncFailed(kind) => format!("sync_failed:{}", kind.name()),
            DurableError::NotSyncable => "not_syncable".to_string(),
            DurableError::NoProgress { .. } => "no_progress".to_string(),
            DurableError::OverReported { .. } => "over_reported".to_string(),
            DurableError::UnexpectedResult { .. } => "unexpected_result".to_string(),
            DurableError::DescriptorRange { .. } => "descriptor_range".to_string(),
            DurableError::OffsetNegative => "offset_negative".to_string(),
            DurableError::OffsetTooLarge => "offset_too_large".to_string(),
            DurableError::Flags(FlagsError::WriteFlagOnReadOnly) => {
                "flags:write_flag_on_read_only".to_string()
            }
            DurableError::Flags(FlagsError::DirectoryWithFileFlag) => {
                "flags:directory_with_file_flag".to_string()
            }
        }
    }

    fn sequence_error_name(error: &SequenceError) -> String {
        match error {
            SequenceError::Missing { expected } => format!("missing:{expected}"),
            SequenceError::OutOfOrder { index, expected } => {
                format!("out_of_order:{index}:{expected}")
            }
            SequenceError::Extra { index } => format!("extra:{index}"),
            SequenceError::ShortWrite { .. } => "short_write".to_string(),
            SequenceError::Failed { index, step, error } => {
                format!("failed:{index}:{step}:{}", error_name(error))
            }
            SequenceError::ReadBackDiffers => "read_back_differs".to_string(),
            SequenceError::OldNameStillThere => "old_name_still_there".to_string(),
        }
    }

    /// Hold a result to a vector's `{"ok": ...}` or `{"err": name}`, where the success side is compared by `ok`.
    fn check_err<T: std::fmt::Debug>(
        result: &Result<T, DurableError>,
        expect: &Value,
        context: &str,
    ) -> bool {
        match (result, expect.get("err")) {
            (Err(got), Some(want)) => {
                assert_eq!(error_name(got), want.as_str().expect("string"), "{context}");
                true
            }
            (Ok(_), None) => false,
            _ => panic!("{context}: got {result:?}, the vector says {expect}"),
        }
    }

    fn step_from(value: &Value) -> Step {
        let kind = text(value, "step");
        match kind {
            "write" => Step::Write {
                requested: usize::try_from(num(value, "requested")).expect("usize"),
                written: usize::try_from(num(value, "written")).expect("usize"),
            },
            "fsync" => Step::Fsync {
                raw: isize::try_from(num(value, "raw")).expect("isize"),
            },
            "rename" => Step::Rename {
                raw: isize::try_from(num(value, "raw")).expect("isize"),
            },
            "read_back" => Step::ReadBack {
                matches: value["matches"].as_bool().expect("bool"),
            },
            "old_name_gone" => Step::OldNameGone {
                raw: isize::try_from(num(value, "raw")).expect("isize"),
            },
            other => panic!("unknown step {other}"),
        }
    }

    // ------------------------------------------------------------------------------------------ the numbers

    #[test]
    fn the_open_flag_numbers_are_the_vectors() {
        let v = vectors();
        for abi in BOTH {
            let row = &v["abi"][key(abi)]["open"];
            for flag in OpenFlag::ALL {
                let want = row[flag.name()].as_u64().expect("a flag number");
                assert_eq!(
                    u64::from(flag.value(abi)),
                    want,
                    "{} on {}",
                    flag.name(),
                    key(abi)
                );
            }
        }
        let common = &v["common"];
        assert_eq!(u64::from(O_RDONLY), common["O_RDONLY"].as_u64().expect("n"));
        assert_eq!(u64::from(O_WRONLY), common["O_WRONLY"].as_u64().expect("n"));
        assert_eq!(u64::from(O_RDWR), common["O_RDWR"].as_u64().expect("n"));
        assert_eq!(u64::from(O_TRUNC), common["O_TRUNC"].as_u64().expect("n"));
        assert_eq!(
            u64::from(O_CLOEXEC),
            common["O_CLOEXEC"].as_u64().expect("n")
        );
        for abi in BOTH {
            assert_eq!(
                u64::from(abi.o_nonblock()),
                v["abi"][key(abi)]["O_NONBLOCK"].as_u64().expect("n"),
                "O_NONBLOCK on {}",
                key(abi)
            );
        }
    }

    #[test]
    fn a_flag_number_names_one_flag_per_abi_and_the_cross_abi_collisions_are_the_vectors() {
        let v = vectors();
        for abi in BOTH {
            let mut seen: Vec<(u32, &str)> = Vec::new();
            for flag in OpenFlag::ALL {
                // O_DSYNC is a bit of O_SYNC by design (O_SYNC = __O_SYNC | O_DSYNC); every other pair must be disjoint.
                if flag == OpenFlag::Sync {
                    assert_eq!(
                        flag.value(abi) & OpenFlag::Dsync.value(abi),
                        OpenFlag::Dsync.value(abi),
                        "O_SYNC contains O_DSYNC on {}",
                        key(abi)
                    );
                    continue;
                }
                assert!(
                    !seen.iter().any(|(value, _)| *value == flag.value(abi)),
                    "{} repeats a value on {}",
                    flag.name(),
                    key(abi)
                );
                seen.push((flag.value(abi), flag.name()));
            }
        }
        let mut found: Vec<(u32, &str, &str)> = Vec::new();
        for a in OpenFlag::ALL {
            for b in OpenFlag::ALL {
                if a != b && a.value(Abi::PowerPc32) == b.value(Abi::Mips32) {
                    found.push((a.value(Abi::PowerPc32), a.name(), b.name()));
                }
            }
        }
        let listed: Vec<(u32, String, String)> = cases(&v, "cross_abi_collisions")
            .iter()
            .map(|case| {
                (
                    u32::try_from(num(case, "value")).expect("u32"),
                    text(case, "powerpc32").to_string(),
                    text(case, "mips32").to_string(),
                )
            })
            .collect();
        let found: Vec<(u32, String, String)> = found
            .into_iter()
            .map(|(value, a, b)| (value, a.to_string(), b.to_string()))
            .collect();
        assert_eq!(found, listed);
    }

    #[test]
    fn the_kernel_release_boundaries_are_the_vectors() {
        let v = vectors();
        let b = &v["kernel_boundaries"];
        let pair = |value: &Value| -> KernelRelease {
            let list = value.as_array().expect("a release");
            (
                u32::try_from(list[0].as_u64().expect("n")).expect("u32"),
                u32::try_from(list[1].as_u64().expect("n")).expect("u32"),
                u32::try_from(list[2].as_u64().expect("n")).expect("u32"),
            )
        };
        assert_eq!(CLOEXEC_HONORED_SINCE, pair(&b["cloexec_honored_since"]));
        assert_eq!(DSYNC_SINCE, pair(&b["dsync_native_since"]));
        for case in cases(&v, "release_checks") {
            let release = pair(&case["release"]);
            assert_eq!(
                cloexec_is_honored(release),
                case["cloexec_honored"].as_bool().expect("bool"),
                "{release:?}"
            );
            assert_eq!(
                dsync_is_native(release),
                case["dsync_native"].as_bool().expect("bool"),
                "{release:?}"
            );
        }
    }

    #[test]
    fn open_requests_build_the_flags_the_vectors_say_or_are_refused() {
        let v = vectors();
        for case in cases(&v, "open_request") {
            let request = OpenRequest {
                access: match text(case, "access") {
                    "read_only" => Access::ReadOnly,
                    "write_only" => Access::WriteOnly,
                    "read_write" => Access::ReadWrite,
                    other => panic!("access {other}"),
                },
                create: match text(case, "create") {
                    "never" => Create::Never,
                    "if_missing" => Create::IfMissing,
                    "must_be_new" => Create::MustBeNew,
                    other => panic!("create {other}"),
                },
                truncate: case["truncate"].as_bool().expect("bool"),
                append: case["append"].as_bool().expect("bool"),
                sync: match text(case, "sync") {
                    "none" => SyncMode::None,
                    "data" => SyncMode::Data,
                    "full" => SyncMode::Full,
                    other => panic!("sync {other}"),
                },
                directory: case["directory"].as_bool().expect("bool"),
                no_follow: case["no_follow"].as_bool().expect("bool"),
                nonblock: case["nonblock"].as_bool().expect("bool"),
                cloexec: case["cloexec"].as_bool().expect("bool"),
                large_file: case["large_file"].as_bool().expect("bool"),
            };
            let abi = abi_named(text(case, "abi"));
            let context = format!("{} on {}", text(case, "name"), text(case, "abi"));
            let result = request.flags(abi);
            if !check_err(&result, &case["expect"], &context) {
                assert_eq!(
                    u64::from(result.expect("a flags value")),
                    case["expect"]["ok"].as_u64().expect("n"),
                    "{context}"
                );
            }
        }
    }

    #[test]
    fn an_append_open_is_not_a_target_for_positioned_writes() {
        let plain = OpenRequest::new(Access::ReadWrite);
        assert!(plain.allows_positioned_write());
        let appending = OpenRequest {
            append: true,
            ..plain
        };
        assert!(!appending.allows_positioned_write());
    }

    // ------------------------------------------------------------------------------------------ the errnos

    #[test]
    fn file_errno_numbers_are_the_vectors_and_name_at_most_one_error_per_abi() {
        let v = vectors();
        for abi in BOTH {
            let row = &v["abi"][key(abi)]["errno"];
            for errno in FileErrno::ALL {
                assert_eq!(
                    i64::from(errno.number(abi)),
                    num(row, errno.name()),
                    "{} on {}",
                    errno.name(),
                    key(abi)
                );
            }
            let mut numbers: Vec<i32> = FileErrno::ALL.iter().map(|e| e.number(abi)).collect();
            numbers.sort_unstable();
            numbers.dedup();
            assert_eq!(numbers.len(), FileErrno::ALL.len(), "{}", key(abi));
            // none of them is a number that SysError already gives a variant to
            for reserved in [4, 11, 22, abi.enosys()] {
                assert!(
                    !numbers.contains(&reserved),
                    "{reserved} is EINTR/EAGAIN/EINVAL/ENOSYS on {}",
                    key(abi)
                );
            }
        }
        let differing: Vec<&str> = FileErrno::ALL
            .into_iter()
            .filter(|e| e.number(Abi::PowerPc32) != e.number(Abi::Mips32))
            .map(FileErrno::name)
            .collect();
        let listed: Vec<&str> = v["differing_errnos"]
            .as_array()
            .expect("list")
            .iter()
            .map(|n| n.as_str().expect("name"))
            .collect();
        assert_eq!(differing, listed);
    }

    #[test]
    fn errno_classification_follows_the_vectors_and_keeps_what_it_does_not_know() {
        let v = vectors();
        for case in cases(&v, "classify") {
            let abi = abi_named(text(case, "abi"));
            let raw = -isize::try_from(num(case, "errno")).expect("isize");
            let got = DurableError::classify(abi, abi.decode(raw).expect_err("an error"));
            assert_eq!(error_name(&got), text(case, "expect"), "{case}");
        }
        // an ABI's number is not the other ABI's error: MIPS 90 is ELOOP, PowerPC 90 is none of the twenty-four
        assert_eq!(FileErrno::of(Abi::Mips32, 90), Some(FileErrno::Loop));
        assert_eq!(FileErrno::of(Abi::PowerPc32, 90), None);
        assert!(DurableError::Sys(SysError::Interrupted).is_retryable());
        assert!(!DurableError::SyncFailed(FileErrno::Io).is_retryable());
        assert!(!DurableError::File(FileErrno::NoSpc).is_retryable());
    }

    // ------------------------------------------------------------------------------------------ decoders

    #[test]
    fn open_results_decode_as_descriptors_or_typed_errors() {
        let v = vectors();
        for case in cases(&v, "open_decode") {
            let abi = abi_named(text(case, "abi"));
            let raw = isize::try_from(num(case, "raw")).expect("isize");
            let result = decode_open(abi, raw);
            if !check_err(&result, &case["expect"], &case.to_string()) {
                assert_eq!(
                    i64::from(result.expect("a descriptor")),
                    case["expect"]["fd"].as_i64().expect("n"),
                    "{case}"
                );
            }
        }
    }

    #[test]
    fn a_short_write_is_neither_success_nor_a_fault() {
        let v = vectors();
        for case in cases(&v, "write_decode") {
            let abi = abi_named(text(case, "abi"));
            let raw = isize::try_from(num(case, "raw")).expect("isize");
            let requested = usize::try_from(num(case, "requested")).expect("usize");
            let result = decode_write(abi, raw, requested);
            if !check_err(&result, &case["expect"], &case.to_string()) {
                let want = &case["expect"];
                match result.expect("progress") {
                    WriteProgress::Full => assert_eq!(want["progress"], "full", "{case}"),
                    WriteProgress::Partial { written } => {
                        assert_eq!(want["progress"], "partial", "{case}");
                        assert_eq!(
                            i64::try_from(written).expect("i64"),
                            num(want, "written"),
                            "{case}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fsync_results_are_durable_or_final_and_a_unit_call_never_returns_a_count() {
        let v = vectors();
        for case in cases(&v, "fsync_decode") {
            let abi = abi_named(text(case, "abi"));
            let raw = isize::try_from(num(case, "raw")).expect("isize");
            let result = decode_fsync(abi, raw);
            if !check_err(&result, &case["expect"], &case.to_string()) {
                assert_eq!(case["expect"]["ok"].as_bool(), Some(true), "{case}");
            }
        }
        for case in cases(&v, "unit_decode") {
            let abi = abi_named(text(case, "abi"));
            let raw = isize::try_from(num(case, "raw")).expect("isize");
            let result = decode_unit(abi, raw);
            if !check_err(&result, &case["expect"], &case.to_string()) {
                assert_eq!(case["expect"]["ok"].as_bool(), Some(true), "{case}");
            }
        }
    }

    // ------------------------------------------------------------------------------------------ offsets

    #[test]
    fn file_offsets_split_into_big_endian_words_and_are_never_truncated() {
        let v = vectors();
        for case in cases(&v, "offset") {
            let offset = case["offset"].as_i64().expect("i64");
            let result = FileOffset::new(offset);
            if !check_err(&result, &case["expect"], &case.to_string()) {
                let got = result.expect("an offset");
                let want = &case["expect"];
                assert_eq!(
                    (u64::from(got.words().0), u64::from(got.words().1)),
                    (
                        want["hi"].as_u64().expect("n"),
                        want["lo"].as_u64().expect("n")
                    ),
                    "{case}"
                );
                assert_eq!(got.value(), offset, "{case}");
                let tail = got.positioned_tail();
                assert_eq!(tail[0], 0, "the pad word is zero: {case}");
                assert_eq!((tail[1], tail[2]), got.words(), "{case}");
                match (got.to_i32(), want.get("i32")) {
                    (Ok(n), Some(expected)) => {
                        assert_eq!(i64::from(n), expected.as_i64().expect("n"), "{case}");
                    }
                    (Err(DurableError::OffsetTooLarge), None) => {}
                    other => panic!("{case}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn an_llseek_result_is_eight_big_endian_bytes_and_a_negative_one_is_refused() {
        let v = vectors();
        for case in cases(&v, "llseek_result") {
            let hex = text(case, "bytes");
            let mut bytes = [0u8; 8];
            for (index, slot) in bytes.iter_mut().enumerate() {
                *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
            }
            let result = FileOffset::from_llseek_result(bytes);
            if !check_err(&result, &case["expect"], &case.to_string()) {
                assert_eq!(
                    result.expect("an offset").value(),
                    case["expect"]["offset"].as_i64().expect("n"),
                    "{case}"
                );
            }
        }
    }

    // ------------------------------------------------------------------------------------------ the sequence

    #[test]
    fn the_replace_sequence_passes_in_order_and_names_the_first_causal_step_otherwise() {
        let v = vectors();
        for case in cases(&v, "replace_sequence") {
            let abi = abi_named(text(case, "abi"));
            let steps: Vec<Step> = case["steps"]
                .as_array()
                .expect("steps")
                .iter()
                .map(step_from)
                .collect();
            let result = judge_replace_sequence(abi, &steps);
            let context = format!("{} on {}", text(case, "name"), text(case, "abi"));
            match (&result, case["expect"].get("err")) {
                (Ok(()), None) => {
                    assert_eq!(case["expect"]["ok"].as_bool(), Some(true), "{context}")
                }
                (Err(got), Some(want)) => assert_eq!(
                    sequence_error_name(got),
                    want.as_str().expect("string"),
                    "{context}"
                ),
                _ => panic!(
                    "{context}: got {result:?}, the vector says {}",
                    case["expect"]
                ),
            }
        }
    }

    // ------------------------------------------------------------------------------------------ the source

    #[test]
    fn the_source_has_no_unsafe_no_filesystem_no_syscall_number_and_no_other_libraries_code() {
        let code: String = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("the code comes before the tests")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "thread_local",
            "unsafe",
            "std::fs",
            "std::net",
            "std::os",
            "libc::",
            "__NR_",
            "NR_",
            "extern ",
            "KernelOps",
        ] {
            assert!(!code.contains(forbidden), "the code mentions {forbidden:?}");
        }
    }
}
