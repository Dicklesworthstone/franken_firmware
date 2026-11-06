//! franken-speaker smoke step (cargo feature `speaker-smoke`; absent from the default build).
//!
//! PID 1 runs `/franken-speaker --catalog` as a child process: stdout goes to a pipe, stdin and stderr stay on
//! the console. PID 1 forwards every stdout byte to the console while measuring it (byte count and FNV-1a-64),
//! reaps the child and prints one `FFW_SPEAKER_EXIT` line. Grammar and verdicts are in
//! `ffw_hello_init::speaker_judge`, which is unit tested on the host; this file is only the syscalls.
//!
//! Failure of `dup2` or `execve` in the child cannot be seen from the parent's `wait4` (the child just exits
//! 127), so the child reports its errno through a second pipe. The parent reads that pipe only after the child
//! has been reaped, so it can never block on it.
//!
//! Syscall numbers are the Linux o32 / PowerPC32 values from zig 0.15.2 `std/os/linux/syscalls.zig`
//! (`MipsO32`, `PowerPC`); the same parse reproduces the eight constants `main.rs` already uses.
//!
//! The thread probe in `e03_probes_rt` runs before this step and leaves signal handlers installed. `execve`
//! resets handlers to their defaults, and the probe restores the signal mask, so the speaker starts clean.

use core::ffi::CStr;

use ffw_hello_init::speaker_judge::{
    decode_exec_probe, decode_wait_status, exit_line, ExecProbe, Fnv1a64, Outcome, Output,
    SpawnStage, WaitStatus,
};
#[cfg(feature = "speaker-platform")]
use ffw_hello_init::speaker_judge::{exit_line_for, Step};

use super::{emit_console, sys, sys_close, sys_exit, sys_raw, sys_read, sys_write, LineWriter};

#[cfg(target_arch = "mips")]
mod nr {
    pub const FORK: usize = 4002;
    pub const EXECVE: usize = 4011;
    pub const DUP2: usize = 4063;
    pub const WAIT4: usize = 4114;
}

#[cfg(target_arch = "powerpc")]
mod nr {
    pub const FORK: usize = 2;
    pub const EXECVE: usize = 11;
    pub const DUP2: usize = 63;
    pub const WAIT4: usize = 114;
}

/// What is executed, and what the BEGIN line reports: the line is built from these same constants.
const PATH: &CStr = c"/franken-speaker";
const ARG_CATALOG: &CStr = c"--catalog";
#[cfg(feature = "speaker-platform")]
const ARG_PLATFORM: &CStr = c"--platform-startup";
/// The one extra argument of the platform step in a build with `speaker-platform-legacy-test-env`: the explicit legacy `/dev/random`
/// provider, in an admitted test environment. Without that feature the child's argv is exactly `/franken-speaker --platform-startup`.
#[cfg(all(
    feature = "speaker-platform",
    feature = "speaker-platform-legacy-test-env"
))]
const PLATFORM_EXTRA: Option<&CStr> =
    Some(c"--entropy-provider=legacy-dev-random-test-environment");
#[cfg(all(
    feature = "speaker-platform",
    not(feature = "speaker-platform-legacy-test-env")
))]
const PLATFORM_EXTRA: Option<&CStr> = None;

/// Bounds on retries (EINTR) so no loop here is unbounded; the external guest watchdog bounds wall-clock time.
const READ_ATTEMPTS: usize = 1 << 20;
const WAIT_ATTEMPTS: usize = 64;

fn sys_fork() -> isize {
    unsafe { sys_raw(nr::FORK, 0, 0, 0, 0) }
}

fn sys_dup2(old: usize, new: usize) -> isize {
    unsafe { sys_raw(nr::DUP2, old, new, 0, 0) }
}

fn sys_wait4(pid: usize, status: &mut i32) -> isize {
    unsafe { sys_raw(nr::WAIT4, pid, status as *mut i32 as usize, 0, 0) }
}

fn sys_pipe2(fds: &mut [i32; 2], flags: usize) -> isize {
    unsafe { sys_raw(sys::NR_PIPE2, fds.as_mut_ptr() as usize, flags, 0, 0) }
}

fn sys_execve(argv: &[usize; 4], envp: &[usize; 1]) -> isize {
    unsafe {
        sys_raw(
            nr::EXECVE,
            PATH.as_ptr() as usize,
            argv.as_ptr() as usize,
            envp.as_ptr() as usize,
            0,
        )
    }
}

fn close_all(fds: &[usize]) {
    for &fd in fds {
        let _ = sys_close(fd);
    }
}

/// Runs in the forked child and never returns: either `execve` replaces the process, or the errno is written
/// to the error pipe and the child exits.
fn run_child(out_write: usize, err_write: usize, arg: &CStr, extra: Option<&CStr>) -> ! {
    // Standard output becomes the pipe; stdin and stderr remain the console.
    let dup_rc = sys_dup2(out_write, 1);
    let errno = if dup_rc < 0 {
        dup_rc.unsigned_abs() as u32
    } else {
        if out_write != 1 {
            let _ = sys_close(out_write);
        }
        // argv ends at the first null: with no extra argument it is exactly the two-argument form every earlier step used.
        let extra_ptr = extra.map_or(0usize, |extra| extra.as_ptr() as usize);
        let argv = [
            PATH.as_ptr() as usize,
            arg.as_ptr() as usize,
            extra_ptr,
            0usize,
        ];
        let envp = [0usize];
        // `execve` only returns on failure, with -errno.
        sys_execve(&argv, &envp).unsigned_abs() as u32
    };
    let _ = sys_write(err_write, &errno.to_be_bytes());
    sys_exit(127)
}

/// The parent after a successful `fork`: drain the child's stdout (forwarding it to the console), reap the
/// child, then read the error pipe.
fn run_parent(console_fd: usize, pid: usize, out_read: usize, err_read: usize) -> Outcome {
    let mut hash = Fnv1a64::new();
    let mut bytes: u32 = 0;
    let mut last = b'\n';
    let mut read_errno: Option<u32> = None;
    let mut reached_eof = false;
    let mut buf = [0u8; 2048];
    for _ in 0..READ_ATTEMPTS {
        let n = sys_read(out_read, &mut buf);
        if n == -4 {
            continue; // EINTR on both bootstrap Linux ABIs.
        }
        if n < 0 {
            read_errno = Some(n.unsigned_abs() as u32);
            break;
        }
        if n == 0 {
            reached_eof = true;
            break;
        }
        let chunk = &buf[..n as usize];
        hash.update(chunk);
        bytes = bytes.saturating_add(n as u32);
        last = chunk[chunk.len() - 1];
        emit_console(console_fd, chunk);
    }
    if !reached_eof && read_errno.is_none() {
        read_errno = Some(0); // attempt budget exhausted without end of file
    }
    // Close our read end before reaping: a child still writing then gets SIGPIPE instead of blocking `wait4`.
    let _ = sys_close(out_read);
    if bytes > 0 && last != b'\n' {
        emit_console(console_fd, b"\n"); // keep the EXIT line at the start of its own line
    }

    let mut status: i32 = 0;
    let mut wait_rc: isize = -4;
    for _ in 0..WAIT_ATTEMPTS {
        wait_rc = sys_wait4(pid, &mut status);
        if wait_rc != -4 {
            break;
        }
    }

    let mut probe = [0u8; 4];
    let probe_rc = sys_read(err_read, &mut probe);
    let _ = sys_close(err_read);

    let output = Output {
        bytes,
        fnv1a64: hash.finish(),
    };
    match decode_exec_probe(probe_rc, probe) {
        ExecProbe::Failed(errno) => {
            return Outcome::Spawn {
                stage: SpawnStage::Exec,
                errno,
            }
        }
        ExecProbe::Unreadable(rc) => {
            return Outcome::ExecProbeError {
                rc_magnitude: rc.unsigned_abs() as u32,
                output,
            }
        }
        ExecProbe::Ran => {}
    }
    if wait_rc < 0 {
        return Outcome::WaitError {
            errno: wait_rc.unsigned_abs() as u32,
            output,
        };
    }
    if let Some(errno) = read_errno {
        return Outcome::ReadError { errno, output };
    }
    match decode_wait_status(status) {
        WaitStatus::Exited(code) => Outcome::Exited { code, output },
        WaitStatus::Signaled(signal) => Outcome::Signaled { signal, output },
        WaitStatus::Other(raw) => Outcome::UnrecognizedStatus {
            raw: raw as u32,
            output,
        },
    }
}

fn spawn_and_collect(console_fd: usize, arg: &CStr, extra: Option<&CStr>) -> Outcome {
    let mut out_fds = [-1i32; 2];
    let mut err_fds = [-1i32; 2];
    let rc = sys_pipe2(&mut out_fds, 0);
    if rc < 0 {
        return Outcome::Spawn {
            stage: SpawnStage::Pipe,
            errno: rc.unsigned_abs() as u32,
        };
    }
    let out_read = out_fds[0] as usize;
    let out_write = out_fds[1] as usize;
    // Nonblocking, so the parent's read after the child is gone can never wait on a stray writer.
    let rc = sys_pipe2(&mut err_fds, sys::O_NONBLOCK);
    if rc < 0 {
        close_all(&[out_read, out_write]);
        return Outcome::Spawn {
            stage: SpawnStage::Pipe,
            errno: rc.unsigned_abs() as u32,
        };
    }
    let err_read = err_fds[0] as usize;
    let err_write = err_fds[1] as usize;

    let pid = sys_fork();
    if pid < 0 {
        close_all(&[out_read, out_write, err_read, err_write]);
        return Outcome::Spawn {
            stage: SpawnStage::Fork,
            errno: pid.unsigned_abs() as u32,
        };
    }
    if pid == 0 {
        close_all(&[out_read, err_read]);
        run_child(out_write, err_write, arg, extra);
    }
    close_all(&[out_write, err_write]);
    run_parent(console_fd, pid as usize, out_read, err_read)
}

/// Runs the step and returns its failure count (0 or 1) for `_start`'s total.
pub fn run(console_fd: usize) -> usize {
    let mut begin = LineWriter::new();
    begin.push(b"FFW_SPEAKER_BEGIN path=");
    begin.push(PATH.to_bytes());
    begin.push(b" argv=");
    begin.push(ARG_CATALOG.to_bytes());
    begin.push(b"\n");
    emit_console(console_fd, begin.as_slice());

    let outcome = spawn_and_collect(console_fd, ARG_CATALOG, None);
    emit_console(console_fd, exit_line(&outcome).as_bytes());
    usize::from(!outcome.is_success())
}

/// The platform step (cargo feature `speaker-platform`): `/franken-speaker --platform-startup` as a second child, after the
/// catalog step, with its own line names (`FFW_PLATFORM_STEP_BEGIN` / `FFW_PLATFORM_STEP_EXIT`) so the catalog step's lines are
/// untouched. Exit 0 (started) and exit 3 (refused) both count as "the step ran"; the host judge reads the speaker's own six
/// `FFW_PLATFORM:*` lines and decides what they mean. Returns its failure count (0 or 1) for `_start`'s total.
#[cfg(feature = "speaker-platform")]
pub fn run_platform(console_fd: usize) -> usize {
    let mut begin = LineWriter::new();
    begin.push(b"FFW_PLATFORM_STEP_BEGIN path=");
    begin.push(PATH.to_bytes());
    begin.push(b" argv=");
    begin.push(ARG_PLATFORM.to_bytes());
    if let Some(extra) = PLATFORM_EXTRA {
        begin.push(b" ");
        begin.push(extra.to_bytes());
    }
    begin.push(b"\n");
    emit_console(console_fd, begin.as_slice());

    let outcome = spawn_and_collect(console_fd, ARG_PLATFORM, PLATFORM_EXTRA);
    emit_console(
        console_fd,
        exit_line_for(Step::Platform, &outcome).as_bytes(),
    );
    usize::from(!outcome.is_success_for(Step::Platform))
}
