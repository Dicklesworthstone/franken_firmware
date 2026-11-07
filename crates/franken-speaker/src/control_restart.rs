//! The process-restart driver for the durable control plane (`N02` / `ffw-ugf`): `franken-speaker --control-restart ...`, harness
//! builds on unix only.
//!
//! The in-process restart test in `control_adapter.rs` builds a second plane over the same RAM medium. This runs the same owner as
//! a PROCESS over a regular file ([`FileMedium`](crate::file_medium::FileMedium)), so a test can start it, let it finish or kill
//! it, and start a NEW process that must restore from the file alone: the revision mark and the relative-command floors come back
//! through [`ControlPlane::new_durable_file`] (`boot_durable`), not through anything the test hands over.
//!
//! ```text
//! --control-restart init <file>
//! --control-restart run  <file> <session> <steps> [--hold] [--fail-at none|program:N|sync:N]
//!     session: `fresh`, or `<revision>:<volume>`: the fixture session with its revision and the kitchen member's volume set
//!              (the session is the group's, G01's, and is NOT stored in the file; the caller rebuilds it)
//!     steps:   `-`, or comma-separated `tail:<seq>:<revision|cur>:<delta>` (a signed tailnet step), `legacy:<delta>` (a plain-SOAP
//!              bridge step) and `panel:<seq>:<0|1>` (the device's own panel, a LOCAL-USER peer, unmutes or mutes; needs --fail-at);
//!              `cur` is the session's revision when the step is sent
//!     --hold:  after the steps, print `held` and wait on stdin until the parent kills the process (or closes stdin, exit 3)
//!     --fail-at: run over a medium that fails ONE storage call counted from the end of the boot: the N-th `program` (an I/O fault, no
//!              effect on the file) or the N-th `sync` (a sync fault; the bytes written stay in the file); `none` is the same plane with
//!              no fault. Without it no panel peer exists.
//! ```
//!
//! Every output line is `N02_PROC: ` and then codes, marks, counts and volumes only: no path, no byte of the file, no key. Exit
//! status 0 is success, 2 is a refusal or a failure (named on the last line), 3 is a held process whose stdin closed first.
//!
//! What a run shows: what the file restored, and what each step was answered. What it does not show: a power cut. A process kill
//! keeps every byte already handed to the operating system, synced or not, so a killed owner is evidence of a restart and says
//! nothing about `sync_all`.

use crate::control_adapter::{ControlPlane, Sent, Target};
use crate::file_medium::{FailAt, FaultingMedium, FileError, FileMedium};
use franken_control::channel::pipeline::Limits;
use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};
use std::cell::Cell;
use std::fmt::Display;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;

const KITCHEN: &str = "kitchen";
const EPOCH: u64 = 1;
const NOW_NS: u64 = 1_000_000_000;
/// The most steps one run takes: a run is a bounded script, not a service.
const MAX_STEPS: usize = 64;

/// The first word of the mode, as `main` matches it.
pub const MODE: &str = "--control-restart";

fn say(text: &str) {
    println!("N02_PROC: {text}");
    let _ = std::io::stdout().flush();
}

fn shown<T: Display>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_string(), |v| v.to_string())
}

/// Two members at the default volume 50: the same session the in-process durable-restart test builds.
fn fixture_session() -> Result<UnifiedGroupSession, String> {
    let catalog = franken_board_profile::synthetic_test_fixture_catalog();
    let mut session = UnifiedGroupSession::new("grp", "coord", EPOCH);
    for (seq, member, model) in [(1, KITCHEN, "S5"), (2, "den", "S12")] {
        let board = catalog
            .iter()
            .find(|profile| profile.model_number == model)
            .ok_or_else(|| "the fixture catalog lacks a model".to_string())?
            .clone();
        session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board,
                    role: ChannelRole::Stereo,
                },
            })
            .map_err(|_| "a fixture member did not admit".to_string())?;
    }
    Ok(session)
}

fn session_from(spec: &str) -> Result<UnifiedGroupSession, String> {
    let mut session = fixture_session()?;
    if spec == "fresh" {
        return Ok(session);
    }
    let (revision, volume) = spec
        .split_once(':')
        .ok_or_else(|| "unreadable session".to_string())?;
    session.state_revision = revision
        .parse()
        .map_err(|_| "unreadable session revision".to_string())?;
    let volume: u8 = volume
        .parse()
        .map_err(|_| "unreadable session volume".to_string())?;
    session
        .members
        .get_mut(KITCHEN)
        .ok_or_else(|| "the fixture lacks the kitchen member".to_string())?
        .volume_0_to_100 = volume;
    Ok(session)
}

enum Step {
    Tail {
        seq: u64,
        revision: Option<u64>,
        delta: i8,
    },
    Legacy {
        delta: i8,
    },
    Panel {
        seq: u64,
        muted: bool,
    },
}

fn parse_step(token: &str) -> Result<Step, String> {
    let unreadable = || "unreadable step".to_string();
    let parts: Vec<&str> = token.split(':').collect();
    match parts.as_slice() {
        ["tail", seq, revision, delta] => Ok(Step::Tail {
            seq: seq.parse().map_err(|_| unreadable())?,
            revision: if *revision == "cur" {
                None
            } else {
                Some(revision.parse().map_err(|_| unreadable())?)
            },
            delta: delta.parse().map_err(|_| unreadable())?,
        }),
        ["legacy", delta] => Ok(Step::Legacy {
            delta: delta.parse().map_err(|_| unreadable())?,
        }),
        ["panel", seq, muted @ ("0" | "1")] => Ok(Step::Panel {
            seq: seq.parse().map_err(|_| unreadable())?,
            muted: *muted == "1",
        }),
        _ => Err(unreadable()),
    }
}

fn parse_steps(text: &str) -> Result<Vec<Step>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    let mut steps = Vec::new();
    for token in text.split(',') {
        if steps.len() == MAX_STEPS {
            return Err("too many steps".to_string());
        }
        steps.push(parse_step(token)?);
    }
    Ok(steps)
}

fn member_volume(session: &UnifiedGroupSession) -> u8 {
    session
        .members
        .get(KITCHEN)
        .map_or(0, |member| member.volume_0_to_100)
}

fn member_muted(session: &UnifiedGroupSession) -> bool {
    session
        .members
        .get(KITCHEN)
        .is_some_and(|member| member.muted)
}

/// What the command line asked for besides the steps.
struct Options {
    hold: bool,
    /// `None`: the plain file plane. `Some(plan)`: the faulting plane (with the panel peer); a plan of `None` is no fault.
    fault: Option<Option<FailAt>>,
}

fn parse_options(flags: &[&str]) -> Result<Options, String> {
    let mut options = Options {
        hold: false,
        fault: None,
    };
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match *flag {
            "--hold" => options.hold = true,
            "--fail-at" => {
                let value = flags
                    .next()
                    .ok_or_else(|| "--fail-at needs a value".to_string())?;
                options.fault = Some(if *value == "none" {
                    None
                } else {
                    Some(FailAt::parse(value).ok_or_else(|| "unreadable --fail-at".to_string())?)
                });
            }
            _ => return Err("unreadable option".to_string()),
        }
    }
    Ok(options)
}

fn init(path: &str) -> ExitCode {
    match FileMedium::create_new(Path::new(path), &Limits::standard()) {
        Ok(medium) => {
            drop(medium);
            let segment = Limits::standard().segment_bytes;
            say(&format!(
                "init ok segment_bytes={segment} file_bytes={}",
                crate::file_medium::FILE_HEADER_BYTES + 2 * segment
            ));
            ExitCode::SUCCESS
        }
        Err(error) => refused(error),
    }
}

fn refused(error: FileError) -> ExitCode {
    say(&format!("refused code={}", error.code()));
    ExitCode::from(2)
}

fn failed(reason: &str) -> ExitCode {
    say(&format!("failed reason={reason}"));
    ExitCode::from(2)
}

/// Wait on stdin until the parent kills this process (its normal end) or closes the pipe (it left first: exit 3).
fn hold() -> ExitCode {
    say(
        "held note=a kill keeps every byte already handed to the OS, synced or not; a killed owner shows a restart and says nothing about sync_all",
    );
    let mut byte = [0u8; 1];
    loop {
        match std::io::stdin().read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    eprintln!("hold: stdin closed before the parent's kill; leaving with exit code 3");
    ExitCode::from(3)
}

fn run(path: &str, session_spec: &str, steps_text: &str, options: &Options) -> ExitCode {
    let steps = match parse_steps(steps_text) {
        Ok(steps) => steps,
        Err(reason) => return failed(&reason),
    };
    if options.fault.is_none() && steps.iter().any(|step| matches!(step, Step::Panel { .. })) {
        return failed("a panel step needs --fail-at: the panel peer exists only in that plane");
    }
    let mut session = match session_from(session_spec) {
        Ok(session) => session,
        Err(reason) => return failed(&reason),
    };
    let medium = match FileMedium::open_existing(Path::new(path), &Limits::standard()) {
        Ok(medium) => medium,
        Err(error) => return refused(error),
    };
    // The fault, if any, is counted from the end of the boot: the journal's own writes while it opens are not steps.
    let armed = Rc::new(Cell::new(false));
    let booted = match options.fault {
        None => ControlPlane::new_durable_file(&session, KITCHEN, NOW_NS, medium),
        Some(plan) => ControlPlane::new_durable_faulting(
            &session,
            KITCHEN,
            NOW_NS,
            FaultingMedium::new(medium, plan, Rc::clone(&armed)),
        ),
    };
    let (mut plane, mark, floors) = match booted {
        Ok(booted) => booted,
        Err(reason) => return failed(&reason),
    };
    armed.set(true);
    // The floors are last: their text has spaces ("Table { identities: 1 }").
    say(&format!(
        "boot session_revision={} member_volume={} member_muted={} restored_mark={mark:?} restored_floors={floors:?}",
        session.state_revision,
        member_volume(&session),
        member_muted(&session)
    ));
    for (index, step) in steps.iter().enumerate() {
        let number = index + 1;
        let (kind, seq, sent_revision, answer): (
            &str,
            Option<u64>,
            Option<u64>,
            Result<Sent, String>,
        ) = match step {
            Step::Tail {
                seq,
                revision,
                delta,
            } => {
                let revision = revision.unwrap_or(session.state_revision);
                (
                    "tail",
                    Some(*seq),
                    Some(revision),
                    plane.send_tailnet(
                        &mut session,
                        NOW_NS,
                        *seq,
                        revision,
                        Target::Member,
                        *delta,
                    ),
                )
            }
            Step::Legacy { delta } => (
                "legacy",
                None,
                None,
                Ok(plane.send_legacy(&mut session, NOW_NS, Target::Member, *delta)),
            ),
            Step::Panel { seq, muted } => (
                "panel",
                Some(*seq),
                None,
                plane.send_panel_mute(&mut session, NOW_NS, *seq, *muted),
            ),
        };
        let sent = match answer {
            Ok(sent) => sent,
            Err(reason) => return failed(&reason),
        };
        say(&format!(
            "step {number} kind={kind} seq={} sent_revision={} status={} volume={} fault={} session_revision={} member_muted={} latched={}",
            shown(seq),
            shown(sent_revision),
            sent.status,
            shown(sent.new_volume),
            shown(sent.fault_code),
            session.state_revision,
            member_muted(&session),
            plane.durability_failed()
        ));
    }
    say(&format!(
        "end session_revision={} member_volume={} member_muted={} latched={}",
        session.state_revision,
        member_volume(&session),
        member_muted(&session),
        plane.durability_failed()
    ));
    if options.hold {
        // `plane` is still alive here: it holds the file's lock until the process ends.
        let code = hold();
        drop(plane);
        return code;
    }
    ExitCode::SUCCESS
}

/// The entry `main` calls for `--control-restart`; `args` is everything after the mode.
#[must_use]
pub fn main(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["init", path] => init(path),
        ["run", path, session, steps, flags @ ..] => match parse_options(flags) {
            Ok(options) => run(path, session, steps, &options),
            Err(reason) => failed(&reason),
        },
        _ => {
            eprintln!(
                "usage: franken-speaker {MODE} init <file> | run <file> <fresh|revision:volume> <-|steps> [--hold] [--fail-at none|program:N|sync:N]"
            );
            ExitCode::from(2)
        }
    }
}
