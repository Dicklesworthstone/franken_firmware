//! Memory snapshots and the one ledger they are accounted in.
//!
//! Input is a text file of `/proc` captures (format below); output is a [`MemoryReport`].
//!
//! ```text
//! ffw.baseline.memory.v1 page_size=4096 [reserve_kib=4096]
//! snapshot label=steady at_mono_ns=1000000000
//! --- meminfo
//! <contents of /proc/meminfo>
//! --- status pid=100
//! <contents of /proc/100/status>
//! --- smaps_rollup pid=100
//! --- statm pid=100
//! ```
//!
//! Accounting rules.
//! * A process's RSS comes from `smaps_rollup`, else `status`, else `statm`. A source that disagrees
//!   with the chosen one is reported as a finding, not averaged away.
//! * Summing RSS across processes counts a page once per process that maps it. PSS divides each shared
//!   page among its mappers, so the PSS sum counts it once. The report gives both sums and their
//!   difference, which is exactly what a naive RSS total would have double counted.
//! * Process memory and kernel-side memory (slab, kernel stacks, page tables) are separate lines. What
//!   remains of `MemTotal - MemFree` after both, the unmapped page cache and the buffers is the
//!   `unattributed_kib` residual: driver, DMA and vmalloc memory plus whatever the simple model does not
//!   capture. It is a residual, not a measurement of any one consumer, and it is signed so that
//!   over-attribution shows up instead of being clamped away.
//! * A field a kernel does not provide is absent, never zero.

use crate::finding::{FindingKind, Findings};
use crate::json::Json;
use crate::parse::{Kv, ParseError, ParseKind, is_label};
use crate::procfs::{
    MemInfo, PageSize, ProcError, ProcStatus, SmapsRollup, StatM, parse_meminfo,
    parse_smaps_rollup, parse_statm, parse_status,
};

pub const HEADER: &str = "ffw.baseline.memory.v1";
pub const MAX_SNAPSHOTS: usize = 4096;
pub const MAX_PROCESSES_PER_SNAPSHOT: usize = 4096;
pub const MAX_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct ProcessInput {
    pub pid: u64,
    pub status: Option<ProcStatus>,
    pub rollup: Option<SmapsRollup>,
    pub statm: Option<StatM>,
}

#[derive(Debug, Clone)]
pub struct SnapshotInput {
    pub label: String,
    pub at_mono_ns: u64,
    pub meminfo: Option<MemInfo>,
    pub processes: Vec<ProcessInput>,
}

#[derive(Debug, Clone)]
pub struct MemoryCapture {
    pub page_size: PageSize,
    pub required_reserve_kib: Option<u64>,
    pub snapshots: Vec<SnapshotInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    MemInfo,
    Status,
    Rollup,
    StatM,
}

impl SectionKind {
    fn as_str(self) -> &'static str {
        match self {
            SectionKind::MemInfo => "meminfo",
            SectionKind::Status => "status",
            SectionKind::Rollup => "smaps_rollup",
            SectionKind::StatM => "statm",
        }
    }
}

struct Section {
    kind: SectionKind,
    pid: u64,
    header_line: usize,
    body: String,
}

fn perr(line: usize, e: ProcError) -> ParseError {
    ParseError::new(line, ParseKind::Proc(e))
}

fn parse_header(no: usize, line: &str) -> Result<(PageSize, Option<u64>), ParseError> {
    let mut tokens = line.split_whitespace();
    if tokens.next() != Some(HEADER) {
        return Err(ParseError::new(no, ParseKind::BadHeader));
    }
    let mut kv = Kv::new(no, tokens)?;
    let bytes = kv.req_u64("page_size")?;
    let reserve = kv.opt_u64("reserve_kib")?;
    kv.finish()?;
    let page = PageSize::new(bytes).map_err(|e| perr(no, e))?;
    Ok((page, reserve))
}

fn parse_snapshot_line(no: usize, line: &str) -> Result<SnapshotInput, ParseError> {
    let mut tokens = line.split_whitespace();
    let _tag = tokens.next();
    let mut kv = Kv::new(no, tokens)?;
    let label = kv.req("label")?;
    let at = kv.req_u64("at_mono_ns")?;
    kv.finish()?;
    if !is_label(label) {
        return Err(ParseError::new(
            no,
            ParseKind::BadIdentifier(crate::parse::bounded(label)),
        ));
    }
    Ok(SnapshotInput {
        label: label.to_string(),
        at_mono_ns: at,
        meminfo: None,
        processes: Vec::new(),
    })
}

fn parse_section_header(no: usize, line: &str) -> Result<Section, ParseError> {
    let mut tokens = line.split_whitespace();
    if tokens.next() != Some("---") {
        return Err(ParseError::new(
            no,
            ParseKind::UnknownSection(crate::parse::bounded(line)),
        ));
    }
    let kind_text = tokens.next().unwrap_or("");
    let kind = match kind_text {
        "meminfo" => SectionKind::MemInfo,
        "status" => SectionKind::Status,
        "smaps_rollup" => SectionKind::Rollup,
        "statm" => SectionKind::StatM,
        other => {
            return Err(ParseError::new(
                no,
                ParseKind::UnknownSection(crate::parse::bounded(other)),
            ));
        }
    };
    let mut kv = Kv::new(no, tokens)?;
    let pid = if kind == SectionKind::MemInfo {
        0
    } else {
        kv.req_u64("pid")?
    };
    kv.finish()?;
    Ok(Section {
        kind,
        pid,
        header_line: no,
        body: String::new(),
    })
}

fn duplicate(line: usize, kind: SectionKind) -> ParseError {
    ParseError::new(line, ParseKind::DuplicateSection(kind.as_str().to_string()))
}

fn flush(section: &mut Option<Section>, snapshots: &mut [SnapshotInput]) -> Result<(), ParseError> {
    let Some(s) = section.take() else {
        return Ok(());
    };
    let Some(snap) = snapshots.last_mut() else {
        return Err(ParseError::new(
            s.header_line,
            ParseKind::SectionOutsideSnapshot,
        ));
    };
    if s.kind == SectionKind::MemInfo {
        if snap.meminfo.is_some() {
            return Err(duplicate(s.header_line, s.kind));
        }
        let info = parse_meminfo(&s.body).map_err(|e| perr(s.header_line, e))?;
        snap.meminfo = Some(info);
        return Ok(());
    }
    let idx = match snap.processes.iter().position(|p| p.pid == s.pid) {
        Some(i) => i,
        None => {
            if snap.processes.len() >= MAX_PROCESSES_PER_SNAPSHOT {
                return Err(ParseError::new(s.header_line, ParseKind::TooLarge));
            }
            snap.processes.push(ProcessInput {
                pid: s.pid,
                status: None,
                rollup: None,
                statm: None,
            });
            snap.processes.len() - 1
        }
    };
    let slot = &mut snap.processes[idx];
    match s.kind {
        SectionKind::Status => {
            if slot.status.is_some() {
                return Err(duplicate(s.header_line, s.kind));
            }
            slot.status = Some(parse_status(&s.body).map_err(|e| perr(s.header_line, e))?);
        }
        SectionKind::Rollup => {
            if slot.rollup.is_some() {
                return Err(duplicate(s.header_line, s.kind));
            }
            slot.rollup = Some(parse_smaps_rollup(&s.body).map_err(|e| perr(s.header_line, e))?);
        }
        SectionKind::StatM => {
            if slot.statm.is_some() {
                return Err(duplicate(s.header_line, s.kind));
            }
            slot.statm = Some(parse_statm(&s.body).map_err(|e| perr(s.header_line, e))?);
        }
        SectionKind::MemInfo => {}
    }
    Ok(())
}

/// Parse a memory snapshot file.
pub fn parse_memory(text: &str) -> Result<MemoryCapture, ParseError> {
    let mut header: Option<(PageSize, Option<u64>)> = None;
    let mut snapshots: Vec<SnapshotInput> = Vec::new();
    let mut section: Option<Section> = None;

    for (idx, raw) in text.lines().enumerate() {
        let no = idx + 1;
        if raw.len() > MAX_LINE_BYTES {
            return Err(ParseError::new(no, ParseKind::LineTooLong));
        }
        let trimmed = raw.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if header.is_none() {
            if trimmed.is_empty() {
                continue;
            }
            header = Some(parse_header(no, trimmed)?);
            continue;
        }
        if trimmed.starts_with("snapshot ") {
            flush(&mut section, &mut snapshots)?;
            if snapshots.len() >= MAX_SNAPSHOTS {
                return Err(ParseError::new(no, ParseKind::TooLarge));
            }
            snapshots.push(parse_snapshot_line(no, trimmed)?);
            continue;
        }
        if trimmed.starts_with("---") {
            flush(&mut section, &mut snapshots)?;
            if snapshots.is_empty() {
                return Err(ParseError::new(no, ParseKind::SectionOutsideSnapshot));
            }
            section = Some(parse_section_header(no, trimmed)?);
            continue;
        }
        match section.as_mut() {
            Some(s) => {
                s.body.push_str(raw);
                s.body.push('\n');
            }
            None => {
                if trimmed.is_empty() {
                    continue;
                }
                return Err(ParseError::new(no, ParseKind::TextOutsideSection));
            }
        }
    }
    flush(&mut section, &mut snapshots)?;
    let Some((page_size, required_reserve_kib)) = header else {
        return Err(ParseError::new(0, ParseKind::EmptyInput));
    };
    if snapshots.is_empty() {
        return Err(ParseError::new(0, ParseKind::NoSamples));
    }
    for snap in &mut snapshots {
        snap.processes.sort_by_key(|p| p.pid);
    }
    Ok(MemoryCapture {
        page_size,
        required_reserve_kib,
        snapshots,
    })
}

// ------------------------------------------------------------------------------------------------
// Accounting

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssSource {
    SmapsRollup,
    Status,
    Statm,
    None,
}

impl RssSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RssSource::SmapsRollup => "smaps_rollup",
            RssSource::Status => "status",
            RssSource::Statm => "statm",
            RssSource::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLedger {
    pub pid: u64,
    pub name: String,
    pub rss_kib: Option<u64>,
    pub rss_source: RssSource,
    pub pss_kib: Option<u64>,
    pub uss_kib: Option<u64>,
    pub shared_kib: Option<u64>,
    pub hwm_kib: Option<u64>,
    pub kernel_thread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemLedger {
    pub mem_total_kib: u64,
    pub mem_free_kib: u64,
    pub used_kib: Option<u64>,
    pub process_rss_naive_sum_kib: u64,
    pub process_pss_sum_kib: Option<u64>,
    pub double_counted_kib: Option<u64>,
    pub kernel_reported_kib: Option<u64>,
    pub unmapped_cache_kib: Option<u64>,
    pub buffers_kib: Option<u64>,
    pub unattributed_kib: Option<i128>,
}

#[derive(Debug, Clone)]
pub struct SnapshotLedger {
    pub label: String,
    pub at_mono_ns: u64,
    pub processes: Vec<ProcessLedger>,
    pub system: Option<SystemLedger>,
    pub findings: Findings,
}

fn account_process(input: &ProcessInput, page: PageSize, findings: &mut Findings) -> ProcessLedger {
    let subject = format!("pid={}", input.pid);
    let name = input
        .status
        .as_ref()
        .map(|s| s.name.clone())
        .unwrap_or_default();
    let rollup_rss = input.rollup.as_ref().map(|r| r.rss_kib);
    let status_rss = input.status.as_ref().and_then(|s| s.vm_rss_kib);
    let statm_rss = input.statm.and_then(|st| st.resident_kib(page).ok());

    let (rss, source) = if let Some(v) = rollup_rss {
        (Some(v), RssSource::SmapsRollup)
    } else if let Some(v) = status_rss {
        (Some(v), RssSource::Status)
    } else if let Some(v) = statm_rss {
        (Some(v), RssSource::Statm)
    } else {
        (None, RssSource::None)
    };

    let mut kernel_thread = false;
    if rss.is_none() {
        if input.status.is_some() {
            // `status` is there but has no VmRSS: a kernel thread, which has no user address space.
            kernel_thread = true;
            findings.push(FindingKind::KernelThread, subject.clone(), &[]);
        } else {
            findings.push(FindingKind::NoRssSource, subject.clone(), &[]);
        }
    }

    if let Some(chosen) = rss {
        for (src, other) in [("status", status_rss), ("statm", statm_rss)] {
            let same_source = (src == "status" && source == RssSource::Status)
                || (src == "statm" && source == RssSource::Statm);
            if let Some(v) = other.filter(|v| !same_source && *v != chosen) {
                findings.push(
                    FindingKind::RssSourceMismatch,
                    format!("{subject} vs={src}"),
                    &[
                        ("chosen_kib", i128::from(chosen)),
                        ("other_kib", i128::from(v)),
                    ],
                );
            }
        }
    }

    let mut pss = None;
    let mut uss = None;
    let mut shared = None;
    if let Some(r) = &input.rollup {
        let parts = r.shared_kib().saturating_add(r.uss_kib());
        if parts != r.rss_kib {
            findings.push(
                FindingKind::RollupRssMismatch,
                subject.clone(),
                &[
                    ("rss_kib", i128::from(r.rss_kib)),
                    ("parts_kib", i128::from(parts)),
                ],
            );
        }
        if !(r.uss_kib() <= r.pss_kib && r.pss_kib <= r.rss_kib) {
            findings.push(
                FindingKind::PssOutOfRange,
                subject.clone(),
                &[
                    ("uss_kib", i128::from(r.uss_kib())),
                    ("pss_kib", i128::from(r.pss_kib)),
                    ("rss_kib", i128::from(r.rss_kib)),
                ],
            );
        }
        pss = Some(r.pss_kib);
        uss = Some(r.uss_kib());
        shared = Some(r.shared_kib());
    }

    let mut hwm = None;
    if let Some(s) = &input.status {
        hwm = s.vm_hwm_kib;
        if let (Some(a), Some(f), Some(sh), Some(total)) = (
            s.rss_anon_kib,
            s.rss_file_kib,
            s.rss_shmem_kib,
            s.vm_rss_kib,
        ) {
            let parts = a.saturating_add(f).saturating_add(sh);
            if parts != total {
                findings.push(
                    FindingKind::RssBreakdownMismatch,
                    subject.clone(),
                    &[
                        ("vm_rss_kib", i128::from(total)),
                        ("parts_kib", i128::from(parts)),
                    ],
                );
            }
        }
        if let Some((h, r)) = s.vm_hwm_kib.zip(s.vm_rss_kib).filter(|(h, r)| h < r) {
            findings.push(
                FindingKind::HwmBelowRss,
                subject.clone(),
                &[("hwm_kib", i128::from(h)), ("rss_kib", i128::from(r))],
            );
        }
    }

    ProcessLedger {
        pid: input.pid,
        name,
        rss_kib: rss,
        rss_source: source,
        pss_kib: pss,
        uss_kib: uss,
        shared_kib: shared,
        hwm_kib: hwm,
        kernel_thread,
    }
}

fn account_system(
    info: &MemInfo,
    processes: &[ProcessLedger],
    findings: &mut Findings,
) -> SystemLedger {
    let used = info.mem_total_kib.checked_sub(info.mem_free_kib);
    if used.is_none() {
        findings.push(
            FindingKind::FreeExceedsTotal,
            "meminfo".to_string(),
            &[
                ("mem_total_kib", i128::from(info.mem_total_kib)),
                ("mem_free_kib", i128::from(info.mem_free_kib)),
            ],
        );
    }

    let naive: u64 = processes
        .iter()
        .filter_map(|p| p.rss_kib)
        .fold(0u64, |a, b| a.saturating_add(b));

    // PSS is only a valid total if every process that has an RSS also has a PSS.
    let pss_complete = processes
        .iter()
        .all(|p| p.rss_kib.is_none() || p.pss_kib.is_some());
    let pss_sum = if pss_complete {
        Some(
            processes
                .iter()
                .filter_map(|p| p.pss_kib)
                .fold(0u64, |a, b| a.saturating_add(b)),
        )
    } else {
        None
    };
    let double_counted = match pss_sum {
        Some(pss) => match naive.checked_sub(pss) {
            Some(d) => Some(d),
            None => {
                findings.push(
                    FindingKind::PssExceedsRss,
                    "system".to_string(),
                    &[
                        ("rss_sum_kib", i128::from(naive)),
                        ("pss_sum_kib", i128::from(pss)),
                    ],
                );
                None
            }
        },
        None => None,
    };

    let kernel = match (info.slab_kib, info.kernel_stack_kib, info.page_tables_kib) {
        (Some(a), Some(b), Some(c)) => Some(a.saturating_add(b).saturating_add(c)),
        _ => None,
    };
    let unmapped = match (info.cached_kib, info.mapped_kib) {
        (Some(cached), Some(mapped)) => match cached.checked_sub(mapped) {
            Some(u) => Some(u),
            None => {
                findings.push(
                    FindingKind::MappedExceedsCached,
                    "meminfo".to_string(),
                    &[
                        ("cached_kib", i128::from(cached)),
                        ("mapped_kib", i128::from(mapped)),
                    ],
                );
                None
            }
        },
        _ => None,
    };

    let unattributed = match (used, pss_sum, kernel, unmapped, info.buffers_kib) {
        (Some(u), Some(p), Some(k), Some(c), Some(b)) => {
            let residual =
                i128::from(u) - i128::from(p) - i128::from(k) - i128::from(c) - i128::from(b);
            if residual < 0 {
                findings.push(
                    FindingKind::OverAttributed,
                    "system".to_string(),
                    &[("by_kib", -residual)],
                );
            }
            Some(residual)
        }
        _ => None,
    };

    SystemLedger {
        mem_total_kib: info.mem_total_kib,
        mem_free_kib: info.mem_free_kib,
        used_kib: used,
        process_rss_naive_sum_kib: naive,
        process_pss_sum_kib: pss_sum,
        double_counted_kib: double_counted,
        kernel_reported_kib: kernel,
        unmapped_cache_kib: unmapped,
        buffers_kib: info.buffers_kib,
        unattributed_kib: unattributed,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadroomVerdict {
    NotAssessed,
    Pass,
    Fail,
}

impl HeadroomVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            HeadroomVerdict::NotAssessed => "not_assessed",
            HeadroomVerdict::Pass => "pass",
            HeadroomVerdict::Fail => "fail",
        }
    }
}

/// Memory left beyond the worst observed `MemTotal - MemFree`, against a reserve declared in the
/// input header before the run. The reserve is never defaulted: without one nothing is assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headroom {
    pub required_reserve_kib: Option<u64>,
    pub reserve_kib: Option<u64>,
    pub verdict: HeadroomVerdict,
}

#[derive(Debug, Clone)]
pub struct MemoryReport {
    pub page_size_bytes: u64,
    pub snapshots: Vec<SnapshotLedger>,
    pub max_used_kib: Option<u64>,
    pub max_process_pss_sum_kib: Option<u64>,
    pub max_vm_hwm_kib: Option<u64>,
    pub headroom: Headroom,
}

pub fn account(cap: &MemoryCapture) -> MemoryReport {
    let mut snapshots = Vec::with_capacity(cap.snapshots.len());
    let mut max_used: Option<(u64, u64)> = None; // (used, mem_total of that snapshot)
    let mut max_pss: Option<u64> = None;
    let mut max_hwm: Option<u64> = None;

    for snap in &cap.snapshots {
        let mut findings = Findings::default();
        let processes: Vec<ProcessLedger> = snap
            .processes
            .iter()
            .map(|p| account_process(p, cap.page_size, &mut findings))
            .collect();
        let system = snap
            .meminfo
            .as_ref()
            .map(|info| account_system(info, &processes, &mut findings));

        if let Some(sys) = &system {
            if let Some(used) = sys.used_kib {
                let better = match max_used {
                    Some((best, _)) => used > best,
                    None => true,
                };
                if better {
                    max_used = Some((used, sys.mem_total_kib));
                }
            }
            if let Some(p) = sys.process_pss_sum_kib {
                max_pss = Some(max_pss.map_or(p, |m| m.max(p)));
            }
        }
        for p in &processes {
            if let Some(h) = p.hwm_kib {
                max_hwm = Some(max_hwm.map_or(h, |m| m.max(h)));
            }
        }
        snapshots.push(SnapshotLedger {
            label: snap.label.clone(),
            at_mono_ns: snap.at_mono_ns,
            processes,
            system,
            findings,
        });
    }

    let reserve = max_used.and_then(|(used, total)| total.checked_sub(used));
    let verdict = match (cap.required_reserve_kib, reserve) {
        (Some(need), Some(have)) => {
            if have >= need {
                HeadroomVerdict::Pass
            } else {
                HeadroomVerdict::Fail
            }
        }
        _ => HeadroomVerdict::NotAssessed,
    };

    MemoryReport {
        page_size_bytes: cap.page_size.bytes(),
        snapshots,
        max_used_kib: max_used.map(|(u, _)| u),
        max_process_pss_sum_kib: max_pss,
        max_vm_hwm_kib: max_hwm,
        headroom: Headroom {
            required_reserve_kib: cap.required_reserve_kib,
            reserve_kib: reserve,
            verdict,
        },
    }
}

impl MemoryReport {
    pub fn to_json(&self) -> Json {
        let snaps: Vec<Json> = self.snapshots.iter().map(snapshot_json).collect();
        Json::obj(vec![
            ("schema", Json::str("ffw.baseline.memory-report.v1")),
            ("page_size_bytes", Json::int(self.page_size_bytes)),
            ("snapshots", Json::Arr(snaps)),
            (
                "peaks",
                Json::obj(vec![
                    ("max_used_kib", Json::opt_u64(self.max_used_kib)),
                    (
                        "max_process_pss_sum_kib",
                        Json::opt_u64(self.max_process_pss_sum_kib),
                    ),
                    ("max_vm_hwm_kib", Json::opt_u64(self.max_vm_hwm_kib)),
                ]),
            ),
            (
                "headroom",
                Json::obj(vec![
                    (
                        "required_reserve_kib",
                        Json::opt_u64(self.headroom.required_reserve_kib),
                    ),
                    ("reserve_kib", Json::opt_u64(self.headroom.reserve_kib)),
                    ("verdict", Json::str(self.headroom.verdict.as_str())),
                ]),
            ),
        ])
    }
}

fn snapshot_json(s: &SnapshotLedger) -> Json {
    let procs: Vec<Json> = s
        .processes
        .iter()
        .map(|p| {
            Json::obj(vec![
                ("pid", Json::int(p.pid)),
                ("name", Json::str(&p.name)),
                ("rss_kib", Json::opt_u64(p.rss_kib)),
                ("rss_source", Json::str(p.rss_source.as_str())),
                ("pss_kib", Json::opt_u64(p.pss_kib)),
                ("uss_kib", Json::opt_u64(p.uss_kib)),
                ("shared_kib", Json::opt_u64(p.shared_kib)),
                ("hwm_kib", Json::opt_u64(p.hwm_kib)),
                ("kernel_thread", Json::Bool(p.kernel_thread)),
            ])
        })
        .collect();
    let system = match &s.system {
        None => Json::Null,
        Some(y) => Json::obj(vec![
            ("mem_total_kib", Json::int(y.mem_total_kib)),
            ("mem_free_kib", Json::int(y.mem_free_kib)),
            ("used_kib", Json::opt_u64(y.used_kib)),
            (
                "process_rss_naive_sum_kib",
                Json::int(y.process_rss_naive_sum_kib),
            ),
            ("process_pss_sum_kib", Json::opt_u64(y.process_pss_sum_kib)),
            ("double_counted_kib", Json::opt_u64(y.double_counted_kib)),
            ("kernel_reported_kib", Json::opt_u64(y.kernel_reported_kib)),
            ("unmapped_cache_kib", Json::opt_u64(y.unmapped_cache_kib)),
            ("buffers_kib", Json::opt_u64(y.buffers_kib)),
            ("unattributed_kib", Json::opt_i128(y.unattributed_kib)),
        ]),
    };
    Json::obj(vec![
        ("label", Json::str(&s.label)),
        ("at_mono_ns", Json::int(s.at_mono_ns)),
        ("processes", Json::Arr(procs)),
        ("system", system),
        (
            "findings",
            Json::Arr(s.findings.items().iter().map(|f| f.to_json()).collect()),
        ),
        ("findings_dropped", Json::int(s.findings.dropped())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "ffw.baseline.memory.v1 page_size=4096 reserve_kib=4096
snapshot label=steady at_mono_ns=1000000000
--- meminfo
MemTotal:       30000 kB
MemFree:        20000 kB
MemAvailable:   24000 kB
Buffers:          500 kB
Cached:          7000 kB
Mapped:          3000 kB
Shmem:            400 kB
Slab:            1500 kB
KernelStack:      100 kB
PageTables:       200 kB
AnonPages:       4000 kB
--- status pid=200
Name:\tnetd
VmHWM:\t    1300 kB
VmRSS:\t    1200 kB
--- smaps_rollup pid=200
Rss: 1200 kB
Pss: 700 kB
Shared_Clean: 800 kB
Shared_Dirty: 0 kB
Private_Clean: 100 kB
Private_Dirty: 300 kB
--- status pid=100
Name:\tplayer
VmHWM:\t    3000 kB
VmRSS:\t    2500 kB
--- smaps_rollup pid=100
Rss: 2500 kB
Pss: 1800 kB
Shared_Clean: 900 kB
Shared_Dirty: 0 kB
Private_Clean: 500 kB
Private_Dirty: 1100 kB
--- statm pid=100
2000 625 150 100 0 400 0
--- status pid=2
Name:\tkthreadd
State:\tS (sleeping)
snapshot label=transition at_mono_ns=2000000000
--- meminfo
MemTotal:       30000 kB
MemFree:        17000 kB
Buffers:          500 kB
Cached:          7000 kB
Mapped:          3000 kB
Slab:            1500 kB
KernelStack:      100 kB
PageTables:       200 kB
--- status pid=100
Name:\tplayer
VmHWM:\t    3400 kB
VmRSS:\t    2800 kB
--- smaps_rollup pid=100
Rss: 2800 kB
Pss: 2000 kB
Shared_Clean: 900 kB
Shared_Dirty: 100 kB
Private_Clean: 600 kB
Private_Dirty: 1200 kB
";

    fn good_report() -> MemoryReport {
        account(&parse_memory(GOOD).expect("parse"))
    }

    #[test]
    fn process_figures_come_from_the_rollup_and_are_sorted_by_pid() {
        let r = good_report();
        let s = &r.snapshots[0];
        let pids: Vec<u64> = s.processes.iter().map(|p| p.pid).collect();
        assert_eq!(pids, vec![2, 100, 200]);
        let player = &s.processes[1];
        assert_eq!(player.name, "player");
        assert_eq!(player.rss_kib, Some(2500));
        assert_eq!(player.rss_source, RssSource::SmapsRollup);
        assert_eq!(player.pss_kib, Some(1800));
        assert_eq!(player.uss_kib, Some(500 + 1100));
        assert_eq!(player.shared_kib, Some(900));
        assert_eq!(player.hwm_kib, Some(3000));
        let netd = &s.processes[2];
        assert_eq!(
            (netd.rss_kib, netd.pss_kib, netd.uss_kib, netd.shared_kib),
            (Some(1200), Some(700), Some(400), Some(800))
        );
    }

    #[test]
    fn a_kernel_thread_contributes_nothing_and_is_named() {
        let r = good_report();
        let kt = &r.snapshots[0].processes[0];
        assert_eq!((kt.pid, kt.kernel_thread, kt.rss_kib), (2, true, None));
        assert_eq!(kt.rss_source, RssSource::None);
        assert_eq!(r.snapshots[0].findings.count(FindingKind::KernelThread), 1);
        assert_eq!(r.snapshots[0].findings.items().len(), 1);
    }

    #[test]
    fn shared_pages_are_not_counted_twice() {
        let r = good_report();
        let y = r.snapshots[0].system.as_ref().expect("meminfo");
        // 2500 + 1200 naive, 1800 + 700 proportional: a naive sum overstates by 1200.
        assert_eq!(y.process_rss_naive_sum_kib, 3700);
        assert_eq!(y.process_pss_sum_kib, Some(2500));
        assert_eq!(y.double_counted_kib, Some(1200));
    }

    #[test]
    fn kernel_memory_is_kept_apart_and_the_residual_is_signed() {
        let r = good_report();
        let y = r.snapshots[0].system.as_ref().expect("meminfo");
        assert_eq!(
            (y.mem_total_kib, y.mem_free_kib, y.used_kib),
            (30000, 20000, Some(10000))
        );
        assert_eq!(y.kernel_reported_kib, Some(1500 + 100 + 200));
        assert_eq!(y.unmapped_cache_kib, Some(7000 - 3000));
        assert_eq!(y.buffers_kib, Some(500));
        // 10000 - 2500 (pss) - 1800 (kernel) - 4000 (unmapped cache) - 500 (buffers)
        assert_eq!(y.unattributed_kib, Some(1200));
    }

    #[test]
    fn peaks_and_headroom_use_the_worst_snapshot() {
        let r = good_report();
        let t = r.snapshots[1].system.as_ref().expect("meminfo");
        assert_eq!(t.used_kib, Some(13000));
        assert_eq!(t.process_rss_naive_sum_kib, 2800);
        assert_eq!(t.process_pss_sum_kib, Some(2000));
        assert_eq!(t.double_counted_kib, Some(800));
        assert_eq!(t.unattributed_kib, Some(13000 - 2000 - 1800 - 4000 - 500));
        assert_eq!(r.max_used_kib, Some(13000));
        assert_eq!(r.max_process_pss_sum_kib, Some(2500));
        assert_eq!(r.max_vm_hwm_kib, Some(3400));
        assert_eq!(r.headroom.reserve_kib, Some(30000 - 13000));
        assert_eq!(r.headroom.required_reserve_kib, Some(4096));
        assert_eq!(r.headroom.verdict, HeadroomVerdict::Pass);
    }

    #[test]
    fn headroom_fails_below_the_declared_reserve_and_is_never_defaulted() {
        let fail = GOOD.replace("reserve_kib=4096", "reserve_kib=20000");
        let r = account(&parse_memory(&fail).expect("parse"));
        assert_eq!(r.headroom.reserve_kib, Some(17000));
        assert_eq!(r.headroom.verdict, HeadroomVerdict::Fail);
        // 17000 is exactly enough for a 17000 reserve.
        let edge = GOOD.replace("reserve_kib=4096", "reserve_kib=17000");
        let r = account(&parse_memory(&edge).expect("parse"));
        assert_eq!(r.headroom.verdict, HeadroomVerdict::Pass);
        let none = GOOD.replace(" reserve_kib=4096", "");
        let r = account(&parse_memory(&none).expect("parse"));
        assert_eq!(r.headroom.required_reserve_kib, None);
        assert_eq!(r.headroom.verdict, HeadroomVerdict::NotAssessed);
    }

    #[test]
    fn unavailable_fields_stay_absent_not_zero() {
        // A capture with only `meminfo` basics and one `status`: every figure that needs an input the
        // capture does not carry is None, never 0.
        let only_status = "ffw.baseline.memory.v1 page_size=4096
snapshot label=a at_mono_ns=1
--- meminfo
MemTotal: 100 kB
MemFree: 40 kB
--- status pid=7
Name:\tx
VmRSS:\t  10 kB
";
        let r2 = account(&parse_memory(only_status).expect("parse"));
        let y = r2.snapshots[0].system.as_ref().expect("meminfo");
        assert_eq!(y.used_kib, Some(60));
        assert_eq!(y.process_rss_naive_sum_kib, 10);
        // Only `status` was captured, so there is no PSS and no valid PSS total.
        assert_eq!(y.process_pss_sum_kib, None);
        assert_eq!(y.double_counted_kib, None);
        assert_eq!(y.kernel_reported_kib, None);
        assert_eq!(y.unattributed_kib, None);
        assert_eq!(r2.snapshots[0].processes[0].rss_source, RssSource::Status);
    }

    #[test]
    fn inconsistent_inputs_are_reported_as_findings_not_corrected() {
        let bad = "ffw.baseline.memory.v1 page_size=16384
snapshot label=bad at_mono_ns=5
--- meminfo
MemTotal: 1000 kB
MemFree: 2000 kB
Cached: 100 kB
Mapped: 300 kB
--- status pid=1
Name:\tx
VmHWM:\t2000 kB
VmRSS:\t2500 kB
RssAnon:\t1000 kB
RssFile:\t1400 kB
RssShmem:\t200 kB
--- smaps_rollup pid=1
Rss: 2500 kB
Pss: 3000 kB
Shared_Clean: 900 kB
Shared_Dirty: 0 kB
Private_Clean: 500 kB
Private_Dirty: 1000 kB
--- statm pid=1
1 625 0 0 0 0 0
";
        let r = account(&parse_memory(bad).expect("parse"));
        let s = &r.snapshots[0];
        // 625 pages at 16 KiB is 10000 KiB, which disagrees with the chosen 2500.
        let kinds = |k| s.findings.count(k);
        // `status` (2500) agrees with the chosen rollup RSS; only `statm` (10000) does not.
        assert_eq!(kinds(FindingKind::RssSourceMismatch), 1);
        assert_eq!(kinds(FindingKind::RollupRssMismatch), 1); // 900 + 0 + 500 + 1000 = 2400 != 2500
        assert_eq!(kinds(FindingKind::PssOutOfRange), 1); // pss 3000 > rss 2500
        assert_eq!(kinds(FindingKind::RssBreakdownMismatch), 1); // 1000 + 1400 + 200 = 2600 != 2500
        assert_eq!(kinds(FindingKind::HwmBelowRss), 1); // 2000 < 2500
        assert_eq!(kinds(FindingKind::FreeExceedsTotal), 1);
        assert_eq!(kinds(FindingKind::MappedExceedsCached), 1);
        assert_eq!(kinds(FindingKind::PssExceedsRss), 1); // pss sum 3000 > rss sum 2500
        let y = s.system.as_ref().expect("meminfo");
        assert_eq!(y.used_kib, None);
        assert_eq!(y.double_counted_kib, None);
    }

    #[test]
    fn parse_errors_are_typed_and_carry_the_line() {
        let e = |text: &str| parse_memory(text).expect_err("must fail");
        assert_eq!(e("").kind, ParseKind::EmptyInput);
        assert_eq!(
            e("not-the-header page_size=4096\n").kind,
            ParseKind::BadHeader
        );
        assert_eq!(
            e("ffw.baseline.memory.v1 page_size=3000\n").kind,
            ParseKind::Proc(ProcError::BadPageSize(3000))
        );
        assert_eq!(
            e("ffw.baseline.memory.v1 page_size=4096 colour=red\n").kind,
            ParseKind::UnknownKey("colour".to_string())
        );
        assert_eq!(
            e("ffw.baseline.memory.v1 page_size=4096\n").kind,
            ParseKind::NoSamples
        );
        let head = "ffw.baseline.memory.v1 page_size=4096\n";
        assert_eq!(
            e(&format!("{head}--- meminfo\nMemTotal: 1 kB\n")).kind,
            ParseKind::SectionOutsideSnapshot
        );
        let snap = format!("{head}snapshot label=a at_mono_ns=1\n");
        assert_eq!(
            e(&format!("{snap}stray text\n")),
            ParseError::new(3, ParseKind::TextOutsideSection)
        );
        assert_eq!(
            e(&format!("{snap}--- cpuinfo\n")).kind,
            ParseKind::UnknownSection("cpuinfo".to_string())
        );
        assert_eq!(
            e(&format!("{snap}--- status\nName: x\n")).kind,
            ParseKind::MissingKey("pid")
        );
        assert_eq!(
            e(&format!(
                "{snap}--- status pid=1\nName: x\n--- status pid=1\nName: y\n"
            )),
            ParseError::new(5, ParseKind::DuplicateSection("status".to_string()))
        );
        assert_eq!(
            e(&format!(
                "{snap}--- meminfo\nMemTotal: 1 kB\nMemFree: 1 MB\n"
            )),
            ParseError::new(3, ParseKind::Proc(ProcError::BadUnit { field: "MemFree" }))
        );
        assert_eq!(
            e(&format!("{head}snapshot label=a b at_mono_ns=1\n")).kind,
            ParseKind::NotKeyValue("b".to_string())
        );
    }
}
