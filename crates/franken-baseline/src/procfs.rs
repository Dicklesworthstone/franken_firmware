//! Parsers for the Linux `/proc` text formats the baseline reads, and the unit conversions.
//!
//! Units. The kernel prints `kB` in `/proc/<pid>/status`, `smaps_rollup` and `meminfo`, and means
//! KiB (1024 bytes). `/proc/<pid>/statm` counts pages. Every figure in this crate is KiB, and pages
//! become KiB only through an explicit [`PageSize`]. A value with a missing or different unit is an
//! error, never a guess.
//!
//! A field the running kernel does not provide (`RssAnon` before 4.5, `MemAvailable` before 3.14,
//! `smaps_rollup` before 4.14) is `None`, not zero.

use std::fmt;

use crate::parse::{bounded, parse_u64};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcError {
    MissingField(&'static str),
    BadValue { field: &'static str, text: String },
    BadUnit { field: &'static str },
    BadPageSize(u64),
    NotPageAligned { kib: u64, page_kib: u64 },
    Overflow,
    Malformed(&'static str),
}

impl fmt::Display for ProcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProcError {}

/// A memory page size in bytes: a power of two that is a whole number of KiB, at most 1 MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(u64);

impl PageSize {
    pub const MAX_BYTES: u64 = 1 << 20;

    pub fn new(bytes: u64) -> Result<Self, ProcError> {
        if bytes == 0 || !bytes.is_power_of_two() || (bytes & 1023) != 0 || bytes > Self::MAX_BYTES
        {
            return Err(ProcError::BadPageSize(bytes));
        }
        Ok(Self(bytes))
    }

    pub fn bytes(self) -> u64 {
        self.0
    }

    pub fn kib(self) -> u64 {
        self.0 / 1024
    }

    pub fn pages_to_kib(self, pages: u64) -> Result<u64, ProcError> {
        pages.checked_mul(self.kib()).ok_or(ProcError::Overflow)
    }

    /// Whole pages in `kib`; an amount that is not a whole number of pages is an error.
    pub fn kib_to_pages_exact(self, kib: u64) -> Result<u64, ProcError> {
        let page_kib = self.kib();
        // `page_kib` is a power of two, so the mask is the remainder.
        if (kib & (page_kib - 1)) != 0 {
            return Err(ProcError::NotPageAligned { kib, page_kib });
        }
        Ok(kib / page_kib)
    }

    /// Pages needed to hold `kib`, rounding up.
    pub fn kib_to_pages_ceil(self, kib: u64) -> u64 {
        kib.div_ceil(self.kib())
    }
}

fn find_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        if let Some(value) = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            return Some(value.trim());
        }
    }
    None
}

/// `Key:   1234 kB` -> `Some(1234)`; the key absent -> `None`; present but not `<integer> kB` -> error.
fn kib_field(text: &str, key: &'static str) -> Result<Option<u64>, ProcError> {
    let Some(value) = find_value(text, key) else {
        return Ok(None);
    };
    let mut parts = value.split_whitespace();
    let Some(num) = parts.next() else {
        return Err(ProcError::BadValue {
            field: key,
            text: String::new(),
        });
    };
    let unit = parts.next();
    if parts.next().is_some() {
        return Err(ProcError::BadValue {
            field: key,
            text: bounded(value),
        });
    }
    if unit != Some("kB") {
        return Err(ProcError::BadUnit { field: key });
    }
    match parse_u64(num) {
        Some(n) => Ok(Some(n)),
        None => Err(ProcError::BadValue {
            field: key,
            text: bounded(num),
        }),
    }
}

fn req_kib(text: &str, key: &'static str) -> Result<u64, ProcError> {
    kib_field(text, key)?.ok_or(ProcError::MissingField(key))
}

/// `/proc/<pid>/status`. A kernel thread has no address space and so no `Vm*` lines at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatus {
    pub name: String,
    pub vm_peak_kib: Option<u64>,
    pub vm_size_kib: Option<u64>,
    pub vm_hwm_kib: Option<u64>,
    pub vm_rss_kib: Option<u64>,
    pub rss_anon_kib: Option<u64>,
    pub rss_file_kib: Option<u64>,
    pub rss_shmem_kib: Option<u64>,
    pub vm_data_kib: Option<u64>,
    pub vm_stk_kib: Option<u64>,
    pub vm_exe_kib: Option<u64>,
    pub vm_lib_kib: Option<u64>,
    pub vm_pte_kib: Option<u64>,
    pub vm_swap_kib: Option<u64>,
}

pub fn parse_status(text: &str) -> Result<ProcStatus, ProcError> {
    let name = find_value(text, "Name").ok_or(ProcError::MissingField("Name"))?;
    Ok(ProcStatus {
        name: bounded(name),
        vm_peak_kib: kib_field(text, "VmPeak")?,
        vm_size_kib: kib_field(text, "VmSize")?,
        vm_hwm_kib: kib_field(text, "VmHWM")?,
        vm_rss_kib: kib_field(text, "VmRSS")?,
        rss_anon_kib: kib_field(text, "RssAnon")?,
        rss_file_kib: kib_field(text, "RssFile")?,
        rss_shmem_kib: kib_field(text, "RssShmem")?,
        vm_data_kib: kib_field(text, "VmData")?,
        vm_stk_kib: kib_field(text, "VmStk")?,
        vm_exe_kib: kib_field(text, "VmExe")?,
        vm_lib_kib: kib_field(text, "VmLib")?,
        vm_pte_kib: kib_field(text, "VmPTE")?,
        vm_swap_kib: kib_field(text, "VmSwap")?,
    })
}

/// `/proc/<pid>/smaps_rollup`: the whole address space summed once, with shared pages split into
/// the proportional share (`Pss`) and the parts no other process maps (`Private_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmapsRollup {
    pub rss_kib: u64,
    pub pss_kib: u64,
    pub shared_clean_kib: u64,
    pub shared_dirty_kib: u64,
    pub private_clean_kib: u64,
    pub private_dirty_kib: u64,
    pub swap_kib: Option<u64>,
}

impl SmapsRollup {
    /// Unique set size: pages only this process maps.
    pub fn uss_kib(&self) -> u64 {
        self.private_clean_kib
            .saturating_add(self.private_dirty_kib)
    }

    /// Resident pages that some other process may also map.
    pub fn shared_kib(&self) -> u64 {
        self.shared_clean_kib.saturating_add(self.shared_dirty_kib)
    }
}

pub fn parse_smaps_rollup(text: &str) -> Result<SmapsRollup, ProcError> {
    Ok(SmapsRollup {
        rss_kib: req_kib(text, "Rss")?,
        pss_kib: req_kib(text, "Pss")?,
        shared_clean_kib: req_kib(text, "Shared_Clean")?,
        shared_dirty_kib: req_kib(text, "Shared_Dirty")?,
        private_clean_kib: req_kib(text, "Private_Clean")?,
        private_dirty_kib: req_kib(text, "Private_Dirty")?,
        swap_kib: kib_field(text, "Swap")?,
    })
}

/// `/proc/meminfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemInfo {
    pub mem_total_kib: u64,
    pub mem_free_kib: u64,
    pub mem_available_kib: Option<u64>,
    pub buffers_kib: Option<u64>,
    pub cached_kib: Option<u64>,
    pub mapped_kib: Option<u64>,
    pub shmem_kib: Option<u64>,
    pub slab_kib: Option<u64>,
    pub kernel_stack_kib: Option<u64>,
    pub page_tables_kib: Option<u64>,
    pub anon_pages_kib: Option<u64>,
}

pub fn parse_meminfo(text: &str) -> Result<MemInfo, ProcError> {
    Ok(MemInfo {
        mem_total_kib: req_kib(text, "MemTotal")?,
        mem_free_kib: req_kib(text, "MemFree")?,
        mem_available_kib: kib_field(text, "MemAvailable")?,
        buffers_kib: kib_field(text, "Buffers")?,
        cached_kib: kib_field(text, "Cached")?,
        mapped_kib: kib_field(text, "Mapped")?,
        shmem_kib: kib_field(text, "Shmem")?,
        slab_kib: kib_field(text, "Slab")?,
        kernel_stack_kib: kib_field(text, "KernelStack")?,
        page_tables_kib: kib_field(text, "PageTables")?,
        anon_pages_kib: kib_field(text, "AnonPages")?,
    })
}

/// `/proc/<pid>/statm`: seven page counts. `shared` is resident file-backed and shared-memory pages
/// (pages that CAN be shared), not pages another process is known to map, so it must never be used
/// to decide that anything was counted twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatM {
    pub size_pages: u64,
    pub resident_pages: u64,
    pub shared_pages: u64,
    pub text_pages: u64,
    pub lib_pages: u64,
    pub data_pages: u64,
    pub dirty_pages: u64,
}

pub fn parse_statm(text: &str) -> Result<StatM, ProcError> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() != 7 {
        return Err(ProcError::Malformed("statm needs exactly 7 fields"));
    }
    let mut v = [0u64; 7];
    for (slot, field) in v.iter_mut().zip(fields.iter()) {
        *slot = parse_u64(field).ok_or_else(|| ProcError::BadValue {
            field: "statm",
            text: bounded(field),
        })?;
    }
    Ok(StatM {
        size_pages: v[0],
        resident_pages: v[1],
        shared_pages: v[2],
        text_pages: v[3],
        lib_pages: v[4],
        data_pages: v[5],
        dirty_pages: v[6],
    })
}

impl StatM {
    pub fn resident_kib(&self, page: PageSize) -> Result<u64, ProcError> {
        page.pages_to_kib(self.resident_pages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tplayer\nUmask:\t0022\nState:\tS (sleeping)\n\
VmPeak:\t    9000 kB\nVmSize:\t    8000 kB\nVmHWM:\t    3000 kB\nVmRSS:\t    2500 kB\n\
RssAnon:\t    1000 kB\nRssFile:\t    1400 kB\nRssShmem:\t     100 kB\n\
VmData:\t    1500 kB\nVmStk:\t     132 kB\nVmExe:\t     400 kB\nVmLib:\t    2000 kB\n\
VmPTE:\t      24 kB\nVmSwap:\t       0 kB\nThreads:\t3\n";

    const ROLLUP: &str = "00400000-7ffe0000 ---p 00000000 00:00 0                    [rollup]\n\
Rss:                2500 kB\nPss:                1800 kB\nPss_Anon:           1000 kB\n\
Shared_Clean:        900 kB\nShared_Dirty:          0 kB\n\
Private_Clean:       500 kB\nPrivate_Dirty:      1100 kB\nReferenced:         2400 kB\n\
Swap:                  0 kB\n";

    const MEMINFO: &str = "MemTotal:       30000 kB\nMemFree:         6000 kB\n\
MemAvailable:   12000 kB\nBuffers:          500 kB\nSwapCached:         9 kB\n\
Cached:          7000 kB\nMapped:          3000 kB\nShmem:            400 kB\n\
Slab:            1500 kB\nKernelStack:      100 kB\nPageTables:       200 kB\n\
AnonPages:       4000 kB\nActive(anon):    1234 kB\n";

    #[test]
    fn page_sizes_are_validated_and_convert_exactly() {
        let p = PageSize::new(4096).expect("4 KiB");
        assert_eq!((p.bytes(), p.kib()), (4096, 4));
        assert_eq!(p.pages_to_kib(100), Ok(400));
        assert_eq!(p.kib_to_pages_exact(400), Ok(100));
        assert_eq!(
            p.kib_to_pages_exact(401),
            Err(ProcError::NotPageAligned {
                kib: 401,
                page_kib: 4
            })
        );
        assert_eq!(p.kib_to_pages_ceil(401), 101);
        assert_eq!(p.kib_to_pages_ceil(400), 100);
        assert_eq!(p.kib_to_pages_ceil(0), 0);
        assert_eq!(p.pages_to_kib(u64::MAX), Err(ProcError::Overflow));
        let big = PageSize::new(16384).expect("16 KiB");
        assert_eq!(big.pages_to_kib(10), Ok(160));
        assert_eq!(PageSize::new(65536).expect("64 KiB").kib(), 64);
        // 1536 is a whole number of KiB but not a power of two; 512 is a power of two but not a
        // whole KiB; 2 MiB is over the cap.
        for bad in [0, 512, 1536, 3000, 4097, 1 << 21] {
            assert_eq!(
                PageSize::new(bad),
                Err(ProcError::BadPageSize(bad)),
                "{bad}"
            );
        }
    }

    #[test]
    fn status_fields_are_read_by_exact_key() {
        let s = parse_status(STATUS).expect("status");
        assert_eq!(s.name, "player");
        assert_eq!(s.vm_peak_kib, Some(9000));
        assert_eq!(s.vm_size_kib, Some(8000));
        assert_eq!(s.vm_hwm_kib, Some(3000));
        assert_eq!(s.vm_rss_kib, Some(2500));
        assert_eq!(
            (s.rss_anon_kib, s.rss_file_kib, s.rss_shmem_kib),
            (Some(1000), Some(1400), Some(100))
        );
        assert_eq!(s.vm_data_kib, Some(1500));
        assert_eq!(s.vm_stk_kib, Some(132));
        assert_eq!(s.vm_exe_kib, Some(400));
        assert_eq!(s.vm_lib_kib, Some(2000));
        assert_eq!(s.vm_pte_kib, Some(24));
        assert_eq!(s.vm_swap_kib, Some(0));
    }

    #[test]
    fn a_kernel_thread_has_no_vm_lines_and_an_old_kernel_has_no_rss_split() {
        let kthread = parse_status("Name:\tkworker/0:1\nState:\tI (idle)\n").expect("kthread");
        assert_eq!(kthread.vm_rss_kib, None);
        assert_eq!(kthread.vm_hwm_kib, None);
        let old = parse_status("Name:\tinit\nVmRSS:\t  100 kB\nVmHWM:\t  120 kB\n").expect("old");
        assert_eq!((old.vm_rss_kib, old.rss_anon_kib), (Some(100), None));
    }

    #[test]
    fn status_without_a_name_or_with_a_bad_unit_is_an_error() {
        assert_eq!(
            parse_status("VmRSS:\t100 kB\n"),
            Err(ProcError::MissingField("Name"))
        );
        assert_eq!(
            parse_status("Name:\tx\nVmRSS:\t100 MB\n"),
            Err(ProcError::BadUnit { field: "VmRSS" })
        );
        assert_eq!(
            parse_status("Name:\tx\nVmRSS:\t100\n"),
            Err(ProcError::BadUnit { field: "VmRSS" })
        );
        assert_eq!(
            parse_status("Name:\tx\nVmRSS:\tlots kB\n"),
            Err(ProcError::BadValue {
                field: "VmRSS",
                text: "lots".to_string()
            })
        );
        assert_eq!(
            parse_status("Name:\tx\nVmRSS:\t1 2 kB\n"),
            Err(ProcError::BadValue {
                field: "VmRSS",
                text: "1 2 kB".to_string()
            })
        );
        assert_eq!(
            parse_status("Name:\tx\nVmRSS:\t-5 kB\n"),
            Err(ProcError::BadValue {
                field: "VmRSS",
                text: "-5".to_string()
            })
        );
    }

    #[test]
    fn smaps_rollup_splits_private_from_shared() {
        let r = parse_smaps_rollup(ROLLUP).expect("rollup");
        assert_eq!((r.rss_kib, r.pss_kib), (2500, 1800));
        assert_eq!(r.uss_kib(), 500 + 1100);
        assert_eq!(r.shared_kib(), 900);
        assert_eq!(r.swap_kib, Some(0));
        // The header line `...00:00 0 [rollup]` contains a colon but is not a field.
        assert_eq!(
            parse_smaps_rollup("Rss: 1 kB\nPss: 1 kB\n"),
            Err(ProcError::MissingField("Shared_Clean"))
        );
    }

    #[test]
    fn meminfo_keys_do_not_match_by_prefix() {
        let m = parse_meminfo(MEMINFO).expect("meminfo");
        assert_eq!((m.mem_total_kib, m.mem_free_kib), (30000, 6000));
        assert_eq!(m.mem_available_kib, Some(12000));
        // `SwapCached: 9` comes first and must not be read as `Cached`.
        assert_eq!(m.cached_kib, Some(7000));
        assert_eq!(m.buffers_kib, Some(500));
        assert_eq!(m.mapped_kib, Some(3000));
        assert_eq!(m.shmem_kib, Some(400));
        assert_eq!(m.slab_kib, Some(1500));
        assert_eq!(m.kernel_stack_kib, Some(100));
        assert_eq!(m.page_tables_kib, Some(200));
        assert_eq!(m.anon_pages_kib, Some(4000));
        let bare = parse_meminfo("MemTotal: 10 kB\nMemFree: 4 kB\n").expect("bare");
        assert_eq!((bare.mem_available_kib, bare.slab_kib), (None, None));
        assert_eq!(
            parse_meminfo("MemTotal: 10 kB\n"),
            Err(ProcError::MissingField("MemFree"))
        );
    }

    #[test]
    fn statm_counts_pages_and_converts_through_the_page_size() {
        let s = parse_statm("2000 625 150 100 0 400 0\n").expect("statm");
        assert_eq!(
            (s.size_pages, s.resident_pages, s.shared_pages),
            (2000, 625, 150)
        );
        let p4 = PageSize::new(4096).expect("4k");
        let p16 = PageSize::new(16384).expect("16k");
        // 625 pages: 2500 KiB at 4 KiB pages, 10000 KiB at 16 KiB pages.
        assert_eq!(s.resident_kib(p4), Ok(2500));
        assert_eq!(s.resident_kib(p16), Ok(10000));
        assert_eq!(
            parse_statm("1 2 3"),
            Err(ProcError::Malformed("statm needs exactly 7 fields"))
        );
        assert_eq!(
            parse_statm("1 2 3 4 5 6 x"),
            Err(ProcError::BadValue {
                field: "statm",
                text: "x".to_string()
            })
        );
    }
}
