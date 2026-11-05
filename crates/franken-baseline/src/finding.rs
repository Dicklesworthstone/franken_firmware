//! Typed diagnostics, kept bounded.
//!
//! A finding names what was noticed (`kind`), where (`subject`, built only from validated identifiers
//! and numbers, never raw input text) and the numbers behind it. At most [`MAX_FINDINGS`] are kept;
//! past that only a count is, so a pathological capture cannot grow a report without limit.

use crate::json::Json;

pub const MAX_FINDINGS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    // memory accounting
    RollupRssMismatch,
    PssOutOfRange,
    PssExceedsRss,
    RssBreakdownMismatch,
    HwmBelowRss,
    RssSourceMismatch,
    KernelThread,
    NoRssSource,
    FreeExceedsTotal,
    MappedExceedsCached,
    OverAttributed,
    // time series
    NonMonotonicClock,
    ValueOutOfWidth,
    ImplausibleValue,
    CounterReset,
    CounterWrap,
    WallStep,
    DeviceRateMissing,
    DeviceClockReset,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::RollupRssMismatch => "rollup_rss_mismatch",
            FindingKind::PssOutOfRange => "pss_out_of_range",
            FindingKind::PssExceedsRss => "pss_exceeds_rss",
            FindingKind::RssBreakdownMismatch => "rss_breakdown_mismatch",
            FindingKind::HwmBelowRss => "hwm_below_rss",
            FindingKind::RssSourceMismatch => "rss_source_mismatch",
            FindingKind::KernelThread => "kernel_thread",
            FindingKind::NoRssSource => "no_rss_source",
            FindingKind::FreeExceedsTotal => "free_exceeds_total",
            FindingKind::MappedExceedsCached => "mapped_exceeds_cached",
            FindingKind::OverAttributed => "over_attributed",
            FindingKind::NonMonotonicClock => "non_monotonic_clock",
            FindingKind::ValueOutOfWidth => "value_out_of_width",
            FindingKind::ImplausibleValue => "implausible_value",
            FindingKind::CounterReset => "counter_reset",
            FindingKind::CounterWrap => "counter_wrap",
            FindingKind::WallStep => "wall_step",
            FindingKind::DeviceRateMissing => "device_rate_missing",
            FindingKind::DeviceClockReset => "device_clock_reset",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub subject: String,
    pub values: Vec<(&'static str, i128)>,
}

impl Finding {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("kind", Json::str(self.kind.as_str())),
            ("subject", Json::str(&self.subject)),
            (
                "values",
                Json::Obj(
                    self.values
                        .iter()
                        .map(|(k, v)| ((*k).to_string(), Json::Int(*v)))
                        .collect(),
                ),
            ),
        ])
    }
}

#[derive(Debug, Clone, Default)]
pub struct Findings {
    items: Vec<Finding>,
    dropped: u64,
}

impl Findings {
    pub fn push(&mut self, kind: FindingKind, subject: String, values: &[(&'static str, i128)]) {
        if self.items.len() >= MAX_FINDINGS {
            self.dropped += 1;
            return;
        }
        self.items.push(Finding {
            kind,
            subject,
            values: values.to_vec(),
        });
    }

    pub fn items(&self) -> &[Finding] {
        &self.items
    }

    /// How many findings were discarded after the cap was reached.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn count(&self, kind: FindingKind) -> usize {
        self.items.iter().filter(|f| f.kind == kind).count()
    }

    pub fn extend_from(&mut self, other: &Findings) {
        for f in &other.items {
            self.push(f.kind, f.subject.clone(), &f.values);
        }
        self.dropped += other.dropped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_are_capped_and_the_overflow_is_counted() {
        let mut f = Findings::default();
        for i in 0..(MAX_FINDINGS as i128 + 10) {
            f.push(FindingKind::WallStep, format!("i={i}"), &[("i", i)]);
        }
        assert_eq!(f.items().len(), MAX_FINDINGS);
        assert_eq!(f.dropped(), 10);
        assert_eq!(f.count(FindingKind::WallStep), MAX_FINDINGS);
        assert_eq!(f.count(FindingKind::CounterReset), 0);
    }

    #[test]
    fn a_finding_renders_its_numbers() {
        let mut f = Findings::default();
        f.push(
            FindingKind::CounterReset,
            "counter=xruns".to_string(),
            &[("from", 1000), ("to", 3)],
        );
        assert_eq!(
            f.items()[0].to_json().render(),
            "{\"kind\":\"counter_reset\",\"subject\":\"counter=xruns\",\"values\":{\"from\":1000,\"to\":3}}"
        );
    }

    #[test]
    fn extend_keeps_the_cap_and_sums_the_drops() {
        let mut a = Findings::default();
        let mut b = Findings::default();
        for i in 0..MAX_FINDINGS {
            a.push(FindingKind::WallStep, i.to_string(), &[]);
        }
        b.push(FindingKind::WallStep, "x".to_string(), &[]);
        a.extend_from(&b);
        assert_eq!(a.items().len(), MAX_FINDINGS);
        assert_eq!(a.dropped(), 1);
    }
}
