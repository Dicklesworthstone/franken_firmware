//! Which native services a build selects, and what the composition root says about each (`P01` BLK-006).
//!
//! The four native services and artwork each have a Cargo feature on this crate, named in the P01 workspace contract
//! (`cargo_feature`, `owner_crate = "franken-speaker"`): `spotify_connect`, `airplay2`, `tailnet_native`, `alexa_bridge` and
//! `artwork`. A profile that disables one of them is built without its flag, so `speaker-*-min` and `speaker-*-full` are
//! different cargo invocations and different artifacts, and a build that does not select a service says so.
//!
//! What a selection means today, and what it does not:
//!
//! * A service whose feature is **off** reports `selected: false`: it is absent from the artifact.
//! * A service whose feature is **on** reports `selected: true, implemented: false, qualified: false`. That is all there is to
//!   report: no provider code exists behind any flag yet. Each service's bead (S01 Spotify Connect, A01 AirPlay 2, T01
//!   tailnet, X01 Alexa, and artwork's owner) takes over its own flag when it has code to put behind it, and changes
//!   [`NativeService::implemented`] for its entry then. Nothing here stands in for a service.
//! * No selection is ever `qualified`. Qualification is the P01 admission result computed from evidence
//!   (`WorkspaceContract::admission`: `required_feature_unqualified` until real evidence of an accepted kind is bound to the
//!   artifact), and a Cargo flag is not evidence. [`ServiceReport::check`] refuses a report that claims it, so a selected
//!   service can never be reported ready by this module.
//! * `protected_render` and `synchronized_groups` have no flag. They are the render path and the group session this crate is
//!   built from: a flag that removed them would remove the speaker, and a flag that did not would change nothing observable,
//!   which the contract does not allow. A profile that disables them (the bootstrap probe, a different crate) is still blocked
//!   by `admission` as `required_feature_disabled`.
//!
//! The selection is a compile-time constant (`cfg!(feature = ...)`), so every line of this module is compiled in every
//! configuration and the tests read the build they were compiled into.
//!
//! The speaker binary reaches this module through `franken-speaker --services`, which prints [`markers`]: one
//! `FFW_SERVICE:<feature> ...` line per service. That caller is what makes the selection real in the artifact: a report nothing
//! calls could be optimized out and leave a build that selects every service byte-for-byte equal to one that selects none. The
//! tests in `tests/cli_services.rs` run the built binary and read those lines in the default and all-on configurations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A native service or artwork: the features of the P01 contract that have a Cargo flag on this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeService {
    SpotifyConnect,
    Airplay2,
    TailnetNative,
    AlexaBridge,
    Artwork,
}

impl NativeService {
    /// Every service, in the order a report lists them.
    pub const ALL: [Self; 5] = [
        Self::SpotifyConnect,
        Self::Airplay2,
        Self::TailnetNative,
        Self::AlexaBridge,
        Self::Artwork,
    ];

    /// The contract's name for the feature, which is also the name of its Cargo feature on this crate.
    #[must_use]
    pub const fn feature(self) -> &'static str {
        match self {
            Self::SpotifyConnect => "spotify_connect",
            Self::Airplay2 => "airplay2",
            Self::TailnetNative => "tailnet_native",
            Self::AlexaBridge => "alexa_bridge",
            Self::Artwork => "artwork",
        }
    }

    /// Whether this build was compiled with the service's Cargo feature.
    #[must_use]
    pub const fn selected(self) -> bool {
        match self {
            Self::SpotifyConnect => cfg!(feature = "spotify_connect"),
            Self::Airplay2 => cfg!(feature = "airplay2"),
            Self::TailnetNative => cfg!(feature = "tailnet_native"),
            Self::AlexaBridge => cfg!(feature = "alexa_bridge"),
            Self::Artwork => cfg!(feature = "artwork"),
        }
    }

    /// Whether any code is behind the flag. The service's bead sets its own entry when it lands an implementation; until
    /// then selecting the feature selects nothing.
    #[must_use]
    pub const fn implemented(self) -> bool {
        match self {
            Self::SpotifyConnect
            | Self::Airplay2
            | Self::TailnetNative
            | Self::AlexaBridge
            | Self::Artwork => false,
        }
    }
}

/// What this build says about one service: selected, implemented, qualified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReport {
    pub service: NativeService,
    /// Compiled in (its Cargo feature is on). `false` is absent.
    pub selected: bool,
    /// Code exists behind the flag.
    pub implemented: bool,
    /// Real evidence of an accepted kind exists. A build selection never states this; see the module documentation.
    pub qualified: bool,
}

impl ServiceReport {
    /// The report this build gives for `service`: the compile-time selection, the implementation table, and never qualified.
    #[must_use]
    pub const fn of(service: NativeService) -> Self {
        Self {
            service,
            selected: service.selected(),
            implemented: service.implemented(),
            qualified: false,
        }
    }

    /// Selected, implemented and qualified: all three. No report this module produces is ready.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.selected && self.implemented && self.qualified
    }

    /// Hold a report (one read back from a status line, say) to this build: it must say exactly what [`ServiceReport::of`]
    /// says for its service, and it must not claim qualification.
    ///
    /// # Errors
    ///
    /// The first way the report differs from the build: a claim of qualification, a selection the build does not have, or an
    /// implementation the build does not have.
    pub fn check(&self) -> Result<(), ReportFault> {
        if self.qualified {
            return Err(ReportFault::ClaimsQualification(self.service));
        }
        if self.selected != self.service.selected() {
            return Err(ReportFault::SelectionDiffersFromBuild(self.service));
        }
        if self.implemented != self.service.implemented() {
            return Err(ReportFault::ImplementationDiffersFromBuild(self.service));
        }
        Ok(())
    }

    /// The line `franken-speaker --services` prints for this report: `FFW_SERVICE:<feature> absent` when the service is not
    /// selected, otherwise `FFW_SERVICE:<feature> selected <unimplemented|implemented> <unqualified|qualified>`. The word
    /// "ready" is never printed.
    #[must_use]
    pub fn marker(&self) -> String {
        let feature = self.service.feature();
        if !self.selected {
            return format!("FFW_SERVICE:{feature} absent");
        }
        let implemented = if self.implemented {
            "implemented"
        } else {
            "unimplemented"
        };
        let qualified = if self.qualified {
            "qualified"
        } else {
            "unqualified"
        };
        format!("FFW_SERVICE:{feature} selected {implemented} {qualified}")
    }

    /// The report a [`ServiceReport::marker`] line states, or `None` for a line this module does not print. A line that says
    /// "qualified" parses, so that [`ServiceReport::check`] can refuse it; nothing else is accepted.
    #[must_use]
    pub fn from_marker(line: &str) -> Option<Self> {
        let (name, standing) = line.strip_prefix("FFW_SERVICE:")?.split_once(' ')?;
        let service = NativeService::ALL
            .into_iter()
            .find(|s| s.feature() == name)?;
        let words: Vec<&str> = standing.split(' ').collect();
        let (implemented, qualified) = match words.as_slice() {
            ["absent"] => {
                return Some(Self {
                    service,
                    selected: false,
                    implemented: false,
                    qualified: false,
                });
            }
            ["selected", implemented, qualified] => (
                match *implemented {
                    "implemented" => true,
                    "unimplemented" => false,
                    _ => return None,
                },
                match *qualified {
                    "qualified" => true,
                    "unqualified" => false,
                    _ => return None,
                },
            ),
            _ => return None,
        };
        Some(Self {
            service,
            selected: true,
            implemented,
            qualified,
        })
    }
}

/// How a report differs from the build it is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReportFault {
    #[error(
        "{0:?} claims qualification: a build selection never qualifies a service (that is P01 admission, from evidence)"
    )]
    ClaimsQualification(NativeService),
    #[error("{0:?} is reported with a selection this build does not have")]
    SelectionDiffersFromBuild(NativeService),
    #[error("{0:?} is reported with an implementation this build does not have")]
    ImplementationDiffersFromBuild(NativeService),
}

/// What this build reports about every native service, in [`NativeService::ALL`] order.
#[must_use]
pub fn report() -> [ServiceReport; 5] {
    NativeService::ALL.map(ServiceReport::of)
}

/// What `franken-speaker --services` prints: the [`ServiceReport::marker`] of every service, in [`NativeService::ALL`] order,
/// each ended by a newline.
#[must_use]
pub fn markers() -> String {
    let mut out = String::new();
    for r in report() {
        out.push_str(&r.marker());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use franken_board_profile::build_contract::WorkspaceContract;

    use super::*;

    const MANIFEST: &str = include_str!("../Cargo.toml");
    const CONTRACT: &str =
        include_str!("../../franken-board-profile/tests/vectors/p01_workspace_contract.json");

    /// The feature names the crate's `[features]` table declares.
    fn manifest_features() -> Vec<&'static str> {
        let mut in_features = false;
        let mut names = Vec::new();
        for line in MANIFEST.lines().map(str::trim) {
            if line.starts_with('[') {
                in_features = line == "[features]";
                continue;
            }
            if !in_features || line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((name, _)) = line.split_once('=') {
                names.push(name.trim());
            }
        }
        names
    }

    fn contract() -> WorkspaceContract {
        WorkspaceContract::from_json(CONTRACT).expect("the declared contract parses")
    }

    // ------------------------------------------------------------------------ the same in every configuration

    #[test]
    fn every_service_has_a_cargo_feature_of_its_name_and_no_other_flag_is_a_service() {
        let declared = manifest_features();
        for service in NativeService::ALL {
            assert!(
                declared.contains(&service.feature()),
                "{service:?}: no Cargo feature {:?} in Cargo.toml",
                service.feature()
            );
        }
        for name in &declared {
            let known = *name == "default"
                || *name == "harness"
                || NativeService::ALL.iter().any(|s| s.feature() == *name);
            assert!(
                known,
                "Cargo.toml declares {name:?}, which no service names"
            );
        }
        assert_eq!(declared.len(), 2 + NativeService::ALL.len());
    }

    #[test]
    fn the_wire_names_are_the_contract_names() {
        for service in NativeService::ALL {
            let wire = serde_json::to_string(&service).unwrap();
            assert_eq!(wire, format!("\"{}\"", service.feature()));
        }
    }

    #[test]
    fn the_contract_names_the_same_flags_on_this_crate_and_none_for_the_render_path() {
        let contract = contract();
        for service in NativeService::ALL {
            let spec = contract
                .features
                .iter()
                .find(|f| f.name == service.feature())
                .unwrap_or_else(|| panic!("{service:?} is not a contract feature"));
            assert_eq!(spec.cargo_feature, service.feature(), "{service:?}");
            assert_eq!(spec.owner_crate, "franken-speaker", "{service:?}");
        }
        // The decision about the core features: no flag, because a flag either removes the speaker or changes nothing.
        for name in ["protected_render", "synchronized_groups"] {
            let spec = contract.features.iter().find(|f| f.name == name).unwrap();
            assert_eq!(spec.cargo_feature, "", "{name}");
        }
    }

    #[test]
    fn the_report_lists_every_service_once_in_a_fixed_order() {
        let services = report().map(|r| r.service);
        assert_eq!(services, NativeService::ALL);
    }

    #[test]
    fn no_build_selection_reports_a_service_implemented_qualified_or_ready() {
        for r in report() {
            assert_eq!(r.check(), Ok(()), "{:?}", r.service);
            assert!(!r.implemented, "{:?}: no provider code exists", r.service);
            assert!(!r.qualified, "{:?}: a flag is not evidence", r.service);
            assert!(!r.ready(), "{:?}", r.service);
        }
    }

    #[test]
    fn a_selected_service_claiming_ready_is_refused_and_the_same_report_without_the_claim_passes() {
        for service in NativeService::ALL {
            let honest = ServiceReport::of(service);
            assert_eq!(honest.check(), Ok(()));
            // Planted: the claim of qualification, with and without an implementation behind it.
            let claims = ServiceReport {
                selected: true,
                implemented: true,
                qualified: true,
                ..honest
            };
            assert!(claims.ready());
            assert_eq!(
                claims.check(),
                Err(ReportFault::ClaimsQualification(service))
            );
            let claims = ServiceReport {
                selected: true,
                qualified: true,
                ..honest
            };
            assert_eq!(
                claims.check(),
                Err(ReportFault::ClaimsQualification(service))
            );
        }
    }

    #[test]
    fn a_report_that_disagrees_with_this_build_is_refused() {
        for service in NativeService::ALL {
            let honest = ServiceReport::of(service);
            let flipped = ServiceReport {
                selected: !honest.selected,
                ..honest
            };
            assert_eq!(
                flipped.check(),
                Err(ReportFault::SelectionDiffersFromBuild(service))
            );
            let invented = ServiceReport {
                implemented: !honest.implemented,
                ..honest
            };
            assert_eq!(
                invented.check(),
                Err(ReportFault::ImplementationDiffersFromBuild(service))
            );
        }
    }

    #[test]
    fn a_marker_says_absent_or_selected_unimplemented_unqualified_in_words_and_never_ready() {
        let absent = ServiceReport {
            service: NativeService::Airplay2,
            selected: false,
            implemented: false,
            qualified: false,
        };
        assert_eq!(absent.marker(), "FFW_SERVICE:airplay2 absent");
        let selected = ServiceReport {
            selected: true,
            ..absent
        };
        assert_eq!(
            selected.marker(),
            "FFW_SERVICE:airplay2 selected unimplemented unqualified"
        );
        for r in report() {
            assert!(!r.marker().contains("ready"), "{}", r.marker());
        }
    }

    #[test]
    fn a_marker_parses_back_to_the_report_it_came_from_and_nothing_else_parses() {
        for r in report() {
            assert_eq!(ServiceReport::from_marker(&r.marker()), Some(r));
        }
        for bad in [
            "",
            "FFW_SERVICE:airplay2",
            "FFW_SERVICE:nosuch absent",
            "FFW_SERVICE:airplay2 ready",
            "FFW_SERVICE:airplay2 selected implemented",
            "FFW_SERVICE:airplay2 selected sorta unqualified",
            "FFW_SERVICE:airplay2 absent ",
            "airplay2 absent",
        ] {
            assert_eq!(ServiceReport::from_marker(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_printed_line_claiming_qualification_parses_and_check_refuses_it() {
        let honest = ServiceReport::of(NativeService::Artwork);
        let parsed = ServiceReport::from_marker(&honest.marker()).unwrap();
        assert_eq!(parsed.check(), Ok(()));
        // Planted: the same service printed as selected, implemented and qualified, which is what "ready" would be.
        let claim =
            ServiceReport::from_marker("FFW_SERVICE:artwork selected implemented qualified")
                .expect("the line has the printed shape");
        assert!(claim.ready());
        assert_eq!(
            claim.check(),
            Err(ReportFault::ClaimsQualification(NativeService::Artwork))
        );
    }

    #[test]
    fn the_markers_are_the_reports_markers_one_per_line_in_order() {
        let text = markers();
        assert!(text.ends_with('\n'));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), NativeService::ALL.len());
        for (line, r) in lines.iter().zip(report()) {
            assert_eq!(*line, r.marker());
            assert!(
                line.starts_with(&format!("FFW_SERVICE:{} ", r.service.feature())),
                "{line}"
            );
        }
    }

    #[test]
    fn the_report_round_trips_as_json_and_refuses_a_field_it_does_not_know() {
        let wire = serde_json::to_string(&report()).unwrap();
        let back: Vec<ServiceReport> = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, report());
        let extra = r#"{"service":"airplay2","selected":true,"implemented":false,"qualified":false,"state":"ready"}"#;
        assert!(serde_json::from_str::<ServiceReport>(extra).is_err());
    }

    #[test]
    fn enabling_a_flag_does_not_change_admissions_blocks() {
        // Admission is computed from the contract and the evidence, never from the build. These lists are literal so that the
        // same test, compiled with no service feature and with all of them, must give the same answer.
        let contract = contract();
        let blocks = |id: &str| {
            contract
                .admission(id)
                .unwrap_or_else(|| panic!("no artifact {id}"))
                .blocks
        };
        assert_eq!(
            blocks("speaker-mips-full"),
            [
                "required_feature_unqualified:airplay2",
                "required_feature_unqualified:alexa_bridge",
                "required_feature_unqualified:protected_render",
                "required_feature_unqualified:spotify_connect",
                "required_feature_unqualified:synchronized_groups",
                "required_feature_unqualified:tailnet_native",
            ]
        );
        assert_eq!(
            blocks("speaker-mips-min"),
            [
                "required_feature_disabled:airplay2",
                "required_feature_disabled:alexa_bridge",
                "required_feature_disabled:spotify_connect",
                "required_feature_disabled:tailnet_native",
                "required_feature_unqualified:protected_render",
                "required_feature_unqualified:synchronized_groups",
            ]
        );
    }

    // ----------------------------------------------------------------- one pair per service: on and off

    #[cfg(feature = "spotify_connect")]
    #[test]
    fn spotify_connect_selected_reports_selected_unimplemented_unqualified() {
        let r = ServiceReport::of(NativeService::SpotifyConnect);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (true, false, false)
        );
        assert!(!r.ready());
    }

    #[cfg(not(feature = "spotify_connect"))]
    #[test]
    fn spotify_connect_not_selected_reports_absent() {
        let r = ServiceReport::of(NativeService::SpotifyConnect);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (false, false, false)
        );
    }

    #[cfg(feature = "airplay2")]
    #[test]
    fn airplay2_selected_reports_selected_unimplemented_unqualified() {
        let r = ServiceReport::of(NativeService::Airplay2);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (true, false, false)
        );
        assert!(!r.ready());
    }

    #[cfg(not(feature = "airplay2"))]
    #[test]
    fn airplay2_not_selected_reports_absent() {
        let r = ServiceReport::of(NativeService::Airplay2);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (false, false, false)
        );
    }

    #[cfg(feature = "tailnet_native")]
    #[test]
    fn tailnet_native_selected_reports_selected_unimplemented_unqualified() {
        let r = ServiceReport::of(NativeService::TailnetNative);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (true, false, false)
        );
        assert!(!r.ready());
    }

    #[cfg(not(feature = "tailnet_native"))]
    #[test]
    fn tailnet_native_not_selected_reports_absent() {
        let r = ServiceReport::of(NativeService::TailnetNative);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (false, false, false)
        );
    }

    #[cfg(feature = "alexa_bridge")]
    #[test]
    fn alexa_bridge_selected_reports_selected_unimplemented_unqualified() {
        let r = ServiceReport::of(NativeService::AlexaBridge);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (true, false, false)
        );
        assert!(!r.ready());
    }

    #[cfg(not(feature = "alexa_bridge"))]
    #[test]
    fn alexa_bridge_not_selected_reports_absent() {
        let r = ServiceReport::of(NativeService::AlexaBridge);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (false, false, false)
        );
    }

    #[cfg(feature = "artwork")]
    #[test]
    fn artwork_selected_reports_selected_unimplemented_unqualified() {
        let r = ServiceReport::of(NativeService::Artwork);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (true, false, false)
        );
        assert!(!r.ready());
    }

    #[cfg(not(feature = "artwork"))]
    #[test]
    fn artwork_not_selected_reports_absent() {
        let r = ServiceReport::of(NativeService::Artwork);
        assert_eq!(
            (r.selected, r.implemented, r.qualified),
            (false, false, false)
        );
    }
}
