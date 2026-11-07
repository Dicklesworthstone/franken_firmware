//! N07 (`ffw-ybr`): the retained-network ownership matrix is held to the committed E04 radio-duty records.
//!
//! The matrix in `franken_stream::link` claims only what this tree performs. For the seven radio duties E04 names, it
//! carries E04's record ids and blocker ids verbatim and must stay unestablished for as long as E04 does. The day E04
//! establishes one of them, this test fails with a message that says so: the matrix is updated from the new E04 record, not
//! worked around.

use franken_stream::link::{
    E04_OWNERSHIP_BLOCKER, E04_QUAL_BLOCKER, Implementation, Owner, matrix_problems,
    ownership_matrix,
};
use serde_json::Value;

const E04_MATRIX: &str = include_str!("../../../tests/e04/matrix_audiodev_m16.json");

fn e04() -> Value {
    serde_json::from_str(E04_MATRIX).expect("the committed E04 matrix parses")
}

#[test]
fn n07_the_ownership_matrix_carries_the_committed_e04_radio_duties_exactly() {
    let e04 = e04();
    assert_eq!(e04["schema"], "ffw.e04.contract_matrix.v1");
    let radio = e04["radio"].as_array().expect("E04 radio records");
    let ours: Vec<_> = ownership_matrix()
        .iter()
        .filter(|duty| duty.e04_record.is_some())
        .collect();
    assert_eq!(
        ours.len(),
        radio.len(),
        "every E04 radio duty is in the N07 matrix, and nothing else claims to be one"
    );
    for record in radio {
        let id = record["id"].as_str().expect("an E04 record id");
        let duty = ours
            .iter()
            .find(|duty| duty.e04_record == Some(id))
            .unwrap_or_else(|| panic!("E04 record {id} is missing from the N07 matrix"));
        assert_eq!(duty.owner, Owner::Unestablished, "{id}");
        assert_eq!(duty.implementation, Implementation::NotStarted, "{id}");
        assert!(duty.wireless_only, "{id}");
        for field in [
            "owner",
            "survives_daemon_replacement",
            "audio_interference_bound_us",
        ] {
            let status = record[field]["status"].as_str().expect("a field status");
            assert_eq!(
                status, "unknown",
                "E04 now says {id}.{field} is {status}: update the N07 ownership matrix from that record"
            );
            let blocker = record[field]["blocker"]["id"]
                .as_str()
                .expect("an unknown E04 field names its blocker");
            assert!(
                duty.blockers.contains(&blocker),
                "{id}.{field}: blocker {blocker} is not carried by the N07 record"
            );
        }
    }
    assert_eq!(matrix_problems(), Vec::<String>::new());
}

#[test]
fn n07_the_two_e04_radio_blockers_are_the_ones_the_matrix_names() {
    let e04 = e04();
    let mut seen: Vec<String> = Vec::new();
    for record in e04["radio"].as_array().expect("E04 radio records") {
        for field in [
            "owner",
            "survives_daemon_replacement",
            "audio_interference_bound_us",
        ] {
            let blocker = record[field]["blocker"]["id"]
                .as_str()
                .expect("a blocker id")
                .to_owned();
            if !seen.contains(&blocker) {
                seen.push(blocker);
            }
        }
    }
    seen.sort();
    let mut named = vec![
        E04_OWNERSHIP_BLOCKER.to_owned(),
        E04_QUAL_BLOCKER.to_owned(),
    ];
    named.sort();
    assert_eq!(seen, named);
}

#[test]
fn n07_the_radio_duties_the_bead_requires_to_stay_tracked_are_all_present() {
    let ids: Vec<&str> = ownership_matrix().iter().map(|duty| duty.id).collect();
    for required in [
        "radio.multicast_delivery",
        "radio.unicast_delivery",
        "radio.power_save",
        "radio.roam",
        "radio.congestion",
        "radio.mesh_membership",
        "radio.scheduler_interference",
        "link.association",
    ] {
        assert!(
            ids.contains(&required),
            "{required} must stay in the matrix"
        );
    }
}
