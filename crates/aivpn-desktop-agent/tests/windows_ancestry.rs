#![cfg(target_os = "windows")]

#[path = "support/windows_control_fixture.rs"]
#[allow(dead_code)]
mod accounts;
#[path = "support/windows_ancestry_fixture.rs"]
mod ancestry;
#[path = "support/windows_driver_fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[path = "support/windows_identity_fixture.rs"]
#[allow(dead_code)]
mod os;

use ancestry::{Case, Chain};

#[test]
#[ignore = "Только изолированная Windows VM с явным lab guard и LocalSystem-службой"]
fn ancestry_chain_child() {
    ancestry::helper_guard();
    ancestry::child();
}

#[test]
#[ignore = "Только изолированная Windows VM с явным lab guard и LocalSystem-службой"]
fn truncated_ancestry_never_looks_like_a_complete_default_system_chain() {
    ancestry::guard();
    for depth in [32, 33, 34] {
        let chain = Chain::start(depth, None, false, false);
        let result = ancestry::diagnose(&chain, Case::new("depth", 2, true));
        chain.finish();
        ancestry::assert_decision(
            &result,
            if depth == 32 {
                (1, 2, 32, 0)
            } else {
                (1, 0, 0, 1)
            },
        );
        assert_eq!(result["parent_count"], 32);
    }
}

#[test]
#[ignore = "Только изолированная Windows VM с явным lab guard и LocalSystem-службой"]
fn incomplete_ancestry_keeps_proven_matches_and_policy_controls() {
    ancestry::guard();
    for (label, selected_depth, action, inherit, outside, expected) in [
        ("self-system", Some(0), 0, true, false, (0, 0, 0, 0)),
        ("self-vpn", Some(0), 2, true, false, (1, 2, 0, 0)),
        ("nearest-known", Some(2), 2, true, false, (1, 2, 2, 0)),
        ("inherit-false", None, 2, false, false, (0, 0, 0, 0)),
        ("outside-cidr", None, 2, true, true, (0, 0, 0, 0)),
    ] {
        let chain = Chain::start(34, selected_depth, false, false);
        let mut case = Case::new(label, action, inherit);
        case.outside = outside;
        let result = ancestry::diagnose(&chain, case);
        chain.finish();
        ancestry::assert_decision(&result, expected);
        assert_eq!(result["parent_count"], 32);
    }
}

#[test]
#[ignore = "Только изолированная Windows VM с явным lab guard и LocalSystem-службой"]
fn complete_unselected_chain_and_owner_boundary_still_use_system() {
    ancestry::guard();
    for boundary in [false, true] {
        let chain = if boundary {
            Chain::start(34, None, false, true)
        } else {
            Chain::complete()
        };
        let mut case = Case::new(
            if boundary {
                "owner-boundary"
            } else {
                "complete-unselected"
            },
            2,
            true,
        );
        case.unselected = !boundary;
        let result = ancestry::diagnose(&chain, case);
        chain.finish();
        ancestry::assert_decision(&result, (0, 0, 0, 0));
        if boundary {
            assert_eq!(result["parent_count"], 0);
            assert_eq!(result["owner_slot"], 0);
        }
    }
}

#[test]
#[ignore = "Только изолированная Windows VM с явным lab guard и LocalSystem-службой"]
fn incomplete_ancestry_survives_creator_exit_and_record_retirement() {
    ancestry::guard();
    let chain = Chain::start(34, None, true, false);
    let result = ancestry::diagnose(&chain, Case::new("retired-creators", 2, true));
    chain.finish();
    ancestry::assert_decision(&result, (1, 0, 0, 1));
    assert_eq!(result["parent_count"], 32);
}
