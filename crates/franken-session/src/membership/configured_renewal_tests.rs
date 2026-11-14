// Configured-issuer renewal validates authority without mutating the session.
use super::*;

fn fixture() -> (
    GroupMembership,
    UnifiedGroupSession,
    AuthorityToken,
    RenewalWindow,
) {
    let config = MembershipConfig {
        lease: LeaseTerms {
            max_lease_ns: 1_000,
            clock_uncertainty_ns: 100,
            ..LeaseTerms::default()
        },
        ..MembershipConfig::default()
    };
    let session = UnifiedGroupSession::new("group", "issuer", 7);
    let token = AuthorityToken::issue(&session, 1_300);
    let window = RenewalWindow {
        earliest_ns: 1_000,
        latest_ns: 1_100,
    };
    (GroupMembership::new(config), session, token, window)
}

#[test]
fn configured_renewal_accepts_exact_horizon_and_keeps_current_token_live() {
    let (membership, session, token, window) = fixture();
    let candidate = AuthorityToken {
        expires_at_ns: 2_000,
        ..token.clone()
    };
    assert_eq!(
        membership.validate_configured_renewal(&session, &token, &candidate, window),
        Ok(())
    );
    assert!(membership.lease_is_live(&session, &token, window.latest_ns));
    assert_eq!(token.expires_at_ns, 1_300);
    assert_eq!(session.current_epoch, 7);
}

#[test]
fn renewal_refuses_nonextension_horizon_and_conservative_expiry() {
    let (membership, session, token, window) = fixture();
    for expiry in [1_299, 1_300] {
        let candidate = AuthorityToken {
            expires_at_ns: expiry,
            ..token.clone()
        };
        assert!(matches!(
            membership.validate_configured_renewal(&session, &token, &candidate, window),
            Err(MembershipError::LeaseNotExtended { .. })
        ));
    }
    let candidate = AuthorityToken {
        expires_at_ns: 2_001,
        ..token.clone()
    };
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &candidate, window),
        Err(MembershipError::LeaseTooLong { max_ns: 2_000, .. })
    ));
    let candidate = AuthorityToken {
        expires_at_ns: 1_500,
        ..token.clone()
    };
    let equal = RenewalWindow {
        earliest_ns: 1_000,
        latest_ns: 1_200,
    };
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &candidate, equal),
        Err(MembershipError::AuthorityExpired { .. })
    ));
    assert!(
        membership
            .validate_configured_renewal(
                &session,
                &token,
                &candidate,
                RenewalWindow {
                    latest_ns: 1_199,
                    ..equal
                }
            )
            .is_ok()
    );
}

#[test]
fn renewal_requires_configured_discovered_canonical_identity() {
    let (membership, session, token, window) = fixture();
    let candidate = AuthorityToken {
        expires_at_ns: 1_500,
        ..token.clone()
    };
    let mut wrong_group = candidate.clone();
    wrong_group.group_id = "other".into();
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &wrong_group, window),
        Err(MembershipError::WrongGroup)
    ));
    let mut wrong_issuer = candidate.clone();
    wrong_issuer.issuer_id = "other".into();
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &wrong_issuer, window),
        Err(MembershipError::NotConfiguredIssuer)
    ));
    let mut stale = candidate.clone();
    stale.epoch -= 1;
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &stale, window),
        Err(MembershipError::StaleAuthority { .. })
    ));
    let mut future = candidate.clone();
    future.epoch += 1;
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &future, window),
        Err(MembershipError::FutureAuthority { .. })
    ));
    assert!(matches!(
        membership.validate_configured_renewal(&session, &wrong_issuer, &candidate, window),
        Err(MembershipError::NotConfiguredIssuer)
    ));
    let config = MembershipConfig {
        epoch_mint: EpochMint::Quorum,
        ..MembershipConfig::default()
    };
    let quorum = GroupMembership::new(config);
    assert!(matches!(
        quorum.validate_configured_renewal(&session, &token, &candidate, window),
        Err(MembershipError::QuorumRequired)
    ));
    let mut restored = GroupMembership::after_restart(MembershipConfig::default());
    assert!(matches!(
        restored.validate_configured_renewal(&session, &token, &candidate, window),
        Err(MembershipError::AuthorityNotDiscovered)
    ));
    restored
        .discover_authority(&session, &token, window.latest_ns)
        .unwrap();
    assert!(
        restored
            .validate_configured_renewal(&session, &token, &candidate, window)
            .is_ok()
    );
}

#[test]
fn renewal_rejects_reversed_and_overflowing_windows() {
    let (membership, session, token, window) = fixture();
    let candidate = AuthorityToken {
        expires_at_ns: 1_500,
        ..token.clone()
    };
    let reversed = RenewalWindow {
        earliest_ns: window.latest_ns + 1,
        latest_ns: window.latest_ns,
    };
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &candidate, reversed),
        Err(MembershipError::InvalidRenewalWindow)
    ));
    let membership = GroupMembership::new(MembershipConfig {
        lease: LeaseTerms {
            max_lease_ns: 100,
            clock_uncertainty_ns: 0,
            ..LeaseTerms::default()
        },
        ..MembershipConfig::default()
    });
    let token = AuthorityToken::issue(&session, u64::MAX - 1);
    let candidate = AuthorityToken {
        expires_at_ns: u64::MAX,
        ..token.clone()
    };
    let overflow = RenewalWindow {
        earliest_ns: u64::MAX - 50,
        latest_ns: u64::MAX - 50,
    };
    assert!(matches!(
        membership.validate_configured_renewal(&session, &token, &candidate, overflow),
        Err(MembershipError::InvalidRenewalWindow)
    ));
}
