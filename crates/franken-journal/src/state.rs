//! The state a journal holds and the operations that change it. Applying an operation validates it completely; a
//! transaction is applied to a copy, so it is all or nothing.

use crate::{JournalError, Limits};
use std::collections::BTreeMap;

/// The five namespaces. They share one log but nothing else: each has its own bounds and its own reset (or none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Namespace {
    Settings,
    Credentials,
    Calibration,
    Records,
    Marks,
}

impl Namespace {
    pub const ORDER: [Self; 5] = [
        Self::Settings,
        Self::Credentials,
        Self::Calibration,
        Self::Records,
        Self::Marks,
    ];

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Settings => 1,
            Self::Credentials => 2,
            Self::Calibration => 3,
            Self::Records => 4,
            Self::Marks => 5,
        }
    }

    #[must_use]
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Settings),
            2 => Some(Self::Credentials),
            3 => Some(Self::Calibration),
            4 => Some(Self::Records),
            5 => Some(Self::Marks),
            _ => None,
        }
    }

    /// Settings, calibration and records are plain keyed blobs; credentials and marks have their own rules.
    #[must_use]
    pub const fn is_blob(self) -> bool {
        matches!(self, Self::Settings | Self::Calibration | Self::Records)
    }
}

/// An identity is live at a version, or revoked with a tombstone at the version it had. A tombstone keeps its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    Live { version: u64, secret: Vec<u8> },
    Revoked { version: u64 },
}

impl Credential {
    #[must_use]
    pub const fn version(&self) -> u64 {
        match self {
            Self::Live { version, .. } | Self::Revoked { version } => *version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Put {
        ns: Namespace,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        ns: Namespace,
        key: Vec<u8>,
    },
    Reset {
        ns: Namespace,
    },
    Install {
        id: Vec<u8>,
        version: u64,
        secret: Vec<u8>,
    },
    Revoke {
        id: Vec<u8>,
    },
    ResetPairing,
    Raise {
        key: Vec<u8>,
        value: u64,
    },
    /// Snapshot encoding of a tombstone; never valid in a transaction.
    Tomb {
        id: Vec<u8>,
        version: u64,
    },
}

type Blobs = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub settings: Blobs,
    pub credentials: BTreeMap<Vec<u8>, Credential>,
    pub calibration: Blobs,
    pub records: Blobs,
    pub marks: BTreeMap<Vec<u8>, u64>,
}

impl State {
    fn blob_mut(&mut self, ns: Namespace) -> Option<&mut Blobs> {
        match ns {
            Namespace::Settings => Some(&mut self.settings),
            Namespace::Calibration => Some(&mut self.calibration),
            Namespace::Records => Some(&mut self.records),
            Namespace::Credentials | Namespace::Marks => None,
        }
    }

    /// The canonical operation list: namespaces in [`Namespace::ORDER`], keys ascending as bytes.
    #[must_use]
    pub fn canonical_ops(&self) -> Vec<Op> {
        let mut ops = Vec::new();
        for (key, value) in &self.settings {
            ops.push(Op::Put {
                ns: Namespace::Settings,
                key: key.clone(),
                value: value.clone(),
            });
        }
        for (id, cred) in &self.credentials {
            ops.push(match cred {
                Credential::Live { version, secret } => Op::Install {
                    id: id.clone(),
                    version: *version,
                    secret: secret.clone(),
                },
                Credential::Revoked { version } => Op::Tomb {
                    id: id.clone(),
                    version: *version,
                },
            });
        }
        for (key, value) in &self.calibration {
            ops.push(Op::Put {
                ns: Namespace::Calibration,
                key: key.clone(),
                value: value.clone(),
            });
        }
        for (key, value) in &self.records {
            ops.push(Op::Put {
                ns: Namespace::Records,
                key: key.clone(),
                value: value.clone(),
            });
        }
        for (key, value) in &self.marks {
            ops.push(Op::Raise {
                key: key.clone(),
                value: *value,
            });
        }
        ops
    }

    /// The snapshot payload of this state: what a compaction writes and what the oracle compares.
    ///
    /// # Errors
    /// Only if the state is larger than any limits allow.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JournalError> {
        crate::codec::encode_ops(&self.canonical_ops())
    }
}

pub(crate) fn check_key(lim: &Limits, ns: Namespace, key: &[u8]) -> Result<(), JournalError> {
    if key.is_empty() || key.len() > lim.ns(ns).key_max {
        return Err(JournalError::InvalidKey);
    }
    Ok(())
}

pub(crate) fn check_value(lim: &Limits, ns: Namespace, value: &[u8]) -> Result<(), JournalError> {
    if value.len() > lim.ns(ns).value_max {
        return Err(JournalError::ValueTooLong);
    }
    Ok(())
}

/// Apply one operation to `state` in place, or say why not. The caller applies a transaction to a copy.
///
/// # Errors
/// The first rule the operation breaks; the error names the rule and never the key or value.
pub fn apply_op(
    lim: &Limits,
    state: &mut State,
    op: &Op,
    snapshot: bool,
) -> Result<(), JournalError> {
    match op {
        Op::Put { ns, key, value } => {
            if !ns.is_blob() {
                return Err(JournalError::BadOp);
            }
            check_key(lim, *ns, key)?;
            check_value(lim, *ns, value)?;
            let entries = lim.ns(*ns).entries;
            let map = state.blob_mut(*ns).ok_or(JournalError::BadOp)?;
            if !map.contains_key(key) && map.len() >= entries {
                return Err(JournalError::NamespaceFull);
            }
            map.insert(key.clone(), value.clone());
        }
        Op::Delete { ns, key } => {
            if !ns.is_blob() {
                return Err(JournalError::BadOp);
            }
            check_key(lim, *ns, key)?;
            let map = state.blob_mut(*ns).ok_or(JournalError::BadOp)?;
            if map.remove(key).is_none() {
                return Err(JournalError::NotFound);
            }
        }
        Op::Reset { ns } => {
            if !ns.is_blob() {
                return Err(JournalError::BadOp);
            }
            state.blob_mut(*ns).ok_or(JournalError::BadOp)?.clear();
        }
        Op::Install {
            id,
            version,
            secret,
        } => {
            check_key(lim, Namespace::Credentials, id)?;
            check_value(lim, Namespace::Credentials, secret)?;
            if *version == 0 {
                return Err(JournalError::BadVersion);
            }
            match state.credentials.get(id) {
                Some(current) if *version <= current.version() => {
                    return Err(match current {
                        Credential::Revoked { version: tombstone } => JournalError::Revoked {
                            tombstone: *tombstone,
                        },
                        Credential::Live { version: live, .. } => {
                            JournalError::NotNewer { current: *live }
                        }
                    });
                }
                None if state.credentials.len() >= lim.credentials.entries => {
                    return Err(JournalError::NamespaceFull);
                }
                _ => {}
            }
            state.credentials.insert(
                id.clone(),
                Credential::Live {
                    version: *version,
                    secret: secret.clone(),
                },
            );
        }
        Op::Revoke { id } => {
            check_key(lim, Namespace::Credentials, id)?;
            let current = state
                .credentials
                .get_mut(id)
                .ok_or(JournalError::NotFound)?;
            let version = match current {
                Credential::Revoked { .. } => return Err(JournalError::AlreadyRevoked),
                Credential::Live { version, .. } => *version,
            };
            *current = Credential::Revoked { version };
        }
        Op::ResetPairing => {
            for current in state.credentials.values_mut() {
                let live_version = match current {
                    Credential::Live { version, .. } => Some(*version),
                    Credential::Revoked { .. } => None,
                };
                if let Some(version) = live_version {
                    *current = Credential::Revoked { version };
                }
            }
        }
        Op::Raise { key, value } => {
            check_key(lim, Namespace::Marks, key)?;
            match state.marks.get(key) {
                Some(&current) if *value < current => {
                    return Err(JournalError::MarkRegressed { current });
                }
                None if state.marks.len() >= lim.marks.entries => {
                    return Err(JournalError::NamespaceFull);
                }
                _ => {}
            }
            state.marks.insert(key.clone(), *value);
        }
        Op::Tomb { id, version } => {
            if !snapshot {
                return Err(JournalError::BadOp);
            }
            check_key(lim, Namespace::Credentials, id)?;
            if state.credentials.contains_key(id)
                || state.credentials.len() >= lim.credentials.entries
            {
                return Err(JournalError::BadOp);
            }
            state
                .credentials
                .insert(id.clone(), Credential::Revoked { version: *version });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::tiny()
    }

    #[test]
    fn a_revoked_identity_returns_only_at_a_strictly_higher_version() {
        let mut s = State::default();
        let install = |v: u64| Op::Install {
            id: b"a".to_vec(),
            version: v,
            secret: b"s".to_vec(),
        };
        apply_op(&lim(), &mut s, &install(2), false).unwrap();
        apply_op(&lim(), &mut s, &Op::Revoke { id: b"a".to_vec() }, false).unwrap();
        assert_eq!(
            apply_op(&lim(), &mut s, &install(2), false),
            Err(JournalError::Revoked { tombstone: 2 })
        );
        assert_eq!(
            apply_op(&lim(), &mut s, &install(1), false),
            Err(JournalError::Revoked { tombstone: 2 })
        );
        apply_op(&lim(), &mut s, &install(3), false).unwrap();
        assert!(matches!(
            s.credentials[b"a".as_slice()],
            Credential::Live { version: 3, .. }
        ));
    }

    #[test]
    fn a_tombstone_keeps_its_slot_and_a_pairing_reset_leaves_one_per_identity() {
        let mut s = State::default();
        for id in [b"a", b"b", b"c"] {
            apply_op(
                &lim(),
                &mut s,
                &Op::Install {
                    id: id.to_vec(),
                    version: 1,
                    secret: b"s".to_vec(),
                },
                false,
            )
            .unwrap();
        }
        apply_op(&lim(), &mut s, &Op::ResetPairing, false).unwrap();
        assert!(
            s.credentials
                .values()
                .all(|c| matches!(c, Credential::Revoked { version: 1 }))
        );
        let fourth = Op::Install {
            id: b"d".to_vec(),
            version: 1,
            secret: b"s".to_vec(),
        };
        assert_eq!(
            apply_op(&lim(), &mut s, &fourth, false),
            Err(JournalError::NamespaceFull)
        );
    }

    #[test]
    fn a_mark_never_goes_down_and_an_equal_value_is_fine() {
        let mut s = State::default();
        let raise = |v: u64| Op::Raise {
            key: b"epoch".to_vec(),
            value: v,
        };
        apply_op(&lim(), &mut s, &raise(5), false).unwrap();
        apply_op(&lim(), &mut s, &raise(5), false).unwrap();
        assert_eq!(
            apply_op(&lim(), &mut s, &raise(4), false),
            Err(JournalError::MarkRegressed { current: 5 })
        );
    }

    #[test]
    fn a_tombstone_operation_is_only_valid_inside_a_snapshot() {
        let mut s = State::default();
        let tomb = Op::Tomb {
            id: b"a".to_vec(),
            version: 1,
        };
        assert_eq!(
            apply_op(&lim(), &mut s, &tomb, false),
            Err(JournalError::BadOp)
        );
        apply_op(&lim(), &mut s, &tomb, true).unwrap();
    }

    #[test]
    fn errors_name_the_rule_and_never_the_key_or_the_value() {
        let mut s = State::default();
        let secret_key = b"PEERKEY".to_vec();
        let err = apply_op(
            &lim(),
            &mut s,
            &Op::Revoke {
                id: secret_key.clone(),
            },
            false,
        )
        .unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(!text.contains("PEERKEY"));
        let err = apply_op(
            &lim(),
            &mut s,
            &Op::Install {
                id: secret_key,
                version: 1,
                secret: vec![7; 40],
            },
            false,
        )
        .unwrap_err();
        assert_eq!(err, JournalError::ValueTooLong);
    }
}
