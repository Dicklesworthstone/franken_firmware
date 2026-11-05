//! Typed secret-store contract (P01 / `ffw-h3g`).
//!
//! Adapters keep long-lived credentials (a Spotify refresh token, an `AirPlay` pairing key, a tailnet
//! auth key, a stream-authentication key) behind this interface, never in their own fields. The
//! contract is about what a credential can and cannot do once it is in the store.
//!
//! A secret is addressed by a [`SecretHandle`]: a closed [`SecretKind`] plus a validated [`SlotName`].
//! A handle is a label, not a secret, so it may be printed, logged and kept in a session record. The
//! value itself is a [`SecretValue`], which has no `Debug`, `Display`, `Clone`, `PartialEq` or
//! `Serialize` implementation; the only way to read it is the explicitly named
//! [`SecretValue::expose`] or [`SecretStore::with_secret`]. No error type in this module carries a
//! value, so a failure cannot leak one through a log line.
//!
//! Replacement is compare-and-swap on a [`Generation`]: a caller that read generation 3 and replaces
//! with `expected = 3` succeeds and produces generation 4; a caller holding a stale generation gets a
//! typed [`SecretError::StaleGeneration`] and the stored secret is left untouched. A failed operation
//! never modifies the store.
//!
//! Zeroing is best effort. The workspace forbids `unsafe` and the `zeroize` crate is not a dependency,
//! so a dropped, replaced or removed value is overwritten with zeros and the buffer is passed through
//! [`std::hint::black_box`]. That discourages the optimizer from deleting the stores, but it is not a
//! guarantee, and copies the allocator or the caller made earlier are not reached.
//!
//! The in-memory implementation, [`EphemeralSecretStore`], exists for tests only. It never persists.

#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;

/// Longest secret value, in bytes.
pub const MAX_SECRET_LEN: usize = 4096;
/// Longest slot name, in bytes.
pub const MAX_SLOT_LEN: usize = 32;
/// Most entries a store may hold; a store refuses further inserts instead of growing.
pub const MAX_SECRETS: usize = 32;

/// What a secret is for. Closed on purpose: a new kind is a reviewed change, not a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretKind {
    SpotifyRefreshToken,
    AirPlayPairingKey,
    TailnetAuthKey,
    AlexaLinkToken,
    StreamAuthKey,
    /// A paired control peer's authentication key (N02, the control channel).
    ControlPeerKey,
}

impl SecretKind {
    /// Stable lowercase label, safe to log.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SpotifyRefreshToken => "spotify-refresh-token",
            Self::AirPlayPairingKey => "airplay-pairing-key",
            Self::TailnetAuthKey => "tailnet-auth-key",
            Self::AlexaLinkToken => "alexa-link-token",
            Self::StreamAuthKey => "stream-auth-key",
            Self::ControlPeerKey => "control-peer-key",
        }
    }
}

/// A validated slot label: one to [`MAX_SLOT_LEN`] bytes of `a-z`, `0-9`, `.`, `_` and `-`, starting
/// with a letter or digit. It names a place in the store; it is never an account identifier or a
/// token, and the restricted alphabet (no `@`, no spaces, no uppercase) makes the common mistakes
/// (an e-mail address, a pasted token) fail to parse. It is a guard against slips, not a proof.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotName(String);

impl SlotName {
    /// Validate and wrap a slot label.
    pub fn parse(raw: &str) -> Result<Self, SecretError> {
        if raw.is_empty() {
            return Err(SecretError::InvalidSlot { reason: "empty" });
        }
        if raw.len() > MAX_SLOT_LEN {
            return Err(SecretError::InvalidSlot {
                reason: "longer than the slot limit",
            });
        }
        let starts_ok = raw
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if !starts_ok {
            return Err(SecretError::InvalidSlot {
                reason: "must start with a lowercase letter or a digit",
            });
        }
        let alphabet_ok = raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
        if !alphabet_ok {
            return Err(SecretError::InvalidSlot {
                reason: "only a-z, 0-9, '.', '_' and '-' are allowed",
            });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The address of one secret. Not itself secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretHandle {
    kind: SecretKind,
    slot: SlotName,
}

impl SecretHandle {
    /// Build a handle from a kind and a raw slot label.
    pub fn new(kind: SecretKind, slot: &str) -> Result<Self, SecretError> {
        Ok(Self {
            kind,
            slot: SlotName::parse(slot)?,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn slot(&self) -> &SlotName {
        &self.slot
    }
}

impl fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind.label(), self.slot.0)
    }
}

/// Version of the value stored under a handle. The first insert is generation 1 and every
/// replacement adds one, so a generation names exactly one value over the life of the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    /// The generation of a freshly inserted secret.
    pub const FIRST: Self = Self(1);

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The generation a replacement produces, or `None` if the counter is exhausted. A store
    /// implementation must refuse the replacement (`GenerationExhausted`) rather than wrap or saturate,
    /// because a generation must name exactly one value.
    #[must_use]
    pub fn successor(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// Overwrite a buffer with zeros and discourage the optimizer from eliding the stores. Best effort;
/// see the module documentation.
pub(crate) fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(&*buf);
}

/// A secret value. Deliberately has no `Debug`, `Display`, `Clone`, `PartialEq`, `Serialize` or
/// `Deserialize`: nothing can print it, copy it, compare it with `==` or write it out by accident.
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    /// Take ownership of `bytes` (no extra copy is made). Empty and over-long values are refused, and
    /// the refused buffer is wiped before it is dropped.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            return Err(SecretError::EmptyValue);
        }
        if bytes.len() > MAX_SECRET_LEN {
            let len = bytes.len();
            wipe(&mut bytes);
            return Err(SecretError::ValueTooLong {
                len,
                max: MAX_SECRET_LEN,
            });
        }
        Ok(Self { bytes })
    }

    /// Length in bytes. Never zero.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// The raw bytes. The name is the point: every use of a secret value is visible to a reader.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Compare against a candidate without stopping at the first differing byte. This avoids the
    /// obvious early exit; it makes no stronger timing promise than that.
    #[must_use]
    pub fn matches(&self, candidate: &[u8]) -> bool {
        let mine = &self.bytes;
        let longest = mine.len().max(candidate.len());
        let mut diff = mine.len() ^ candidate.len();
        for i in 0..longest {
            let a = mine.get(i).copied().unwrap_or(0);
            let b = candidate.get(i).copied().unwrap_or(0);
            diff |= usize::from(a ^ b);
        }
        std::hint::black_box(diff) == 0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

/// What the store knows about an entry without revealing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub handle: SecretHandle,
    pub generation: Generation,
    pub byte_len: usize,
}

/// Why a secret-store operation failed. No variant carries a secret value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    #[error("invalid secret slot name: {reason}")]
    InvalidSlot { reason: &'static str },
    #[error("a secret value must not be empty")]
    EmptyValue,
    #[error("a secret value of {len} bytes is over the {max}-byte limit")]
    ValueTooLong { len: usize, max: usize },
    #[error("no secret is stored under `{handle}`")]
    NotFound { handle: SecretHandle },
    #[error("a secret is already stored under `{handle}`; replace it with its current generation")]
    AlreadyExists { handle: SecretHandle },
    #[error(
        "stale replacement for `{handle}`: expected generation {expected} but the store holds {actual}"
    )]
    StaleGeneration {
        handle: SecretHandle,
        expected: u64,
        actual: u64,
    },
    #[error("the secret store is full ({max} entries)")]
    StoreFull { max: usize },
    #[error("the generation counter for `{handle}` is exhausted")]
    GenerationExhausted { handle: SecretHandle },
}

/// The explicit storage interface for credentials. Implementations decide where bytes live
/// (memory, a sealed file); the semantics below are the contract.
pub trait SecretStore {
    /// Store a new secret as generation 1. Fails with `AlreadyExists` if the handle is taken, and
    /// with `StoreFull` at the bound. A failure leaves the store unchanged.
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError>;

    /// Replace the secret only if it is still at `expected`. Returns the new generation. Stale
    /// generations, missing handles and an exhausted counter leave the stored secret untouched.
    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError>;

    /// Revoke a secret. The value is wiped.
    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError>;

    /// The current generation, without exposing the value.
    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError>;

    /// Run `f` with the current generation and the secret bytes. The bytes are borrowed for the
    /// call only, so a caller cannot keep them without copying them on purpose.
    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError>;

    /// Every entry's handle, generation and length, in handle order. Never a value.
    fn list(&self) -> Vec<SecretMeta>;
}

/// In-memory store for tests. Volatile by construction: nothing is ever written anywhere.
#[cfg(test)]
pub struct EphemeralSecretStore {
    entries: BTreeMap<SecretHandle, Entry>,
    capacity: usize,
}

#[cfg(test)]
struct Entry {
    generation: Generation,
    value: SecretValue,
}

#[cfg(test)]
impl EphemeralSecretStore {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: capacity.min(MAX_SECRETS),
        }
    }
}

/// Shows how many entries exist and nothing about them.
#[cfg(test)]
impl fmt::Debug for EphemeralSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralSecretStore")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
impl SecretStore for EphemeralSecretStore {
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError> {
        if self.entries.contains_key(handle) {
            return Err(SecretError::AlreadyExists {
                handle: handle.clone(),
            });
        }
        if self.entries.len() >= self.capacity {
            return Err(SecretError::StoreFull { max: self.capacity });
        }
        self.entries.insert(
            handle.clone(),
            Entry {
                generation: Generation::FIRST,
                value,
            },
        );
        Ok(Generation::FIRST)
    }

    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let entry = self
            .entries
            .get_mut(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        if entry.generation != expected {
            return Err(SecretError::StaleGeneration {
                handle: handle.clone(),
                expected: expected.get(),
                actual: entry.generation.get(),
            });
        }
        let next =
            entry
                .generation
                .successor()
                .ok_or_else(|| SecretError::GenerationExhausted {
                    handle: handle.clone(),
                })?;
        // The old value is dropped here, and `Drop` wipes it.
        entry.value = value;
        entry.generation = next;
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        match self.entries.remove(handle) {
            Some(_) => Ok(()),
            None => Err(SecretError::NotFound {
                handle: handle.clone(),
            }),
        }
    }

    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError> {
        self.entries
            .get(handle)
            .map(|entry| entry.generation)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        let entry = self
            .entries
            .get(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        Ok(f(entry.generation, entry.value.expose()))
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.entries
            .iter()
            .map(|(handle, entry)| SecretMeta {
                handle: handle.clone(),
                generation: entry.generation,
                byte_len: entry.value.byte_len(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A compile-time check that `$ty` implements none of the listed traits: if it implemented one,
    /// the call below would be ambiguous and the crate's tests would not build. This is the technique
    /// the `static_assertions` crate uses, written out because it is not a dependency.
    macro_rules! assert_not_impl_any {
        ($ty:ty: $($tr:path),+ $(,)?) => {
            const _: fn() = || {
                trait AmbiguousIfImpl<A> {
                    fn some_item() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                $({
                    #[allow(dead_code)]
                    struct Invalid;
                    impl<T: ?Sized + $tr> AmbiguousIfImpl<Invalid> for T {}
                })+
                let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
            };
        };
    }

    assert_not_impl_any!(
        SecretValue: std::fmt::Debug,
        std::fmt::Display,
        Clone,
        PartialEq,
        serde::Serialize,
        serde::de::DeserializeOwned
    );

    /// The positive control: the handle, which is not secret, does have the traits the value lacks,
    /// so the assertion above is not vacuous.
    fn handle_is_printable_and_copyable<T: std::fmt::Debug + std::fmt::Display + Clone + Eq>() {}

    const MARKER: &str = "tok-SECRET-9f3a";

    fn handle(kind: SecretKind, slot: &str) -> SecretHandle {
        SecretHandle::new(kind, slot).unwrap()
    }

    fn value(bytes: &[u8]) -> SecretValue {
        SecretValue::new(bytes.to_vec()).unwrap()
    }

    fn read(store: &EphemeralSecretStore, h: &SecretHandle) -> (Generation, Vec<u8>) {
        store.with_secret(h, |g, b| (g, b.to_vec())).unwrap()
    }

    #[test]
    fn the_handle_has_the_traits_the_value_deliberately_lacks() {
        handle_is_printable_and_copyable::<SecretHandle>();
    }

    #[test]
    fn insert_read_replace_remove_lifecycle() {
        let mut store = EphemeralSecretStore::with_capacity(4);
        let h = handle(SecretKind::SpotifyRefreshToken, "main");

        assert_eq!(
            store.insert(&h, value(b"first")).unwrap(),
            Generation::FIRST
        );
        assert_eq!(read(&store, &h), (Generation::FIRST, b"first".to_vec()));

        let g2 = store
            .replace(&h, value(b"second"), Generation::FIRST)
            .unwrap();
        assert_eq!(g2.get(), 2);
        assert_eq!(read(&store, &h), (g2, b"second".to_vec()));
        assert_eq!(store.generation(&h).unwrap(), g2);

        store.remove(&h).unwrap();
        assert_eq!(
            store.generation(&h).unwrap_err(),
            SecretError::NotFound { handle: h.clone() }
        );
        assert!(store.list().is_empty());
    }

    #[test]
    fn list_reports_handles_generations_and_lengths_but_never_values() {
        let mut store = EphemeralSecretStore::with_capacity(4);
        let a = handle(SecretKind::TailnetAuthKey, "node-a");
        let b = handle(SecretKind::AirPlayPairingKey, "den");
        store.insert(&a, value(MARKER.as_bytes())).unwrap();
        store.insert(&b, value(b"pair")).unwrap();
        let listed = store.list();
        assert_eq!(listed.len(), 2);
        let lens: Vec<usize> = listed.iter().map(|m| m.byte_len).collect();
        assert!(lens.contains(&MARKER.len()) && lens.contains(&4));
        assert!(!format!("{listed:?}").contains(MARKER));
    }

    #[test]
    fn a_second_insert_under_the_same_handle_is_refused_and_changes_nothing() {
        let mut store = EphemeralSecretStore::with_capacity(4);
        let h = handle(SecretKind::AlexaLinkToken, "household");
        store.insert(&h, value(b"original")).unwrap();
        let err = store.insert(&h, value(b"intruder")).unwrap_err();
        assert_eq!(err, SecretError::AlreadyExists { handle: h.clone() });
        assert_eq!(read(&store, &h), (Generation::FIRST, b"original".to_vec()));
    }

    #[test]
    fn a_stale_replacement_is_refused_and_the_stored_secret_survives() {
        let mut store = EphemeralSecretStore::with_capacity(4);
        let h = handle(SecretKind::SpotifyRefreshToken, "main");
        store.insert(&h, value(b"v1")).unwrap();
        let g2 = store.replace(&h, value(b"v2"), Generation::FIRST).unwrap();

        // A second writer that still believes generation 1 is current.
        let err = store
            .replace(&h, value(b"late-writer"), Generation::FIRST)
            .unwrap_err();
        assert_eq!(
            err,
            SecretError::StaleGeneration {
                handle: h.clone(),
                expected: 1,
                actual: 2
            }
        );
        assert_eq!(read(&store, &h), (g2, b"v2".to_vec()));
        // The correct generation still works afterwards.
        assert_eq!(store.replace(&h, value(b"v3"), g2).unwrap().get(), 3);
    }

    #[test]
    fn replacing_or_removing_a_missing_handle_is_not_found() {
        let mut store = EphemeralSecretStore::with_capacity(4);
        let h = handle(SecretKind::StreamAuthKey, "g1");
        assert_eq!(
            store
                .replace(&h, value(b"x"), Generation::FIRST)
                .unwrap_err(),
            SecretError::NotFound { handle: h.clone() }
        );
        assert_eq!(
            store.remove(&h).unwrap_err(),
            SecretError::NotFound { handle: h.clone() }
        );
    }

    #[test]
    fn the_store_is_bounded_and_a_refused_insert_changes_nothing() {
        let mut store = EphemeralSecretStore::with_capacity(1);
        let a = handle(SecretKind::SpotifyRefreshToken, "a");
        let b = handle(SecretKind::SpotifyRefreshToken, "b");
        store.insert(&a, value(b"1")).unwrap();
        assert_eq!(
            store.insert(&b, value(b"2")).unwrap_err(),
            SecretError::StoreFull { max: 1 }
        );
        assert_eq!(store.list().len(), 1);
        // Removing frees the slot.
        store.remove(&a).unwrap();
        store.insert(&b, value(b"2")).unwrap();
    }

    #[test]
    fn capacity_cannot_exceed_the_contract_bound() {
        let mut store = EphemeralSecretStore::with_capacity(MAX_SECRETS + 100);
        for i in 0..MAX_SECRETS {
            let h = handle(SecretKind::StreamAuthKey, &format!("slot-{i}"));
            store.insert(&h, value(b"k")).unwrap();
        }
        let extra = handle(SecretKind::StreamAuthKey, "one-too-many");
        assert_eq!(
            store.insert(&extra, value(b"k")).unwrap_err(),
            SecretError::StoreFull { max: MAX_SECRETS }
        );
    }

    #[test]
    fn an_exhausted_generation_counter_is_refused_and_the_value_survives() {
        let mut store = EphemeralSecretStore::with_capacity(2);
        let h = handle(SecretKind::TailnetAuthKey, "n");
        store.insert(&h, value(b"old")).unwrap();
        store.entries.get_mut(&h).unwrap().generation = Generation(u64::MAX);
        let err = store
            .replace(&h, value(b"new"), Generation(u64::MAX))
            .unwrap_err();
        assert_eq!(err, SecretError::GenerationExhausted { handle: h.clone() });
        assert_eq!(read(&store, &h), (Generation(u64::MAX), b"old".to_vec()));
    }

    #[test]
    fn values_are_validated_and_a_refused_value_is_an_error() {
        assert!(matches!(
            SecretValue::new(Vec::new()),
            Err(SecretError::EmptyValue)
        ));
        let too_long = vec![0x41; MAX_SECRET_LEN + 1];
        assert!(matches!(
            SecretValue::new(too_long),
            Err(SecretError::ValueTooLong { len, max })
                if len == MAX_SECRET_LEN + 1 && max == MAX_SECRET_LEN
        ));
        // The boundary itself is accepted.
        assert_eq!(
            SecretValue::new(vec![1; MAX_SECRET_LEN])
                .unwrap()
                .byte_len(),
            MAX_SECRET_LEN
        );
    }

    #[test]
    fn slot_names_reject_the_common_mistakes() {
        let ok = [
            "main",
            "node-a",
            "a.b_c-d",
            "0",
            "x".repeat(MAX_SLOT_LEN).as_str(),
        ]
        .map(|s| SlotName::parse(s).is_ok());
        assert_eq!(ok, [true; 5]);

        let long = "x".repeat(MAX_SLOT_LEN + 1);
        let bad = [
            "",
            "Main",
            "has space",
            "user@example.com",
            "-leading-dash",
            ".leading-dot",
            "slash/inside",
            "tok-SECRET-9f3a",
            "caf\u{e9}",
            long.as_str(),
        ];
        for raw in bad {
            assert!(
                matches!(SlotName::parse(raw), Err(SecretError::InvalidSlot { .. })),
                "{raw:?} must be refused"
            );
        }
    }

    #[test]
    fn matches_compares_content_and_length() {
        let v = value(b"s3cret");
        assert!(v.matches(b"s3cret"));
        assert!(!v.matches(b"s3creT"));
        assert!(!v.matches(b"s3cre"));
        assert!(!v.matches(b"s3cret!"));
        assert!(!v.matches(b""));
        // A zero byte past the end must not be mistaken for padding that matches.
        assert!(!value(b"ab").matches(b"ab\0"));
    }

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut buf = *b"tok-SECRET-9f3a";
        wipe(&mut buf);
        assert_eq!(buf, [0u8; 15]);
        let mut empty: [u8; 0] = [];
        wipe(&mut empty);
    }

    #[test]
    fn nothing_that_can_be_printed_contains_the_secret() {
        let mut store = EphemeralSecretStore::with_capacity(1);
        let h = handle(SecretKind::SpotifyRefreshToken, "main");
        store.insert(&h, value(MARKER.as_bytes())).unwrap();

        // Every error variant, each triggered with the marker as the value involved.
        let errors: Vec<SecretError> = vec![
            store.insert(&h, value(MARKER.as_bytes())).unwrap_err(),
            store
                .replace(&h, value(MARKER.as_bytes()), Generation(99))
                .unwrap_err(),
            store
                .insert(
                    &handle(SecretKind::TailnetAuthKey, "other"),
                    value(MARKER.as_bytes()),
                )
                .unwrap_err(),
            store
                .remove(&handle(SecretKind::AlexaLinkToken, "absent"))
                .unwrap_err(),
            SecretValue::new(Vec::new()).err().unwrap(),
            SecretValue::new(vec![0x41; MAX_SECRET_LEN + 1])
                .err()
                .unwrap(),
            SecretHandle::new(SecretKind::StreamAuthKey, MARKER).unwrap_err(),
        ];
        assert_eq!(errors.len(), 7);
        for err in &errors {
            for text in [format!("{err}"), format!("{err:?}")] {
                assert!(!text.contains(MARKER), "leaked through {text:?}");
            }
        }
        // The store, its listing and the handle print without the value.
        for text in [
            format!("{store:?}"),
            format!("{:?}", store.list()),
            format!("{h} {h:?}"),
        ] {
            assert!(!text.contains(MARKER), "leaked through {text:?}");
        }
        // And the value is still there for a caller that asks for it by name.
        assert!(
            store
                .with_secret(&h, |_, b| b == MARKER.as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn a_store_error_names_the_handle_label_and_nothing_else() {
        let h = handle(SecretKind::SpotifyRefreshToken, "main");
        let err = SecretError::NotFound { handle: h };
        assert_eq!(
            err.to_string(),
            "no secret is stored under `spotify-refresh-token/main`"
        );
    }
}
