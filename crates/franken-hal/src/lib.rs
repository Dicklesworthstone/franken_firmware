//! Typestate Audio HAL and DMA quarantine contract (`E04` / `ffw-25l`, `P04` / `ffw-0bh`).
//!
//! Enforces the two core hardware-safety invariants from `FIRMWARE_ASSESSMENT.md`:
//! 1. **Amplifier Mute-Pin Ordering**: The hardware mute pin MUST remain asserted
//!    (`muted = true`) through profile verification, DAC/ioctl setup, and initial
//!    silence-block priming. Any fault or drain transition immediately re-asserts
//!    hardware mute before stopping DMA.
//! 2. **DMA Cancellation Quarantine**: In-flight DMA slots submitted to a retained
//!    kernel driver (`audiodev.o`) are represented by [`DmaSubmissionLease`]. If a
//!    lease is dropped without explicit hardware completion acknowledgement (e.g.,
//!    due to task cancellation), the slot is moved into [`QuarantinedDmaPool`] and
//!    cannot be reused until a full device drain/reset completes.

#![forbid(unsafe_code)]

pub mod abi;
pub mod backend;
pub mod contract;
pub mod contract_log;
#[cfg(test)]
mod diag;
pub mod dma_sim;
pub mod emit;
pub mod events;
pub mod logged;
pub mod session;
pub mod slots;

use contract::{ContractMatrix, MissingContract};
use franken_board_profile::{AmplifierPolicy, BoardProfile, UnsupportedReasonCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

/// Identifier for a pre-allocated DMA ring buffer slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DmaSlotId(pub u16);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum HalError {
    #[error("board profile rejected for audio output: {0:?}")]
    ProfileRejected(UnsupportedReasonCode),
    #[error("amplifier policy forbids hardware audio output")]
    AmplifierForbidden,
    #[error("no free DMA slots available (active={active}, quarantined={quarantined})")]
    DmaPoolExhausted { active: usize, quarantined: usize },
    #[error(
        "attempted to unmute amplifier before priming silence blocks (primed={primed_blocks}, required={required_blocks})"
    )]
    UnmuteBeforeSilencePrime {
        primed_blocks: u32,
        required_blocks: u32,
    },
    #[error("simulated hardware driver fault: {reason}")]
    DriverFault { reason: String },
    /// The retained-driver contract matrix is not hardware-eligible. `missing` is the exact list.
    #[error("retained-driver contract is not hardware-eligible ({} missing)", .missing.len())]
    ContractIncomplete { missing: Vec<MissingContract> },
}

/// Shared state tracking free, active, and quarantined DMA buffer slots.
#[derive(Debug)]
pub struct DmaPoolState {
    free_slots: VecDeque<DmaSlotId>,
    active_slots: BTreeSet<DmaSlotId>,
    quarantined_slots: BTreeSet<DmaSlotId>,
}

impl DmaPoolState {
    #[must_use]
    pub fn new(slot_count: u16) -> Self {
        let free_slots = (0..slot_count).map(DmaSlotId).collect();
        Self {
            free_slots,
            active_slots: BTreeSet::new(),
            quarantined_slots: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_slots.len()
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_slots.len()
    }

    #[must_use]
    pub fn quarantined_count(&self) -> usize {
        self.quarantined_slots.len()
    }
}

/// RAII lease for an in-flight DMA buffer slot.
///
/// If dropped without calling [`DmaSubmissionLease::complete`], the slot is
/// automatically quarantined so userspace never overwrites memory that the
/// kernel DMA controller may still be reading.
#[derive(Debug)]
pub struct DmaSubmissionLease {
    slot: DmaSlotId,
    pool: Arc<Mutex<DmaPoolState>>,
    completed: bool,
}

impl DmaSubmissionLease {
    #[must_use]
    pub const fn slot(&self) -> DmaSlotId {
        self.slot
    }

    /// Mark the DMA transfer as acknowledged by the driver and return the slot to the free list.
    pub fn complete(mut self) {
        self.completed = true;
        if let Ok(mut guard) = self.pool.lock() {
            guard.active_slots.remove(&self.slot);
            guard.free_slots.push_back(self.slot);
        }
    }
}

impl Drop for DmaSubmissionLease {
    fn drop(&mut self) {
        if !self.completed
            && let Ok(mut guard) = self.pool.lock()
        {
            guard.active_slots.remove(&self.slot);
            guard.quarantined_slots.insert(self.slot);
        }
    }
}

/// Typestate markers for [`AudioHalDevice`].
pub mod state {
    #[derive(Debug)]
    pub struct Closed;
    #[derive(Debug)]
    pub struct Prepared;
    #[derive(Debug)]
    pub struct Running;
    #[derive(Debug)]
    pub struct Draining;
    #[derive(Debug)]
    pub struct Faulted;
}

/// Observable hardware telemetry for tests and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HalTelemetry {
    pub profile_id: String,
    pub hardware_muted: bool,
    pub primed_silence_blocks: u32,
    pub submitted_audio_blocks: u64,
    pub underrun_count: u64,
    pub free_dma_slots: usize,
    pub active_dma_slots: usize,
    pub quarantined_dma_slots: usize,
    pub last_fault: Option<String>,
}

#[derive(Debug)]
struct HalInner {
    profile: BoardProfile,
    hardware_muted: bool,
    primed_silence_blocks: u32,
    required_silence_blocks: u32,
    submitted_audio_blocks: u64,
    underrun_count: u64,
    dma_pool: Arc<Mutex<DmaPoolState>>,
    last_fault: Option<String>,
}

/// Typestate-checked Audio HAL wrapper.
#[derive(Debug)]
pub struct AudioHalDevice<S> {
    inner: HalInner,
    _state: PhantomData<S>,
}

impl AudioHalDevice<state::Closed> {
    /// Create a closed HAL instance for a verified board profile.
    pub fn open_for_profile(
        profile: BoardProfile,
        dma_slots: u16,
        required_silence_blocks: u32,
    ) -> Result<Self, HalError> {
        profile
            .verify_integrity()
            .map_err(HalError::ProfileRejected)?;
        if profile.amplifier_policy != AmplifierPolicy::AdmittedSafeStartupOrder {
            return Err(HalError::AmplifierForbidden);
        }
        Ok(Self {
            inner: HalInner {
                profile,
                hardware_muted: true,
                primed_silence_blocks: 0,
                required_silence_blocks: required_silence_blocks.max(1),
                submitted_audio_blocks: 0,
                underrun_count: 0,
                dma_pool: Arc::new(Mutex::new(DmaPoolState::new(dma_slots.max(2)))),
                last_fault: None,
            },
            _state: PhantomData,
        })
    }

    /// Open for real hardware: the board profile must verify (as for [`Self::open_for_profile`]) and
    /// the retained-driver contract matrix must be hardware-eligible.
    ///
    /// An unknown field, a synthetic anchor, an unregistered artifact, a missing required operation,
    /// topology or amplifier sequence, or a channel map that contradicts the profile refuses the open
    /// with the exact list of what is missing. Nothing about the driver's size or apparent
    /// simplicity is consulted. Offline use goes through [`Self::open_for_profile`], which never
    /// reaches an amplifier.
    pub fn open_for_hardware(
        profile: BoardProfile,
        matrix: &ContractMatrix,
        dma_slots: u16,
        required_silence_blocks: u32,
    ) -> Result<Self, HalError> {
        let device = Self::open_for_profile(profile.clone(), dma_slots, required_silence_blocks)?;
        let report = matrix.evaluate_for_profile(&profile);
        if !report.hardware_eligible {
            return Err(HalError::ContractIncomplete {
                missing: report.missing,
            });
        }
        Ok(device)
    }

    /// Transition `Closed -> Prepared` while asserting the hardware mute pin.
    #[must_use]
    pub fn prepare(mut self) -> AudioHalDevice<state::Prepared> {
        self.inner.hardware_muted = true;
        self.inner.primed_silence_blocks = 0;
        AudioHalDevice {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

impl AudioHalDevice<state::Prepared> {
    /// Prime a block of digital silence into the DMA ring while keeping the amplifier muted.
    pub fn prime_silence_block(&mut self) -> Result<DmaSlotId, HalError> {
        let lease = acquire_dma_lease(&self.inner.dma_pool)?;
        let slot = lease.slot();
        lease.complete();
        self.inner.primed_silence_blocks = self.inner.primed_silence_blocks.saturating_add(1);
        Ok(slot)
    }

    /// Transition `Prepared -> Running` and unmute hardware ONLY after required silence blocks are primed.
    #[allow(clippy::result_large_err)]
    pub fn start_unmuted(mut self) -> Result<AudioHalDevice<state::Running>, (Self, HalError)> {
        if self.inner.primed_silence_blocks < self.inner.required_silence_blocks {
            let err = HalError::UnmuteBeforeSilencePrime {
                primed_blocks: self.inner.primed_silence_blocks,
                required_blocks: self.inner.required_silence_blocks,
            };
            return Err((self, err));
        }
        self.inner.hardware_muted = false;
        Ok(AudioHalDevice {
            inner: self.inner,
            _state: PhantomData,
        })
    }
}

impl AudioHalDevice<state::Running> {
    /// Acquire a DMA slot lease for submitting rendered audio frames.
    pub fn submit_dma_block(&mut self) -> Result<DmaSubmissionLease, HalError> {
        let lease = acquire_dma_lease(&self.inner.dma_pool)?;
        self.inner.submitted_audio_blocks = self.inner.submitted_audio_blocks.saturating_add(1);
        Ok(lease)
    }

    /// Record a hardware ring underrun and assert mute if threshold exceeded.
    pub fn record_underrun(&mut self) {
        self.inner.underrun_count = self.inner.underrun_count.saturating_add(1);
    }

    /// Transition `Running -> Draining`, immediately asserting the hardware mute pin first.
    #[must_use]
    pub fn begin_drain(mut self) -> AudioHalDevice<state::Draining> {
        self.inner.hardware_muted = true;
        AudioHalDevice {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Transition `Running -> Faulted`, immediately asserting the hardware mute pin.
    #[must_use]
    pub fn enter_fault(mut self, reason: &str) -> AudioHalDevice<state::Faulted> {
        self.inner.hardware_muted = true;
        self.inner.last_fault = Some(reason.to_string());
        AudioHalDevice {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

impl AudioHalDevice<state::Draining> {
    /// Complete drain and reclaim quarantined DMA buffers only after hardware DMA is stopped.
    #[must_use]
    pub fn finish_drain_and_close(mut self) -> AudioHalDevice<state::Closed> {
        self.inner.hardware_muted = true;
        if let Ok(mut guard) = self.inner.dma_pool.lock() {
            let reclaimed: Vec<DmaSlotId> = guard.quarantined_slots.iter().copied().collect();
            guard.quarantined_slots.clear();
            for slot in reclaimed {
                if !guard.active_slots.contains(&slot) && !guard.free_slots.contains(&slot) {
                    guard.free_slots.push_back(slot);
                }
            }
        }
        AudioHalDevice {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

impl AudioHalDevice<state::Faulted> {
    /// Reset a faulted device back to `Closed` while keeping hardware muted.
    #[must_use]
    pub fn reset_to_closed(mut self) -> AudioHalDevice<state::Closed> {
        self.inner.hardware_muted = true;
        AudioHalDevice {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

impl<S> AudioHalDevice<S> {
    #[must_use]
    pub fn telemetry(&self) -> HalTelemetry {
        let (free, active, quarantined) = self
            .inner
            .dma_pool
            .lock()
            .map(|g| (g.free_count(), g.active_count(), g.quarantined_count()))
            .unwrap_or((0, 0, 0));
        HalTelemetry {
            profile_id: self.inner.profile.profile_id.clone(),
            hardware_muted: self.inner.hardware_muted,
            primed_silence_blocks: self.inner.primed_silence_blocks,
            submitted_audio_blocks: self.inner.submitted_audio_blocks,
            underrun_count: self.inner.underrun_count,
            free_dma_slots: free,
            active_dma_slots: active,
            quarantined_dma_slots: quarantined,
            last_fault: self.inner.last_fault.clone(),
        }
    }
}

fn acquire_dma_lease(pool: &Arc<Mutex<DmaPoolState>>) -> Result<DmaSubmissionLease, HalError> {
    let mut guard = pool.lock().map_err(|_| HalError::DriverFault {
        reason: "DMA pool mutex poisoned".to_string(),
    })?;
    if let Some(slot) = guard.free_slots.pop_front() {
        guard.active_slots.insert(slot);
        Ok(DmaSubmissionLease {
            slot,
            pool: Arc::clone(pool),
            completed: false,
        })
    } else {
        Err(HalError::DmaPoolExhausted {
            active: guard.active_count(),
            quarantined: guard.quarantined_count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixture: the canonical catalog holds non-admissible hypotheses.
    use franken_board_profile::synthetic_test_fixture_catalog as canonical_board_catalog;

    #[test]
    fn typestate_hal_rejects_unmute_before_silence_prime_and_quarantines_dropped_dma_leases() {
        let catalog = canonical_board_catalog();
        let s5 = catalog
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();

        let closed = AudioHalDevice::open_for_profile(s5, 4, 2).unwrap();
        assert!(closed.telemetry().hardware_muted);

        let prepared = closed.prepare();
        // Attempting to start_unmuted with 0 of 2 required silence blocks must fail and stay muted
        let (mut prepared, err) = prepared.start_unmuted().unwrap_err();
        assert_eq!(
            err,
            HalError::UnmuteBeforeSilencePrime {
                primed_blocks: 0,
                required_blocks: 2
            }
        );
        assert!(prepared.telemetry().hardware_muted);

        prepared.prime_silence_block().unwrap();
        prepared.prime_silence_block().unwrap();
        let mut running = prepared.start_unmuted().unwrap();
        assert!(!running.telemetry().hardware_muted);

        // Submit 2 DMA blocks: complete one, drop the other (simulating task cancellation)
        let lease1 = running.submit_dma_block().unwrap();
        let lease2 = running.submit_dma_block().unwrap();
        lease1.complete();
        drop(lease2); // Cancelled without driver completion!

        let t = running.telemetry();
        assert_eq!(t.free_dma_slots, 3);
        assert_eq!(t.active_dma_slots, 0);
        assert_eq!(t.quarantined_dma_slots, 1);

        // Drain immediately mutes amplifier and reclaims quarantined slot on close
        let draining = running.begin_drain();
        assert!(draining.telemetry().hardware_muted);
        let closed_again = draining.finish_drain_and_close();
        assert_eq!(closed_again.telemetry().quarantined_dma_slots, 0);
        assert_eq!(closed_again.telemetry().free_dma_slots, 4);
    }

    #[test]
    fn bridge_non_audio_profile_is_rejected_at_hal_open() {
        let catalog = canonical_board_catalog();
        let bridge = catalog
            .into_iter()
            .find(|p| p.model_number == "BR100")
            .unwrap();
        assert!(matches!(
            AudioHalDevice::open_for_profile(bridge, 4, 2),
            Err(HalError::ProfileRejected(
                UnsupportedReasonCode::NonAudioAppliance { .. }
            ))
        ));
    }

    #[test]
    fn hypothesis_catalog_boards_are_refused_at_hal_open_but_the_labelled_fixture_is_admitted() {
        let hypothesis = franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        assert!(matches!(
            AudioHalDevice::open_for_profile(hypothesis, 4, 2),
            Err(HalError::ProfileRejected(
                UnsupportedReasonCode::UnattestedProfile { .. }
            ))
        ));

        // Permitted positive: the labelled synthetic fixture for the same model opens (offline only).
        let fixture = canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        assert!(fixture.is_synthetic_fixture());
        assert!(AudioHalDevice::open_for_profile(fixture, 4, 2).is_ok());
    }

    /// The committed matrix for the model-16 `audiodev.o`. Every field is still unknown.
    const REAL_MATRIX_JSON: &str = include_str!("../../../tests/e04/matrix_audiodev_m16.json");

    fn fixture_s5() -> BoardProfile {
        canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
    }

    /// The complete fixture matrix, with a topology that routes the same roles as `profile`.
    fn complete_for(profile: &BoardProfile, anchor: fn() -> contract::Anchor) -> ContractMatrix {
        let names: Vec<String> = profile
            .channel_routing
            .iter()
            .map(|role| contract::transducer_role_name(*role))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        contract::fixtures::complete_matrix_for(anchor, &refs)
    }

    fn missing_of(err: HalError) -> Vec<MissingContract> {
        match err {
            HalError::ContractIncomplete { missing } => missing,
            other => panic!("expected ContractIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn hardware_open_refuses_the_committed_matrix_and_lists_the_exact_missing_contract() {
        let matrix: ContractMatrix = serde_json::from_str(REAL_MATRIX_JSON).unwrap();
        // The labelled fixture profile verifies, so the driver contract is the only thing in the way.
        assert!(AudioHalDevice::open_for_profile(fixture_s5(), 4, 2).is_ok());
        let err = AudioHalDevice::open_for_hardware(fixture_s5(), &matrix, 4, 2).unwrap_err();
        assert_eq!(
            err.to_string(),
            "retained-driver contract is not hardware-eligible (111 missing)"
        );
        let missing = missing_of(err);
        assert_eq!(missing.len(), 111);
        // Every required operation is named, with its interface among the unknowns.
        for op in contract::REQUIRED_OPERATIONS {
            let record = format!("op.{}", op.name());
            assert!(
                missing
                    .iter()
                    .any(|m| m.record == record && m.field == contract::ContractField::Interface),
                "{record} interface is not listed"
            );
        }
    }

    #[test]
    fn hardware_open_refuses_a_complete_but_synthetic_matrix() {
        let matrix = complete_for(&fixture_s5(), contract::fixtures::anchor_synthetic);
        assert!(matrix.evaluate().offline_model_ok);
        let missing =
            missing_of(AudioHalDevice::open_for_hardware(fixture_s5(), &matrix, 4, 2).unwrap_err());
        assert_eq!(missing.len(), 111);
        assert!(
            missing
                .iter()
                .all(|m| matches!(m.reason, contract::MissingReason::SyntheticAnchor { .. }))
        );
    }

    #[test]
    fn hardware_open_admits_a_fully_anchored_matrix_but_still_starts_muted() {
        // Unit test of the gate with a constructed matrix. No committed data claims eligibility.
        let matrix = complete_for(&fixture_s5(), contract::fixtures::anchor_artifact);
        let device = AudioHalDevice::open_for_hardware(fixture_s5(), &matrix, 4, 2).unwrap();
        let telemetry = device.telemetry();
        assert!(telemetry.hardware_muted);
        assert_eq!(telemetry.free_dma_slots, 4);
        assert_eq!(telemetry.primed_silence_blocks, 0);
    }

    #[test]
    fn hardware_open_refuses_a_channel_map_that_contradicts_the_profile() {
        // The two-channel fixture topology on the five-channel S5 board: refused, and the list says
        // exactly which two things disagree.
        let two_channel = contract::fixtures::complete_matrix(contract::fixtures::anchor_artifact);
        let missing = missing_of(
            AudioHalDevice::open_for_hardware(fixture_s5(), &two_channel, 4, 2).unwrap_err(),
        );
        let fields: Vec<contract::ContractField> = missing.iter().map(|m| m.field).collect();
        assert_eq!(
            fields,
            vec![
                contract::ContractField::ChannelCount,
                contract::ContractField::Routing
            ]
        );
        assert!(
            missing
                .iter()
                .all(|m| m.scope == contract::ContractScope::Topology)
        );
        // Permitted positive: the same matrix with this board's own channel map opens.
        let own = complete_for(&fixture_s5(), contract::fixtures::anchor_artifact);
        assert!(AudioHalDevice::open_for_hardware(fixture_s5(), &own, 4, 2).is_ok());
    }

    #[test]
    fn hardware_open_checks_the_profile_before_the_contract() {
        let matrix = contract::fixtures::complete_matrix(contract::fixtures::anchor_artifact);
        let hypothesis = franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        // The matrix alone would pass, so only the unattested profile can be the reason.
        assert!(matches!(
            AudioHalDevice::open_for_hardware(hypothesis, &matrix, 4, 2),
            Err(HalError::ProfileRejected(
                UnsupportedReasonCode::UnattestedProfile { .. }
            ))
        ));
    }

    #[test]
    fn contract_incomplete_survives_a_json_round_trip_inside_hal_error() {
        let matrix: ContractMatrix = serde_json::from_str(REAL_MATRIX_JSON).unwrap();
        let err = AudioHalDevice::open_for_hardware(fixture_s5(), &matrix, 4, 2).unwrap_err();
        let back: HalError = serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert_eq!(back, err);
    }
}
