//! The update state machine (`docs/contracts/u02.md` sections 4 and 5), persisted in U01's journal and a staging medium behind a trait.
//!
//! ```text
//! Idle --begin_stage--> Staging --finish_stage--> Staged --activate--> Trial --report_boot(healthy)--> Idle (new image installed, floor raised)
//!   ^                      |  ^                      |                    |
//!   |                      |  +-- write_chunk        +-- abort            +-- report_boot(unhealthy) x TRIAL_BOOTS --> Idle (rolled back)
//!   +----------------------+-------- abort ----------+
//! ```
//!
//! What is durable: the journal's record `u02.upd` (phase, the candidate's SHA-256, the staged checkpoint, the boots left), `u02.inst` (the
//! installed image's summary), `u02.fail` (the last candidate that failed, so it is not retried) and the mark `u02.floor` (the anti-rollback
//! floor). Every transition is ONE journal transaction, so recovery returns exactly the old or exactly the new state; the transition that
//! installs an image writes the image and raises the floor in the same frame. The floor is raised only there: staging, activating and a failed
//! trial never move it, so a failed trial rolls back to an image that is still above the floor.
//!
//! The staged bytes live on the staging medium, whose writes are not durable until `sync`. The journal records a checkpoint only after a sync,
//! so a restart resumes at the checkpoint and discards anything after it; the manifest copy that sits beside the staged bytes is untrusted and
//! is hashed against the journal's record and verified again before anything is resumed. Whole-artifact verification re-reads the medium at
//! `finish_stage` and again at `activate`: a verdict remembered from before is not trusted over the bytes now there.

use franken_journal::{Journal, Namespace, Op, Storage};

use crate::UpdateError;
use crate::manifest::Manifest;
use crate::policy::{self, Admitted, Dynamic, Installed, Policy};

/// Bytes of staged artifact between two persisted checkpoints.
pub const CHECKPOINT: usize = 64;
/// Unhealthy boots a trial image may have before it is rolled back.
pub const TRIAL_BOOTS: u8 = 3;
pub const KEY_INSTALLED: &[u8] = b"u02.inst";
pub const KEY_UPDATE: &[u8] = b"u02.upd";
pub const KEY_FAILED: &[u8] = b"u02.fail";
pub const MARK_FLOOR: &[u8] = b"u02.floor";
const READ_BLOCK: usize = 256;
const UPDATE_LEN: usize = 39;
const FAILED_LEN: usize = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Staging,
    Staged,
    Trial,
}

impl Phase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Staging => "staging",
            Self::Staged => "staged",
            Self::Trial => "trial",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOutcome {
    Committed,
    Retry,
    RolledBack,
}

impl BootOutcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Retry => "retry",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// The record of an update in progress (`u02.upd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upd {
    pub phase: Phase,
    pub sha: [u8; 32],
    pub staged: u32,
    pub boots: u8,
}

impl Upd {
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let code = match self.phase {
            Phase::Idle => 0,
            Phase::Staging => 1,
            Phase::Staged => 2,
            Phase::Trial => 3,
        };
        let mut out = Vec::with_capacity(UPDATE_LEN);
        out.push(1);
        out.push(code);
        out.extend_from_slice(&self.sha);
        out.extend_from_slice(&self.staged.to_be_bytes());
        out.push(self.boots);
        out
    }

    #[must_use]
    pub fn unpack(raw: &[u8]) -> Option<Self> {
        if raw.len() != UPDATE_LEN || raw[0] != 1 {
            return None;
        }
        let phase = match raw[1] {
            1 => Phase::Staging,
            2 => Phase::Staged,
            3 => Phase::Trial,
            _ => return None,
        };
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&raw[2..34]);
        Some(Self {
            phase,
            sha,
            staged: u32::from_be_bytes([raw[34], raw[35], raw[36], raw[37]]),
            boots: raw[38],
        })
    }
}

/// The record of the candidate that failed (`u02.fail`).
#[must_use]
pub fn pack_failed(sha: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FAILED_LEN);
    out.push(1);
    out.extend_from_slice(&sha);
    out
}

/// The staging medium: a slot for the manifest copy and a byte area whose writes are durable only after `sync`.
pub trait Staging {
    fn capacity(&self) -> u32;
    fn manifest(&self) -> Option<Vec<u8>>;
    fn put_manifest(&mut self, raw: &[u8]);
    /// Forget the manifest copy and every staged byte.
    fn reset(&mut self);
    /// Write `chunk` at `offset`, which may not be beyond the end of what is staged.
    ///
    /// # Errors
    /// [`UpdateError::StagingGap`] for an offset beyond the end, [`UpdateError::InsufficientCapacity`] for a write past the capacity.
    fn write(&mut self, offset: usize, chunk: &[u8]) -> Result<(), UpdateError>;
    fn sync(&mut self);
    fn truncate(&mut self, len: usize);
    fn staged_len(&self) -> usize;
    /// Copy up to `out.len()` staged bytes starting at `offset`; returns how many were copied.
    fn read_at(&self, offset: usize, out: &mut [u8]) -> usize;
}

/// An in-memory staging medium with the faults the tests inject: a power cut that keeps the synced bytes and a torn prefix of the rest,
/// bit rot in the staged bytes, and a damaged manifest copy.
#[derive(Debug, Clone, Default)]
pub struct MemStaging {
    capacity: u32,
    manifest: Option<Vec<u8>>,
    data: Vec<u8>,
    synced: usize,
}

impl MemStaging {
    #[must_use]
    pub fn new(capacity: u32) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    /// A medium that already holds `data`, all of it synced.
    #[must_use]
    pub fn with_data(capacity: u32, data: &[u8]) -> Self {
        Self {
            capacity,
            manifest: None,
            data: data.to_vec(),
            synced: data.len(),
        }
    }

    /// Cut the power: keep the synced bytes and `keep` bytes of the rest; the last kept unsynced byte is torn.
    pub fn power_cut(&mut self, keep: usize) {
        let unsynced = self.data.len().saturating_sub(self.synced);
        let end = self.synced + keep.min(unsynced);
        self.data.truncate(end);
        if end > self.synced
            && let Some(last) = self.data.last_mut()
        {
            *last ^= 0x5A;
        }
        self.synced = self.synced.min(self.data.len());
    }

    /// Flip one bit of a staged byte, as bit rot would.
    pub fn corrupt(&mut self, at: usize, bit: u8) {
        if let Some(byte) = self.data.get_mut(at) {
            *byte ^= 1 << (bit & 7);
        }
    }

    /// Flip one bit of the manifest copy.
    pub fn tamper_manifest(&mut self, at: usize) {
        if let Some(byte) = self.manifest.as_mut().and_then(|raw| raw.get_mut(at)) {
            *byte ^= 1;
        }
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Staging for MemStaging {
    fn capacity(&self) -> u32 {
        self.capacity
    }

    fn manifest(&self) -> Option<Vec<u8>> {
        self.manifest.clone()
    }

    fn put_manifest(&mut self, raw: &[u8]) {
        self.manifest = Some(raw.to_vec());
    }

    fn reset(&mut self) {
        self.manifest = None;
        self.data.clear();
        self.synced = 0;
    }

    fn write(&mut self, offset: usize, chunk: &[u8]) -> Result<(), UpdateError> {
        if offset > self.data.len() {
            return Err(UpdateError::StagingGap);
        }
        let end = offset
            .checked_add(chunk.len())
            .ok_or(UpdateError::InsufficientCapacity)?;
        if end > self.capacity as usize {
            return Err(UpdateError::InsufficientCapacity);
        }
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(chunk);
        Ok(())
    }

    fn sync(&mut self) {
        self.synced = self.data.len();
    }

    fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
        self.synced = self.synced.min(len);
    }

    fn staged_len(&self) -> usize {
        self.data.len()
    }

    fn read_at(&self, offset: usize, out: &mut [u8]) -> usize {
        let Some(rest) = self.data.get(offset..) else {
            return 0;
        };
        let n = rest.len().min(out.len());
        out[..n].copy_from_slice(&rest[..n]);
        n
    }
}

/// The staged bytes against the manifest: a short artifact, a long one and a wrong one are three different refusals.
///
/// # Errors
/// [`UpdateError::ArtifactTruncated`], [`UpdateError::ArtifactOversized`] or [`UpdateError::ArtifactDigestMismatch`].
pub fn check_artifact<G: Staging + ?Sized>(m: &Manifest, staging: &G) -> Result<(), UpdateError> {
    use sha2::{Digest, Sha256};
    let total = staging.staged_len();
    let size = m.artifact_size as usize;
    if total < size {
        return Err(UpdateError::ArtifactTruncated);
    }
    if total > size {
        return Err(UpdateError::ArtifactOversized);
    }
    let mut hasher = Sha256::new();
    let mut block = [0u8; READ_BLOCK];
    let mut offset = 0;
    while offset < total {
        let want = READ_BLOCK.min(total - offset);
        let got = staging.read_at(offset, &mut block[..want]);
        if got == 0 {
            return Err(UpdateError::ArtifactTruncated);
        }
        hasher.update(&block[..got]);
        offset += got;
    }
    let digest = hasher.finalize();
    if digest[..32] == m.artifact_sha256 {
        Ok(())
    } else {
        Err(UpdateError::ArtifactDigestMismatch)
    }
}

/// What is persisted, as a restart would find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Persisted {
    pub phase: Phase,
    pub installed: Option<u32>,
    pub installed_security: Option<u32>,
    pub floor: u64,
    pub checkpoint: u32,
}

/// What a caller sees right now: the persisted phase and numbers, and the offset the next staged byte goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub installed: Option<u32>,
    pub floor: u64,
    pub next: usize,
}

pub struct Engine<S: Storage, G: Staging> {
    journal: Journal<S>,
    staging: G,
    policy: Policy,
    /// The candidate's parsed manifest, re-verified from the staging copy on every open.
    cache: Option<Manifest>,
    /// Bytes of the artifact written so far in this process.
    live: usize,
}

impl<S: Storage, G: Staging> Engine<S, G> {
    /// Open the engine over a journal that was just opened and a staging medium. This is also a restart, and a restart is an admission: an update
    /// in progress is resumed only if the manifest copy on the staging medium (untrusted, like everything on it) hashes to what the journal
    /// recorded AND [`policy::admit`] accepts it again under the policy this engine was opened with and the journal's current installed image,
    /// floor and failed candidate. A key revoked, a board or feature requirement changed, a floor raised, consent withdrawn or a capacity
    /// shrunk since the stage began therefore drops it. A dropped update leaves the installed image untouched and the engine idle. Admission
    /// never consults the update record, so a stage is not refused for being in progress.
    ///
    /// # Errors
    /// [`UpdateError::CorruptState`] for a journal record this code cannot read, or a journal fault while dropping an unresumable update.
    pub fn open(journal: Journal<S>, staging: G, policy: Policy) -> Result<Self, UpdateError> {
        let mut engine = Self {
            journal,
            staging,
            policy,
            cache: None,
            live: 0,
        };
        let Some(update) = engine.update()? else {
            return Ok(engine);
        };
        let state = engine.dynamic()?;
        let resumed = engine
            .staging
            .manifest()
            .filter(|copy| crate::sha256(&[copy.as_slice()]) == update.sha)
            .and_then(|copy| policy::admit(&engine.policy, &state, &copy).ok());
        let Some(admitted) = resumed else {
            engine.commit(Vec::new(), &[KEY_UPDATE], None)?;
            return Ok(engine);
        };
        let m = admitted.manifest;
        if update.phase == Phase::Staging {
            let checkpoint = update.staged as usize;
            engine.staging.truncate(checkpoint);
            engine.live = checkpoint;
        } else {
            engine.live = m.artifact_size as usize;
        }
        engine.cache = Some(m);
        Ok(engine)
    }

    #[must_use]
    pub fn into_parts(self) -> (Journal<S>, G, Policy) {
        (self.journal, self.staging, self.policy)
    }

    #[must_use]
    pub fn journal(&self) -> &Journal<S> {
        &self.journal
    }

    #[must_use]
    pub fn staging(&self) -> &G {
        &self.staging
    }

    pub fn staging_mut(&mut self) -> &mut G {
        &mut self.staging
    }

    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    // ---- what is persisted

    fn record(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.journal.state().records.get(key)
    }

    /// # Errors
    /// [`UpdateError::CorruptState`] if the record is present and unreadable.
    pub fn installed(&self) -> Result<Option<Installed>, UpdateError> {
        match self.record(KEY_INSTALLED) {
            None => Ok(None),
            Some(raw) => Installed::unpack(raw)
                .map(Some)
                .ok_or(UpdateError::CorruptState),
        }
    }

    #[must_use]
    pub fn floor(&self) -> u64 {
        self.journal
            .state()
            .marks
            .get(MARK_FLOOR)
            .copied()
            .unwrap_or(0)
    }

    /// # Errors
    /// [`UpdateError::CorruptState`] if the record is present and unreadable.
    pub fn update(&self) -> Result<Option<Upd>, UpdateError> {
        match self.record(KEY_UPDATE) {
            None => Ok(None),
            Some(raw) => Upd::unpack(raw).map(Some).ok_or(UpdateError::CorruptState),
        }
    }

    /// # Errors
    /// [`UpdateError::CorruptState`] if the record is present and unreadable.
    pub fn failed(&self) -> Result<Option<[u8; 32]>, UpdateError> {
        match self.record(KEY_FAILED) {
            None => Ok(None),
            Some(raw) if raw.len() == FAILED_LEN && raw[0] == 1 => {
                let mut sha = [0u8; 32];
                sha.copy_from_slice(&raw[1..]);
                Ok(Some(sha))
            }
            Some(_) => Err(UpdateError::CorruptState),
        }
    }

    /// # Errors
    /// As [`Engine::update`].
    pub fn phase(&self) -> Result<Phase, UpdateError> {
        Ok(self.update()?.map_or(Phase::Idle, |u| u.phase))
    }

    fn dynamic(&self) -> Result<Dynamic, UpdateError> {
        Ok(Dynamic {
            installed: self.installed()?,
            floor: self.floor(),
            failed: self.failed()?,
        })
    }

    /// # Errors
    /// As [`Engine::installed`] and [`Engine::update`].
    pub fn persisted(&self) -> Result<Persisted, UpdateError> {
        let installed = self.installed()?;
        let update = self.update()?;
        Ok(Persisted {
            phase: update.map_or(Phase::Idle, |u| u.phase),
            installed: installed.as_ref().map(|i| i.version),
            installed_security: installed.as_ref().map(|i| i.security_version),
            floor: self.floor(),
            checkpoint: update
                .filter(|u| u.phase == Phase::Staging)
                .map_or(0, |u| u.staged),
        })
    }

    /// # Errors
    /// As [`Engine::persisted`].
    pub fn snapshot(&self) -> Result<Snapshot, UpdateError> {
        let persisted = self.persisted()?;
        Ok(Snapshot {
            phase: persisted.phase,
            installed: persisted.installed,
            floor: persisted.floor,
            next: if persisted.phase == Phase::Staging {
                self.live
            } else {
                0
            },
        })
    }

    // ---- one journal transaction per transition

    fn commit(
        &mut self,
        puts: Vec<(&'static [u8], Vec<u8>)>,
        deletes: &[&'static [u8]],
        raise_floor: Option<u64>,
    ) -> Result<(), UpdateError> {
        let mut ops = Vec::with_capacity(puts.len() + deletes.len() + 1);
        for (key, value) in puts {
            ops.push(Op::Put {
                ns: Namespace::Records,
                key: key.to_vec(),
                value,
            });
        }
        for key in deletes {
            if self.record(key).is_some() {
                ops.push(Op::Delete {
                    ns: Namespace::Records,
                    key: key.to_vec(),
                });
            }
        }
        if let Some(value) = raise_floor {
            ops.push(Op::Raise {
                key: MARK_FLOOR.to_vec(),
                value,
            });
        }
        self.journal.commit(&ops)?;
        Ok(())
    }

    // ---- transitions

    /// Admit a candidate and open its stage. Nothing is written to the journal or the staging medium unless the candidate is admitted.
    ///
    /// # Errors
    /// [`UpdateError::UpdateInProgress`], any refusal of [`policy::admit`], or a journal fault.
    pub fn begin_stage(&mut self, raw: &[u8]) -> Result<Admitted, UpdateError> {
        if self.update()?.is_some() {
            return Err(UpdateError::UpdateInProgress);
        }
        let state = self.dynamic()?;
        let admitted = policy::admit(&self.policy, &state, raw)?;
        self.staging.reset();
        self.staging.put_manifest(raw);
        let record = Upd {
            phase: Phase::Staging,
            sha: admitted.manifest.sha256,
            staged: 0,
            boots: 0,
        };
        self.commit(vec![(KEY_UPDATE, record.pack())], &[], None)?;
        self.cache = Some(admitted.manifest.clone());
        self.live = 0;
        Ok(admitted)
    }

    /// Append the next bytes of the artifact. A checkpoint is persisted once `CHECKPOINT` bytes have been written since the last one.
    ///
    /// # Errors
    /// [`UpdateError::NotStaging`], [`UpdateError::ArtifactOversized`] (nothing is written), the staging medium's refusals, or a journal fault.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), UpdateError> {
        let update = self
            .update()?
            .filter(|u| u.phase == Phase::Staging)
            .ok_or(UpdateError::NotStaging)?;
        let size = self
            .cache
            .as_ref()
            .map(|m| m.artifact_size as usize)
            .ok_or(UpdateError::NotStaging)?;
        if self.live.saturating_add(chunk.len()) > size {
            return Err(UpdateError::ArtifactOversized);
        }
        self.staging.write(self.live, chunk)?;
        self.live += chunk.len();
        if self.live.saturating_sub(update.staged as usize) >= CHECKPOINT {
            self.staging.sync();
            let staged = u32::try_from(self.live).map_err(|_| UpdateError::CorruptState)?;
            let record = Upd { staged, ..update };
            self.commit(vec![(KEY_UPDATE, record.pack())], &[], None)?;
        }
        Ok(())
    }

    /// Check the staged bytes against the manifest. A wrong artifact clears the stage and remembers the candidate as failed; a short one keeps
    /// the stage open so the missing bytes can be sent.
    fn verify_staged(&mut self, sha: [u8; 32], m: &Manifest) -> Result<(), UpdateError> {
        if let Err(error) = check_artifact(m, &self.staging) {
            if error != UpdateError::ArtifactTruncated {
                self.commit(vec![(KEY_FAILED, pack_failed(sha))], &[KEY_UPDATE], None)?;
                self.cache = None;
                self.live = 0;
            }
            return Err(error);
        }
        Ok(())
    }

    /// # Errors
    /// [`UpdateError::NotStaging`], [`UpdateError::ArtifactTruncated`], [`UpdateError::ArtifactOversized`],
    /// [`UpdateError::ArtifactDigestMismatch`], or a journal fault.
    pub fn finish_stage(&mut self) -> Result<(), UpdateError> {
        let update = self
            .update()?
            .filter(|u| u.phase == Phase::Staging)
            .ok_or(UpdateError::NotStaging)?;
        let m = self.cache.clone().ok_or(UpdateError::NotStaging)?;
        self.staging.sync();
        self.verify_staged(update.sha, &m)?;
        let record = Upd {
            phase: Phase::Staged,
            sha: update.sha,
            staged: m.artifact_size,
            boots: 0,
        };
        self.commit(vec![(KEY_UPDATE, record.pack())], &[], None)
    }

    /// Start the trial: the bytes now on the medium are verified again, then the trial begins with `TRIAL_BOOTS` boots left.
    ///
    /// # Errors
    /// [`UpdateError::NotStaged`], an artifact refusal (bit rot clears the stage), or a journal fault.
    pub fn activate(&mut self) -> Result<(), UpdateError> {
        let update = self
            .update()?
            .filter(|u| u.phase == Phase::Staged)
            .ok_or(UpdateError::NotStaged)?;
        let m = self.cache.clone().ok_or(UpdateError::NotStaged)?;
        self.verify_staged(update.sha, &m)?;
        let record = Upd {
            phase: Phase::Trial,
            boots: TRIAL_BOOTS,
            ..update
        };
        self.commit(vec![(KEY_UPDATE, record.pack())], &[], None)
    }

    /// Give up on a stage that has not started its trial. The candidate is not marked failed.
    ///
    /// # Errors
    /// [`UpdateError::NothingToAbort`], [`UpdateError::TrialInProgress`], or a journal fault.
    pub fn abort(&mut self) -> Result<(), UpdateError> {
        match self.update()? {
            None => Err(UpdateError::NothingToAbort),
            Some(u) if u.phase == Phase::Trial => Err(UpdateError::TrialInProgress),
            Some(_) => {
                self.commit(Vec::new(), &[KEY_UPDATE], None)?;
                self.cache = None;
                self.live = 0;
                Ok(())
            }
        }
    }

    /// Report how a trial boot went. A healthy boot installs the image and raises the floor in one transaction; an unhealthy one spends a
    /// boot, and the last one rolls back and remembers the candidate as failed.
    ///
    /// # Errors
    /// [`UpdateError::NotInTrial`], or a journal fault.
    pub fn report_boot(&mut self, healthy: bool) -> Result<BootOutcome, UpdateError> {
        let update = self
            .update()?
            .filter(|u| u.phase == Phase::Trial)
            .ok_or(UpdateError::NotInTrial)?;
        let m = self.cache.clone().ok_or(UpdateError::NotInTrial)?;
        if healthy {
            let installed = Installed::of(&m).pack();
            self.commit(
                vec![(KEY_INSTALLED, installed)],
                &[KEY_UPDATE],
                Some(u64::from(m.security_version)),
            )?;
            self.cache = None;
            self.live = 0;
            return Ok(BootOutcome::Committed);
        }
        let boots = update.boots.saturating_sub(1);
        if boots > 0 {
            let record = Upd { boots, ..update };
            self.commit(vec![(KEY_UPDATE, record.pack())], &[], None)?;
            return Ok(BootOutcome::Retry);
        }
        self.commit(
            vec![(KEY_FAILED, pack_failed(update.sha))],
            &[KEY_UPDATE],
            None,
        )?;
        self.cache = None;
        self.live = 0;
        Ok(BootOutcome::RolledBack)
    }
}
