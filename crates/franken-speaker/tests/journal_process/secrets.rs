//! Volatile credentials for the process integration fixture, never device storage.
use franken_control::contracts::secret_store::{
    Generation, SecretError, SecretHandle, SecretMeta, SecretStore, SecretValue,
};
use std::collections::BTreeMap;

pub(super) struct TestSecrets(BTreeMap<SecretHandle, (Generation, SecretValue)>);

impl TestSecrets {
    pub(super) fn fleet_control_development() -> Self {
        Self(BTreeMap::new())
    }
}

impl SecretStore for TestSecrets {
    fn insert(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
    ) -> Result<Generation, SecretError> {
        if self.0.contains_key(handle) {
            return Err(SecretError::AlreadyExists {
                handle: handle.clone(),
            });
        }
        if self.0.len() >= 33 {
            return Err(SecretError::StoreFull { max: 33 });
        }
        self.0.insert(handle.clone(), (Generation::FIRST, value));
        Ok(Generation::FIRST)
    }

    fn replace(
        &mut self,
        handle: &SecretHandle,
        value: SecretValue,
        expected: Generation,
    ) -> Result<Generation, SecretError> {
        let entry = self
            .0
            .get_mut(handle)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })?;
        if entry.0 != expected {
            return Err(SecretError::StaleGeneration {
                handle: handle.clone(),
                expected: expected.get(),
                actual: entry.0.get(),
            });
        }
        let next = entry
            .0
            .successor()
            .ok_or_else(|| SecretError::GenerationExhausted {
                handle: handle.clone(),
            })?;
        *entry = (next, value);
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        self.0
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn generation(&self, handle: &SecretHandle) -> Result<Generation, SecretError> {
        self.0
            .get(handle)
            .map(|entry| entry.0)
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
    }

    fn with_secret<R>(
        &self,
        handle: &SecretHandle,
        f: impl FnOnce(Generation, &[u8]) -> R,
    ) -> Result<R, SecretError> {
        let (generation, value) = self.0.get(handle).ok_or_else(|| SecretError::NotFound {
            handle: handle.clone(),
        })?;
        Ok(f(*generation, value.expose()))
    }

    fn list(&self) -> Vec<SecretMeta> {
        self.0
            .iter()
            .map(|(handle, (generation, value))| SecretMeta {
                handle: handle.clone(),
                generation: *generation,
                byte_len: value.byte_len(),
            })
            .collect()
    }
}
