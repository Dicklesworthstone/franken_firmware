//! The actual loopback HTTP worker using a caller-supplied durable host fleet owner.

use super::*;
use franken_control::channel::peer::{PeerId, PeerRole, compute_proof};
use franken_control::channel::pipeline::{ChannelConfig, Limits, RamMedium, StorageFault};
use franken_control::channel::request::{ControlCommand, RequestBody};
use franken_control::contracts::secret_store::{
    Generation, SecretError, SecretHandle, SecretMeta, SecretValue,
};
use franken_control::fsonos::{Endpoint, EndpointConfig, LegacyBridge, Service};
use franken_session::AuthorityToken;
use std::collections::BTreeMap;
use std::fmt;

struct KeyEntry {
    generation: Generation,
    value: SecretValue,
}

/// A volatile secret store for the harness. `franken-control`'s own in-memory store is `cfg(test)` and cannot be reached from
/// another crate. Nothing is written anywhere; a value is wiped when it is dropped (`SecretValue`).
struct HarnessKeys {
    entries: BTreeMap<SecretHandle, KeyEntry>,
    capacity: usize,
}

impl HarnessKeys {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: 33,
        }
    }
}

/// Shows how many entries exist and nothing about them.
impl fmt::Debug for HarnessKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessKeys")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl SecretStore for HarnessKeys {
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
            KeyEntry {
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
        // The old value is dropped here, which wipes it.
        entry.value = value;
        entry.generation = next;
        Ok(next)
    }

    fn remove(&mut self, handle: &SecretHandle) -> Result<(), SecretError> {
        self.entries
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound {
                handle: handle.clone(),
            })
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

#[derive(Clone)]
struct SharedMedium(Arc<Mutex<RamMedium>>);
impl Storage for SharedMedium {
    fn segment_bytes(&self) -> usize {
        self.0.lock().unwrap().segment_bytes()
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageFault> {
        self.0.lock().unwrap().read(offset, out)
    }
    fn program(&mut self, offset: usize, bytes: &[u8]) -> Result<(), StorageFault> {
        self.0.lock().unwrap().program(offset, bytes)
    }
    fn erase(&mut self, segment: usize) -> Result<(), StorageFault> {
        self.0.lock().unwrap().erase(segment)
    }
    fn sync(&mut self) -> Result<(), StorageFault> {
        self.0.lock().unwrap().sync()
    }
}

const KEY: &[u8] = b"public-loopback-controller-key-0123456789";
const BRIDGE_KEY: &[u8] = b"public-loopback-legacy-bridge-key-0123456789";

fn start_fleet(
    session: UnifiedGroupSession,
    keys: HarnessKeys,
    medium: SharedMedium,
    enroll: bool,
) -> FsonosLoopback {
    FsonosLoopback::start_with_control(
        session,
        FIXTURE_MEMBER,
        Policy::UnauthenticatedTailnet,
        LoopbackLimits::standard(),
        move |session, member, incarnation| {
            let (mut owner, _) =
                FleetControlOwner::boot(keys, medium, ChannelConfig::provisional())
                    .map_err(|e| format!("fleet boot: {e:?}"))?;
            let peer = PeerId::parse("controller").map_err(|e| format!("peer: {e}"))?;
            let bridge = PeerId::parse("legacy-bridge").map_err(|e| format!("bridge: {e}"))?;
            if enroll {
                owner
                    .admit(
                        &peer,
                        PeerRole::Controller,
                        KEY,
                        Some(session.current_epoch),
                        1,
                    )
                    .map_err(|e| format!("admission: {e:?}"))?;
                owner
                    .admit(
                        &bridge,
                        PeerRole::Controller,
                        BRIDGE_KEY,
                        Some(session.current_epoch),
                        1,
                    )
                    .map_err(|e| format!("bridge admission: {e:?}"))?;
            }
            owner
                .install_lease(session, AuthorityToken::issue(session, u64::MAX), START_NS)
                .map_err(|e| format!("lease: {e:?}"))?;
            let endpoint = Endpoint::with_incarnation(
                EndpointConfig::provisional(member),
                LegacyBridge::new(bridge, BRIDGE_KEY.to_vec()),
                incarnation,
                1,
            )
            .map_err(|e| format!("endpoint: {e:?}"))?;
            let plane = FleetSoapPlane::new(owner, endpoint)
                .map_err(|e| format!("legacy reservation: {e:?}"))?;
            Ok(Box::new(plane))
        },
    )
    .expect("fleet loopback starts")
}

fn relative(
    addr: SocketAddr,
    epoch: u64,
    revision: u64,
    seq: u64,
    peer_name: &str,
    signing_key: &[u8],
) -> (u16, String) {
    let peer = PeerId::parse(peer_name).unwrap();
    let body = RequestBody::new(
        peer,
        seq,
        epoch,
        Some(revision),
        ControlCommand::AdjustMemberVolume {
            member_id: FIXTURE_MEMBER.into(),
            delta: 10,
        },
    )
    .unwrap();
    let proof: String = compute_proof(signing_key, &body.signing_bytes())
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let service = Service::RenderingControl;
    let xml = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:SetRelativeVolume xmlns:u=\"{}\"><InstanceID>0</InstanceID><Channel>Master</Channel><Adjustment>10</Adjustment></u:SetRelativeVolume></s:Body></s:Envelope>",
        service.urn()
    );
    let wire = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nSOAPACTION: \"{}#SetRelativeVolume\"\r\nX-Franken-Peer: {peer_name}\r\nX-Franken-Seq: {seq}\r\nX-Franken-Epoch: {epoch}\r\nX-Franken-Revision: {revision}\r\nX-Franken-Proof: {proof}\r\nContent-Length: {}\r\n\r\n{xml}",
        service.control_path(),
        service.urn(),
        xml.len()
    );
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(wire.as_bytes()).unwrap();
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                assert!(response.len() <= 64 * 1024);
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("reading loopback response: {error}"),
        }
    }
    let response = String::from_utf8(response).unwrap();
    let status = response
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, response)
}

#[test]
fn fleet_loopback_authenticates_commits_and_restores_replay_floor() {
    let session = fixture_session().unwrap();
    let epoch = session.current_epoch;
    let revision = session.state_revision;
    let medium = SharedMedium(Arc::new(Mutex::new(RamMedium::new(
        Limits::fleet_control_development().segment_bytes,
    ))));
    let server = start_fleet(session, HarnessKeys::new(), medium.clone(), true);
    assert_eq!(
        relative(
            server.addr(),
            epoch,
            revision,
            1,
            "legacy-bridge",
            BRIDGE_KEY
        )
        .0,
        401
    );
    assert_ne!(
        relative(
            server.addr(),
            epoch,
            revision,
            1,
            "controller",
            b"wrong-key-01234567890123456789"
        )
        .0,
        200
    );
    assert_eq!(server.with_session(|s| s.state_revision), revision);
    assert_eq!(
        relative(server.addr(), epoch, revision, 1, "controller", KEY).0,
        200
    );
    assert_eq!(
        server.with_session(|s| s.members[FIXTURE_MEMBER].volume_0_to_100),
        60
    );
    assert_eq!(
        relative(server.addr(), epoch, revision, 1, "controller", KEY).0,
        200
    );
    let restored_session = server.with_session(|session| session.clone());
    assert_eq!(restored_session.state_revision, revision + 1);
    assert!(server.stop().reconciled());
    // Restore credentials from the journal into a fresh volatile key store.
    let restored = start_fleet(restored_session, HarnessKeys::new(), medium, false);
    let replay = relative(restored.addr(), epoch, revision, 1, "controller", KEY);
    assert_eq!(replay.0, 500);
    assert!(replay.1.contains("<errorCode>801</errorCode>"));
    assert_eq!(
        relative(restored.addr(), epoch, revision + 1, 2, "controller", KEY).0,
        200
    );
    assert_eq!(
        restored.with_session(|s| s.members[FIXTURE_MEMBER].volume_0_to_100),
        70
    );
    assert!(restored.stop().reconciled());
}

#[test]
fn failed_control_factory_refuses_start_without_legacy_fallback() {
    let started = FsonosLoopback::start_with_control(
        fixture_session().unwrap(),
        FIXTURE_MEMBER,
        Policy::LocalLink,
        LoopbackLimits::standard(),
        |_, member, incarnation| {
            let (owner, _) = FleetControlOwner::boot(
                HarnessKeys::new(),
                RamMedium::new(1),
                ChannelConfig::provisional(),
            )
            .map_err(|error| format!("fleet boot: {error:?}"))?;
            let peer = PeerId::parse("legacy-bridge").map_err(|error| format!("peer: {error}"))?;
            let endpoint = Endpoint::with_incarnation(
                EndpointConfig::provisional(member),
                LegacyBridge::new(peer, BRIDGE_KEY.to_vec()),
                incarnation,
                1,
            )
            .map_err(|error| format!("endpoint: {error:?}"))?;
            let plane = FleetSoapPlane::new(owner, endpoint)
                .map_err(|error| format!("legacy reservation: {error:?}"))?;
            Ok(Box::new(plane))
        },
    );
    let Err(reason) = started else {
        panic!("failed factory unexpectedly started")
    };
    assert!(reason.starts_with("fleet boot:"), "{reason}");
    assert!(
        FsonosLoopback::start(
            fixture_session().unwrap(),
            FIXTURE_MEMBER,
            Policy::LocalLink,
            LoopbackLimits::standard()
        )
        .unwrap()
        .stop()
        .reconciled()
    );
}
