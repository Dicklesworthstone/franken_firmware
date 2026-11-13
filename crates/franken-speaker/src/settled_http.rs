//! A bounded control-path handoff to the owner of protected playback.
//!
//! No thread or socket is started here. A transport submits one bounded request;
//! the playback supervisor explicitly services it outside its render callback.
//! Capacity checks never wait. Only the transport waits for a bounded reply.
//! A timeout or lost reply does not prove that a started command was unapplied.
//! Request payload caps are not a measured heap or legacy-target resource budget.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use franken_control::fsonos::{Handled, HttpRequest, Ingress};
use franken_session::UnifiedGroupSession;

use crate::settled_render::{ControlResult, OwnerError};

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMailboxError {
    InvalidLimits,
    TooLarge,
    TooManyHeaders,
    Busy,
    Unavailable,
    /// Before submission this is a refusal. After submission the outcome may
    /// have been committed before the owner or reply channel disappeared.
    Disconnected,
    TimeoutOutcomeUnknown,
}

#[derive(Debug, Clone, Copy)]
pub struct HttpMailboxConfig {
    max_request_bytes: usize,
    max_headers: usize,
    response_timeout: Duration,
}

impl HttpMailboxConfig {
    pub fn new(
        max_request_bytes: usize,
        max_headers: usize,
        response_timeout: Duration,
    ) -> Result<Self, HttpMailboxError> {
        if max_request_bytes == 0
            || max_request_bytes > MAX_REQUEST_BYTES
            || max_headers == 0
            || max_headers > MAX_HEADERS
            || response_timeout.is_zero()
            || response_timeout > MAX_RESPONSE_TIMEOUT
        {
            return Err(HttpMailboxError::InvalidLimits);
        }
        Ok(Self {
            max_request_bytes,
            max_headers,
            response_timeout,
        })
    }

    fn validate(self, request: &HttpRequest<'_>) -> Result<(), HttpMailboxError> {
        if request.headers.len() > self.max_headers {
            return Err(HttpMailboxError::TooManyHeaders);
        }
        let mut bytes = request
            .method
            .len()
            .checked_add(request.path.len())
            .and_then(|n| n.checked_add(request.body.len()))
            .ok_or(HttpMailboxError::TooLarge)?;
        for (name, value) in request.headers {
            bytes = bytes
                .checked_add(name.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(HttpMailboxError::TooLarge)?;
        }
        if bytes > self.max_request_bytes {
            return Err(HttpMailboxError::TooLarge);
        }
        Ok(())
    }
}

/// The real owner's response and read-only diagnostic snapshot. Copying this
/// snapshot is control-path host-development work, not a render-time operation
/// or evidence of a bounded deployment profile. It carries no recovered grant.
#[derive(Debug)]
pub struct OwnedHttpReply {
    pub result: Result<ControlResult<Handled>, OwnerError>,
    pub session: UnifiedGroupSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpService {
    Idle,
    Expired,
    /// A reply was queued. This is neither a hardware ACK nor client receipt.
    Replied,
    /// The handler ran but the client left; its command may have committed.
    ReplyLost,
}

struct OwnedRequest {
    method: String,
    path: String,
    peer_ip: IpAddr,
    ingress: Ingress,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl OwnedRequest {
    fn copy(request: &HttpRequest<'_>) -> Self {
        Self {
            method: request.method.into(),
            path: request.path.into(),
            peer_ip: request.peer_ip,
            ingress: request.ingress,
            headers: request
                .headers
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
            body: request.body.into(),
        }
    }

    fn with_view<T>(&self, handler: impl FnOnce(HttpRequest<'_>) -> T) -> T {
        let headers: Vec<_> = self
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        handler(HttpRequest {
            method: &self.method,
            path: &self.path,
            peer_ip: self.peer_ip,
            ingress: self.ingress,
            headers: &headers,
            body: &self.body,
        })
    }
}

struct Permit(Arc<AtomicBool>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Envelope {
    request: OwnedRequest,
    reply: SyncSender<OwnedHttpReply>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    // Last, so request storage and the reply sender drop before capacity opens.
    _permit: Permit,
}

impl Envelope {
    fn expired(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
}

struct Shared {
    slot: Mutex<Option<Envelope>>,
    busy: Arc<AtomicBool>,
    connected: AtomicBool,
}

#[derive(Clone)]
pub struct HttpMailboxClient {
    shared: Arc<Shared>,
    config: HttpMailboxConfig,
}

pub struct HttpMailboxOwner {
    shared: Arc<Shared>,
}

/// An admitted request. Dropping it cancels queued work, but cannot roll back
/// a handler that already started. A subsequent submit can reclaim the orphan.
pub struct PendingHttp {
    reply: Receiver<OwnedHttpReply>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

pub fn http_mailbox(
    config: HttpMailboxConfig,
) -> Result<(HttpMailboxClient, HttpMailboxOwner), HttpMailboxError> {
    let config = HttpMailboxConfig::new(
        config.max_request_bytes,
        config.max_headers,
        config.response_timeout,
    )?;
    let shared = Arc::new(Shared {
        slot: Mutex::new(None),
        busy: Arc::new(AtomicBool::new(false)),
        connected: AtomicBool::new(true),
    });
    Ok((
        HttpMailboxClient {
            shared: Arc::clone(&shared),
            config,
        },
        HttpMailboxOwner { shared },
    ))
}

impl HttpMailboxClient {
    pub fn submit(&self, request: &HttpRequest<'_>) -> Result<PendingHttp, HttpMailboxError> {
        self.config.validate(request)?;
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(HttpMailboxError::Disconnected);
        }
        let deadline = Instant::now()
            .checked_add(self.config.response_timeout)
            .ok_or(HttpMailboxError::InvalidLimits)?;
        // A cancelled/expired queued entry can be retired by a new submit.
        // An executing entry is absent from the slot but retains the busy permit.
        {
            let mut slot = self.shared.slot.try_lock().map_err(|error| match error {
                TryLockError::WouldBlock => HttpMailboxError::Busy,
                TryLockError::Poisoned(_) => HttpMailboxError::Unavailable,
            })?;
            if slot.as_ref().is_some_and(Envelope::expired) {
                *slot = None;
            }
        }
        self.shared
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HttpMailboxError::Busy)?;
        let permit = Permit(Arc::clone(&self.shared.busy));
        let owned = OwnedRequest::copy(request);
        let (reply, received) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut slot = self.shared.slot.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => HttpMailboxError::Busy,
            TryLockError::Poisoned(_) => HttpMailboxError::Unavailable,
        })?;
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(HttpMailboxError::Disconnected);
        }
        if slot.is_some() {
            return Err(HttpMailboxError::Busy);
        }
        *slot = Some(Envelope {
            request: owned,
            reply,
            cancelled: Arc::clone(&cancelled),
            deadline,
            _permit: permit,
        });
        Ok(PendingHttp {
            reply: received,
            cancelled,
            deadline,
        })
    }
}

impl PendingHttp {
    /// Wait only on the HTTP/control transport side, never on the renderer.
    pub fn wait(self) -> Result<OwnedHttpReply, HttpMailboxError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HttpMailboxError::TimeoutOutcomeUnknown);
        }
        self.reply
            .recv_timeout(remaining)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => HttpMailboxError::TimeoutOutcomeUnknown,
                RecvTimeoutError::Disconnected => HttpMailboxError::Disconnected,
            })
    }
}

impl Drop for PendingHttp {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl HttpMailboxOwner {
    /// Service at most one request outside the render callback. The slot lock
    /// is released before constructing a view or invoking application code.
    pub fn service_one(
        &mut self,
        handler: impl FnOnce(HttpRequest<'_>) -> OwnedHttpReply,
    ) -> Result<HttpService, HttpMailboxError> {
        let envelope = match self.shared.slot.try_lock() {
            Ok(mut slot) => slot.take(),
            Err(TryLockError::WouldBlock) => return Ok(HttpService::Idle),
            Err(TryLockError::Poisoned(_)) => return Err(HttpMailboxError::Unavailable),
        };
        let Some(envelope) = envelope else {
            return Ok(HttpService::Idle);
        };
        if envelope.expired() {
            return Ok(HttpService::Expired);
        }
        let reply = envelope.request.with_view(handler);
        Ok(if envelope.reply.try_send(reply).is_ok() {
            HttpService::Replied
        } else {
            HttpService::ReplyLost
        })
    }
}

impl Drop for HttpMailboxOwner {
    fn drop(&mut self) {
        self.shared.connected.store(false, Ordering::Release);
        // Destruction is not a render operation. This only waits for the tiny
        // internal slot publication; application code never runs under it.
        match self.shared.slot.lock() {
            Ok(mut slot) => *slot = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_control::fsonos::HttpResponse;
    use std::net::{IpAddr, Ipv4Addr};

    fn config() -> HttpMailboxConfig {
        HttpMailboxConfig::new(1024, 8, Duration::from_millis(500)).unwrap()
    }
    fn request() -> HttpRequest<'static> {
        HttpRequest {
            method: "GET",
            path: "/state",
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ingress: Ingress::Tailnet,
            headers: &[("x-test", "value")],
            body: b"body",
        }
    }
    fn reply() -> OwnedHttpReply {
        OwnedHttpReply {
            result: Ok(ControlResult {
                control: Handled {
                    response: HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: "actual handler".into(),
                    },
                    notifications: Vec::new(),
                    settled_others: Vec::new(),
                },
                render: Ok(crate::settled_render::RenderApplication::WaitingJoin),
                notifications: Vec::new(),
            }),
            session: UnifiedGroupSession::new("group", "issuer", 1),
        }
    }

    #[test]
    fn valid_request_reaches_one_handler_and_copies_every_transport_field() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        assert!(matches!(
            client.clone().submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert_eq!(
            owner.service_one(|view| {
                assert_eq!(view.method, "GET");
                assert_eq!(view.path, "/state");
                assert_eq!(view.headers, &[("x-test", "value")]);
                assert_eq!(view.body, b"body");
                assert_eq!(view.ingress, Ingress::Tailnet);
                assert_eq!(view.peer_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert!(matches!(
                    client.submit(&request()),
                    Err(HttpMailboxError::Busy)
                ));
                reply()
            }),
            Ok(HttpService::Replied)
        );
        assert_eq!(
            pending
                .wait()
                .unwrap()
                .result
                .unwrap()
                .control
                .response
                .body,
            "actual handler"
        );
        assert_eq!(
            owner.service_one(|_| panic!("no duplicate handler")),
            Ok(HttpService::Idle)
        );
        assert!(client.submit(&request()).is_ok());
    }

    #[test]
    fn dropped_and_expired_queued_requests_are_reclaimed_without_owner_polling() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        drop(client.submit(&request()).unwrap());
        let mut pending = client.submit(&request()).unwrap();
        {
            let mut slot = client.shared.slot.lock().unwrap();
            let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            slot.as_mut().unwrap().deadline = expired;
            pending.deadline = expired;
        }
        assert!(matches!(
            pending.wait(),
            Err(HttpMailboxError::TimeoutOutcomeUnknown)
        ));
        let fresh = client.submit(&request()).unwrap();
        assert_eq!(owner.service_one(|_| reply()), Ok(HttpService::Replied));
        assert_eq!(
            fresh
                .wait()
                .unwrap()
                .result
                .unwrap()
                .control
                .response
                .status,
            200
        );
    }

    #[test]
    fn expired_owner_service_skips_handler_but_permitted_successor_still_works() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        drop(pending);
        assert_eq!(
            owner.service_one(|_| panic!("cancelled request ran")),
            Ok(HttpService::Expired)
        );
        let pending = client.submit(&request()).unwrap();
        assert_eq!(owner.service_one(|_| reply()), Ok(HttpService::Replied));
        assert!(pending.wait().is_ok());
    }

    #[test]
    fn lost_reply_reports_executed_work_without_reapplying_or_retaining_capacity() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        let mut effects = 0;
        assert_eq!(
            owner.service_one(|_| {
                effects += 1;
                drop(pending);
                reply()
            }),
            Ok(HttpService::ReplyLost)
        );
        assert_eq!(effects, 1);
        assert_eq!(
            owner.service_one(|_| panic!("reply loss replayed command")),
            Ok(HttpService::Idle)
        );
        assert!(client.submit(&request()).is_ok());
    }

    #[test]
    fn request_and_header_caps_refuse_before_consuming_the_single_slot() {
        assert!(matches!(
            HttpMailboxConfig::new(0, 1, Duration::from_secs(1)),
            Err(HttpMailboxError::InvalidLimits)
        ));
        assert!(matches!(
            HttpMailboxConfig::new(1, 65, Duration::from_secs(1)),
            Err(HttpMailboxError::InvalidLimits)
        ));
        assert!(matches!(
            HttpMailboxConfig::new(1, 1, Duration::ZERO),
            Err(HttpMailboxError::InvalidLimits)
        ));
        assert!(matches!(
            HttpMailboxConfig::new(1, 1, Duration::from_secs(2)),
            Err(HttpMailboxError::InvalidLimits)
        ));
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let data = [0_u8; 1025];
        let mut too_large = request();
        too_large.body = &data;
        assert!(matches!(
            client.submit(&too_large),
            Err(HttpMailboxError::TooLarge)
        ));
        let many = [("name", "value"); 9];
        let mut too_many = request();
        too_many.headers = &many;
        assert!(matches!(
            client.submit(&too_many),
            Err(HttpMailboxError::TooManyHeaders)
        ));
        let pending = client.submit(&request()).unwrap();
        assert_eq!(owner.service_one(|_| reply()), Ok(HttpService::Replied));
        assert!(pending.wait().is_ok());
    }

    #[test]
    fn owner_drop_disconnects_pending_work_and_refuses_later_submissions() {
        let (client, owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        drop(owner);
        assert!(matches!(
            pending.wait(),
            Err(HttpMailboxError::Disconnected)
        ));
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Disconnected)
        ));
    }
}
