//! A bounded control-path handoff to the owner of protected playback.
//!
//! No thread or socket is started here. A transport submits one bounded request;
//! the playback supervisor explicitly services it outside its render callback.
//! Capacity checks never wait. Only the transport waits for a bounded reply.
//! A timeout or lost reply does not prove that a started command was unapplied.
//! Request payload caps are not a measured heap or legacy-target resource budget.

use std::net::IpAddr;
#[cfg(any(test, feature = "harness"))]
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    reply: SyncSender<TrackedReply>,
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
    identity: Arc<()>,
    slot: Mutex<Option<Envelope>>,
    // Updated under slot's lock, after publication and on every removal.
    // Empty owner polls must not compete with the transport's try_lock.
    published: AtomicBool,
    busy: Arc<AtomicBool>,
    connected: AtomicBool,
    lost_replies: AtomicUsize,
    lost_notifications: AtomicUsize,
    #[cfg(any(test, feature = "harness"))]
    eventing_state: AtomicU8,
    #[cfg(any(test, feature = "harness"))]
    delivery_terminal: Mutex<Option<Arc<AtomicBool>>>,
}

/// Saturating counts of produced owner replies abandoned before consumption.
/// These are not callback-delivery counts. The two relaxed counter reads are
/// independently monotonic, not a transactional snapshot. A maximum value
/// means at least that many losses; reading does not reset either counter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpMailboxDiagnostics {
    pub lost_replies: usize,
    pub lost_notifications: usize,
}

impl Shared {
    fn diagnostics(&self) -> HttpMailboxDiagnostics {
        HttpMailboxDiagnostics {
            lost_replies: self.lost_replies.load(Ordering::Relaxed),
            lost_notifications: self.lost_notifications.load(Ordering::Relaxed),
        }
    }

    fn note_lost_reply(&self, reply: &OwnedHttpReply) {
        let notifications = reply.result.as_ref().map_or(0, |result| {
            result
                .control
                .notifications
                .len()
                .saturating_add(result.notifications.len())
        });
        for (counter, count) in [
            (&self.lost_replies, 1),
            (&self.lost_notifications, notifications),
        ] {
            let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(count))
            });
        }
    }
}

// Count actual notification loss even if try_send succeeds and the receiver
// is then dropped. Merely checking the send result misses that race.
struct TrackedReply {
    reply: Option<OwnedHttpReply>,
    shared: Arc<Shared>,
}

impl TrackedReply {
    fn consume(mut self) -> OwnedHttpReply {
        self.reply.take().expect("tracked reply has one value")
    }
}

impl Drop for TrackedReply {
    fn drop(&mut self) {
        if let Some(reply) = &self.reply {
            self.shared.note_lost_reply(reply);
        }
    }
}

#[derive(Clone)]
pub struct HttpMailboxClient {
    shared: Arc<Shared>,
    config: HttpMailboxConfig,
}

pub struct HttpMailboxOwner {
    shared: Arc<Shared>,
    association: ServiceAssociation,
}

enum ServiceAssociation {
    Unbound,
    Generic,
    Owned(Arc<()>),
}

/// Stable per-instance identity, private to actual owner composition. It is
/// not a group name, credential, cloneable public handle or recovered grant.
pub(crate) struct HttpOwnerIdentity {
    identity: Arc<()>,
    mailbox: Option<Arc<()>>,
}

impl HttpOwnerIdentity {
    pub(crate) fn new() -> Self {
        Self {
            identity: Arc::new(()),
            mailbox: None,
        }
    }
}

pub(crate) struct HttpOwnerPermit {
    owner: Arc<()>,
    mailbox: Arc<()>,
}

/// Only the isolated transport can acquire this non-cloneable capability.
/// One eventing HTTP worker serializes responses and their notification offers;
/// every raw/cloned client stays fenced after worker exit until its actual
/// endpoint owner invalidates stale subscriptions and completes cleanup.
#[cfg(any(test, feature = "harness"))]
pub(crate) struct AttachedHttpMailboxClient {
    client: HttpMailboxClient,
}

#[cfg(any(test, feature = "harness"))]
impl AttachedHttpMailboxClient {
    pub(crate) fn submit(
        &self,
        request: &HttpRequest<'_>,
    ) -> Result<PendingHttp, HttpMailboxError> {
        self.client.submit_inner(request, true)
    }
}

#[cfg(any(test, feature = "harness"))]
impl Drop for AttachedHttpMailboxClient {
    fn drop(&mut self) {
        self.client
            .shared
            .eventing_state
            .store(2, Ordering::Release);
    }
}

/// An admitted request. Dropping it cancels queued work, but cannot roll back
/// a handler that already started. A subsequent submit can reclaim the orphan.
pub struct PendingHttp {
    reply: Receiver<TrackedReply>,
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
        identity: Arc::new(()),
        slot: Mutex::new(None),
        published: AtomicBool::new(false),
        busy: Arc::new(AtomicBool::new(false)),
        connected: AtomicBool::new(true),
        lost_replies: AtomicUsize::new(0),
        lost_notifications: AtomicUsize::new(0),
        #[cfg(any(test, feature = "harness"))]
        eventing_state: AtomicU8::new(0),
        #[cfg(any(test, feature = "harness"))]
        delivery_terminal: Mutex::new(None),
    });
    Ok((
        HttpMailboxClient {
            shared: Arc::clone(&shared),
            config,
        },
        HttpMailboxOwner {
            shared,
            association: ServiceAssociation::Unbound,
        },
    ))
}

impl HttpMailboxClient {
    pub fn submit(&self, request: &HttpRequest<'_>) -> Result<PendingHttp, HttpMailboxError> {
        self.submit_inner(request, false)
    }

    #[must_use]
    pub fn diagnostics(&self) -> HttpMailboxDiagnostics {
        self.shared.diagnostics()
    }

    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn attach_eventing(
        &self,
        delivery_terminal: Arc<AtomicBool>,
    ) -> Result<AttachedHttpMailboxClient, HttpMailboxError> {
        let mut slot = self.shared.slot.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => HttpMailboxError::Busy,
            TryLockError::Poisoned(_) => HttpMailboxError::Unavailable,
        })?;
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(HttpMailboxError::Disconnected);
        }
        if slot.as_ref().is_some_and(Envelope::expired) {
            *slot = None;
            self.shared.published.store(false, Ordering::Release);
        }
        if slot.is_some() || self.shared.busy.load(Ordering::Acquire) {
            return Err(HttpMailboxError::Busy);
        }
        let mut terminal =
            self.shared
                .delivery_terminal
                .try_lock()
                .map_err(|error| match error {
                    TryLockError::WouldBlock => HttpMailboxError::Busy,
                    TryLockError::Poisoned(_) => HttpMailboxError::Unavailable,
                })?;
        if terminal.is_some() {
            return Err(HttpMailboxError::Busy);
        }
        self.shared
            .eventing_state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HttpMailboxError::Busy)?;
        *terminal = Some(delivery_terminal);
        Ok(AttachedHttpMailboxClient {
            client: self.clone(),
        })
    }

    fn check_attachment(&self, attached: bool) -> Result<(), HttpMailboxError> {
        let _ = attached;
        #[cfg(any(test, feature = "harness"))]
        if self.shared.eventing_state.load(Ordering::Acquire) != u8::from(attached) {
            return Err(HttpMailboxError::Busy);
        }
        Ok(())
    }

    fn submit_inner(
        &self,
        request: &HttpRequest<'_>,
        attached: bool,
    ) -> Result<PendingHttp, HttpMailboxError> {
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
            self.check_attachment(attached)?;
            if slot.as_ref().is_some_and(Envelope::expired) {
                *slot = None;
                self.shared.published.store(false, Ordering::Release);
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
        // A raw submit may have passed its first check just before attachment.
        // Recheck under the publication lock; it must not enter the owner slot.
        self.check_attachment(attached)?;
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
        self.shared.published.store(true, Ordering::Release);
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
            .map(TrackedReply::consume)
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
    /// Both mutable instances are exclusively borrowed while association is
    /// checked and latched. A second owner or a second mailbox cannot reuse
    /// either half; no caller-supplied string can stand in for instance identity.
    pub(crate) fn associate_owner(
        &mut self,
        owner: &mut HttpOwnerIdentity,
    ) -> Result<HttpOwnerPermit, HttpMailboxError> {
        if owner
            .mailbox
            .as_ref()
            .is_some_and(|id| !Arc::ptr_eq(id, &self.shared.identity))
        {
            return Err(HttpMailboxError::Unavailable);
        }
        match &self.association {
            ServiceAssociation::Generic => return Err(HttpMailboxError::Unavailable),
            ServiceAssociation::Owned(id) if !Arc::ptr_eq(id, &owner.identity) => {
                return Err(HttpMailboxError::Unavailable);
            }
            _ => {}
        }
        owner.mailbox = Some(Arc::clone(&self.shared.identity));
        self.association = ServiceAssociation::Owned(Arc::clone(&owner.identity));
        self.owner_permit(owner)
    }

    pub(crate) fn owner_permit(
        &self,
        owner: &HttpOwnerIdentity,
    ) -> Result<HttpOwnerPermit, HttpMailboxError> {
        let ServiceAssociation::Owned(id) = &self.association else {
            return Err(HttpMailboxError::Unavailable);
        };
        if !Arc::ptr_eq(id, &owner.identity)
            || !owner
                .mailbox
                .as_ref()
                .is_some_and(|mailbox| Arc::ptr_eq(mailbox, &self.shared.identity))
        {
            return Err(HttpMailboxError::Unavailable);
        }
        Ok(HttpOwnerPermit {
            owner: Arc::clone(id),
            mailbox: Arc::clone(&self.shared.identity),
        })
    }

    fn check_owner(&self, permit: &HttpOwnerPermit) -> Result<(), HttpMailboxError> {
        if let ServiceAssociation::Owned(owner) = &self.association
            && Arc::ptr_eq(owner, &permit.owner)
            && Arc::ptr_eq(&self.shared.identity, &permit.mailbox)
        {
            return Ok(());
        }
        Err(HttpMailboxError::Unavailable)
    }

    pub(crate) fn service_owned(
        &mut self,
        permit: &HttpOwnerPermit,
        handler: impl FnOnce(HttpRequest<'_>) -> OwnedHttpReply,
    ) -> Result<HttpService, HttpMailboxError> {
        self.check_owner(permit)?;
        self.service_inner(handler)
    }

    #[must_use]
    pub fn diagnostics(&self) -> HttpMailboxDiagnostics {
        self.shared.diagnostics()
    }

    /// Only the actual endpoint owner may reopen a detached event transport.
    /// No application code runs under the publication lock. A panic while
    /// invalidating leaves the mailbox fenced in Cleaning, never reopened.
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn finish_eventing(
        &mut self,
        permit: &HttpOwnerPermit,
        invalidate: impl FnOnce() -> usize,
    ) -> Result<usize, HttpMailboxError> {
        self.check_owner(permit)?;
        let mut slot = self.shared.slot.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => HttpMailboxError::Busy,
            TryLockError::Poisoned(_) => HttpMailboxError::Unavailable,
        })?;
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(HttpMailboxError::Disconnected);
        }
        if self.shared.eventing_state.load(Ordering::Acquire) != 2 {
            return Err(HttpMailboxError::Busy);
        }
        if slot.as_ref().is_some_and(Envelope::expired) {
            *slot = None;
            self.shared.published.store(false, Ordering::Release);
        }
        if slot.is_some() || self.shared.busy.load(Ordering::Acquire) {
            return Err(HttpMailboxError::Busy);
        }
        let mut terminal =
            self.shared
                .delivery_terminal
                .try_lock()
                .map_err(|error| match error {
                    TryLockError::WouldBlock => HttpMailboxError::Busy,
                    TryLockError::Poisoned(_) => HttpMailboxError::Unavailable,
                })?;
        if !terminal
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(HttpMailboxError::Busy);
        }
        self.shared.eventing_state.store(3, Ordering::Release);
        *terminal = None;
        drop(terminal);
        drop(slot);
        let removed = invalidate();
        self.shared.eventing_state.store(0, Ordering::Release);
        Ok(removed)
    }

    /// Service at most one request outside the render callback. The slot lock
    /// is released before constructing a view or invoking application code.
    /// This compatibility API selects generic service, even when idle. A
    /// mailbox already associated with a protected owner refuses it; generic
    /// mailboxes cannot later be adopted by a protected owner.
    pub fn service_one(
        &mut self,
        handler: impl FnOnce(HttpRequest<'_>) -> OwnedHttpReply,
    ) -> Result<HttpService, HttpMailboxError> {
        if matches!(self.association, ServiceAssociation::Owned(_)) {
            return Err(HttpMailboxError::Unavailable);
        }
        self.association = ServiceAssociation::Generic;
        self.service_inner(handler)
    }

    fn service_inner(
        &mut self,
        handler: impl FnOnce(HttpRequest<'_>) -> OwnedHttpReply,
    ) -> Result<HttpService, HttpMailboxError> {
        if !self.shared.published.load(Ordering::Acquire) {
            return if self.shared.slot.is_poisoned() {
                Err(HttpMailboxError::Unavailable)
            } else {
                Ok(HttpService::Idle)
            };
        }
        let envelope = match self.shared.slot.try_lock() {
            Ok(mut slot) => {
                let envelope = slot.take();
                self.shared.published.store(false, Ordering::Release);
                envelope
            }
            Err(TryLockError::WouldBlock) => return Ok(HttpService::Idle),
            Err(TryLockError::Poisoned(_)) => return Err(HttpMailboxError::Unavailable),
        };
        let Some(envelope) = envelope else {
            return Ok(HttpService::Idle);
        };
        if envelope.expired() {
            return Ok(HttpService::Expired);
        }
        let reply = TrackedReply {
            reply: Some(envelope.request.with_view(handler)),
            shared: Arc::clone(&self.shared),
        };
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
        self.shared.published.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_control::fsonos::HttpResponse;
    use std::net::{IpAddr, Ipv4Addr};

    // Unit mechanics use an already-retired modeled delivery worker. Actual
    // socket retirement is tested by the protected-owner callback integration.
    fn terminal_fence() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(true))
    }

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

    fn reply_with_notifications() -> OwnedHttpReply {
        let notice = |seq| franken_control::fsonos::Notification {
            sid: "uuid:00000000-0000-4000-8000-000000000001".into(),
            service: franken_control::fsonos::Service::RenderingControl,
            callback: "http://127.0.0.1:3400/events".into(),
            seq,
            body: "public unit fixture".into(),
        };
        let mut value = reply();
        let result = value.result.as_mut().unwrap();
        result.control.notifications.push(notice(0));
        result.notifications.extend([notice(1), notice(2)]);
        value
    }

    #[test]
    fn consumed_reply_does_not_count_notifications_as_lost() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_one(|_| reply_with_notifications()),
            Ok(HttpService::Replied)
        );
        let delivered_to_transport = pending.wait().unwrap();
        assert_eq!(
            delivered_to_transport
                .result
                .as_ref()
                .unwrap()
                .notifications
                .len(),
            2
        );
        drop(delivered_to_transport);
        assert_eq!(client.diagnostics(), HttpMailboxDiagnostics::default());
        assert_eq!(owner.diagnostics(), client.diagnostics());
    }

    #[test]
    fn queued_reply_abandoned_after_successful_send_counts_both_vectors_once() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_one(|_| reply_with_notifications()),
            Ok(HttpService::Replied)
        );
        assert_eq!(client.diagnostics(), HttpMailboxDiagnostics::default());
        drop(pending);
        assert_eq!(
            client.diagnostics(),
            HttpMailboxDiagnostics {
                lost_replies: 1,
                lost_notifications: 3
            }
        );
        assert_eq!(
            owner.service_one(|_| panic!("not replayed")),
            Ok(HttpService::Idle)
        );
        let next = client.submit(&request()).unwrap();
        assert_eq!(owner.service_one(|_| reply()), Ok(HttpService::Replied));
        assert!(next.wait().is_ok());
        assert_eq!(client.diagnostics().lost_notifications, 3);
    }

    #[test]
    fn begun_handler_outliving_caller_counts_actual_reply_loss_without_replay() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let mut pending = client.submit(&request()).unwrap();
        let (began_tx, began_rx) = mpsc::sync_channel(1);
        let (finish_tx, finish_rx) = mpsc::sync_channel(1);
        let service = std::thread::spawn(move || {
            let result = owner.service_one(|_| {
                began_tx.send(()).unwrap();
                finish_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                reply_with_notifications()
            });
            (result, owner)
        });
        began_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Force caller expiry only after the handler is proven to have begun;
        // thread scheduling must not turn this into a cancelled-before-run case.
        pending.deadline = Instant::now();
        assert!(matches!(
            pending.wait(),
            Err(HttpMailboxError::TimeoutOutcomeUnknown)
        ));
        finish_tx.send(()).unwrap();
        let (result, mut owner) = service.join().unwrap();
        assert_eq!(result, Ok(HttpService::ReplyLost));
        assert_eq!(
            client.diagnostics(),
            HttpMailboxDiagnostics {
                lost_replies: 1,
                lost_notifications: 3
            }
        );
        assert_eq!(
            owner.service_one(|_| panic!("no second execution")),
            Ok(HttpService::Idle)
        );
        assert!(client.submit(&request()).is_ok());
    }

    #[test]
    fn reply_loss_with_no_notifications_and_counter_saturation_are_explicit() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_one(|_| {
                drop(pending);
                reply()
            }),
            Ok(HttpService::ReplyLost)
        );
        assert_eq!(
            client.diagnostics(),
            HttpMailboxDiagnostics {
                lost_replies: 1,
                lost_notifications: 0
            }
        );
        client
            .shared
            .lost_replies
            .store(usize::MAX - 1, Ordering::Relaxed);
        client
            .shared
            .lost_notifications
            .store(usize::MAX - 1, Ordering::Relaxed);
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_one(|_| reply_with_notifications()),
            Ok(HttpService::Replied)
        );
        drop(pending);
        assert_eq!(
            client.diagnostics(),
            HttpMailboxDiagnostics {
                lost_replies: usize::MAX,
                lost_notifications: usize::MAX
            }
        );
        // A cancelled request skipped before handling never produced a reply.
        drop(client.submit(&request()).unwrap());
        assert_eq!(
            owner.service_one(|_| panic!("cancelled")),
            Ok(HttpService::Expired)
        );
        assert_eq!(client.diagnostics().lost_replies, usize::MAX);
    }

    #[test]
    fn eventing_attachment_fences_raw_clones_and_releases_for_normal_use() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let mut identity = HttpOwnerIdentity::new();
        let permit = owner.associate_owner(&mut identity).unwrap();
        let attached = client.attach_eventing(terminal_fence()).unwrap();
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert!(matches!(
            client.clone().submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert!(matches!(
            client.attach_eventing(terminal_fence()),
            Err(HttpMailboxError::Busy)
        ));
        let pending = attached.submit(&request()).unwrap();
        assert_eq!(
            owner.service_owned(&permit, |_| reply()),
            Ok(HttpService::Replied)
        );
        assert!(pending.wait().is_ok());
        drop(attached);
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert_eq!(owner.finish_eventing(&permit, || 0), Ok(0));
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_owned(&permit, |_| reply()),
            Ok(HttpService::Replied)
        );
        assert!(pending.wait().is_ok());
    }

    #[test]
    fn attachment_refuses_queued_and_executing_work_but_reclaims_cancelled_queue() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let pending = client.submit(&request()).unwrap();
        assert!(matches!(
            client.attach_eventing(terminal_fence()),
            Err(HttpMailboxError::Busy)
        ));
        assert_eq!(
            owner.service_one(|_| {
                assert!(matches!(
                    client.attach_eventing(terminal_fence()),
                    Err(HttpMailboxError::Busy)
                ));
                reply()
            }),
            Ok(HttpService::Replied)
        );
        assert!(pending.wait().is_ok());
        drop(client.submit(&request()).unwrap());
        let attached = client.attach_eventing(terminal_fence()).unwrap();
        let pending = attached.submit(&request()).unwrap();
        assert_eq!(owner.service_one(|_| reply()), Ok(HttpService::Replied));
        assert!(pending.wait().is_ok());
        drop(attached);
        drop(owner);
        assert!(matches!(
            client.attach_eventing(terminal_fence()),
            Err(HttpMailboxError::Disconnected)
        ));
    }

    #[test]
    fn attachment_and_raw_publication_never_both_succeed() {
        for _ in 0..64 {
            let (client, _owner) = http_mailbox(config()).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let a = client.clone();
            let b = client.clone();
            let ba = Arc::clone(&barrier);
            let bb = Arc::clone(&barrier);
            let raw = std::thread::spawn(move || {
                ba.wait();
                a.submit(&request())
            });
            let attachment = std::thread::spawn(move || {
                bb.wait();
                b.attach_eventing(terminal_fence())
            });
            barrier.wait();
            let raw = raw.join().unwrap();
            let attachment = attachment.join().unwrap();
            assert!(
                !(raw.is_ok() && attachment.is_ok()),
                "concurrent capability bypass"
            );
        }
    }

    #[test]
    fn owner_and_mailbox_association_is_two_sided_and_generic_service_cannot_bypass() {
        let (_client_a, mut a) = http_mailbox(config()).unwrap();
        let (_client_b, mut b) = http_mailbox(config()).unwrap();
        let mut identity_a = HttpOwnerIdentity::new();
        let mut identity_b = HttpOwnerIdentity::new();
        let permit_a = a.associate_owner(&mut identity_a).unwrap();
        let permit_b = b.associate_owner(&mut identity_b).unwrap();
        assert!(matches!(
            a.associate_owner(&mut identity_b),
            Err(HttpMailboxError::Unavailable)
        ));
        assert!(matches!(
            b.associate_owner(&mut identity_a),
            Err(HttpMailboxError::Unavailable)
        ));
        assert_eq!(
            a.service_one(|_| panic!("generic bypass")),
            Err(HttpMailboxError::Unavailable)
        );
        assert_eq!(
            a.service_owned(&permit_b, |_| panic!("wrong owner")),
            Err(HttpMailboxError::Unavailable)
        );
        assert_eq!(
            a.service_owned(&permit_a, |_| panic!("empty queue")),
            Ok(HttpService::Idle)
        );
        let (_other_client, mut other_box) = http_mailbox(config()).unwrap();
        assert!(matches!(
            other_box.associate_owner(&mut identity_a),
            Err(HttpMailboxError::Unavailable)
        ));
        // A failed association cannot consume the other box for its own owner.
        let mut own_identity = HttpOwnerIdentity::new();
        let permit = other_box.associate_owner(&mut own_identity).unwrap();
        assert_eq!(
            other_box.service_owned(&permit, |_| panic!("empty")),
            Ok(HttpService::Idle)
        );
    }

    #[test]
    fn generic_mailbox_cannot_be_adopted_and_unbound_cleanup_is_refused() {
        let (_client, mut owner) = http_mailbox(config()).unwrap();
        let mut identity = HttpOwnerIdentity::new();
        assert!(matches!(
            owner.owner_permit(&identity),
            Err(HttpMailboxError::Unavailable)
        ));
        assert_eq!(
            owner.service_one(|_| panic!("empty")),
            Ok(HttpService::Idle)
        );
        assert!(matches!(
            owner.associate_owner(&mut identity),
            Err(HttpMailboxError::Unavailable)
        ));
        let (_client, mut fresh_box) = http_mailbox(config()).unwrap();
        assert!(fresh_box.associate_owner(&mut identity).is_ok());
    }

    #[test]
    fn detached_eventing_stays_fenced_until_matching_cleanup_with_no_inflight_work() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let mut identity = HttpOwnerIdentity::new();
        let permit = owner.associate_owner(&mut identity).unwrap();
        let (_other, mut other_box) = http_mailbox(config()).unwrap();
        let mut other_identity = HttpOwnerIdentity::new();
        let wrong = other_box.associate_owner(&mut other_identity).unwrap();
        let attached = client.attach_eventing(terminal_fence()).unwrap();
        assert_eq!(
            owner.finish_eventing(&permit, || panic!("active")),
            Err(HttpMailboxError::Busy)
        );
        let pending = attached.submit(&request()).unwrap();
        drop(attached);
        assert_eq!(
            owner.finish_eventing(&wrong, || panic!("wrong endpoint")),
            Err(HttpMailboxError::Unavailable)
        );
        assert_eq!(
            owner.finish_eventing(&permit, || panic!("queued")),
            Err(HttpMailboxError::Busy)
        );
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert!(matches!(
            client.attach_eventing(terminal_fence()),
            Err(HttpMailboxError::Busy)
        ));
        drop(pending);
        let mut cleaned = false;
        assert_eq!(
            owner.finish_eventing(&permit, || {
                cleaned = true;
                2
            }),
            Ok(2)
        );
        assert!(cleaned);
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_owned(&permit, |_| reply()),
            Ok(HttpService::Replied)
        );
        assert!(pending.wait().is_ok());
        let attached = client.attach_eventing(terminal_fence()).unwrap();
        drop(attached);
    }

    #[test]
    fn cleanup_panic_keeps_mailbox_fenced_instead_of_reopening_stale_subscriptions() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let mut identity = HttpOwnerIdentity::new();
        let permit = owner.associate_owner(&mut identity).unwrap();
        drop(client.attach_eventing(terminal_fence()).unwrap());
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.finish_eventing(&permit, || panic!("invalidation failed"))
        }));
        assert!(failed.is_err());
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert!(matches!(
            client.attach_eventing(terminal_fence()),
            Err(HttpMailboxError::Busy)
        ));
        assert_eq!(
            owner.finish_eventing(&permit, || panic!("no guessed recovery")),
            Err(HttpMailboxError::Busy)
        );
        assert_eq!(
            owner.service_owned(&permit, |_| panic!("no work")),
            Ok(HttpService::Idle)
        );
    }

    #[test]
    fn detached_http_worker_is_not_delivery_terminal_and_cleanup_does_not_guess() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let mut identity = HttpOwnerIdentity::new();
        let permit = owner.associate_owner(&mut identity).unwrap();
        let terminal = Arc::new(AtomicBool::new(false));
        let attached = client.attach_eventing(Arc::clone(&terminal)).unwrap();
        drop(attached);
        assert_eq!(
            owner.finish_eventing(&permit, || panic!("delivery still in flight")),
            Err(HttpMailboxError::Busy)
        );
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Busy)
        ));
        assert!(matches!(
            client.attach_eventing(terminal_fence()),
            Err(HttpMailboxError::Busy)
        ));
        terminal.store(true, Ordering::Release);
        assert_eq!(owner.finish_eventing(&permit, || 1), Ok(1));
        let pending = client.submit(&request()).unwrap();
        assert_eq!(
            owner.service_owned(&permit, |_| reply()),
            Ok(HttpService::Replied)
        );
        assert!(pending.wait().is_ok());
    }

    #[test]
    fn poisoned_unpublished_mailbox_is_unavailable_instead_of_idle() {
        let (client, mut owner) = http_mailbox(config()).unwrap();
        assert_eq!(
            owner.service_one(|_| panic!("empty mailbox")),
            Ok(HttpService::Idle)
        );
        let shared = Arc::clone(&client.shared);
        assert!(
            std::thread::spawn(move || {
                let _slot = shared.slot.lock().unwrap();
                panic!("poison empty publication lock");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            owner.service_one(|_| panic!("poisoned mailbox must not run a handler")),
            Err(HttpMailboxError::Unavailable)
        );
        assert!(matches!(
            client.submit(&request()),
            Err(HttpMailboxError::Unavailable)
        ));
    }

    #[test]
    fn idle_owner_polling_does_not_refuse_sequential_publications() {
        // Each completion is sent only AFTER service_one returns and retires
        // its capacity permit. There is one producer and never an outstanding
        // request when the next submit starts. Busy is therefore spurious.
        const ATTEMPTS: usize = 5_000;
        let (client, mut owner) = http_mailbox(config()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (completed, completion) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || -> Result<usize, String> {
            let mut serviced = 0;
            while !worker_stop.load(Ordering::Acquire) {
                match owner.service_one(|_| reply()) {
                    Ok(HttpService::Idle) => std::thread::yield_now(),
                    Ok(HttpService::Replied) => {
                        serviced += 1;
                        if completed.send(()).is_err() {
                            break;
                        }
                    }
                    other => return Err(format!("owner service: {other:?}")),
                }
            }
            Ok(serviced)
        });
        let mut accepted = 0;
        let mut busy = 0;
        let mut failure = None;
        for _ in 0..ATTEMPTS {
            match client.submit(&request()) {
                Ok(pending) => {
                    if let Err(error) = pending.wait() {
                        failure = Some(format!("reply: {error:?}"));
                        break;
                    }
                    if let Err(error) = completion.recv_timeout(config().response_timeout) {
                        failure = Some(format!("permit retirement: {error:?}"));
                        break;
                    }
                    accepted += 1;
                }
                Err(HttpMailboxError::Busy) => busy += 1,
                Err(error) => {
                    failure = Some(format!("submit: {error:?}"));
                    break;
                }
            }
        }
        // Retire the real worker before any assertion can unwind the test.
        stop.store(true, Ordering::Release);
        drop(completion);
        let serviced = worker.join().expect("owner thread must not panic");
        eprintln!(
            "idle-publication attempts={ATTEMPTS} accepted={accepted} busy={busy} failure={failure:?} serviced={serviced:?}"
        );
        assert!(failure.is_none(), "{failure:?}");
        assert_eq!(accepted + busy, ATTEMPTS);
        assert_eq!(busy, 0, "idle owner polling must not cause a false Busy");
        assert_eq!(serviced.unwrap(), accepted);
    }
}
