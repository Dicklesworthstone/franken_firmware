//! The `fsonos` compatibility adapter: the bounded server side of the UPnP/SOAP/GENA surface the
//! `fsonos` controller speaks (G03 / `ffw-xvv`), slice 1.
//!
//! * [`xml`]: a bounded pull reader and an escaper. It refuses, before allocating, anything over its
//!   byte, depth, element, attribute and length caps, and refuses DTDs, entities, comments, CDATA and
//!   processing instructions outright, so none of the XML attacks that need them can happen.
//! * [`soap`]: parsing one call and building the response or fault, with fixed-word faults.
//! * [`actions`]: the action matrix (every action the controller side sends, with measured call-site
//!   counts), strict argument validation, and the mapping onto commands.
//! * [`state`]: what the endpoint reports, read from the live session at the moment it is asked.
//! * [`gena`]: a bounded subscription table with expiry, renewal, per-subscriber deltas and `SEQ`
//!   wrap, and the event bodies, which carry the state revision.
//! * [`server`]: the request handler. It routes, applies the ingress policy, and turns every command
//!   into an N02 control request so N02's authentication, limits, lease check and exactly-once
//!   application apply to it.
//! * [`ssdp`]: discovery and the device description, slice 2: a bounded `M-SEARCH` parser, the search
//!   responses and `NOTIFY alive`/`byebye` datagrams, and the description document, for exactly the
//!   services served. It builds and parses bytes only; the transport owns the multicast group, the
//!   clock and the entropy for the response delay.
//!
//! `docs/contracts/g03.md` is the contract: the action matrix, the access policy, what is deferred and
//! why, and the one acceptance clause this slice leaves open.
//!
//! Nothing here opens a socket or reads a clock.

pub mod actions;
pub mod gena;
pub mod server;
pub mod soap;
pub mod ssdp;
pub mod state;
pub mod xml;

#[cfg(test)]
mod replay;

pub use actions::{ActionSpec, Cmd, MATRIX, Plan, Read};
pub use gena::{GenaConfig, GenaError, Notification, SubscribeGrant, SubscriptionTable};
pub use server::{
    Context, Endpoint, EndpointConfig, EndpointError, Handled, HttpRequest, HttpResponse, Ingress,
    LegacyBridge,
};
pub use soap::{Fault, Service, SoapCall};
pub use state::{Directory, EventState, TransportState};
pub use xml::XmlLimits;
