//! Five std-only application interfaces over the unchanged STP transport.
//!
//! Start with [`Config::new`] (the message-size limit is deliberately required),
//! then choose [`blocking`], [`asynchronous`], [`callback`], [`readiness`] or
//! [`channel`]. All transfer owned message buffers without copying their contents.
//! See `docs/API_STYLES.md` for admission, shutdown and delivery semantics.

pub mod asynchronous;
pub mod blocking;
pub mod callback;
pub mod channel;
mod driver;
pub mod readiness;

use crate::stp::{ConnectionKey, ConnectionStats, IdentityKeyPair, STPAddress};
use std::{net::SocketAddr, time::Duration};

/// Explicit application choices. There is intentionally no `Default` implementation.
/// A nonzero port is required: the legacy core does not report its bound address.
/// Socket startup failures are returned by `open` (the legacy constructor's
/// panic diagnostic is also emitted). The caller's panic=abort build cannot recover.
pub struct Config {
    pub bind: SocketAddr,
    pub keys: Vec<IdentityKeyPair>,
    pub max_message_size: usize,
    /// Maximum adapter-owned sends (including a batch being submitted to the core).
    pub send_slots: usize,
    /// Maximum adapter-owned payload capacity, excluding the core's own send queues.
    pub send_bytes: usize,
    /// Maximum unread events, including lifecycle. The oldest event is evicted
    /// whole on overflow; inspect Stats::dropped_events. A message whose buffer
    /// capacity alone exceeds receive_bytes is discarded whole instead.
    pub receive_slots: usize,
    /// Maximum payload-buffer capacity held in unread events.
    pub receive_bytes: usize,
    /// Core's existing queue target (microseconds), minimum bytes, maximum bytes.
    pub core_send_buffer: (u32, u32, u32),
    pub max_pps: Option<u64>,
    /// Temporary core-service cadence, centralized in one driver. Not a wire policy.
    pub service_interval: Duration,
    /// Idle receive-discovery latency/CPU trade-off. Commands wake immediately;
    /// idle service waits double up to this cap, then reset on observed activity.
    pub idle_service_interval: Duration,
}
impl Config {
    pub fn new(bind: SocketAddr, keys: Vec<IdentityKeyPair>, max_message_size: usize) -> Self {
        Self {
            bind,
            keys,
            max_message_size,
            send_slots: 64,
            send_bytes: max_message_size.saturating_mul(64),
            receive_slots: 64,
            receive_bytes: max_message_size.saturating_mul(64),
            core_send_buffer: (1_000_000, 1 << 20, 1 << 20),
            max_pps: None,
            service_interval: Duration::from_millis(1),
            idle_service_interval: Duration::from_millis(2),
        }
    }
}

/// Full authenticated address and Noise session hash. `ConnectionKey` alone is
/// only the core's compact routing key, NOT an authenticated public identity.
#[derive(Clone, Debug)]
pub struct Peer {
    pub address: std::sync::Arc<STPAddress>,
    pub session: [u8; 64],
}
impl Peer {
    pub fn key(&self) -> ConnectionKey {
        self.address.connection_key()
    }
}

#[derive(Debug)]
pub enum Event {
    Connected(Peer),
    Message {
        peer: Peer,
        data: Vec<u8>,
    },
    Disconnected(Peer),
    /// Admitted buffer later rejected permanently by the core (for example,
    /// peer message-size limit), or its peer disappeared before core admission.
    SendFailed {
        peer: ConnectionKey,
        data: Vec<u8>,
    },
    Closed,
}
impl Event {
    pub fn peer_key(&self) -> Option<ConnectionKey> {
        match self {
            Self::Connected(p) | Self::Disconnected(p) | Self::Message { peer: p, .. } => {
                Some(p.key())
            }
            Self::SendFailed { peer, .. } => Some(*peer),
            Self::Closed => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendErrorKind {
    Full,
    TooLarge,
    NotConnected,
    Closed,
    TimedOut,
}
/// A failed admission returns the original allocation, untouched.
#[derive(Debug)]
pub struct SendError {
    pub kind: SendErrorKind,
    pub data: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    TimedOut,
    Closed,
}
impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "STP message admission: {:?}", self.kind)
    }
}
impl std::error::Error for SendError {}
impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "STP receive: {self:?}")
    }
}
impl std::error::Error for ReceiveError {}
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub connections: Vec<(ConnectionKey, ConnectionStats)>,
    pub queued_sends: usize,
    pub queued_send_bytes: usize,
    pub received_messages: u64,
    pub dropped_receive_messages: u64,
    /// Oldest events evicted at the bounded application event mailbox.
    pub dropped_events: u64,
    pub core_rejections: u64,
}
