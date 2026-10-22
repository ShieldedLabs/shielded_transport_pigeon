//! Encrypted, caller-driven UDP message transport with forward error correction.
//!
//! Construct a [`pump::Pump`] and a [`pump::LockfreeEndpoint`] with [`stp::new_pump`] or [`stp::new`]. The application
//! drives the pump; the library creates no threads. The endpoint exchanges messages and lifecycle events through three
//! bounded SPSC rings. Accepted sends do not guarantee delivery.
//!
//! See the repository's `PROTOCOL.md` for the wire specification and `docs/rings-api.html` for the application guide.
#![allow(non_snake_case, non_upper_case_globals)]
#![allow(
    dead_code,
    unused_variables,
    unused_mut,
    unused_imports,
    unused_assignments,
    unused_unsafe
)]
#![allow(deprecated)]
mod crypto;
mod encoding;
mod ship;
mod wirehair;
#[doc(hidden)]
pub mod blake3 {
    pub use ::blake3::*;
}
pub mod ack;
#[cfg(feature = "research_budget_diagnostic")]
pub mod budget_diagnostic;
#[cfg(feature = "research_cohort_observer")]
pub mod cohort_observe;
pub mod fec;
pub mod fec_adapt;
pub mod helpers;
mod loss_trace;
mod mtu_recovery;
pub mod native_sockets;
mod platform;
pub mod pump;
#[doc(hidden)]
pub mod random;
pub mod receive_memory;
pub mod sequence;
pub mod stp;
pub mod target_validation;
