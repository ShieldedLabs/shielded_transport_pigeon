//! Encrypted, caller-driven UDP message transport with forward error correction.
//!
//! Construct a [`pump::Pump`] and a [`pump::LockfreeEndpoint`] with
//! [`stp::new_pump`] or [`stp::new`]. The application drives the pump; the library
//! creates no threads. The endpoint exchanges messages and lifecycle events
//! through three bounded SPSC rings. Accepted sends do not guarantee delivery.
//!
//! See the repository's `PROTOCOL.md` for the wire specification and
//! `docs/rings-api.html` for the application guide.
#![allow(non_snake_case, non_upper_case_globals)]
#![allow(dead_code, unused_variables, unused_mut, unused_imports, unused_assignments, unused_unsafe)]
#![allow(deprecated)]
mod ship; mod encoding; mod crypto; mod wirehair;
#[doc(hidden)] pub mod blake3 { pub use ::blake3::*; }
mod platform;
#[doc(hidden)] pub mod random;
mod mtu_recovery; pub mod ack; pub mod pump; pub mod fec; pub mod fec_adapt; mod loss_trace; pub mod helpers;
pub mod native_sockets;
#[cfg(feature="research_cohort_observer")] pub mod cohort_observe;
pub mod stp; pub mod receive_memory; pub mod sequence;
#[cfg(feature = "research_budget_diagnostic")] pub mod budget_diagnostic;
pub mod target_validation;
