//! Shielded Transport Pigeon: encrypted, optionally reliable UDP.
//!
//! Extracted unchanged from Tenderlink. Tenderlink and New Network call this
//! crate. Nym mixnet support has been removed; STP targets ordinary networks.

#![allow(non_snake_case, non_upper_case_globals)]
#![allow(dead_code, unused_variables, unused_mut, unused_imports, unused_assignments, unused_unsafe)]
#![allow(deprecated)]

mod ship;
pub mod ack;
pub mod fec;
pub mod fec_adapt;
mod loss_trace;
pub mod helpers;
pub mod native_sockets;
pub mod stp;
pub mod receive_memory;
pub mod sequence;
