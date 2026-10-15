//! One transport policy, not application configuration.
//!
//! Evidence: stp_research/cc2/results.md, "Final recommendation" (slow110);
//! stp_research/fec/results.md, "Decision and limits"; and
//! stp_research/ack/results.md (Adaptive ACK). These are measured policy choices,
//! not a universal reliability guarantee. The public API deliberately has no tuning knobs.

pub(crate) const CC: crate::stp::CongestionPolicy = crate::stp::CongestionPolicy {
    beta: 0.67,
    recovery_rtts: 9,
    rate_rp: 0.98,
    rate_pg: 1.05,
    rate_gs: 4.0,
    time_pg: 2.0,
    time_gs: 8.0,
    loss_threshold: 2,
    loss_timeout_rtts: 2.0,
    event_guard_rtts: 0.5,
    rate_floor_upps: 100_000_000,
    initial_rate_upps: 100_000_000,
    min_growth_uppsps: 25_000_000.0,
    max_growth_uppsps: 500_000_000.0,
    relative_growth_per_rtt: 0.02,
    startup_multiplier: 1.1,
    startup_backoff_rtts: 1.0,
};

pub(crate) const FEC: crate::fec_adapt::AdaptiveFecConfig = crate::fec_adapt::AdaptiveFecConfig {
    eps: 0.5,
    min_loss: 0.005,
    initial_loss: 0.01,
    max_redundancy: 1.0,
    extra_blocks: 1,
    bucket_ns: 1_000_000_000,
    min_packets: 500,
    slot_ns: 60_000_000_000,
    slots: 10,
    window_ns: 600_000_000_000,
};

pub(crate) const ACK: crate::ack::AckPolicy = crate::ack::AckPolicy {
    every_packets: 8,
    max_delay_us: 10_000,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ship_policy_is_the_only_configuration() {
        assert_eq!(CC.initial_rate_upps, 100_000_000);
        assert_eq!(CC.max_growth_uppsps, 500e6);
        assert_eq!(CC.relative_growth_per_rtt, 0.02);
        assert_eq!(CC.startup_multiplier, 1.1);
        assert_eq!(CC.loss_threshold, 2);
        assert_eq!(FEC.eps, 0.5);
        assert_eq!((ACK.every_packets, ACK.max_delay_us), (8, 10_000));
    }
}
