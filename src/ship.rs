//! One transport policy, not application configuration.
//!
//! Evidence: stp_research/cc2/results.md, "Final recommendation" (slow110);
//! stp_research/fec/results.md, "Decision and limits"; and
//! stp_research/ack/results.md (Adaptive ACK). These are measured policy choices,
//! not a universal reliability guarantee. The public API deliberately has no tuning knobs.

pub(crate) const CC: crate::stp::CongestionControlOptions = crate::stp::CongestionControlOptions {
    beta: 0.67,
    recovery_rtts: 9,
    rate_rp: 0.98,
    rate_pg: 1.05,
    rate_gs: 4.0,
    time_pg: 2.0,
    time_gs: 8.0,
    loss_threshold: 2,
    loss_fraction_ppm: 0,
    loss_response_fraction_ppm: 0,
    loss_timeout_rtts: 2.0,
    event_guard_rtts: 0.5,
    ecn_event_guard_rtts: 0.0,
    rate_floor_upps: 100_000_000,
    initial_rate_upps: 100_000_000,
    min_growth_uppsps: 25_000_000.0,
    max_growth_uppsps: 500_000_000.0,
    friendly_growth_alpha: 0.0,
    relative_growth_per_rtt: 0.02,
    bound_recovery_growth: true,
    compound_growth: true,
    proportional_growth: false,
    record_loss_episodes: false,
    startup_multiplier: 1.1,
    startup_backoff_rtts: 1.0,
};

pub(crate) const FEC: crate::fec_adapt::AdaptiveFecConfig = crate::fec_adapt::AdaptiveFecConfig {
    kind: crate::fec_adapt::LossEstimatorKind::SpanTail,
    span_floor: crate::fec_adapt::SpanFloorKind::Real,
    eps: 0.5,
    min_loss: 0.005,
    initial_loss: 0.01,
    max_redundancy: 1.0,
    extra_blocks: 1,
    bucket_ns: 1_000_000_000,
    min_packets: 500,
    slot_ns: 60_000_000_000,
    slots: 10,
    half_life_ns: 180_000_000_000,
    window_ns: 600_000_000_000,
    quantile: 0.97,
    topup: true,
    closed_loop: true,
    loss_signal: crate::fec_adapt::LossSignal::NetOfSpurious { delay_ns: 1_000_000_000 },
};

pub(crate) const ACK: crate::ack::AckOptions = crate::ack::AckOptions::Adaptive {
    every_packets: 8,
    max_delay_us: 10_000,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ship_policy_matches_research_flag_mapping() {
        let mut reference = crate::stp::CongestionControlOptions::balanced();
        reference.max_growth_uppsps = 500e6;
        reference.relative_growth_per_rtt = 0.02;
        reference.bound_recovery_growth = true;
        reference.compound_growth = true;
        reference.initial_rate_upps = 100e6 as u64;
        reference.startup_multiplier = 1.1;
        assert_eq!(format!("{CC:?}"), format!("{reference:?}"));
        CC.validate().unwrap();
        let fec = crate::fec_adapt::AdaptiveFecConfig {
            kind: crate::fec_adapt::LossEstimatorKind::SpanTail,
            span_floor: crate::fec_adapt::SpanFloorKind::Real,
            eps: 0.5, topup: true, closed_loop: true,
            ..Default::default()
        };
        assert_eq!(format!("{FEC:?}"), format!("{fec:?}"));
    }
}
