//! One transport policy, not application configuration.
//!
//! Evidence: stp_research/cc2/results.md, "Final recommendation" (slow110);
//! stp_research/fec/results.md, "Decision and limits"; and
//! stp_research/ack/results.md (Adaptive ACK). These are measured policy choices,
//! not a universal reliability guarantee. The public API deliberately has no tuning knobs.

pub(crate) const CC: crate::stp::CongestionPolicy = crate::stp::CongestionPolicy {
    beta: 0.8,
    recovery_rtts: 9,
    rate_rp: 0.92,
    rate_pg: 1.02,
    rate_gs: 2.0,
    time_pg: 6.0,
    time_gs: 10.0,
    loss_threshold: 2,
    loss_timeout_rtts: 2.0,
    event_guard_rtts: 0.5,
    rate_floor_upps: 100_000_000,
    initial_rate_upps: 100_000_000,
    min_growth_uppsps: 2_000_000_000.0,
    max_growth_uppsps: 1_000_000_000.0,
    relative_growth_per_rtt: 0.015,
    startup_multiplier: 1.05,
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

/// Frozen c4rand release-candidate design. H = 100/3 is the real-path-tested
/// exposure scale (not the older g4 emulator's 1000/3). Applications do not
/// configure transport policy. Only the research feature permits overrides.
pub(crate) const FROZEN_POLICY: &[(&str, &str)] = &[
    ("STP_CC_DELAY_BETA", "0.5"),
    ("STP_CC_DELAY_EVENT", "1"),
    ("STP_CC_DELAY_GIVEUP", "0"),
    ("STP_CC_DELAY_HOLD_MAX_RTTS", "256"),
    ("STP_CC_DELAY_HOLD_RTTS", "16"),
    ("STP_CC_DELAY_INTERVAL_RTTS", "1"),
    ("STP_CC_DELAY_K", "0.5"),
    ("STP_CC_DELAY_MAX_MS", "50"),
    ("STP_CC_DELAY_MIN_MS", "10"),
    ("STP_P4_BASE_PARITY_MODEL", "0"),
    ("STP_P4_BUDGET_BASE", "1"),
    ("STP_P4_COST_SMOOTH", "1"),
    ("STP_P4_EMPIRICAL_TAIL_CALIBRATION", "1"),
    ("STP_P4_EVENT_REPAIR", "0"),
    ("STP_P4_INTERLEAVE_WIDTH", "1"),
    ("STP_P4_MEDIUM_BONUS_PERCENT", "0"),
    ("STP_P4_REPAIR_CAP_PERCENT", "0"),
    ("STP_P4_SLIPSTREAM", "0"),
    ("STP_P4_TARGET_VALIDATION", "2"),
    ("STP_RACE_POLICY", "P4"),
    ("STP_TV_ALIVE", "1"),
    ("STP_TV_DUP", "1"),
    ("STP_TV_E", "1"),
    ("STP_TV_H", "33.333333333333336"),
    ("STP_TV_P", "0.001"),
    ("STP_TV_RAND", "1"),
    ("STP_TV_RAND_HALF_PKTS", "4000"),
    ("STP_TV_RAND_MAX", "0.05"),
    ("STP_TV_RAND_MULT", "2"),
    ("STP_TV_RISK_EPS", "0.002"),
    ("STP_TV_RISK_HI", "1.02"),
    ("STP_TV_RISK_HI2", "0.7"),
    ("STP_TV_RISK_HOLD_MAX_RTTS", "10"),
    ("STP_TV_RISK_HOLD_RTTS", "1"),
    ("STP_TV_RISK_LO", "0.98"),
    ("STP_TV_RISK_LO2", "0.5"),
    ("STP_TV_RISK_PHI", "0.1"),
    ("STP_TV_RISK_SRC", "4"),
    ("STP_TV_RISK_STEP", "2"),
    ("STP_TV_RISK_TAIL", "3.0"),
    ("STP_COHORT_PROFILE", "b20r20"),
];
pub(crate) fn policy_var(name: &str) -> Result<String, std::env::VarError> {
    #[cfg(feature = "research_target_validation")]
    {
        // Opt out as a whole for predecessor experiments: dependent frozen
        // knobs (TAIL/HOLD/EPS, for example) must not leak into an off arm.
        if std::env::var("STP_POLICY_FROZEN").as_deref() == Ok("0") {
            return std::env::var(name);
        }
        match std::env::var(name) {
            Ok(value) => return Ok(value),
            Err(std::env::VarError::NotPresent) => {},
            Err(error) => return Err(error),
        }
    }
    FROZEN_POLICY.iter().find(|(key, _)| *key == name)
        .map(|(_, value)| (*value).to_owned()).ok_or(std::env::VarError::NotPresent)
}
pub(crate) fn policy_var_os(name: &str) -> Option<std::ffi::OsString> {
    policy_var(name).ok().map(Into::into)
}
