/// Behavioral rate limiter
/// Tracks requests-per-minute and token-volume per source host.
/// Raises risk score when anomalous patterns are detected.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;
use crate::security::rules_loader::get_rules;

struct HostStats {
    request_timestamps: Vec<u64>,   // unix seconds of recent requests
    token_counts:       Vec<(u64, usize)>, // (unix second, token count)
    block_count:        usize,
}

impl HostStats {
    fn new() -> Self {
        Self { request_timestamps: vec![], token_counts: vec![], block_count: 0 }
    }
}

lazy_static! {
    static ref STATS: Mutex<HashMap<String, HostStats>> = Mutex::new(HashMap::new());
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub struct BehaviorResult {
    pub extra_risk: i32,
    pub reasons:    Vec<String>,
}

/// Call this for every request. Returns extra risk from behavioral analysis.
pub fn check_behavior(host: &str, prompt: &str, was_blocked: bool) -> BehaviorResult {
    let rules = get_rules();
    if !rules.behavioral.enabled {
        return BehaviorResult { extra_risk: 0, reasons: vec![] };
    }

    let now = now_secs();
    let window = 60u64; // 1 minute window
    let token_estimate = prompt.split_whitespace().count();

    let mut stats_map = STATS.lock().unwrap();
    let entry = stats_map.entry(host.to_string()).or_insert_with(HostStats::new);

    // Prune old entries
    entry.request_timestamps.retain(|&t| now - t < window);
    entry.token_counts.retain(|(t, _)| now - t < window);

    // Record this request
    entry.request_timestamps.push(now);
    entry.token_counts.push((now, token_estimate));
    if was_blocked { entry.block_count += 1; }

    let req_count    = entry.request_timestamps.len();
    let token_total: usize = entry.token_counts.iter().map(|(_, c)| c).sum();
    let block_count  = entry.block_count;

    drop(stats_map); // release lock before building result

    let mut extra_risk = 0i32;
    let mut reasons    = Vec::new();

    if req_count > rules.behavioral.max_requests_per_minute {
        extra_risk += 40;
        reasons.push(format!(
            "Rate limit: {} requests/min (max {}) (+40)", req_count,
            rules.behavioral.max_requests_per_minute
        ));
    }

    if token_total > rules.behavioral.max_tokens_per_minute {
        extra_risk += 30;
        reasons.push(format!(
            "Token volume: {} tokens/min (max {}) (+30)", token_total,
            rules.behavioral.max_tokens_per_minute
        ));
    }

    if block_count >= rules.behavioral.repeated_block_threshold {
        extra_risk += 50;
        reasons.push(format!(
            "Repeated blocks: {} blocks for this host (+50)", block_count
        ));
    }

    BehaviorResult { extra_risk, reasons }
}

/// Reset stats for a host (called on approval)
pub fn reset_host(host: &str) {
    let mut stats_map = STATS.lock().unwrap();
    stats_map.remove(host);
}