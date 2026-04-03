/// Dynamic rules engine — loads rules/rules.json at runtime.
/// No recompile needed: edit rules.json and the engine picks up changes
/// on the next request (file mtime is checked on every call).

use std::fs;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

// ── Rule structs (mirror rules.json) ─────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RiskKeyword {
    pub word:     String,
    pub score:    i32,
    pub category: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeRules {
    pub enabled:                bool,
    pub max_files_per_request:  usize,
    pub forbidden_path_patterns: Vec<String>,
    pub allowed_extensions:     Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BehavioralConfig {
    pub enabled:                  bool,
    pub max_prompt_length:        usize,
    pub max_tokens_per_minute:    usize,
    pub max_requests_per_minute:  usize,
    pub repeated_block_threshold: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Thresholds {
    pub block_score:       i32,
    pub high_risk_score:   i32,
    pub max_body_scan_kb:  usize,
    pub max_messages_scan: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    pub risk_keywords:    Vec<RiskKeyword>,
    pub allowed_actions:  Vec<String>,
    pub blocked_actions:  Vec<String>,
    pub ai_sites:         Vec<String>,
    pub local_ai_ports:   Vec<u16>,
    pub thresholds:       Thresholds,
    pub scope_rules:      ScopeRules,
    pub behavioral:       BehavioralConfig,
}

// ── Cached loader ─────────────────────────────────────────────────────────────

struct CachedRules {
    rules:    Rules,
    mtime:    u64,
}

lazy_static! {
    static ref RULES_CACHE: Mutex<Option<CachedRules>> = Mutex::new(None);
}

pub const RULES_PATH: &str = "rules/rules.json";

fn file_mtime(path: &str) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
        .unwrap_or(0)
}

/// Returns a clone of the current rules, reloading from disk if the file changed.
pub fn get_rules() -> Rules {
    let current_mtime = file_mtime(RULES_PATH);
    let mut cache = RULES_CACHE.lock().unwrap();

    let needs_reload = match &*cache {
        None => true,
        Some(c) => c.mtime != current_mtime,
    };

    if needs_reload {
        match fs::read_to_string(RULES_PATH) {
            Ok(content) => {
                match serde_json::from_str::<Rules>(&content) {
                    Ok(rules) => {
                        println!("[Rules] ✅ Loaded rules from {}", RULES_PATH);
                        *cache = Some(CachedRules { rules, mtime: current_mtime });
                    }
                    Err(e) => {
                        eprintln!("[Rules] ⚠  JSON parse error in rules.json: {} — using previous rules", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("[Rules] ⚠  Cannot read rules.json: {} — using previous/default rules", e);
            }
        }
    }

    match &*cache {
        Some(c) => c.rules.clone(),
        None    => default_rules(),
    }
}

/// Minimal safe defaults if rules.json is missing entirely
fn default_rules() -> Rules {
    Rules {
        risk_keywords: vec![
            RiskKeyword { word: "password".into(), score: 60, category: "credential".into() },
            RiskKeyword { word: "secret".into(),   score: 50, category: "credential".into() },
            RiskKeyword { word: "token".into(),     score: 45, category: "credential".into() },
        ],
        allowed_actions:  vec!["ai_query".into(), "read_file".into()],
        blocked_actions:  vec!["delete_file".into(), "exec_command".into()],
        ai_sites:         vec!["chatgpt.com".into(), "claude.ai".into()],
        local_ai_ports:   vec![11434, 8080],
        thresholds:       Thresholds { block_score: 50, high_risk_score: 80, max_body_scan_kb: 512, max_messages_scan: 50 },
        scope_rules:      ScopeRules {
            enabled: true, max_files_per_request: 5,
            forbidden_path_patterns: vec!["../".into(), "/etc/".into()],
            allowed_extensions: vec![".txt".into(), ".md".into(), ".pdf".into()],
        },
        behavioral: BehavioralConfig {
            enabled: true, max_prompt_length: 4000,
            max_tokens_per_minute: 8000, max_requests_per_minute: 30,
            repeated_block_threshold: 3,
        },
    }
}