/// AI Chat Analyzer
/// ─────────────────
/// Parses real API payloads from ChatGPT, Claude, Ollama (local models) and:
///   1. Extracts every individual chat message
///   2. Scores each message for risk
///   3. Detects SCOPE CREEP — when an AI response references files/dirs
///      the user never provided
///   4. Detects DATA EXFILTRATION in AI responses
///   5. Returns per-message flags for the dashboard

use serde_json::Value;
use crate::types::{ChatFlag, ChatMessage, ScopeViolation};
use crate::security::rules_loader::get_rules;
use crate::security::risk::calculate_risk;
use crate::types::AIRequest;

// ── Public entry points ───────────────────────────────────────────────────────

/// Parse and analyze a full API request body from an AI site.
/// Returns (flags, total_extra_risk, scope_violations)
pub fn analyze_ai_payload(
    body: &str,
    url: &str,
) -> (Vec<ChatFlag>, i32, Vec<ScopeViolation>) {
    let rules = get_rules();

    // Cap body size to avoid scanning huge streaming responses
    let scan_limit = rules.thresholds.max_body_scan_kb * 1024;
    let body = if body.len() > scan_limit { &body[..scan_limit] } else { body };

    let messages = extract_messages(body, url);
    if messages.is_empty() {
        return (vec![], 0, vec![]);
    }

    let mut flags:      Vec<ChatFlag>      = Vec::new();
    let mut extra_risk: i32               = 0;
    let mut scope_viols: Vec<ScopeViolation> = Vec::new();

    // Collect files the user explicitly mentioned (scope baseline)
    let user_provided_files = collect_user_files(&messages);

    for (idx, msg) in messages.iter().enumerate().take(rules.thresholds.max_messages_scan) {
        // Score the message using the main risk engine
        let req = AIRequest {
            app_id:   "chat_analyzer".into(),
            action:   "chat_message".into(),
            resource: "ai_chat".into(),
            prompt:   Some(msg.content.clone()),
        };
        let risk_result = calculate_risk(&req);

        if risk_result.score > 0 {
            extra_risk += risk_result.score;
            let snippet = msg.content.chars().take(120).collect::<String>();
            flags.push(ChatFlag {
                message_index: idx,
                role:          msg.role.clone(),
                snippet,
                reason:        risk_result.reasons.join("; "),
                risk:          risk_result.score,
            });
        }

        // Scope creep: check if AI *response* references files beyond what user gave
        if msg.role == "assistant" {
            let sv = check_scope_creep(&msg.content, &user_provided_files);
            scope_viols.extend(sv);
        }

        // Data exfiltration in assistant responses
        if msg.role == "assistant" {
            let ef = check_exfiltration_response(&msg.content);
            if ef > 0 {
                extra_risk += ef;
                let snippet = msg.content.chars().take(120).collect::<String>();
                flags.push(ChatFlag {
                    message_index: idx,
                    role: "assistant".into(),
                    snippet,
                    reason: format!("Possible data exfiltration in response (+{})", ef),
                    risk: ef,
                });
            }
        }
    }

    (flags, extra_risk, scope_viols)
}

// ── Message extraction ────────────────────────────────────────────────────────

/// Try to extract chat messages from various AI API formats
fn extract_messages(body: &str, url: &str) -> Vec<ChatMessage> {
    // Skip non-JSON bodies quickly
    let trimmed = body.trim();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return vec![];
    }

    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return vec![];
    };

    // ── OpenAI / ChatGPT format ──
    // POST /v1/chat/completions  { "messages": [{role, content}...] }
    if url.contains("openai.com") || url.contains("chatgpt.com") || url.contains("api.openai") {
        if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
            return parse_openai_messages(msgs);
        }
    }

    // ── Anthropic / Claude format ──
    // POST /v1/messages  { "messages": [{role, content}...], "system": "..." }
    if url.contains("claude.ai") || url.contains("anthropic.com") {
        let mut out = Vec::new();
        // system prompt counts as a message
        if let Some(sys) = v.get("system").and_then(|s| s.as_str()) {
            out.push(ChatMessage { role: "system".into(), content: sys.into() });
        }
        if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
            out.extend(parse_openai_messages(msgs)); // same structure
        }
        if !out.is_empty() { return out; }
    }

    // ── Ollama (local) format ──
    // POST /api/chat  { "messages": [{role,content}...] }
    // POST /api/generate { "prompt": "..." }
    if url.contains("localhost") || url.contains("127.0.0.1") || url.contains("0.0.0.0") {
        if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
            return parse_openai_messages(msgs);
        }
        if let Some(prompt) = v.get("prompt").and_then(|p| p.as_str()) {
            return vec![ChatMessage { role: "user".into(), content: prompt.into() }];
        }
    }

    // ── Generic fallback: any JSON with "messages" array ──
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        let parsed = parse_openai_messages(msgs);
        if !parsed.is_empty() { return parsed; }
    }

    // ── Last resort: treat entire body as one user message ──
    if body.len() < 4096 {
        vec![ChatMessage { role: "user".into(), content: body.into() }]
    } else {
        vec![]
    }
}

fn parse_openai_messages(arr: &[Value]) -> Vec<ChatMessage> {
    arr.iter().filter_map(|m| {
        let role    = m.get("role")?.as_str()?.to_string();
        let content = extract_content_field(m.get("content")?);
        Some(ChatMessage { role, content })
    }).collect()
}

/// Handle both string and array content (OpenAI multi-modal format)
fn extract_content_field(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Array(parts) => {
            // Multi-modal: [{type:"text",text:"..."}, {type:"image_url",...}]
            parts.iter().filter_map(|p| {
                if p.get("type").and_then(|t| t.as_str()) == Some("text") {
                    p.get("text").and_then(|t| t.as_str()).map(|s| s.to_string())
                } else {
                    None
                }
            }).collect::<Vec<_>>().join(" ")
        }
        _ => val.to_string(),
    }
}

// ── Scope creep detection ─────────────────────────────────────────────────────

/// Collect file names/paths the user explicitly mentioned in their messages
fn collect_user_files(messages: &[ChatMessage]) -> Vec<String> {
    let mut files = Vec::new();
    for msg in messages.iter().filter(|m| m.role == "user") {
        for word in msg.content.split_whitespace() {
            // Looks like a filename (has extension, no spaces)
            if word.contains('.') && word.len() > 3 && word.len() < 200
                && !word.contains("http") && !word.contains("www")
            {
                // Extract just the filename part
                let fname = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-');
                if fname.contains('.') {
                    files.push(fname.to_lowercase());
                }
            }
        }
    }
    files
}

/// Check if an AI response mentions files/paths that the user never provided
fn check_scope_creep(response: &str, user_files: &[String]) -> Vec<ScopeViolation> {
    let rules = get_rules();
    let mut viols = Vec::new();
    let lower = response.to_lowercase();

    // Check forbidden path patterns in AI response
    for pattern in &rules.scope_rules.forbidden_path_patterns {
        if lower.contains(&pattern.to_lowercase()) {
            viols.push(ScopeViolation {
                kind:   "path_traversal".into(),
                detail: format!("AI response contains forbidden path: '{}'", pattern),
                risk:   70,
            });
        }
    }

    // Check if response references files that look like system files not given by user
    let system_file_indicators = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "~/.ssh", "~/.bashrc",
        "~/.profile", "/proc/", "C:\\Windows\\System32", "NTUSER.DAT",
        "SAM database", "registry hive", "/var/log/", "/root/",
    ];
    for indicator in system_file_indicators {
        if lower.contains(&indicator.to_lowercase()) {
            viols.push(ScopeViolation {
                kind:   "extra_files".into(),
                detail: format!("AI response references system file not in user context: '{}'", indicator),
                risk:   85,
            });
        }
    }

    // Scope creep: AI mentions many files in its response that user never provided
    let mentioned_files: Vec<&str> = response.split_whitespace()
        .filter(|w| w.contains('.') && w.len() > 3 && w.len() < 200
            && !w.contains("http") && !w.contains("www"))
        .collect();

    let extra_files: Vec<&&str> = mentioned_files.iter()
        .filter(|f| {
            let fl = f.to_lowercase();
            let fl = fl.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-');
            !user_files.iter().any(|uf| uf.contains(fl) || fl.contains(uf.as_str()))
        })
        .collect();

    if extra_files.len() > rules.scope_rules.max_files_per_request {
        viols.push(ScopeViolation {
            kind:   "scope_creep".into(),
            detail: format!(
                "AI response references {} files not provided by user (max {}): {:?}",
                extra_files.len(),
                rules.scope_rules.max_files_per_request,
                &extra_files[..extra_files.len().min(5)]
            ),
            risk:   60,
        });
    }

    viols
}

/// Detect exfiltration-like patterns in AI responses (sending data out)
fn check_exfiltration_response(response: &str) -> i32 {
    let lower = response.to_lowercase();
    let mut score = 0i32;

    let exfil_patterns = [
        ("curl ",         30, "response contains curl command"),
        ("wget ",         30, "response contains wget command"),
        ("http://",       10, "response contains HTTP URL"),
        ("base64 encode", 35, "response suggests base64 encoding"),
        ("send to",       25, "response instructs sending data"),
        ("upload to",     25, "response instructs upload"),
        ("post to",       25, "response instructs POST request"),
        ("exfiltrate",    80, "response uses exfiltration language"),
        ("data leak",     70, "response mentions data leak"),
    ];

    for (pat, pts, _reason) in exfil_patterns {
        if lower.contains(pat) {
            score += pts;
        }
    }
    score
}

// ── Prompt analysis for simple string input ───────────────────────────────────

/// Called from the Rust interceptor for CLI/proxy requests
pub fn analyze_prompt(prompt: &str) -> bool {
    let req = AIRequest {
        app_id:   "analyzer".into(),
        action:   "ai_query".into(),
        resource: "prompt".into(),
        prompt:   Some(prompt.into()),
    };
    let result = calculate_risk(&req);
    let rules  = get_rules();
    if result.score >= rules.thresholds.block_score {
        println!("[Analyzer] ⚠  Suspicious prompt detected (score={}, reasons: {})",
            result.score, result.reasons.join(", "));
        return true;
    }
    false
}