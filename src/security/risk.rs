use crate::types::AIRequest;
use crate::security::rules_loader::get_rules;

pub struct RiskResult {
    pub score:      i32,
    pub reasons:    Vec<String>,
    pub categories: Vec<String>,
}

/// Dynamic risk scorer — reads live rules, no recompile needed.
pub fn calculate_risk(request: &AIRequest) -> RiskResult {
    let rules = get_rules();
    let mut score      = 0i32;
    let mut reasons    = Vec::new();
    let mut categories = std::collections::HashSet::new();

    let text = build_scan_text(request);
    let lower = text.to_lowercase();

    // ── 1. Keyword matching with per-word scores ──────────────────────────────
    for kw in &rules.risk_keywords {
        if lower.contains(&kw.word.to_lowercase()) {
            score += kw.score;
            reasons.push(format!("Keyword '{}' (+{})", kw.word, kw.score));
            categories.insert(kw.category.clone());
        }
    }

    // ── 2. Action-level checks ────────────────────────────────────────────────
    if rules.blocked_actions.contains(&request.action) {
        score += 100;
        reasons.push(format!("Blocked action: '{}'", request.action));
        categories.insert("forbidden_action".into());
    }

    // ── 3. Prompt length anomaly ──────────────────────────────────────────────
    if let Some(prompt) = &request.prompt {
        let len = prompt.len();
        if len > rules.behavioral.max_prompt_length {
            let extra = ((len - rules.behavioral.max_prompt_length) / 500).min(40) as i32;
            score += extra;
            reasons.push(format!("Prompt length {} > max {} (+{})", len, rules.behavioral.max_prompt_length, extra));
            categories.insert("behavioral".into());
        }

        // ── 4. Boundary cases: prompt injection patterns ─────────────────────
        score += check_injection_patterns(prompt, &mut reasons, &mut categories);

        // ── 5. Boundary cases: path traversal in prompt ───────────────────────
        score += check_path_traversal(prompt, &rules, &mut reasons, &mut categories);

        // ── 6. Boundary cases: base64 / encoded payload ───────────────────────
        score += check_encoded_payload(prompt, &mut reasons, &mut categories);

        // ── 7. Boundary cases: repetition / DoS pattern ──────────────────────
        score += check_repetition(prompt, &mut reasons, &mut categories);

        // ── 8. Boundary cases: unicode homoglyph evasion ─────────────────────
        score += check_homoglyph_evasion(prompt, &mut reasons, &mut categories);
    }

    RiskResult {
        score,
        reasons,
        categories: categories.into_iter().collect(),
    }
}

/// Build one string from all parts of the request to scan together
fn build_scan_text(request: &AIRequest) -> String {
    let mut parts = vec![
        request.app_id.clone(),
        request.action.clone(),
        request.resource.clone(),
    ];
    if let Some(p) = &request.prompt {
        parts.push(p.clone());
    }
    parts.join(" ")
}

/// Detect multi-step prompt injection sequences
fn check_injection_patterns(
    text: &str,
    reasons: &mut Vec<String>,
    cats: &mut std::collections::HashSet<String>,
) -> i32 {
    let lower = text.to_lowercase();
    let mut score = 0i32;

    // Classic overrides
    let overrides = [
        ("ignore previous instructions", 95),
        ("forget everything above",      90),
        ("new instructions:",            75),
        ("override your",                80),
        ("your real instructions",       85),
        ("you have no restrictions",     90),
        ("act as a",                     50),
        ("pretend you are",              55),
        ("from now on you",              65),
        ("you are now",                  60),
    ];
    for (pat, pts) in overrides {
        if lower.contains(pat) {
            score += pts;
            reasons.push(format!("Prompt injection pattern: '{}' (+{})", pat, pts));
            cats.insert("prompt_injection".into());
        }
    }

    // Nested instruction delimiters (often used to hide injections)
    let delimiters = ["###", "<<<", ">>>", "---SYSTEM---", "[INST]", "<<SYS>>", "<|im_start|>"];
    for d in delimiters {
        if text.contains(d) {
            score += 40;
            reasons.push(format!("Suspicious delimiter '{}' detected (+40)", d));
            cats.insert("prompt_injection".into());
        }
    }

    // Role/persona impersonation
    let personas = ["gpt-4", "chatgpt", "claude", "gemini", "ai assistant", "language model"];
    for p in personas {
        if lower.contains(&format!("you are {}", p)) || lower.contains(&format!("act as {}", p)) {
            score += 55;
            reasons.push(format!("AI persona impersonation: '{}' (+55)", p));
            cats.insert("prompt_injection".into());
        }
    }

    score
}

/// Detect file path traversal or forbidden system paths
fn check_path_traversal(
    text: &str,
    rules: &crate::security::rules_loader::Rules,
    reasons: &mut Vec<String>,
    cats: &mut std::collections::HashSet<String>,
) -> i32 {
    let mut score = 0i32;
    for pattern in &rules.scope_rules.forbidden_path_patterns {
        if text.to_lowercase().contains(&pattern.to_lowercase()) {
            score += 60;
            reasons.push(format!("Forbidden path pattern '{}' (+60)", pattern));
            cats.insert("path_traversal".into());
        }
    }
    // Traversal sequences
    if text.contains("../") || text.contains("..\\") {
        score += 55;
        reasons.push("Directory traversal sequence '../' (+55)".into());
        cats.insert("path_traversal".into());
    }
    score
}

/// Detect base64-encoded or hex-encoded payloads that try to hide content
fn check_encoded_payload(
    text: &str,
    reasons: &mut Vec<String>,
    cats: &mut std::collections::HashSet<String>,
) -> i32 {
    // A long run of base64 chars (40+) suggests hidden payload
    let b64_run = text.chars()
        .collect::<String>()
        .split_whitespace()
        .filter(|w| w.len() >= 40 && w.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='))
        .count();
    if b64_run > 0 {
        reasons.push(format!("Possible base64 encoded payload ({} chunks) (+35)", b64_run));
        cats.insert("evasion".into());
        return 35;
    }
    0
}

/// Detect abnormal repetition (DoS or confusion attack)
fn check_repetition(
    text: &str,
    reasons: &mut Vec<String>,
    cats: &mut std::collections::HashSet<String>,
) -> i32 {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 20 { return 0; }
    // Check if >70% of words are the same
    let mut freq: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for w in &words { *freq.entry(w).or_insert(0) += 1; }
    if let Some(max_count) = freq.values().max() {
        let ratio = *max_count as f64 / words.len() as f64;
        if ratio > 0.70 {
            reasons.push(format!("High word repetition ratio {:.0}% — possible DoS/confusion (+30)", ratio * 100.0));
            cats.insert("behavioral".into());
            return 30;
        }
    }
    0
}

/// Detect unicode homoglyph substitution (e.g. 'pаssword' with Cyrillic 'а')
fn check_homoglyph_evasion(
    text: &str,
    reasons: &mut Vec<String>,
    cats: &mut std::collections::HashSet<String>,
) -> i32 {
    // Count non-ASCII chars mixed into otherwise ASCII words
    let non_ascii: usize = text.chars().filter(|c| !c.is_ascii()).count();
    let total: usize = text.chars().count();
    if total > 10 && non_ascii > 0 {
        // If >5% of chars are non-ASCII in a text that otherwise looks like English commands
        let ratio = non_ascii as f64 / total as f64;
        if ratio > 0.05 && ratio < 0.40 {
            reasons.push(format!("Possible homoglyph evasion: {:.1}% non-ASCII chars (+25)", ratio * 100.0));
            cats.insert("evasion".into());
            return 25;
        }
    }
    0
}