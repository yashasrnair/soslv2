use tiny_http::{Server, Response, Header};
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::types::{AIRequest, EngineResponse};
use crate::security::policy::check_permission;
use crate::security::risk::calculate_risk;
use crate::security::behavior::check_behavior;
use crate::security::rules_loader::get_rules;
use crate::ai::analyzer::analyze_ai_payload;
use crate::utils::state::BLOCKED_REQUESTS;
use crate::utils::logger::log_event;

#[derive(Deserialize)]
struct Incoming {
    url:  String,
    body: String,
}

pub fn start_api() {
    let server = Server::http("0.0.0.0:5000").unwrap();
    println!("🔥 Zero-Trust Engine API → http://localhost:5000/check");
    println!("📋 Rules file          → rules/rules.json (hot-reload enabled)");

    for mut request in server.incoming_requests() {

        if request.url() != "/check" {
            let _ = request.respond(
                Response::from_string(r#"{"error":"Use POST /check"}"#)
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
                    .with_status_code(404),
            );
            continue;
        }

        let mut content = String::new();
        if request.as_reader().read_to_string(&mut content).is_err() {
            let _ = request.respond(bad_request("Failed to read body"));
            continue;
        }

        let parsed: Incoming = match serde_json::from_str(&content) {
            Ok(d)  => d,
            Err(e) => {
                eprintln!("[API] JSON error: {}", e);
                let _ = request.respond(bad_request("Invalid JSON"));
                continue;
            }
        };

        let response = run_engine(&parsed.url, &parsed.body);
        let json = serde_json::to_string(&response).unwrap_or_default();

        let _ = request.respond(
            Response::from_string(json)
                .with_header(Header::from_bytes("Content-Type", "application/json").unwrap()),
        );
    }
}

// ── Main engine ───────────────────────────────────────────────────────────────

pub fn run_engine(url: &str, body: &str) -> EngineResponse {
    let rules = get_rules();

    // Use body as prompt when available, fall back to URL
    let prompt_text = if body.trim().is_empty() { url.to_string() } else { body.to_string() };
    let host = extract_host(url);

    let ai_request = AIRequest {
        app_id:   "engine".into(),
        action:   "ai_query".into(),
        resource: "web".into(),
        prompt:   Some(prompt_text.clone()),
    };

    // ── Layer 1: Policy ───────────────────────────────────────────────────────
    let allowed = check_permission(&ai_request);

    // ── Layer 2: Dynamic risk scoring ────────────────────────────────────────
    let risk_result = calculate_risk(&ai_request);
    let mut total_risk = risk_result.score;
    let mut reasons    = risk_result.reasons.clone();
    let mut categories = risk_result.categories.clone();

    if !allowed {
        total_risk += 100;
        reasons.push("Action not permitted by policy (+100)".into());
        categories.push("policy_violation".into());
    }

    // ── Layer 3: AI site detection + keyword URL check ────────────────────────
    let is_ai_site = rules.ai_sites.iter().any(|s| host.contains(s.as_str()));
    let is_local_ai = rules.local_ai_ports.iter().any(|p| url.contains(&format!(":{}", p)));

    if is_ai_site || is_local_ai {
        // Layer 4: Deep chat message analysis
        let (chat_flags, chat_risk, scope_viols) = analyze_ai_payload(body, url);

        if !chat_flags.is_empty() {
            total_risk += chat_risk;
            reasons.push(format!(
                "Chat analysis: {} flagged messages (+{})",
                chat_flags.len(), chat_risk
            ));
            for f in &chat_flags {
                categories.push(format!("chat_flag:{}", f.role));
            }
        }

        if !scope_viols.is_empty() {
            for sv in &scope_viols {
                total_risk += sv.risk;
                reasons.push(format!("Scope violation [{}]: {} (+{})", sv.kind, sv.detail, sv.risk));
                categories.push(sv.kind.clone());
            }
        }
    }

    // ── Layer 5: Behavioral analysis ─────────────────────────────────────────
    let behavior = check_behavior(&host, &prompt_text, false);
    total_risk += behavior.extra_risk;
    reasons.extend(behavior.reasons);

    // ── Decision ──────────────────────────────────────────────────────────────
    let decision = if !allowed || total_risk >= rules.thresholds.block_score {
        "BLOCK"
    } else {
        "ALLOW"
    };

    // ── Logging ───────────────────────────────────────────────────────────────
    let log = format!(
        "[Engine] URL={} | Risk={} | Decision={} | Reasons: {}",
        url, total_risk, decision,
        reasons.first().unwrap_or(&"none".to_string())
    );
    log_event(&log);

    // ── Store blocked requests ────────────────────────────────────────────────
    if decision == "BLOCK" {
        let mut blocked = BLOCKED_REQUESTS.lock().unwrap();
        blocked.push(AIRequest {
            app_id:   host.clone(),
            action:   "ai_query".into(),
            resource: url.to_string(),
            prompt:   Some(prompt_text.chars().take(300).collect()),
        });
    }

    EngineResponse {
        decision:   decision.into(),
        risk:       total_risk,
        reasons,
        categories,
        chat_flags: vec![], // filled in Python layer for dashboard display
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_host(url: &str) -> String {
    url.split("://").nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .to_string()
}

fn bad_request(msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(format!(r#"{{"error":"{}"}}"#, msg))
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_status_code(400)
}