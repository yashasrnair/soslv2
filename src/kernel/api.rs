use tiny_http::{Server, Response, Header};
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::types::AIRequest;
use crate::security::policy::check_permission;
use crate::security::risk::calculate_risk;
use crate::ai::analyzer::analyze_prompt;
use crate::utils::state::BLOCKED_REQUESTS;
use crate::utils::logger::log_event;

#[derive(Deserialize)]
struct Incoming {
    url: String,
    body: String,
}

#[derive(Serialize)]
struct Outgoing {
    decision: String,
    risk: i32,
}

pub fn start_api() {
    let server = Server::http("0.0.0.0:5000").unwrap();
    println!("🔥 Rust API running on http://localhost:5000/check");

    for mut request in server.incoming_requests() {

        // CORS pre-flight or invalid route
        if request.url() != "/check" {
            let _ = request.respond(
                Response::from_string(r#"{"error":"Invalid route. Use POST /check"}"#)
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
                    .with_status_code(404)
            );
            continue;
        }

        let mut content = String::new();

        if request.as_reader().read_to_string(&mut content).is_err() {
            let _ = request.respond(
                Response::from_string(r#"{"error":"Failed to read request body"}"#)
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
                    .with_status_code(400)
            );
            continue;
        }

        let parsed: Incoming = match serde_json::from_str(&content) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("[API] JSON parse error: {}", e);
                let _ = request.respond(
                    Response::from_string(r#"{"error":"Invalid JSON body"}"#)
                        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
                        .with_status_code(400)
                );
                continue;
            }
        };

        // Use body as prompt if non-empty, else fall back to URL
        let prompt_text = if parsed.body.trim().is_empty() {
            parsed.url.clone()
        } else {
            parsed.body.clone()
        };

        let ai_request = AIRequest {
            app_id: "mitm".to_string(),
            action: "ai_query".to_string(),
            resource: "web".to_string(),
            prompt: Some(prompt_text.clone()),
        };

        // 🔥 ENGINE LOGIC
        let allowed = check_permission(&ai_request);
        let risk = calculate_risk(&ai_request);

        let suspicious = if let Some(prompt) = &ai_request.prompt {
            analyze_prompt(prompt)
        } else {
            false
        };

        // 🔥 KEYWORD DETECTION on URL
        let keyword_block = parsed.url.contains("chatgpt")
            || parsed.url.contains("claude")
            || parsed.url.contains("openai")
            || parsed.url.contains("password")
            || parsed.url.contains("token");

        let decision = if keyword_block || !allowed || risk > 50 || suspicious {
            "BLOCK"
        } else {
            "ALLOW"
        };

        // 🔥 LOGGING
        let log = format!(
            "[MITM] URL: {} | Body: {} | Risk: {} | Suspicious: {} | Decision: {}",
            parsed.url, parsed.body, risk, suspicious, decision
        );
        log_event(&log);

        // 🔥 STORE BLOCKED
        if decision == "BLOCK" {
            BLOCKED_REQUESTS.lock().unwrap().push(ai_request);
        }

        let response_body = serde_json::to_string(&Outgoing {
            decision: decision.to_string(),
            risk,
        }).unwrap_or_else(|_| r#"{"decision":"BLOCK","risk":0}"#.to_string());

        let _ = request.respond(
            Response::from_string(response_body)
                .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        );
    }
}