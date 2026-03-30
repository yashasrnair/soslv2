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
}

pub fn start_api() {
    let server = Server::http("0.0.0.0:5000").unwrap();
    println!("🔥 Rust API running on port 5000");

    for mut request in server.incoming_requests() {
        let mut content = String::new();

        if let Err(_) = request.as_reader().read_to_string(&mut content) {
            request.respond(Response::from_string("Invalid request")).unwrap();
            continue;
        }

        let parsed: Incoming = match serde_json::from_str(&content) {
            Ok(data) => data,
            Err(_) => {
                request.respond(Response::from_string("Invalid JSON")).unwrap();
                continue;
            }
        };

        let ai_request = AIRequest {
            app_id: "mitm".to_string(),
            action: "ai_query".to_string(),
            resource: "web".to_string(),
            prompt: Some(parsed.url.clone()),
        };

        // 🔥 ENGINE LOGIC
        let allowed = check_permission(&ai_request);
        let risk = calculate_risk(&ai_request);

        let suspicious = if let Some(prompt) = &ai_request.prompt {
            analyze_prompt(prompt)
        } else {
            false
        };

        let decision = if !allowed || risk > 50 || suspicious {
            "BLOCK"
        } else {
            "ALLOW"
        };

        // 🔥 LOGGING
        let log = format!(
            "[MITM] URL: {} | Risk: {} | Suspicious: {} | Decision: {}",
            parsed.url, risk, suspicious, decision
        );
        log_event(&log);

        // 🔥 STORE BLOCKED REQUEST
        if decision == "BLOCK" {
            BLOCKED_REQUESTS
                .lock()
                .unwrap()
                .push(ai_request.clone());
        }

        // 🔥 RESPONSE
        let response = Outgoing {
            decision: decision.to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();

        request
            .respond(
                Response::from_string(json).with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
            )
            .unwrap();
    }
}