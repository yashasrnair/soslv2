use tiny_http::{Server, Response};
use serde::{Deserialize, Serialize};
use crate::types::AIRequest;
use crate::kernel::interceptor::intercept;

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
    println!("Rust API running on port 5000");

    for mut request in server.incoming_requests() {
        let mut content = String::new();
        request.as_reader().read_to_string(&mut content).unwrap();

        let parsed: Incoming = serde_json::from_str(&content).unwrap();

        let _ai_request = AIRequest {
            app_id: "mitm".to_string(),
            action: "ai_query".to_string(),
            resource: "web".to_string(),
            prompt: Some(parsed.url.clone()),
        };

        // 🔥 Use your logic
        let decision = if parsed.url.contains("password") {
            "BLOCK"
        } else {
            "ALLOW"
        };

        let response = Outgoing {
            decision: decision.to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();

        request.respond(Response::from_string(json)).unwrap();
    }
}