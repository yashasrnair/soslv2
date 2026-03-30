use tiny_http::{Server, Response};
use crate::types::AIRequest;
use crate::kernel::interceptor::intercept;

pub fn start_proxy() {
    let server = Server::http("0.0.0.0:8080").unwrap();

    println!("Proxy running on http://localhost:8080");

    for request in server.incoming_requests() {
        let url = request.url().to_string();

        println!("\n[Intercepted Request]: {}", url);

        let ai_request = AIRequest {
            app_id: "proxy_user".to_string(),
            action: "ai_query".to_string(),
            resource: "web_request".to_string(),
            prompt: Some(url.clone()),
        };

        // 🔥 Intercept decision
        intercept(ai_request);

        // TEMP response (we simulate forward)
        let response = Response::from_string(
            "Request processed through Zero Trust Layer"
        );

        request.respond(response).unwrap();
    }
}