use tiny_http::{Server, Response};
use crate::types::AIRequest;
use crate::kernel::interceptor::intercept;

pub fn start_proxy() {
    let server = Server::http("0.0.0.0:8080").unwrap();
    println!("Proxy running on http://localhost:8080");
    for request in server.incoming_requests() {
        let url = request.url().to_string();
        println!("\n[Proxy] {}", url);
        intercept(AIRequest {
            app_id:   "proxy_user".into(),
            action:   "ai_query".into(),
            resource: "web_request".into(),
            prompt:   Some(url),
        });
        let _ = request.respond(
            Response::from_string("Processed by Zero Trust Layer v3")
        );
    }
}