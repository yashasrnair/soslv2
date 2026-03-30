use tiny_http::{Server, Response};
use crate::utils::state::BLOCKED_REQUESTS;

pub fn start_dashboard() {
    let server = Server::http("0.0.0.0:9090").unwrap();
    println!("Dashboard: http://localhost:9090");

    for request in server.incoming_requests() {
        let requests = BLOCKED_REQUESTS.lock().unwrap();

        let mut html = String::from("
        <h1>🚫 Blocked AI Requests</h1>
        <style>
            body { font-family: Arial; }
            .card { margin:10px; padding:10px; border:1px solid red; }
        </style>
        ");

        for (i, req) in requests.iter().enumerate() {
            html.push_str(&format!(
                "<div class='card'>
                    <b>ID:</b> {} <br>
                    <b>Prompt:</b> {:?} <br>
                </div>",
                i, req.prompt
            ));
        }

        let response = Response::from_string(html);
        request.respond(response).unwrap();
    }
}