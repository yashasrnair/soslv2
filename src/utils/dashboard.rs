use tiny_http::{Server, Response};
use crate::utils::state::BLOCKED_REQUESTS;


pub fn start_dashboard() {
    let server = Server::http("0.0.0.0:9090").unwrap();
    println!("🔥 Dashboard running at http://localhost:9090");

    for request in server.incoming_requests() {
        let url = request.url().to_string();

        // ✅ HANDLE APPROVAL
        if url.starts_with("/approve") {
            if let Some(id_str) = url.split("id=").nth(1) {
                if let Ok(id) = id_str.parse::<usize>() {
                    let mut requests = BLOCKED_REQUESTS.lock().unwrap();
                    if id < requests.len() {
                        requests.remove(id);
                        println!("✅ Approved request {}", id);
                    }
                }
            }
        }

        let requests = BLOCKED_REQUESTS.lock().unwrap();

        let mut html = String::from("
        <html>
        <head>
            <title>Zero Trust AI Dashboard</title>
            <meta http-equiv='refresh' content='2'>
            <style>
                body { font-family: Arial; background: #111; color: white; }
                h1 { color: #00ffcc; }
                .card {
                    margin: 10px;
                    padding: 15px;
                    border: 1px solid red;
                    border-radius: 10px;
                    background: #1e1e1e;
                }
                button {
                    background: #00ffcc;
                    border: none;
                    padding: 8px;
                    cursor: pointer;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <h1>🚫 Blocked AI Requests</h1>
        ");

        for (i, req) in requests.iter().enumerate() {
            html.push_str(&format!(
                "<div class='card'>
                    <b>ID:</b> {} <br>
                    <b>App:</b> {} <br>
                    <b>Prompt:</b> {:?} <br>
                    <form action='/approve' method='get'>
                        <input type='hidden' name='id' value='{}'>
                        <button type='submit'>Approve</button>
                    </form>
                </div>",
                i, req.app_id, req.prompt, i
            ));
        }

        html.push_str("</body></html>");

        request.respond(Response::from_string(html)).unwrap();
    }
}