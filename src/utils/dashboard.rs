use tiny_http::{Server, Response, Header};
use crate::utils::state::BLOCKED_REQUESTS;

pub fn start_dashboard() {
    let server = Server::http("0.0.0.0:9090").unwrap();
    println!("🔥 Dashboard running at http://localhost:9090");

    for request in server.incoming_requests() {
        let url = request.url().to_string();

        // 🔥 APPROVE HANDLER — acquire and release lock before re-reading
        if url.starts_with("/approve") {
            if let Some(id_str) = url.split("id=").nth(1) {
                // Strip any trailing query params or fragments
                let id_str = id_str.split('&').next().unwrap_or(id_str);
                if let Ok(id) = id_str.trim().parse::<usize>() {
                    let mut requests = BLOCKED_REQUESTS.lock().unwrap();
                    if id < requests.len() {
                        requests.remove(id);
                        println!("✅ Approved request {}", id);
                    }
                }
                // Lock is dropped here at end of block
            }
        }

        // Re-acquire lock only after approve block is done
        let requests = BLOCKED_REQUESTS.lock().unwrap();

        let mut html = String::from(r#"
        <html>
        <head>
            <title>Zero Trust AI Dashboard</title>
            <meta http-equiv="refresh" content="2">
            <style>
                body { font-family: Arial; background: #111; color: white; padding: 20px; }
                h1 { color: #00ffcc; }
                .card {
                    margin: 10px 0;
                    padding: 15px;
                    border: 1px solid red;
                    border-radius: 10px;
                    background: #1e1e1e;
                }
                button {
                    background: #00ffcc;
                    border: none;
                    padding: 8px 16px;
                    cursor: pointer;
                    border-radius: 5px;
                    font-weight: bold;
                }
                .empty { color: #888; font-style: italic; }
            </style>
        </head>
        <body>
            <h1>🚫 Blocked AI Requests — Zero Trust Dashboard</h1>
        "#);

        if requests.is_empty() {
            html.push_str("<p class='empty'>No blocked requests at this time.</p>");
        }

        for (i, req) in requests.iter().enumerate() {
            let prompt_display = req.prompt.as_deref().unwrap_or("(none)");
            html.push_str(&format!(
                "<div class='card'>
                    <b>ID:</b> {i} <br>
                    <b>App:</b> {app} <br>
                    <b>Prompt:</b> {prompt} <br>
                    <b>Resource:</b> {resource} <br>
                    <a href='/approve?id={i}'>
                        <button type='button'>✅ Approve</button>
                    </a>
                </div>",
                i = i,
                app = req.app_id,
                prompt = prompt_display,
                resource = req.resource,
            ));
        }

        html.push_str("</body></html>");

        // Drop lock before responding to avoid holding it during I/O
        drop(requests);

        request.respond(
            Response::from_string(html)
                .with_header(Header::from_bytes("Content-Type", "text/html").unwrap())
        ).unwrap();
    }
}