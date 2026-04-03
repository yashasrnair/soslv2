use tiny_http::{Server, Response, Header};
use crate::utils::state::BLOCKED_REQUESTS;

pub fn start_dashboard() {
    let server = Server::http("0.0.0.0:9090").unwrap();
    println!("Dashboard running at http://localhost:9090");

    for request in server.incoming_requests() {
        let url = request.url().to_string();

        // Approve handler
        if url.starts_with("/approve") {
            if let Some(id_str) = url.split("id=").nth(1) {
                let id_str = id_str.split('&').next().unwrap_or(id_str);
                if let Ok(id) = id_str.trim().parse::<usize>() {
                    let mut reqs = BLOCKED_REQUESTS.lock().unwrap();
                    if id < reqs.len() {
                        reqs.remove(id);
                        println!("Approved request {}", id);
                    }
                }
            }
        }

        let reqs = BLOCKED_REQUESTS.lock().unwrap();

        let mut html = String::from(r#"<!DOCTYPE html>
<html>
<head>
  <title>Zero Trust Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;padding:28px}
    h1{color:#00ffcc;font-size:1.3rem;margin-bottom:18px}
    .card{background:#141414;border:1px solid #c0392b;border-radius:10px;
          padding:14px 18px;margin-bottom:12px}
    .card b{color:#aaa}
    .prompt{font-family:monospace;font-size:.8rem;color:#888;
            background:#0d0d0d;padding:6px 10px;border-radius:4px;margin:6px 0;
            word-break:break-all;max-height:60px;overflow:hidden}
    .btn{display:inline-block;margin-top:8px;padding:6px 14px;
         background:#00ffcc;color:#000;border:none;border-radius:6px;
         cursor:pointer;font-weight:bold;font-size:.8rem;text-decoration:none}
    .empty{color:#333;font-style:italic;padding:20px 0}
  </style>
</head>
<body>
  <h1>&#x1F6AB; Blocked AI Requests (Rust Engine)</h1>
"#);

        if reqs.is_empty() {
            html.push_str("<p class='empty'>No blocked requests at this time.</p>");
        }

        for (i, req) in reqs.iter().enumerate() {
            let prompt = req.prompt.as_deref().unwrap_or("(none)");
            let short  = &prompt[..prompt.len().min(200)];
            html.push_str(&format!(
                r#"<div class='card'>
                  <b>ID:</b> {i} &nbsp; <b>App:</b> {app} &nbsp; <b>Resource:</b> {res}<br>
                  <div class='prompt'>{prompt}</div>
                  <a class='btn' href='/approve?id={i}'>&#x2705; Approve</a>
                </div>"#,
                i      = i,
                app    = req.app_id,
                res    = req.resource,
                prompt = short,
            ));
        }

        html.push_str("</body></html>");
        drop(reqs);

        let _ = request.respond(
            Response::from_string(html)
                .with_header(Header::from_bytes("Content-Type", "text/html").unwrap()),
        );
    }
}