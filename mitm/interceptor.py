from mitmproxy import http
import requests

RUST_API = "http://localhost:5000"

def request(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    body = flow.request.get_text()

    print(f"\n[MITM] Intercepted URL: {url}")

    # 🔥 Send to your Rust engine
    try:
        res = requests.post(RUST_API, json={
            "url": url,
            "body": body
        })

        decision = res.json().get("decision")

        print(f"[RUST DECISION]: {decision}")

        # 🚫 Block if needed
        if decision == "BLOCK":
            flow.response = http.Response.make(
                403,
                b"Blocked by Zero Trust AI Layer",
                {"Content-Type": "text/plain"}
            )

    except Exception as e:
        print(f"[ERROR] Rust engine not reachable: {e}")