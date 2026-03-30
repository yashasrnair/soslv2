from mitmproxy import http
import requests

RUST_API = "http://localhost:5000/check"

def request(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    body = flow.request.get_text()

    print(f"\n[MITM] Intercepted URL: {url}")

    try:
        res = requests.post(
            RUST_API,
            json={"url": url, "body": body},
            headers={"Content-Type": "application/json"}
        )

        decision = res.json().get("decision")

        print(f"[RUST DECISION]: {decision}")

        if decision == "BLOCK":
            print("🚫 BLOCKED BY ZERO TRUST")

            flow.response = http.Response.make(
                403,
                b"Blocked by Zero Trust AI Layer",
                {"Content-Type": "text/plain"}
            )

    except Exception as e:
        print(f"[ERROR] Rust engine not reachable: {e}")