"""
Zero Trust MITM Interceptor — Pause & Resume Edition
=====================================================
How it works:
  1. Every request is sent to the Rust Zero-Trust engine at :5000/check
  2. ALLOWED  → forwarded immediately, site loads normally
  3. BLOCKED  → request is HELD (flow is paused via mitmproxy async/threading)
               A unique flow_id is registered in a shared pending dict
               The dashboard shows an Approve button
               When approved, the held flow is resumed and forwarded normally
               The user sees the page load as if nothing happened (just a delay)

Run with:
  mitmproxy -s mitm/interceptor.py --listen-port 8888
  OR
  mitmweb  -s mitm/interceptor.py --listen-port 8888   (has built-in web UI too)

Then set Windows proxy to:
  HTTP Proxy:  127.0.0.1:8888
  HTTPS Proxy: 127.0.0.1:8888

For HTTPS to work, install the mitmproxy CA cert:
  1. With proxy set, visit http://mitm.it
  2. Download and install the Windows certificate
  3. Place it in "Trusted Root Certification Authorities"
"""

import uuid
import threading
import time
import requests
from mitmproxy import http
from mitmproxy import ctx

# ── Config ──────────────────────────────────────────────────────────────────
RUST_API      = "http://localhost:5000/check"
APPROVAL_PORT = 9091          # separate lightweight approval endpoint (not the Rust dashboard)
POLL_INTERVAL = 0.5           # seconds between approval checks
MAX_WAIT_SECS = 120           # abandon hold after 2 minutes (send 503)

# ── Shared state ────────────────────────────────────────────────────────────
# flow_id → {"flow": ..., "approved": bool, "event": threading.Event, "meta": {...}}
pending_flows: dict = {}
pending_lock  = threading.Lock()

# ── Approval HTTP server (runs in background thread) ────────────────────────
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import urllib.parse

class ApprovalHandler(BaseHTTPRequestHandler):
    """
    Tiny HTTP server that the dashboard talks to for approvals.
    GET /pending          → list of pending flow IDs + metadata (JSON)
    GET /approve?id=<id>  → approve a specific flow
    GET /reject?id=<id>   → reject a specific flow (sends 403 to browser)
    """

    def log_message(self, format, *args):
        pass  # silence default access log

    def _send_json(self, code: int, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code: int, html: str):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/pending":
            with pending_lock:
                result = [
                    {
                        "id":     fid,
                        "url":    meta["meta"]["url"],
                        "method": meta["meta"]["method"],
                        "host":   meta["meta"]["host"],
                        "risk":   meta["meta"].get("risk", "?"),
                        "age_s":  round(time.time() - meta["meta"]["timestamp"], 1),
                    }
                    for fid, meta in pending_flows.items()
                    if not meta["approved"] and not meta.get("rejected")
                ]
            self._send_json(200, result)

        elif parsed.path == "/approve":
            fid = params.get("id", [None])[0]
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["approved"] = True
                    pending_flows[fid]["event"].set()
                    self._send_json(200, {"status": "approved", "id": fid})
                else:
                    self._send_json(404, {"error": "flow not found"})

        elif parsed.path == "/reject":
            fid = params.get("id", [None])[0]
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["rejected"] = True
                    pending_flows[fid]["event"].set()
                    self._send_json(200, {"status": "rejected", "id": fid})
                else:
                    self._send_json(404, {"error": "flow not found"})

        elif parsed.path == "/" or parsed.path == "/dashboard":
            self._send_html(200, DASHBOARD_HTML)

        else:
            self._send_json(404, {"error": "unknown route"})


DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Zero Trust — Approval Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d0d0d; color: #e0e0e0; padding: 30px; }
    h1 { color: #00ffcc; margin-bottom: 6px; font-size: 1.6rem; }
    .subtitle { color: #666; font-size: 0.85rem; margin-bottom: 24px; }
    .card {
      background: #1a1a1a;
      border: 1px solid #ff4444;
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .card-info { flex: 1; }
    .card-info .url { font-size: 0.95rem; color: #fff; word-break: break-all; }
    .card-info .meta { font-size: 0.78rem; color: #888; margin-top: 4px; }
    .card-info .meta span { margin-right: 14px; }
    .card-info .meta .risk { color: #ff8800; font-weight: bold; }
    .btn { padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 0.85rem; }
    .approve { background: #00ffcc; color: #000; margin-right: 8px; }
    .reject  { background: #ff4444; color: #fff; }
    .approve:hover { background: #00ddb3; }
    .reject:hover  { background: #cc2222; }
    .empty { color: #555; font-style: italic; padding: 20px 0; }
    .badge { display: inline-block; background: #ff4444; color: #fff; border-radius: 999px; padding: 2px 10px; font-size: 0.75rem; margin-left: 10px; }
    #count { }
  </style>
</head>
<body>
  <h1>🛡 Zero Trust — Pending Approvals <span class="badge" id="count">…</span></h1>
  <p class="subtitle">Requests held by the Zero-Trust engine. Approve to let the page load normally. Reject to block permanently.</p>
  <div id="list"><p class="empty">Loading…</p></div>

  <script>
    async function load() {
      const res = await fetch('/pending');
      const items = await res.json();
      document.getElementById('count').textContent = items.length;
      const list = document.getElementById('list');
      if (items.length === 0) {
        list.innerHTML = '<p class="empty">✅ No pending requests — all clear.</p>';
        return;
      }
      list.innerHTML = items.map(item => `
        <div class="card" id="card-${item.id}">
          <div class="card-info">
            <div class="url">🔒 [${item.method}] ${item.url}</div>
            <div class="meta">
              <span>Host: <b>${item.host}</b></span>
              <span class="risk">Risk Score: ${item.risk}</span>
              <span>Waiting: ${item.age_s}s</span>
              <span>ID: <code>${item.id.substring(0,8)}…</code></span>
            </div>
          </div>
          <div class="card-actions">
            <button class="btn approve" onclick="act('approve','${item.id}')">✅ Approve</button>
            <button class="btn reject"  onclick="act('reject', '${item.id}')">🚫 Reject</button>
          </div>
        </div>
      `).join('');
    }

    async function act(action, id) {
      const card = document.getElementById('card-' + id);
      if (card) card.style.opacity = '0.4';
      await fetch('/' + action + '?id=' + id);
      setTimeout(load, 400);
    }

    load();
    setInterval(load, 3000);
  </script>
</body>
</html>
"""


def start_approval_server():
    server = HTTPServer(("0.0.0.0", APPROVAL_PORT), ApprovalHandler)
    print(f"[ZeroTrust] Approval dashboard → http://localhost:{APPROVAL_PORT}")
    server.serve_forever()


# ── mitmproxy addon ──────────────────────────────────────────────────────────

class ZeroTrustAddon:

    def __init__(self):
        # Start the approval HTTP server in a daemon thread
        t = threading.Thread(target=start_approval_server, daemon=True)
        t.start()
        print("[ZeroTrust] Interceptor active — all requests will be evaluated.")

    # ── called for every HTTP/HTTPS request ──
    def request(self, flow: http.HTTPFlow):
        url    = flow.request.pretty_url
        method = flow.request.method
        host   = flow.request.pretty_host

        # Skip the approval server's own traffic to avoid recursion
        if f":{APPROVAL_PORT}" in url or "localhost" in host:
            return

        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = ""

        print(f"\n[ZeroTrust] ▶ {method} {url}")

        # ── Ask Rust engine ──
        decision = "ALLOW"
        risk      = 0
        try:
            res = requests.post(
                RUST_API,
                json={"url": url, "body": body},
                headers={"Content-Type": "application/json"},
                timeout=3,
            )
            data     = res.json()
            decision = data.get("decision", "ALLOW")
            risk     = data.get("risk", 0)
        except Exception as e:
            print(f"[ZeroTrust] ⚠ Rust engine unreachable ({e}) — defaulting ALLOW")

        print(f"[ZeroTrust] Decision: {decision}  Risk: {risk}")

        if decision == "BLOCK":
            self._hold_flow(flow, url, method, host, risk)

    # ── Hold the flow until approved / rejected / timeout ──
    def _hold_flow(self, flow: http.HTTPFlow, url, method, host, risk):
        flow_id = str(uuid.uuid4())
        event   = threading.Event()

        entry = {
            "flow":     flow,
            "approved": False,
            "rejected": False,
            "event":    event,
            "meta": {
                "url":       url,
                "method":    method,
                "host":      host,
                "risk":      risk,
                "timestamp": time.time(),
            },
        }

        with pending_lock:
            pending_flows[flow_id] = entry

        print(f"[ZeroTrust] ⏸  Flow held — id={flow_id[:8]}… Waiting for dashboard approval.")
        print(f"            Open http://localhost:{APPROVAL_PORT} to approve/reject.")

        # Block this thread (mitmproxy runs each flow in its own thread)
        signalled = event.wait(timeout=MAX_WAIT_SECS)

        with pending_lock:
            state = pending_flows.pop(flow_id, {})

        if not signalled or state.get("rejected"):
            # Timeout or explicit reject → send 403 to browser
            reason = "timed out" if not signalled else "rejected by operator"
            print(f"[ZeroTrust] 🚫 Flow {flow_id[:8]}… {reason} — sending 403")
            flow.response = http.Response.make(
                403,
                f"<h2>🚫 Blocked by Zero Trust AI Layer</h2>"
                f"<p>URL: {url}</p>"
                f"<p>Reason: {reason}</p>"
                f"<p>Risk score: {risk}</p>",
                {"Content-Type": "text/html"},
            )
        else:
            # Approved — let mitmproxy forward the original request normally
            print(f"[ZeroTrust] ✅ Flow {flow_id[:8]}… approved — resuming normally")
            # flow.response is NOT set → mitmproxy forwards to origin and returns real response


# ── Register the addon ───────────────────────────────────────────────────────
addons = [ZeroTrustAddon()]