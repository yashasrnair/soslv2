"""
Zero Trust MITM Interceptor — Pause & Resume Edition (Fixed)
=============================================================
Root cause of the previous error:
  The `requests` library inherits the system proxy settings (127.0.0.1:8888).
  So when the interceptor called http://localhost:5000/check, it tried to route
  THAT call through itself (the proxy), causing:
    ProxyError → 'No connection could be made because the target machine actively refused it'

Fix applied:
  1. Replaced `requests` with `urllib.request` + a NO_PROXY handler so the
     call to the Rust engine ALWAYS goes direct, never through the proxy.
  2. mitmproxy ignore_hosts set to skip localhost/127.0.0.1 entirely.
  3. Host-level approval cache: once a host is approved, all further requests
     to that host pass through instantly without re-asking the engine.
  4. Dashboard now shows the cache table and lets you clear individual entries.

Run:
  mitmdump -s mitm/interceptor.py --listen-port 8888

Windows proxy settings:
  Settings > Network & Internet > Proxy > Manual proxy setup
  HTTP:  127.0.0.1  Port: 8888
  HTTPS: 127.0.0.1  Port: 8888
  "Don't use the proxy server for": localhost;127.0.0.1   <- ADD THIS
"""

import uuid
import threading
import time
import json
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

from mitmproxy import http

# ── Config ────────────────────────────────────────────────────────────────────
RUST_API      = "http://127.0.0.1:5000/check"   # direct IP, never proxied
APPROVAL_PORT = 9091
MAX_WAIT_SECS = 120

# ── Shared state ──────────────────────────────────────────────────────────────
pending_flows: dict = {}
pending_lock  = threading.Lock()

# Host-level decision cache  {host: "approved" | "rejected"}
host_cache: dict = {}
host_cache_lock  = threading.Lock()


# ── Rust engine caller (proxy-free) ───────────────────────────────────────────
def call_rust_engine(url: str, body: str) -> dict:
    payload = json.dumps({"url": url, "body": body}).encode()
    req = urllib.request.Request(
        RUST_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # Empty ProxyHandler dict = bypass ALL system proxies for this one call
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=3) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[ZeroTrust] ⚠  Rust engine unreachable ({e}) — defaulting ALLOW")
        return {"decision": "ALLOW", "risk": 0}


# ── Approval dashboard ────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Zero Trust — Approval Dashboard</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;padding:30px}
    h1{color:#00ffcc;margin-bottom:6px;font-size:1.5rem}
    .sub{color:#555;font-size:.82rem;margin-bottom:22px}
    .card{background:#1a1a1a;border:1px solid #c0392b;border-radius:10px;
          padding:14px 18px;margin-bottom:12px;display:flex;align-items:center;gap:16px}
    .card.fading{opacity:.4;transition:opacity .3s}
    .info{flex:1}
    .url{font-size:.9rem;color:#fff;word-break:break-all}
    .meta{font-size:.76rem;color:#777;margin-top:5px}
    .meta b{color:#aaa}
    .risk{color:#e67e22;font-weight:bold}
    .btn{padding:7px 16px;border:none;border-radius:6px;cursor:pointer;font-weight:bold;font-size:.82rem}
    .ok{background:#00ffcc;color:#000;margin-right:7px}
    .no{background:#c0392b;color:#fff}
    .ok:hover{background:#00ddb3}
    .no:hover{background:#962d22}
    .empty{color:#444;font-style:italic;padding:16px 0}
    .badge{background:#c0392b;color:#fff;border-radius:999px;padding:2px 9px;font-size:.72rem;margin-left:8px}
    .section-title{color:#555;font-size:1rem;margin:28px 0 10px}
    .crow{display:flex;gap:10px;align-items:center;padding:6px 10px;
          background:#111;border-radius:6px;margin-bottom:6px;font-size:.82rem}
    .crow .host{flex:1;color:#888}
    .ta{color:#27ae60;font-weight:bold}
    .tb{color:#c0392b;font-weight:bold}
    .small-btn{padding:3px 10px;font-size:.72rem}
  </style>
</head>
<body>
  <h1>&#x1F6E1; Zero Trust Approval Dashboard <span class="badge" id="cnt">…</span></h1>
  <p class="sub">Requests held by the engine. Approve = site loads normally. Reject = 403. Decisions are cached per-host.</p>
  <div id="pending-list"><p class="empty">Loading…</p></div>

  <h2 class="section-title">&#x1F5C2; Host Decision Cache</h2>
  <div id="cache-list"><p class="empty">No cached decisions yet.</p></div>

  <script>
    async function load(){
      const [pr,cr]=await Promise.all([fetch('/pending'),fetch('/cache')]);
      const items=await pr.json(), cache=await cr.json();
      document.getElementById('cnt').textContent=items.length;

      const pl=document.getElementById('pending-list');
      pl.innerHTML=items.length
        ? items.map(it=>`
          <div class="card" id="c-${it.id}">
            <div class="info">
              <div class="url">&#x1F512; [${it.method}] ${it.url}</div>
              <div class="meta">
                <b>Host:</b> ${it.host} &nbsp;
                <span class="risk">Risk: ${it.risk}</span> &nbsp;
                <b>Waiting:</b> ${it.age_s}s
              </div>
            </div>
            <div>
              <button class="btn ok" onclick="act('approve','${it.id}','${it.host}')">&#x2705; Approve</button>
              <button class="btn no"  onclick="act('reject', '${it.id}','${it.host}')">&#x1F6AB; Reject</button>
            </div>
          </div>`).join('')
        : '<p class="empty">&#x2705; No held requests — all clear.</p>';

      const cl=document.getElementById('cache-list');
      const entries=Object.entries(cache);
      cl.innerHTML=entries.length
        ? entries.map(([host,dec])=>`
          <div class="crow">
            <span class="host">${host}</span>
            <span class="${dec==='approved'?'ta':'tb'}">${dec.toUpperCase()}</span>
            <button class="btn no small-btn" onclick="clearCache('${host}')">Clear</button>
          </div>`).join('')
        : '<p class="empty">No cached decisions yet.</p>';
    }

    async function act(action,id,host){
      document.getElementById('c-'+id)?.classList.add('fading');
      await fetch('/'+action+'?id='+id+'&host='+encodeURIComponent(host));
      setTimeout(load,350);
    }

    async function clearCache(host){
      await fetch('/clear-cache?host='+encodeURIComponent(host));
      setTimeout(load,200);
    }

    load();
    setInterval(load,2500);
  </script>
</body>
</html>
"""


class ApprovalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)

        if p.path in ("/", "/dashboard"):
            self._html(DASHBOARD_HTML)

        elif p.path == "/pending":
            with pending_lock:
                out = [
                    {"id": fid, "url": e["meta"]["url"], "method": e["meta"]["method"],
                     "host": e["meta"]["host"], "risk": e["meta"].get("risk", 0),
                     "age_s": round(time.time() - e["meta"]["ts"], 1)}
                    for fid, e in pending_flows.items()
                    if not e["approved"] and not e.get("rejected")
                ]
            self._json(200, out)

        elif p.path == "/cache":
            with host_cache_lock:
                self._json(200, dict(host_cache))

        elif p.path == "/approve":
            fid  = q.get("id",   [None])[0]
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock:
                    host_cache[host] = "approved"
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["approved"] = True
                    pending_flows[fid]["event"].set()
            self._json(200, {"status": "approved"})

        elif p.path == "/reject":
            fid  = q.get("id",   [None])[0]
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock:
                    host_cache[host] = "rejected"
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["rejected"] = True
                    pending_flows[fid]["event"].set()
            self._json(200, {"status": "rejected"})

        elif p.path == "/clear-cache":
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock:
                    host_cache.pop(host, None)
            self._json(200, {"status": "cleared"})

        else:
            self._json(404, {"error": "unknown route"})


def _start_approval_server():
    srv = HTTPServer(("0.0.0.0", APPROVAL_PORT), ApprovalHandler)
    print(f"[ZeroTrust] Dashboard → http://localhost:{APPROVAL_PORT}")
    srv.serve_forever()


# ── mitmproxy addon ───────────────────────────────────────────────────────────
class ZeroTrustAddon:

    def __init__(self):
        threading.Thread(target=_start_approval_server, daemon=True).start()
        print("[ZeroTrust] Interceptor active.")

    def configure(self, updated):
        """Tell mitmproxy to never intercept localhost — prevents self-loop."""
        try:
            from mitmproxy import ctx
            ctx.options.ignore_hosts = [
                r"^localhost$",
                r"^127\.0\.0\.1$",
                r"^::1$",
            ]
        except Exception:
            pass

    def request(self, flow: http.HTTPFlow):
        host   = flow.request.pretty_host
        url    = flow.request.pretty_url
        method = flow.request.method

        # Never touch localhost / approval server traffic
        if host in ("localhost", "127.0.0.1", "::1"):
            return

        # ── Fast path: check host cache ──
        with host_cache_lock:
            cached = host_cache.get(host)

        if cached == "approved":
            print(f"[ZeroTrust] ⚡ CACHE-APPROVED  {host}")
            return
        if cached == "rejected":
            print(f"[ZeroTrust] ⚡ CACHE-REJECTED   {host}")
            flow.response = http.Response.make(
                403,
                f"<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px'>"
                f"<h2 style='color:#e74c3c'>&#x1F6AB; Blocked by Zero Trust</h2>"
                f"<p>Host <b>{host}</b> is cached as REJECTED.</p>"
                f"<p>Open <a href='http://localhost:{APPROVAL_PORT}' style='color:#00ffcc'>"
                f"the dashboard</a> and clear the cache to re-evaluate.</p></body></html>",
                {"Content-Type": "text/html"},
            )
            return

        # ── Ask Rust engine (direct, no proxy) ──
        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = ""

        print(f"\n[ZeroTrust] ▶ {method} {url}")
        data     = call_rust_engine(url, body)
        decision = data.get("decision", "ALLOW")
        risk     = int(data.get("risk", 0))
        print(f"[ZeroTrust]   → {decision}  risk={risk}")

        if decision == "ALLOW":
            return

        # ── BLOCK: pause the flow ──
        self._hold_flow(flow, url, method, host, risk)

    def _hold_flow(self, flow: http.HTTPFlow, url, method, host, risk):
        flow_id = str(uuid.uuid4())
        event   = threading.Event()

        with pending_lock:
            pending_flows[flow_id] = {
                "approved": False, "rejected": False, "event": event,
                "meta": {"url": url, "method": method, "host": host,
                         "risk": risk, "ts": time.time()},
            }

        print(f"[ZeroTrust] ⏸  HELD  {host}  (id={flow_id[:8]}…)")
        print(f"[ZeroTrust]    Approve/reject at http://localhost:{APPROVAL_PORT}")

        signalled = event.wait(timeout=MAX_WAIT_SECS)

        with pending_lock:
            entry = pending_flows.pop(flow_id, {})

        if entry.get("approved"):
            print(f"[ZeroTrust] ✅ APPROVED  {host} — forwarding")
            # flow.response NOT set → mitmproxy forwards to real origin → page loads normally
            return

        reason = "operator rejected" if entry.get("rejected") else f"timed out ({MAX_WAIT_SECS}s)"
        print(f"[ZeroTrust] &#x1F6AB; BLOCKED  {host}  ({reason})")
        flow.response = http.Response.make(
            403,
            f"""<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px'>
            <h2 style='color:#e74c3c'>&#x1F6AB; Blocked by Zero Trust AI Layer</h2>
            <p><b>URL:</b> {url}</p>
            <p><b>Host:</b> {host}</p>
            <p><b>Risk score:</b> {risk}</p>
            <p><b>Reason:</b> {reason}</p>
            <p style='margin-top:20px'>
              <a href='http://localhost:{APPROVAL_PORT}' style='color:#00ffcc'>
              Open Zero Trust Dashboard</a>
            </p></body></html>""",
            {"Content-Type": "text/html"},
        )


addons = [ZeroTrustAddon()]