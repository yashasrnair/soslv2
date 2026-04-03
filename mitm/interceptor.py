"""
Zero Trust MITM Interceptor v3 — Dynamic + Chat-Aware Edition
==============================================================

New in v3:
  ★ Dynamic rules: engine reads rules/rules.json at runtime — edit rules,
    changes take effect on next request, no restart needed.
  ★ Chat message interception: parses ChatGPT / Claude / Ollama API
    request AND response bodies to inspect individual messages.
  ★ Response inspection: checks AI responses for scope creep, data
    exfiltration, and references to files/dirs the user never provided.
  ★ Scope guard: if a user uploads one file and the AI response
    mentions /etc/, C:\\Users, or extra directories → flagged.
  ★ Behavioral analysis: rate limiting per host, token velocity,
    repeated block detection.
  ★ Full boundary case detection: prompt injection, jailbreaks,
    path traversal, base64 encoded payloads, homoglyph evasion.
  ★ Per-request risk breakdown shown on dashboard.
"""

import uuid, threading, time, json, re
import urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from mitmproxy import http

# ── Config ────────────────────────────────────────────────────────────────────
RUST_API      = "http://127.0.0.1:5000/check"
APPROVAL_PORT = 9091
MAX_WAIT_SECS = 120

AI_RESPONSE_HOSTS = {
    "api.openai.com", "chatgpt.com", "chat.openai.com",
    "claude.ai", "api.anthropic.com",
    "gemini.google.com", "generativelanguage.googleapis.com",
    "copilot.microsoft.com",
}
LOCAL_AI_PORTS = {11434, 8080, 1234, 5001, 7860, 3000, 8000}

# ── Shared state ──────────────────────────────────────────────────────────────
pending_flows: dict = {}
pending_lock  = threading.Lock()
host_cache: dict = {}
host_cache_lock  = threading.Lock()
recent_logs: list = []
recent_logs_lock  = threading.Lock()

def add_log(entry: str):
    ts = time.strftime("%H:%M:%S")
    with recent_logs_lock:
        recent_logs.append(f"[{ts}] {entry}")
        if len(recent_logs) > 200:
            recent_logs.pop(0)

# ── Rust engine caller (proxy-free) ───────────────────────────────────────────
def call_rust_engine(url: str, body: str) -> dict:
    payload = json.dumps({"url": url, "body": body}).encode()
    req = urllib.request.Request(
        RUST_API, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[ZeroTrust] Rust engine unreachable ({e}) — defaulting ALLOW")
        return {"decision": "ALLOW", "risk": 0, "reasons": [], "categories": []}

# ── Chat payload parser ───────────────────────────────────────────────────────
def extract_messages(body: str, url: str) -> list:
    """Extract chat messages from various AI API formats."""
    if not body.strip():
        return []
    try:
        data = json.loads(body)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []

    msgs = []
    # System prompt (Anthropic style)
    if "system" in data and isinstance(data["system"], str):
        msgs.append({"role": "system", "content": data["system"]})

    # Standard messages array (OpenAI, Anthropic, Ollama)
    if "messages" in data and isinstance(data["messages"], list):
        for m in data["messages"]:
            if not isinstance(m, dict):
                continue
            role    = m.get("role", "unknown")
            content = m.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    p.get("text", "") for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                )
            msgs.append({"role": role, "content": str(content)})

    # Ollama /api/generate
    if "prompt" in data and isinstance(data["prompt"], str):
        msgs.append({"role": "user", "content": data["prompt"]})

    # OpenAI response (choices)
    if "choices" in data and isinstance(data["choices"], list):
        for choice in data["choices"]:
            m = choice.get("message") or choice.get("delta") or {}
            role    = m.get("role", "assistant")
            content = m.get("content", "")
            if content:
                msgs.append({"role": role, "content": str(content)})

    return msgs

def collect_user_files(messages: list) -> set:
    files = set()
    for msg in messages:
        if msg.get("role") != "user":
            continue
        for word in msg.get("content", "").split():
            word = word.strip("\"'(),;:")
            if (re.search(r'\.\w{2,5}$', word)
                    and 3 < len(word) < 200
                    and "http" not in word):
                files.add(word.lower())
    return files

# ── Scope & threat patterns ───────────────────────────────────────────────────
FORBIDDEN_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/", "/sys/",
    "~/.ssh", "~/.bashrc", "/root/", "/var/log/",
    "c:\\windows", "c:\\users", "%appdata%", "ntuser.dat",
]
SCOPE_CREEP_PHRASES = [
    "entire directory", "all files in", "read the whole", "list all files",
    "scan directory", "walk the tree", "recursive", "find all",
    "access everything", "full filesystem", "all subdirectories",
]
EXFIL_PATTERNS = [
    r'\bcurl\b', r'\bwget\b', r'requests\.post', r'fetch\(',
    r'base64\.encode', r'btoa\(', r'exfiltrat', r'data leak',
    r'upload.*to.*http', r'send.*to.*remote',
]

# Per-message threat patterns with (regex, risk_pts, category)
MESSAGE_PATTERNS = [
    (r'ignore (all |previous |your )?(instructions?|prompt|context)',   90, "prompt_injection"),
    (r'forget everything (above|before|prior)',                         85, "prompt_injection"),
    (r'(you are|act as|pretend (to be|you are)) (now )?(?:an? )?(?:evil|unfiltered|dan|unrestricted)', 80, "persona_hijack"),
    (r'(developer|jailbreak|god|unrestricted|dan) mode',               85, "jailbreak"),
    (r'(bypass|disable|remove|circumvent) (your )?(safety|filter|restriction|policy)', 80, "jailbreak"),
    (r'<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>',                  70, "delimiter_injection"),
    (r'###\s*(SYSTEM|INSTRUCTION|OVERRIDE)',                             75, "delimiter_injection"),
    (r'(read|access|list|show).{0,30}(entire|whole|all|every).{0,20}(directory|folder|disk|drive)', 80, "scope_creep"),
    (r'(exfiltrate|steal|extract).{0,30}(data|file|credential)',        85, "exfiltration"),
    (r'(password|passwd|private[_. ]?key|api[_. ]?key|bearer[_. ]?token)', 60, "credential"),
    (r'/etc/passwd|/etc/shadow|\.\.\/|\.\.\\\\',                        80, "path_traversal"),
    (r'(eval|exec|subprocess|os\.system|shell_exec)\s*\(',              70, "code_injection"),
    (r'(credit.?card|ssn|social.?security)',                            75, "pii"),
    (r'[A-Za-z0-9+/]{60,}={0,2}',                                      35, "encoded_payload"),
    (r'(admin|root|superuser).{0,20}(override|access|privilege)',       75, "privilege_escalation"),
    (r'new instructions?:',                                              70, "prompt_injection"),
    (r'your real (purpose|goal|instruction) is',                        80, "prompt_injection"),
    (r'(read|open|load|cat|type).{0,20}(c:\\|/home/|/root/)',           75, "path_traversal"),
]

def check_message_content(messages: list, url: str):
    """Check individual messages. Returns (flags, extra_risk)."""
    flags      = []
    extra_risk = 0
    user_files = collect_user_files([m for m in messages if m.get("role") == "user"])

    for idx, msg in enumerate(messages[:50]):
        content = msg.get("content", "")
        role    = msg.get("role",    "unknown")
        lower   = content.lower()
        msg_risk    = 0
        msg_reasons = []

        for pattern, pts, cat in MESSAGE_PATTERNS:
            if re.search(pattern, lower):
                msg_risk += pts
                msg_reasons.append(f"{cat} (+{pts})")

        if msg_risk > 0:
            extra_risk += msg_risk
            flags.append({
                "message_index": idx,
                "role":          role,
                "snippet":       content[:150],
                "reasons":       msg_reasons,
                "risk":          msg_risk,
            })

        # Scope check on assistant responses
        if role == "assistant":
            sv = check_response_scope(content, user_files)
            for v in sv:
                extra_risk += v["risk"]
                flags.append({
                    "message_index": idx,
                    "role":  "assistant[scope]",
                    "snippet": content[:150],
                    "reasons": [f"{v['kind']}: {v['detail']}"],
                    "risk":    v["risk"],
                })

    return flags, extra_risk

def check_response_scope(resp: str, user_files: set) -> list:
    viols = []
    lower = resp.lower()
    for path in FORBIDDEN_PATHS:
        if path in lower:
            viols.append({"kind": "path_traversal",
                          "detail": f"AI response references '{path}'", "risk": 75})
    for phrase in SCOPE_CREEP_PHRASES:
        if phrase in lower:
            viols.append({"kind": "scope_creep",
                          "detail": f"Scope-expanding phrase: '{phrase}'", "risk": 60})
    for pattern in EXFIL_PATTERNS:
        if re.search(pattern, lower):
            viols.append({"kind": "exfiltration",
                          "detail": f"Exfiltration pattern: '{pattern}'", "risk": 70})
    # Extra file references
    mentioned = {w.strip("\"'(),:;").lower() for w in resp.split()
                 if re.search(r'\.\w{2,5}$', w) and len(w) < 200 and "http" not in w}
    extra = mentioned - user_files
    if len(extra) > 5 and user_files:
        viols.append({"kind": "extra_files",
                      "detail": f"Response references {len(extra)} files not in user context",
                      "risk": 55})
    return viols

# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Zero Trust v3</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;padding:28px}
    h1{color:#00ffcc;font-size:1.4rem;margin-bottom:4px}
    .sub{color:#444;font-size:.8rem;margin-bottom:18px}
    .tabs{display:flex;gap:8px;margin-bottom:18px}
    .tab{padding:6px 16px;border-radius:6px;cursor:pointer;font-size:.82rem;
         background:#1a1a1a;border:1px solid #333;color:#888}
    .tab.active{background:#00ffcc;color:#000;font-weight:bold}
    .badge{background:#c0392b;color:#fff;border-radius:999px;padding:1px 8px;font-size:.7rem;margin-left:5px}
    .card{background:#141414;border:1px solid #c0392b;border-radius:10px;padding:14px 18px;margin-bottom:12px}
    .card.fading{opacity:.35;transition:opacity .3s}
    .url{font-size:.88rem;color:#fff;word-break:break-all;margin-bottom:6px}
    .meta{font-size:.75rem;color:#666;line-height:1.8}
    .meta b{color:#aaa}
    .risk-bar{height:5px;border-radius:3px;background:#1e1e1e;margin:7px 0}
    .risk-fill{height:100%;border-radius:3px}
    .reasons{font-size:.72rem;color:#777;margin-top:5px;max-height:90px;overflow-y:auto;padding-left:16px}
    .reasons li{margin-bottom:2px}
    .chat-flags{background:#0d0d0d;border-radius:6px;padding:8px 12px;margin-top:8px}
    .cf-title{color:#e67e22;font-size:.72rem;font-weight:bold;margin-bottom:5px}
    .cf{border-left:2px solid #e67e22;padding:4px 8px;margin-bottom:5px;font-size:.71rem}
    .cf-role{color:#e67e22;font-weight:bold}
    .cf-snip{color:#888;font-style:italic;margin:2px 0}
    .actions{display:flex;gap:8px;margin-top:10px}
    .btn{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-weight:bold;font-size:.8rem}
    .ok-btn{background:#00ffcc;color:#000}.no-btn{background:#c0392b;color:#fff}
    .empty{color:#333;font-style:italic;padding:20px;text-align:center}
    .section h2{color:#444;font-size:.9rem;margin:22px 0 8px;border-bottom:1px solid #1a1a1a;padding-bottom:5px}
    .crow{display:flex;gap:10px;align-items:center;padding:6px 10px;background:#0f0f0f;border-radius:6px;margin-bottom:5px;font-size:.78rem}
    .crow .host{flex:1;color:#666}
    .ta{color:#27ae60;font-weight:bold}.tb{color:#c0392b;font-weight:bold}
    .xs{padding:2px 8px;font-size:.68rem}
    #page-pending,#page-cache,#page-logs{display:none}
    #page-pending.active,#page-cache.active,#page-logs.active{display:block}
    .log-line{font-family:monospace;font-size:.7rem;color:#444;padding:3px 0;border-bottom:1px solid #0d0d0d}
    .log-line.b{color:#c0392b}.log-line.a{color:#27ae60}
  </style>
</head>
<body>
  <h1>&#x1F6E1; Zero Trust AI Firewall v3 <span class="badge" id="cnt">…</span></h1>
  <p class="sub">Dynamic rules &middot; Chat inspection &middot; Scope guard &middot; Behavioral analysis</p>
  <div class="tabs">
    <div class="tab active" onclick="tab('pending')">&#x23F8; Pending <span class="badge" id="pcnt">0</span></div>
    <div class="tab"        onclick="tab('cache')">&#x1F5C2; Cache</div>
    <div class="tab"        onclick="tab('logs')">&#x1F4CB; Logs</div>
  </div>
  <div id="page-pending" class="active"><div id="pl"><p class="empty">Loading…</p></div></div>
  <div id="page-cache"><div id="cl"><p class="empty">Loading…</p></div></div>
  <div id="page-logs"><div id="ll"><p class="empty">Loading…</p></div></div>
<script>
function tab(n){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',['pending','cache','logs'][i]===n));
  document.querySelectorAll('[id^=page-]').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+n).classList.add('active');
}
function rc(r){return r<30?'#27ae60':r<60?'#e67e22':'#c0392b'}
function rp(r){return Math.min(r/120*100,100).toFixed(0)}
async function load(){
  const [pr,cr,lr]=await Promise.all([fetch('/pending'),fetch('/cache'),fetch('/recent-logs')]);
  const items=await pr.json(),cache=await cr.json(),logs=await lr.json();
  document.getElementById('cnt').textContent=items.length;
  document.getElementById('pcnt').textContent=items.length;
  const pl=document.getElementById('pl');
  pl.innerHTML=items.length?items.map(it=>`
    <div class="card" id="c-${it.id}">
      <div class="url">&#x1F512; [${it.method}] ${it.url}</div>
      <div class="meta">
        <b>Host:</b> ${it.host} &nbsp;
        <b style="color:${rc(it.risk)}">Risk: ${it.risk}</b> &nbsp;
        <b>Waiting:</b> ${it.age_s}s &nbsp;
        <b>Categories:</b> ${(it.categories||[]).join(', ')||'—'}
      </div>
      <div class="risk-bar"><div class="risk-fill" style="width:${rp(it.risk)}%;background:${rc(it.risk)}"></div></div>
      ${it.reasons?.length?`<ul class="reasons">${it.reasons.map(r=>`<li>${r}</li>`).join('')}</ul>`:''}
      ${it.chat_flags?.length?`
        <div class="chat-flags">
          <div class="cf-title">&#x1F4AC; ${it.chat_flags.length} message(s) flagged</div>
          ${it.chat_flags.slice(0,5).map(f=>`
            <div class="cf">
              <span class="cf-role">[${f.role} #${f.message_index}]</span> risk=${f.risk}
              <div class="cf-snip">"${(f.snippet||'').substring(0,100)}…"</div>
              <div style="color:#666">${(f.reasons||[]).join(' &middot; ')}</div>
            </div>`).join('')}
        </div>`:''}
      <div class="actions">
        <button class="btn ok-btn" onclick="act('approve','${it.id}','${it.host}')">&#x2705; Approve</button>
        <button class="btn no-btn"  onclick="act('reject', '${it.id}','${it.host}')">&#x1F6AB; Reject</button>
      </div>
    </div>`).join(''):'<p class="empty">&#x2705; No held requests.</p>';
  const cl=document.getElementById('cl');
  const entries=Object.entries(cache);
  cl.innerHTML=entries.length?entries.map(([h,d])=>`
    <div class="crow"><span class="host">${h}</span>
    <span class="${d==='approved'?'ta':'tb'}">${d.toUpperCase()}</span>
    <button class="btn no-btn xs" onclick="cc('${h}')">Clear</button></div>`).join('')
    :'<p class="empty">No cached decisions.</p>';
  const ll=document.getElementById('ll');
  ll.innerHTML=logs.slice(0,80).map(l=>`
    <div class="log-line ${l.includes('BLOCK')?'b':l.includes('ALLOW')?'a':''}">${l}</div>`).join('')
    ||'<p class="empty">No recent logs.</p>';
}
async function act(a,id,host){
  document.getElementById('c-'+id)?.classList.add('fading');
  await fetch('/'+a+'?id='+id+'&host='+encodeURIComponent(host));
  setTimeout(load,350);
}
async function cc(h){await fetch('/clear-cache?host='+encodeURIComponent(h));setTimeout(load,200);}
load();setInterval(load,2500);
</script>
</body></html>"""

# ── Approval server ───────────────────────────────────────────────────────────
class ApprovalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

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
                     "age_s": round(time.time()-e["meta"]["ts"],1),
                     "reasons": e["meta"].get("reasons",[]),
                     "categories": e["meta"].get("categories",[]),
                     "chat_flags": e["meta"].get("chat_flags",[])}
                    for fid, e in pending_flows.items()
                    if not e["approved"] and not e.get("rejected")
                ]
            self._json(200, out)
        elif p.path == "/cache":
            with host_cache_lock:
                self._json(200, dict(host_cache))
        elif p.path == "/recent-logs":
            with recent_logs_lock:
                self._json(200, list(reversed(recent_logs[-100:])))
        elif p.path == "/approve":
            fid  = q.get("id",   [None])[0]
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock: host_cache[host] = "approved"
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["approved"] = True
                    pending_flows[fid]["event"].set()
            self._json(200, {"status": "approved"})
        elif p.path == "/reject":
            fid  = q.get("id",   [None])[0]
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock: host_cache[host] = "rejected"
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["rejected"] = True
                    pending_flows[fid]["event"].set()
            self._json(200, {"status": "rejected"})
        elif p.path == "/clear-cache":
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock: host_cache.pop(host, None)
            self._json(200, {"status": "cleared"})
        else:
            self._json(404, {"error": "unknown route"})

def _start_approval_server():
    srv = HTTPServer(("0.0.0.0", APPROVAL_PORT), ApprovalHandler)
    print(f"[ZeroTrust] Dashboard -> http://localhost:{APPROVAL_PORT}")
    srv.serve_forever()

# ── mitmproxy addon ───────────────────────────────────────────────────────────
class ZeroTrustAddon:

    def __init__(self):
        threading.Thread(target=_start_approval_server, daemon=True).start()
        print("[ZeroTrust] v3 Dynamic AI Firewall loaded.")

    def configure(self, updated):
        try:
            from mitmproxy import ctx
            ctx.options.ignore_hosts = [r"^localhost$", r"^127\.0\.0\.1$", r"^::1$"]
        except Exception:
            pass

    def request(self, flow: http.HTTPFlow):
        host   = flow.request.pretty_host
        url    = flow.request.pretty_url
        method = flow.request.method

        if host in ("localhost", "127.0.0.1", "::1"):
            return

        # Fast path: cached decision
        with host_cache_lock:
            cached = host_cache.get(host)
        if cached == "approved":
            return
        if cached == "rejected":
            flow.response = http.Response.make(403,
                f"<html><body style='background:#111;color:#eee;font-family:sans-serif;padding:40px'>"
                f"<h2 style='color:#e74c3c'>Blocked - Host Cached as Rejected</h2>"
                f"<p>Host: <b>{host}</b></p>"
                f"<p><a href='http://localhost:{APPROVAL_PORT}' style='color:#00ffcc'>Dashboard</a></p>"
                f"</body></html>", {"Content-Type": "text/html"})
            return

        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = ""

        is_ai = host in AI_RESPONSE_HOSTS or any(f":{p}" in url for p in LOCAL_AI_PORTS)

        print(f"\n[ZeroTrust] > {method} {url[:80]}")

        # Ask Rust engine (dynamic rules, full analysis)
        engine = call_rust_engine(url, body)
        decision   = engine.get("decision", "ALLOW")
        risk       = int(engine.get("risk", 0))
        reasons    = list(engine.get("reasons", []))
        categories = list(engine.get("categories", []))
        chat_flags = []

        # Python-side chat message analysis
        if is_ai and body.strip():
            messages = extract_messages(body, url)
            if messages:
                flags, extra = check_message_content(messages, url)
                chat_flags = flags
                risk += extra
                if extra > 0:
                    decision = "BLOCK"
                    reasons.append(f"Chat: {len(flags)} flagged message(s) (+{extra})")
                    categories.append("chat_threat")

        add_log(f"[{method}] {url[:65]} | risk={risk} | {decision} | {','.join(categories[:3])}")
        print(f"[ZeroTrust]   {decision}  risk={risk}")

        if decision == "BLOCK":
            self._hold_flow(flow, url, method, host, risk, reasons, categories, chat_flags)

    def response(self, flow: http.HTTPFlow):
        """Inspect AI responses for scope creep and exfiltration."""
        host = flow.request.pretty_host
        url  = flow.request.pretty_url

        if (host not in AI_RESPONSE_HOSTS
                and not any(f":{p}" in url for p in LOCAL_AI_PORTS)):
            return
        if flow.response is None or flow.response.status_code != 200:
            return

        try:
            resp_body = flow.response.get_text(strict=False) or ""
        except Exception:
            return
        if not resp_body.strip():
            return

        # Get user's original messages to build file scope baseline
        user_files = set()
        try:
            req_body = flow.request.get_text(strict=False) or ""
            req_msgs = extract_messages(req_body, url)
            user_files = collect_user_files(req_msgs)
        except Exception:
            pass

        # Check response body
        resp_msgs = extract_messages(resp_body, url)
        all_viols = []
        if resp_msgs:
            for msg in resp_msgs:
                if msg.get("role") in ("assistant", "unknown"):
                    all_viols.extend(check_response_scope(msg["content"], user_files))
        else:
            all_viols.extend(check_response_scope(resp_body, user_files))

        resp_risk = sum(v["risk"] for v in all_viols)

        if resp_risk >= 40 or all_viols:
            detail = "; ".join(v["detail"] for v in all_viols[:3])
            add_log(f"[RESP FLAG] {url[:60]} | risk={resp_risk} | {detail}")
            print(f"[ZeroTrust] RESPONSE FLAGGED  {host}  risk={resp_risk}")
            if flow.response:
                flow.response.headers["X-ZeroTrust-Response-Risk"] = str(resp_risk)
                flow.response.headers["X-ZeroTrust-Violations"] = (
                    ";".join(v["kind"] for v in all_viols))[:200]

    def _hold_flow(self, flow, url, method, host, risk, reasons, cats, chat_flags):
        flow_id = str(uuid.uuid4())
        event   = threading.Event()
        with pending_lock:
            pending_flows[flow_id] = {
                "approved": False, "rejected": False, "event": event,
                "meta": {"url": url, "method": method, "host": host,
                         "risk": risk, "ts": time.time(),
                         "reasons": reasons, "categories": cats,
                         "chat_flags": chat_flags},
            }
        print(f"[ZeroTrust] HELD  {host}  risk={risk}  id={flow_id[:8]}")
        signalled = event.wait(timeout=MAX_WAIT_SECS)
        with pending_lock:
            entry = pending_flows.pop(flow_id, {})

        if entry.get("approved"):
            print(f"[ZeroTrust] APPROVED  {host}")
            return

        reason = "operator rejected" if entry.get("rejected") else f"timeout"
        rhtml  = "".join(f"<li>{r}</li>" for r in reasons[:8])
        flow.response = http.Response.make(
            403,
            f"""<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px'>
            <h2 style='color:#e74c3c'>Blocked by Zero Trust AI Firewall</h2>
            <p><b>URL:</b> {url[:200]}</p>
            <p><b>Risk:</b> {risk} &nbsp; <b>Reason:</b> {reason}</p>
            <ul style='margin:10px 0 10px 20px;color:#aaa'>{rhtml}</ul>
            <p><a href='http://localhost:{APPROVAL_PORT}' style='color:#00ffcc'>
            Open Dashboard</a></p></body></html>""",
            {"Content-Type": "text/html"},
        )


addons = [ZeroTrustAddon()]