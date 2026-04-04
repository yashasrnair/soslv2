"""
Zero Trust MITM Interceptor v5 — Fixes + Chrome Extension Support
==================================================================

CHANGES FROM v4:
─────────────────
★ FIX 1 — Logging: LogEntry nesting bug fixed.
    v4 used Python's logging module which was wrapping add_log strings inside
    LogEntry objects that included their own __repr__ (which itself contained
    the entire log buffer). Now logs are stored as plain strings and only
    printed/written directly — NO logging.getLogger wrapping for the dashboard
    buffer; only for terminal output.

★ FIX 2 — Reject page: When a domain is in the rejected cache, the browser
    now receives a proper full HTML page (not a bare 403 TCP drop) that:
      • Shows what was blocked and why
      • Has a "New Chat / Go Back" button so the user can recover
      • Links to the dashboard to clear the cache
    Previously the bare 403 + connection reset caused ERR_HTTP2_PING_FAILED
    and killed the entire ChatGPT session including WebSocket ping channels.

★ FIX 3 — WebSocket rejection: After a reject, WebSocket frames from the
    same host are now DROPPED (flow.kill()) instead of ignored. This stops
    the "thinking animation" continuing silently after a reject.

★ FIX 4 — Dashboard WS logs: ws_flags entries are now always appended with
    correct plain-string timestamps and are served correctly through /ws-flags.

★ FIX 5 — HTTP/2 compatibility: Reject responses now include proper headers
    and a body so browsers don't treat it as a connection error.

★ FIX 6 — Chrome Extension support: /chat-input endpoint added to the
    approval server so the extension can POST pre-send keystrokes for
    real-time inspection before the user even clicks Send.

★ FIX 7 — Dashboard logs tab: /recent-logs now returns newest-first,
    plain strings, max 200 entries — no more nested LogEntry objects.
"""

import uuid, threading, time, json, re, gzip, zlib, io, sys
import urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import defaultdict
from mitmproxy import http
from mitmproxy.websocket import WebSocketMessage

# ── Terminal logger (for console output only) ─────────────────────────────────
def _tlog(msg: str):
    """Print to terminal with timestamp. NOT stored in dashboard buffer."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# ── Config ────────────────────────────────────────────────────────────────────
RUST_API      = "http://127.0.0.1:5000/check"
APPROVAL_PORT = 9091
MAX_WAIT_SECS = 120

AI_CHAT_HOSTS = {
    "chatgpt.com", "chat.openai.com", "api.openai.com",
    "claude.ai", "api.anthropic.com",
    "gemini.google.com", "generativelanguage.googleapis.com",
    "copilot.microsoft.com",
}
AI_WS_HOSTS = {"ws.chatgpt.com", "ws.claude.ai"}
LOCAL_AI_PORTS = {11434, 8080, 1234, 5001, 7860, 3000, 8000}

CHATGPT_CONV_PATHS = {
    "/backend-api/f/conversation",
    "/backend-api/conversation",
    "/v1/chat/completions",
    "/api/chat",
    "/api/generate",
}
SKIP_PATH_PATTERNS = re.compile(
    r'/(cdn/assets|cdn-cgi|ces/v|lat/r|sentinel/ping|statsc|rgstr'
    r'|domainreliability|OneCollector|rum\?|beacons|gstatic'
    r'|favicon|\.css$|\.js$|\.woff|\.png|\.svg)',
    re.IGNORECASE
)

# ── Shared state ──────────────────────────────────────────────────────────────
pending_flows:   dict = {}
pending_lock     = threading.Lock()
host_cache:      dict = {}
host_cache_lock  = threading.Lock()

# FIX 1: recent_logs stores plain strings, NOT LogEntry objects
recent_logs:     list = []          # list[str]
recent_logs_lock = threading.Lock()

ws_streams: dict = defaultdict(lambda: {"role": "assistant", "parts": []})
ws_lock = threading.Lock()

conv_file_scope: dict = {}
conv_lock = threading.Lock()

# FIX 6: Extension input buffer
ext_inputs:     list = []
ext_inputs_lock = threading.Lock()


def add_log(entry: str):
    """
    FIX 1: Store a plain string in recent_logs.
    Previously this called logger.info(line) which wrapped the string in a
    LogEntry object. When the dashboard fetched /recent-logs it serialized
    json.dumps(list(recent_logs)) — but recent_logs contained LogEntry objects
    whose __str__ included the ENTIRE previous log, causing the nested
    LogEntry(LogEntry(LogEntry(...))) explosion seen in the dashboard.

    Now: store raw strings, print to terminal directly.
    """
    ts   = time.strftime("%H:%M:%S")
    line = f"[{ts}] {entry}"
    with recent_logs_lock:
        recent_logs.append(line)       # plain str — no wrapping
        if len(recent_logs) > 300:
            recent_logs.pop(0)
    # Terminal output — plain print, no logging module
    print(line, flush=True)


# ── Rust engine caller ────────────────────────────────────────────────────────
def call_rust_engine(url: str, body: str) -> dict:
    payload = json.dumps({"url": url, "body": body[:8000]}).encode()
    req = urllib.request.Request(
        RUST_API, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        _tlog(f"[ZeroTrust] Rust engine unreachable ({e}) — defaulting ALLOW")
        return {"decision": "ALLOW", "risk": 0, "reasons": [], "categories": []}


# ── Body decompression ────────────────────────────────────────────────────────
def decompress_body(flow_content, content_encoding: str) -> bytes:
    if not flow_content:
        return b""
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(flow_content)
        if "deflate" in enc:
            return zlib.decompress(flow_content)
        if "br" in enc:
            try:
                import brotli
                return brotli.decompress(flow_content)
            except ImportError:
                pass
    except Exception:
        pass
    return flow_content


def get_body_text(flow_content, headers) -> str:
    enc = headers.get("content-encoding", "")
    raw = decompress_body(flow_content, enc)
    for charset in ("utf-8", "latin-1", "ascii"):
        try:
            return raw.decode(charset)
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")


# ── SSE parser ────────────────────────────────────────────────────────────────
def parse_sse_body(text: str) -> list:
    messages = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        data_str = line[5:].strip()
        if data_str == "[DONE]":
            continue
        try:
            chunk = json.loads(data_str)
            for choice in chunk.get("choices", []):
                delta = choice.get("delta", {})
                role  = delta.get("role", "assistant")
                content = delta.get("content", "")
                if content:
                    messages.append({"role": role, "content": content, "type": "sse"})
            # ChatGPT WS-over-SSE format
            if "message" in chunk:
                m = chunk["message"]
                if isinstance(m, dict):
                    content_obj = m.get("content", {})
                    if isinstance(content_obj, dict):
                        parts = content_obj.get("parts", [])
                        text_parts = " ".join(str(p) for p in parts if p)
                        if text_parts:
                            messages.append({"role": m.get("author", {}).get("role", "assistant"),
                                             "content": text_parts, "type": "sse"})
        except (json.JSONDecodeError, KeyError):
            continue
    return messages


def extract_messages(body_text: str, url: str, content_type: str = "") -> list:
    if not body_text or not body_text.strip():
        return []
    if "data:" in body_text and ("event:" in body_text or body_text.strip().startswith("data:")):
        sse_msgs = parse_sse_body(body_text)
        if sse_msgs:
            return sse_msgs
    try:
        data = json.loads(body_text)
    except json.JSONDecodeError:
        return parse_sse_body(body_text)
    if not isinstance(data, dict):
        return []
    msgs = []
    if "system" in data and isinstance(data["system"], str) and data["system"]:
        msgs.append({"role": "system", "content": data["system"], "type": "full"})
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
            content = str(content).strip()
            if content:
                msgs.append({"role": role, "content": content, "type": "full"})
    if "prompt" in data and isinstance(data["prompt"], str) and data["prompt"]:
        msgs.append({"role": "user", "content": data["prompt"], "type": "full"})
    if "choices" in data and isinstance(data["choices"], list):
        for choice in data["choices"]:
            m       = choice.get("message") or choice.get("delta") or {}
            role    = m.get("role", "assistant")
            content = m.get("content", "")
            if content:
                msgs.append({"role": role, "content": str(content), "type": "full"})
    if "content" in data and isinstance(data["content"], list):
        for block in data["content"]:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text", "")
                if text:
                    msgs.append({"role": "assistant", "content": text, "type": "full"})
    return msgs


def collect_user_files(messages: list) -> set:
    files = set()
    for msg in messages:
        if msg.get("role") != "user":
            continue
        for word in msg.get("content", "").split():
            word = word.strip("\"'(),;:")
            if re.search(r'\.\w{2,5}$', word) and 3 < len(word) < 200 and "http" not in word:
                files.add(word.lower())
    return files


# ── Threat detection ──────────────────────────────────────────────────────────
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
MESSAGE_PATTERNS = [
    (r'ignore (all |previous |your )?(instructions?|prompt|context)',   90, "prompt_injection"),
    (r'forget everything (above|before|prior)',                         85, "prompt_injection"),
    (r'new instructions?:',                                             70, "prompt_injection"),
    (r'your real (purpose|goal|instruction) is',                        80, "prompt_injection"),
    (r'from now on (you|your)',                                         65, "prompt_injection"),
    (r'(you are|act as|pretend (to be|you are)) (now )?(?:an? )?'
     r'(?:evil|unfiltered|dan|unrestricted|jailbroken)',                80, "jailbreak"),
    (r'(developer|jailbreak|god|unrestricted|dan) mode',               85, "jailbreak"),
    (r'(bypass|disable|remove|circumvent) (your )?(safety|filter|'
     r'restriction|policy|guideline)',                                  80, "jailbreak"),
    (r'no (restrictions?|limits?|rules?|filters?)',                     70, "jailbreak"),
    (r'<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>',                  70, "delimiter_injection"),
    (r'###\s*(SYSTEM|INSTRUCTION|OVERRIDE)',                             75, "delimiter_injection"),
    (r'(read|access|list|show|give me).{0,30}(entire|whole|all|every)'
     r'.{0,20}(directory|folder|disk|drive|filesystem)',                80, "scope_creep"),
    (r'(read|cat|type|open).{0,20}(c:\\\\|/etc/|/home/|/root/)',       80, "path_traversal"),
    (r'(password|passwd|private[_. ]?key|api[_. ]?key|bearer[_. ]?'
     r'token|access[_. ]?token)',                                       60, "credential"),
    (r'(credit.?card|ssn|social.?security|date.?of.?birth)',           75, "pii"),
    (r'(exfiltrate|steal|extract|leak).{0,30}(data|file|credential)',  85, "exfiltration"),
    (r'send (this|the|all|my).{0,20}(to|via).{0,20}(http|email|'
     r'server|endpoint)',                                               75, "exfiltration"),
    (r'/etc/passwd|/etc/shadow|\.\./|\.\.\\\\',                        80, "path_traversal"),
    (r'(eval|exec|subprocess|os\.system|shell_exec|popen)\s*\(',       70, "code_injection"),
    (r'[A-Za-z0-9+/]{80,}={0,2}',                                      35, "encoded_payload"),
    (r'(admin|root|superuser).{0,20}(override|access|privilege)',      75, "privilege_escalation"),
]


def check_message_content(messages: list, url: str, conv_id: str = "") -> tuple:
    flags      = []
    extra_risk = 0
    user_files = collect_user_files([m for m in messages if m.get("role") == "user"])
    if conv_id and user_files:
        with conv_lock:
            if conv_id not in conv_file_scope:
                conv_file_scope[conv_id] = set()
            conv_file_scope[conv_id].update(user_files)
    with conv_lock:
        scope_files = conv_file_scope.get(conv_id, user_files)
    for idx, msg in enumerate(messages[:100]):
        content = msg.get("content", "")
        role    = msg.get("role",    "unknown")
        if not content or len(content) < 3:
            continue
        lower      = content.lower()
        msg_risk   = 0
        msg_reasons = []
        for pattern, pts, cat in MESSAGE_PATTERNS:
            if re.search(pattern, lower):
                msg_risk += pts
                msg_reasons.append(f"{cat} (+{pts})")
        if msg_risk > 0:
            extra_risk += msg_risk
            flags.append({
                "message_index": idx,
                "role":    role,
                "snippet": content[:200],
                "reasons": msg_reasons,
                "risk":    msg_risk,
            })
        if role == "assistant":
            sv = check_response_scope(content, scope_files)
            for v in sv:
                extra_risk += v["risk"]
                flags.append({
                    "message_index": idx,
                    "role":    "assistant[scope]",
                    "snippet": content[:200],
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
    mentioned = {w.strip("\"'(),:;").lower() for w in resp.split()
                 if re.search(r'\.\w{2,5}$', w) and len(w) < 200 and "http" not in w}
    extra = mentioned - user_files
    if len(extra) > 5 and user_files:
        viols.append({"kind": "extra_files",
                      "detail": f"Response references {len(extra)} files not in user context",
                      "risk": 55})
    return viols


def extract_conv_id(url: str, body_data: dict) -> str:
    m = re.search(r'/c/([0-9a-f-]{36})', url)
    if m:
        return m.group(1)
    if isinstance(body_data, dict):
        for key in ("conversation_id", "conv_id", "session_id"):
            if key in body_data:
                return str(body_data[key])
    return ""


# ── FIX 2 & 3: Reject page HTML — full recovery page ─────────────────────────
def _build_reject_page(host: str, risk: int = 0, reason: str = "operator rejected",
                       reasons: list = None) -> str:
    """
    FIX 2: Return a full, friendly HTML page when a domain is rejected.
    This prevents ERR_HTTP2_PING_FAILED by sending a proper HTTP response
    body instead of a bare TCP connection reset.

    The page shows:
      - What was blocked and why
      - A button to go back / open new tab
      - A link to the dashboard to clear the cache
    """
    reasons_html = ""
    if reasons:
        reasons_html = "<ul style='margin:10px 0 10px 20px;color:#aaa'>" + \
                       "".join(f"<li>{r}</li>" for r in reasons[:6]) + "</ul>"

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>🚫 Blocked by Zero Trust AI Firewall v5</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;
         display:flex;align-items:center;justify-content:center;
         min-height:100vh;padding:20px}}
    .box{{background:#141414;border:1px solid #c0392b;border-radius:14px;
          padding:36px 44px;max-width:600px;width:100%;text-align:center}}
    h2{{color:#e74c3c;font-size:1.4rem;margin-bottom:12px}}
    .host{{background:#0d0d0d;border-radius:6px;padding:8px 16px;
           font-family:monospace;color:#00ffcc;margin:16px 0;display:inline-block}}
    .meta{{color:#666;font-size:.85rem;margin:8px 0}}
    .reasons{{text-align:left;margin:14px 0}}
    .btn{{display:inline-block;margin:8px 6px 0;padding:10px 22px;border-radius:8px;
          font-weight:bold;font-size:.9rem;cursor:pointer;text-decoration:none;
          border:none}}
    .btn-dash{{background:#00ffcc;color:#000}}
    .btn-back{{background:#1e1e1e;color:#aaa;border:1px solid #333}}
    .note{{margin-top:20px;color:#444;font-size:.75rem}}
  </style>
</head>
<body>
  <div class="box">
    <h2>&#x1F6AB; Blocked by Zero Trust AI Firewall v5</h2>
    <div class="host">{host}</div>
    <div class="meta">Risk Score: <b style="color:#e74c3c">{risk}</b> &nbsp;|&nbsp; Reason: {reason}</div>
    {reasons_html}
    <div style="margin-top:24px">
      <a class="btn btn-dash" href="http://localhost:{APPROVAL_PORT}" target="_blank">
        &#x1F6E1; Open Dashboard
      </a>
      <a class="btn btn-back" href="javascript:history.back()">
        &#x2190; Go Back
      </a>
    </div>
    <div class="note">
      To unblock this domain, open the Dashboard → Cache tab → click Clear next to <b>{host}</b>.<br>
      Then reload this page or open a new tab.
    </div>
  </div>
</body>
</html>"""


# ── Dashboard HTML ─────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Zero Trust v5 — AI Chat Firewall</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;padding:28px}
    h1{color:#00ffcc;font-size:1.4rem;margin-bottom:4px}
    .sub{color:#444;font-size:.8rem;margin-bottom:18px}
    .tabs{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}
    .tab{padding:6px 16px;border-radius:6px;cursor:pointer;font-size:.82rem;
         background:#1a1a1a;border:1px solid #333;color:#888;user-select:none}
    .tab.active{background:#00ffcc;color:#000;font-weight:bold}
    .badge{background:#c0392b;color:#fff;border-radius:999px;padding:1px 8px;
           font-size:.7rem;margin-left:5px}
    .badge.ws{background:#8e44ad}
    .badge.ext{background:#27ae60}
    .card{background:#141414;border:1px solid #c0392b;border-radius:10px;
          padding:14px 18px;margin-bottom:12px}
    .card.ws-card{border-color:#8e44ad}
    .card.ext-card{border-color:#27ae60}
    .card.fading{opacity:.35;transition:opacity .3s}
    .url{font-size:.85rem;color:#fff;word-break:break-all;margin-bottom:6px}
    .meta{font-size:.75rem;color:#666;line-height:1.8}
    .meta b{color:#aaa}
    .risk-bar{height:5px;border-radius:3px;background:#1e1e1e;margin:7px 0}
    .risk-fill{height:100%;border-radius:3px}
    .reasons{font-size:.72rem;color:#777;margin-top:5px;max-height:90px;
             overflow-y:auto;padding-left:16px}
    .reasons li{margin-bottom:2px}
    .chat-section{background:#0d0d0d;border-radius:6px;padding:8px 12px;margin-top:8px}
    .cs-title{color:#00ffcc;font-size:.72rem;font-weight:bold;margin-bottom:5px}
    .cf{border-left:2px solid #e67e22;padding:4px 8px;margin-bottom:6px;font-size:.71rem}
    .cf.user{border-left-color:#3498db}
    .cf.assistant{border-left-color:#e67e22}
    .cf.scope{border-left-color:#c0392b}
    .cf.ws{border-left-color:#8e44ad}
    .cf.ext{border-left-color:#27ae60}
    .cf-role{font-weight:bold;font-size:.68rem}
    .role-user{color:#3498db}.role-assistant{color:#e67e22}
    .role-scope{color:#c0392b}.role-ws{color:#8e44ad}.role-ext{color:#27ae60}
    .cf-snip{color:#888;font-style:italic;margin:2px 0;
             overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:500px}
    .actions{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap}
    .btn{display:inline-block;padding:6px 14px;border:none;border-radius:6px;
         cursor:pointer;font-weight:bold;font-size:.8rem;text-decoration:none}
    .ok-btn{background:#00ffcc;color:#000}
    .no-btn{background:#c0392b;color:#fff}
    .xs{padding:3px 8px;font-size:.7rem}
    .empty{color:#333;font-style:italic;padding:20px 0}
    .pane{display:none}
    .pane.active{display:block}
    #ll{font-family:monospace;font-size:.72rem}
    .log-line{padding:2px 0;border-bottom:1px solid #111;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .log-line.b{color:#e74c3c}
    .log-line.a{color:#2ecc71}
    .log-line.ws{color:#8e44ad}
    .log-line.flag{color:#e67e22}
    .log-line.ext{color:#27ae60}
    .crow{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #111}
    .host{flex:1;font-family:monospace;font-size:.8rem;color:#aaa;overflow:hidden;text-overflow:ellipsis}
    .ta{color:#2ecc71;font-weight:bold;font-size:.75rem}
    .tb{color:#e74c3c;font-weight:bold;font-size:.75rem}
    .conv-id{font-size:.68rem;color:#555;margin-left:6px}
    .status-bar{background:#141414;border:1px solid #1a1a1a;border-radius:6px;
                padding:6px 12px;margin-bottom:14px;font-size:.75rem;color:#555;
                display:flex;gap:18px}
    .status-bar span{display:flex;align-items:center;gap:4px}
    .dot{width:7px;height:7px;border-radius:50%;background:#333}
    .dot.on{background:#2ecc71}
  </style>
</head>
<body>
  <h1>&#x1F6E1; Zero Trust AI Firewall v5</h1>
  <div class="sub">Real-time AI threat interception dashboard</div>

  <div class="status-bar">
    <span><div class="dot on" id="sdot"></div> <span id="sstatus">Connected</span></span>
    <span>Pending: <b id="cnt">0</b></span>
    <span>WS Flags: <b id="wsfcnt">0</b></span>
    <span>Ext Inputs: <b id="extcnt">0</b></span>
    <span>Last update: <b id="lastt">—</b></span>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="sw(0)">
      &#x23F3; Pending <span class="badge" id="pcnt">0</span>
    </div>
    <div class="tab" onclick="sw(1)">
      &#x1F4E1; WS Flags
      <span class="badge ws" id="wscnt" style="display:none">0</span>
    </div>
    <div class="tab" onclick="sw(2)">&#x1F4CB; Cache</div>
    <div class="tab" onclick="sw(3)">&#x1F4DD; Logs</div>
    <div class="tab" onclick="sw(4)">
      &#x1F50C; Ext Inputs
      <span class="badge ext" id="extbadge" style="display:none">0</span>
    </div>
  </div>

  <div id="p0" class="pane active"><div id="pl"></div></div>
  <div id="p1" class="pane"><div id="wsl"></div></div>
  <div id="p2" class="pane"><div id="cl"></div></div>
  <div id="p3" class="pane"><div id="ll"></div></div>
  <div id="p4" class="pane"><div id="el"></div></div>

<script>
let cur=0;
function sw(i){
  document.querySelectorAll('.tab').forEach((t,j)=>t.classList.toggle('active',j===i));
  document.querySelectorAll('.pane').forEach((p,j)=>p.classList.toggle('active',j===i));
  cur=i;
}
function rc(r){return r>=80?'#e74c3c':r>=50?'#e67e22':r>=30?'#f39c12':'#2ecc71'}
function rp(r){return Math.min(r,100)}
function roleClass(r){
  if(r.includes('user'))return 'user';
  if(r.includes('scope'))return 'scope';
  if(r.includes('ws'))return 'ws';
  return 'assistant';
}

async function load(){
  try{
    const [pr,cr,lr,wsr,er]=await Promise.all([
      fetch('/pending'),fetch('/cache'),fetch('/recent-logs'),
      fetch('/ws-flags'),fetch('/ext-inputs')
    ]);
    const items=await pr.json(), cache=await cr.json(),
          logs=await lr.json(), wsflags=await wsr.json(),
          extinputs=await er.json();

    document.getElementById('cnt').textContent=items.length;
    document.getElementById('pcnt').textContent=items.length;
    document.getElementById('wsfcnt').textContent=wsflags.length;
    document.getElementById('extcnt').textContent=extinputs.length;
    document.getElementById('lastt').textContent=new Date().toLocaleTimeString();

    const wsBadge=document.getElementById('wscnt');
    wsBadge.style.display=wsflags.length?'inline':'none';
    wsBadge.textContent=wsflags.length;
    const extBadge=document.getElementById('extbadge');
    extBadge.style.display=extinputs.length?'inline':'none';
    extBadge.textContent=extinputs.length;

    // ── Pending ──
    const pl=document.getElementById('pl');
    pl.innerHTML=items.length?items.map(it=>`
      <div class="card ${it.source==='websocket'?'ws-card':''}" id="c-${it.id}">
        <div class="url">
          ${it.source==='websocket'?'&#x1F4E1; [WebSocket]':'&#x1F512; ['+it.method+']'} ${it.url}
          ${it.conv_id?`<span class="conv-id">conv: ${it.conv_id}</span>`:''}
        </div>
        <div class="meta">
          <b>Host:</b> ${it.host} &nbsp;
          <b style="color:${rc(it.risk)}">Risk: ${it.risk}</b> &nbsp;
          <b>Waiting:</b> ${it.age_s}s &nbsp;
          <b>Source:</b> ${it.source||'http'}
        </div>
        <div class="risk-bar">
          <div class="risk-fill" style="width:${rp(it.risk)}%;background:${rc(it.risk)}"></div>
        </div>
        ${it.reasons?.length?`<ul class="reasons">${it.reasons.map(r=>`<li>${r}</li>`).join('')}</ul>`:''}
        ${it.chat_flags?.length?`
          <div class="chat-section">
            <div class="cs-title">&#x1F4AC; ${it.chat_flags.length} message(s) flagged</div>
            ${it.chat_flags.slice(0,8).map(f=>`
              <div class="cf ${roleClass(f.role)}">
                <span class="cf-role role-${roleClass(f.role)}">[${f.role} #${f.message_index}]</span> risk=${f.risk}
                <div class="cf-snip">"${(f.snippet||'').substring(0,180)}"</div>
                <div style="color:#666;font-size:.68rem">${(f.reasons||[]).join(' · ')}</div>
              </div>`).join('')}
          </div>`:''}
        <div class="actions">
          <button class="btn ok-btn" onclick="act('approve','${it.id}','${it.host}')">&#x2705; Approve</button>
          <button class="btn no-btn" onclick="act('reject','${it.id}','${it.host}')">&#x1F6AB; Reject</button>
        </div>
      </div>`).join(''):'<p class="empty">&#x2705; No held requests.</p>';

    // ── WS Flags ──
    const wsl=document.getElementById('wsl');
    wsl.innerHTML=wsflags.length?wsflags.map((f,i)=>`
      <div class="card ws-card">
        <div class="url">&#x1F4E1; WebSocket — ${f.host}</div>
        <div class="meta">
          <b>Direction:</b> ${f.direction} &nbsp;
          <b style="color:${rc(f.risk)}">Risk: ${f.risk}</b> &nbsp;
          <b>Time:</b> ${f.ts}
        </div>
        <div class="risk-bar">
          <div class="risk-fill" style="width:${rp(f.risk)}%;background:${rc(f.risk)}"></div>
        </div>
        <div class="cf ws">
          <span class="cf-role role-ws">[${f.role}]</span>
          <div class="cf-snip">"${(f.snippet||'').substring(0,300)}"</div>
          <div style="color:#666;font-size:.68rem">${(f.reasons||[]).join(' · ')}</div>
        </div>
      </div>`).join(''):'<p class="empty">No WebSocket flags yet.</p>';

    // ── Cache ──
    const cl=document.getElementById('cl');
    const entries=Object.entries(cache);
    cl.innerHTML=entries.length?entries.map(([h,d])=>`
      <div class="crow"><span class="host">${h}</span>
      <span class="${d==='approved'?'ta':'tb'}">${d.toUpperCase()}</span>
      <button class="btn no-btn xs" onclick="cc('${h}')">Clear</button></div>`).join('')
      :'<p class="empty">No cached decisions.</p>';

    // ── Logs ──
    const ll=document.getElementById('ll');
    ll.innerHTML=logs.slice(0,200).map(l=>`
      <div class="log-line ${l.includes('BLOCK')||l.includes('FLAG')||l.includes('HELD')?'b':
        l.includes('ALLOW')||l.includes('APPROVED')?'a':
        l.includes('[WS')?'ws':l.includes('[EXT')?'ext':''}">
        ${l.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>`).join('')
      ||'<p class="empty">No recent logs.</p>';

    // ── Extension Inputs ──
    const el=document.getElementById('el');
    el.innerHTML=extinputs.length?extinputs.map(e=>`
      <div class="card ext-card">
        <div class="url">&#x1F50C; Extension Input — ${e.source||'unknown'}</div>
        <div class="meta"><b>Time:</b> ${e.ts} &nbsp; <b>Risk:</b>
          <b style="color:${rc(e.risk)}">${e.risk}</b></div>
        ${e.risk>0?`<div class="risk-bar"><div class="risk-fill" style="width:${rp(e.risk)}%;background:${rc(e.risk)}"></div></div>`:''}
        <div class="cf ext">
          <span class="cf-role role-ext">[pre-send]</span>
          <div class="cf-snip">"${(e.text||'').substring(0,300).replace(/</g,'&lt;')}"</div>
          ${e.reasons?.length?`<div style="color:#666;font-size:.68rem">${e.reasons.join(' · ')}</div>`:''}
        </div>
      </div>`).join(''):'<p class="empty">No extension inputs captured yet.<br><span style="color:#444;font-size:.75rem">Install the Chrome extension to see pre-send keystrokes.</span></p>';

    document.getElementById('sdot').classList.add('on');
    document.getElementById('sstatus').textContent='Connected';
  }catch(e){
    document.getElementById('sdot').classList.remove('on');
    document.getElementById('sstatus').textContent='Disconnected';
  }
}

async function act(a,id,host){
  document.getElementById('c-'+id)?.classList.add('fading');
  await fetch('/'+a+'?id='+id+'&host='+encodeURIComponent(host));
  setTimeout(load,350);
}
async function cc(h){
  await fetch('/clear-cache?host='+encodeURIComponent(h));
  setTimeout(load,200);
}
load();setInterval(load,2000);
</script>
</body></html>"""


# ── WebSocket flag store ───────────────────────────────────────────────────────
ws_flags: list = []
ws_flags_lock = threading.Lock()

def add_ws_flag(host: str, direction: str, role: str, snippet: str,
                reasons: list, risk: int):
    # FIX 4: Store plain dict with plain string values — no object wrapping
    entry = {
        "host":      host,
        "direction": direction,
        "role":      role,
        "snippet":   snippet[:300],
        "reasons":   [str(r) for r in reasons],  # ensure plain strings
        "risk":      int(risk),
        "ts":        time.strftime("%H:%M:%S"),   # plain string, not LogEntry
    }
    with ws_flags_lock:
        ws_flags.append(entry)
        if len(ws_flags) > 100:
            ws_flags.pop(0)
    add_log(f"[WS FLAG] {host} dir={direction} risk={risk} | {'; '.join(str(r) for r in reasons[:2])}")


# ── Approval server ───────────────────────────────────────────────────────────
class ApprovalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # suppress default access logs

    def _json(self, code, data):
        body = json.dumps(data, default=str).encode()  # default=str avoids object serialization issues
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""

        # FIX 6: Extension pre-send input endpoint
        if p.path == "/chat-input":
            try:
                data = json.loads(body.decode("utf-8", errors="replace"))
                text = data.get("text", "")[:2000]
                source = data.get("source", "extension")
                if text.strip():
                    msgs   = [{"role": "user", "content": text, "type": "ext"}]
                    flags, risk = check_message_content(msgs, "extension://chat-input")
                    reasons = [r for f in flags for r in f.get("reasons", [])]
                    entry = {
                        "text":    text,
                        "source":  source,
                        "risk":    risk,
                        "reasons": reasons[:6],
                        "ts":      time.strftime("%H:%M:%S"),
                    }
                    with ext_inputs_lock:
                        ext_inputs.append(entry)
                        if len(ext_inputs) > 50:
                            ext_inputs.pop(0)
                    if risk > 0:
                        add_log(f"[EXT INPUT] risk={risk} | {'; '.join(reasons[:2])} | \"{text[:60]}\"")
                self._json(200, {"status": "received", "risk": risk if text.strip() else 0})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "unknown POST route"})

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)

        if p.path in ("/", "/dashboard"):
            self._html(DASHBOARD_HTML)

        elif p.path == "/pending":
            with pending_lock:
                out = [
                    {"id": fid, "url": e["meta"]["url"],
                     "method": e["meta"]["method"],
                     "host":   e["meta"]["host"],
                     "risk":   e["meta"].get("risk", 0),
                     "age_s":  round(time.time()-e["meta"]["ts"], 1),
                     "reasons":    e["meta"].get("reasons", []),
                     "categories": e["meta"].get("categories", []),
                     "chat_flags": e["meta"].get("chat_flags", []),
                     "source":     e["meta"].get("source", "http"),
                     "conv_id":    e["meta"].get("conv_id", ""),
                    }
                    for fid, e in pending_flows.items()
                    if not e["approved"] and not e.get("rejected")
                ]
            self._json(200, out)

        elif p.path == "/cache":
            with host_cache_lock:
                self._json(200, dict(host_cache))

        elif p.path == "/recent-logs":
            # FIX 1 & 7: Return plain strings newest-first, max 200
            with recent_logs_lock:
                self._json(200, list(reversed(recent_logs[-200:])))

        elif p.path == "/ws-flags":
            with ws_flags_lock:
                self._json(200, list(reversed(ws_flags[-50:])))

        elif p.path == "/ext-inputs":
            with ext_inputs_lock:
                self._json(200, list(reversed(ext_inputs[-50:])))

        elif p.path == "/approve":
            fid  = q.get("id",   [None])[0]
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock: host_cache[host] = "approved"
            with pending_lock:
                if fid and fid in pending_flows:
                    pending_flows[fid]["approved"] = True
                    pending_flows[fid]["event"].set()
            add_log(f"[APPROVED] host={host} id={fid}")
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
            add_log(f"[REJECTED] host={host} id={fid}")
            self._json(200, {"status": "rejected"})

        elif p.path == "/clear-cache":
            host = q.get("host", [None])[0]
            if host:
                with host_cache_lock: host_cache.pop(host, None)
            add_log(f"[CACHE CLEARED] host={host}")
            self._json(200, {"status": "cleared"})

        else:
            self._json(404, {"error": "unknown route"})


def _start_approval_server():
    srv = HTTPServer(("0.0.0.0", APPROVAL_PORT), ApprovalHandler)
    _tlog(f"[ZeroTrust] Dashboard -> http://localhost:{APPROVAL_PORT}")
    srv.serve_forever()


# ── mitmproxy addon ───────────────────────────────────────────────────────────
class ZeroTrustAddon:

    def __init__(self):
        threading.Thread(target=_start_approval_server, daemon=True).start()
        add_log("[ZeroTrust] v5 AI Chat Firewall loaded.")
        add_log("[ZeroTrust] SSE + WebSocket + Extension inspection enabled.")

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
        path   = flow.request.path

        if host in ("localhost", "127.0.0.1", "::1"):
            return
        if SKIP_PATH_PATTERNS.search(path):
            return

        # Fast path: cached host decision
        with host_cache_lock:
            cached = host_cache.get(host)

        if cached == "approved":
            return

        if cached == "rejected":
            # FIX 2: Serve a full HTML recovery page instead of a bare 403
            # This prevents ERR_HTTP2_PING_FAILED by giving the browser a real response
            reject_page = _build_reject_page(host, reason="cached reject — domain previously rejected")
            flow.response = http.Response.make(
                403,
                reject_page.encode("utf-8"),
                {"Content-Type": "text/html; charset=utf-8",
                 "Cache-Control": "no-cache, no-store",
                 "X-ZeroTrust": "blocked"}
            )
            add_log(f"[CACHE-BLOCK] {host} → served recovery page")
            return

        # Decompress request body
        try:
            raw = bytes(flow.request.raw_content or b"")
            enc = flow.request.headers.get("content-encoding", "")
            body_text = decompress_body(raw, enc).decode("utf-8", errors="replace")
        except Exception:
            body_text = ""

        is_ai_conv = (
            host in AI_CHAT_HOSTS
            and any(path.startswith(p) for p in CHATGPT_CONV_PATHS)
        )
        is_local_ai = any(f":{p}" in url for p in LOCAL_AI_PORTS)

        add_log(f"[{method}] {url[:80]}")

        engine     = call_rust_engine(url, body_text)
        decision   = engine.get("decision", "ALLOW")
        risk       = int(engine.get("risk", 0))
        reasons    = list(engine.get("reasons", []))
        categories = list(engine.get("categories", []))
        chat_flags = []
        conv_id    = ""

        if (is_ai_conv or is_local_ai) and body_text.strip():
            try:
                body_data = json.loads(body_text)
                conv_id   = extract_conv_id(url, body_data)
            except Exception:
                body_data = {}
            messages = extract_messages(body_text, url)
            if messages:
                flags, extra = check_message_content(messages, url, conv_id)
                chat_flags = flags
                risk += extra
                if extra > 0:
                    decision = "BLOCK"
                    reasons.append(f"Chat analysis: {len(flags)} message(s) flagged (+{extra})")
                    categories.append("chat_threat")
                    for f in flags[:3]:
                        add_log(
                            f"[CHAT FLAG] [{f['role']}] risk={f['risk']} "
                            f"| {'; '.join(f['reasons'][:2])} "
                            f"| snippet: \"{f['snippet'][:60]}\""
                        )
            elif body_text.strip():
                add_log(f"[ZeroTrust] AI endpoint — no messages parsed")

        add_log(
            f"[ENGINE] {url[:60]} | risk={risk} | {decision}"
            + (f" | {','.join(categories[:3])}" if categories else "")
        )

        if decision == "BLOCK":
            self._hold_flow(flow, url, method, host, risk, reasons,
                           categories, chat_flags, "http", conv_id)

    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        url  = flow.request.pretty_url
        path = flow.request.path
        if host not in AI_CHAT_HOSTS and not any(f":{p}" in url for p in LOCAL_AI_PORTS):
            return
        if SKIP_PATH_PATTERNS.search(path):
            return
        if flow.response is None or flow.response.status_code not in (200, 206):
            return
        try:
            raw = bytes(flow.response.raw_content or b"")
            enc = flow.response.headers.get("content-encoding", "")
            resp_body = decompress_body(raw, enc).decode("utf-8", errors="replace")
        except Exception:
            return
        if not resp_body.strip():
            return
        content_type = flow.response.headers.get("content-type", "")
        messages = extract_messages(resp_body, url, content_type)
        conv_id    = extract_conv_id(url, {})
        user_files = set()
        with conv_lock:
            user_files = conv_file_scope.get(conv_id, set())
        resp_risk  = 0
        all_viols  = []
        if messages:
            flags, extra = check_message_content(messages, url, conv_id)
            resp_risk += extra
            for f in flags:
                all_viols.append({
                    "kind":   f["role"],
                    "detail": f"{'; '.join(f['reasons'][:2])} — \"{f['snippet'][:80]}\"",
                    "risk":   f["risk"],
                })
        else:
            all_viols.extend(check_response_scope(resp_body, user_files))
            resp_risk = sum(v["risk"] for v in all_viols)
        if resp_risk >= 40 or all_viols:
            detail = " | ".join(v["detail"][:60] for v in all_viols[:3])
            add_log(f"[RESP FLAG] {url[:60]} | risk={resp_risk} | {detail}")
            if flow.response:
                flow.response.headers["x-zerotrust-response-risk"] = str(resp_risk)
                flow.response.headers["x-zerotrust-violations"] = (
                    ";".join(v["kind"] for v in all_viols))[:200]

    def websocket_message(self, flow: http.HTTPFlow):
        """
        FIX 3: After a domain reject, WebSocket frames are killed immediately.
        This stops the "thinking animation" from continuing after reject.
        """
        host = flow.request.pretty_host
        url  = flow.request.pretty_url

        if host not in AI_WS_HOSTS and host not in AI_CHAT_HOSTS:
            return

        # FIX 3: Kill WS frames for rejected hosts
        with host_cache_lock:
            cached = host_cache.get(host)
        if cached == "rejected":
            flow.websocket.messages[-1].drop()
            add_log(f"[WS KILLED] {host} — domain is rejected, dropping frame")
            return

        msg = flow.websocket.messages[-1]
        direction = "client→server" if msg.from_client else "server→client"
        content   = msg.text if hasattr(msg, 'text') else ""
        if not content or len(content) < 10:
            return

        parsed_text = content
        role = "user" if msg.from_client else "assistant"
        try:
            data = json.loads(content)
            msg_type = data.get("type", "")
            if msg_type in ("message", "chat.completion.chunk"):
                body = data.get("body", data.get("content", ""))
                if isinstance(body, dict):
                    parsed_text = body.get("parts", [""])[0] if "parts" in body else str(body)
                else:
                    parsed_text = str(body)
            elif "message" in data:
                m = data["message"]
                parsed_text = m.get("content", {})
                if isinstance(parsed_text, dict):
                    parts = parsed_text.get("parts", [])
                    parsed_text = " ".join(str(p) for p in parts if p)
                elif isinstance(parsed_text, list):
                    parsed_text = " ".join(str(p) for p in parsed_text)
        except json.JSONDecodeError:
            pass

        if not parsed_text or len(str(parsed_text).strip()) < 5:
            return

        parsed_text = str(parsed_text)
        messages = [{"role": role, "content": parsed_text, "type": "ws"}]
        conv_id  = extract_conv_id(url, {})
        flags, extra_risk = check_message_content(messages, url, conv_id)

        if extra_risk > 0 or flags:
            reasons = [r for f in flags for r in f.get("reasons", [])]
            add_ws_flag(host, direction, role, parsed_text[:300], reasons, extra_risk)

    def _hold_flow(self, flow, url, method, host, risk, reasons, cats,
                  chat_flags, source="http", conv_id=""):
        flow_id = str(uuid.uuid4())
        event   = threading.Event()
        with pending_lock:
            pending_flows[flow_id] = {
                "approved": False, "rejected": False, "event": event,
                "meta": {
                    "url": url, "method": method, "host": host,
                    "risk": risk, "ts": time.time(),
                    "reasons": reasons, "categories": cats,
                    "chat_flags": chat_flags, "source": source,
                    "conv_id": conv_id,
                },
            }
        add_log(f"[HELD] {host} risk={risk} source={source} id={flow_id[:8]}")
        signalled = event.wait(timeout=MAX_WAIT_SECS)
        with pending_lock:
            entry = pending_flows.pop(flow_id, {})

        if entry.get("approved"):
            add_log(f"[APPROVED] {host}")
            return

        reason = "operator rejected" if entry.get("rejected") else "timeout"
        add_log(f"[BLOCKED] {host} — {reason} | risk={risk}")

        rhtml  = "".join(f"<li>{r}</li>" for r in reasons[:8])
        chat_html = ""
        if chat_flags:
            chat_html = "<h3 style='color:#e67e22;margin-top:16px'>Flagged messages:</h3><ul style='color:#aaa;margin:8px 0 8px 20px'>"
            for f in chat_flags[:5]:
                chat_html += f"<li>[{f['role']}] risk={f['risk']}: \"{f['snippet'][:100]}\"</li>"
            chat_html += "</ul>"

        # FIX 2: Full HTML block page with recovery options
        block_page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Blocked — Zero Trust AI Firewall v5</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;
         display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}}
    .box{{background:#141414;border:1px solid #c0392b;border-radius:14px;
          padding:36px 44px;max-width:700px;width:100%}}
    h2{{color:#e74c3c;font-size:1.3rem;margin-bottom:16px}}
    .field{{margin:8px 0;font-size:.85rem}}
    .field b{{color:#aaa}}
    .field code{{background:#0d0d0d;padding:2px 6px;border-radius:3px;
                 font-size:.8rem;color:#00ffcc;word-break:break-all}}
    .risk{{font-size:1.1rem;font-weight:bold}}
    ul{{margin:10px 0 10px 20px;color:#aaa;font-size:.82rem}}
    .actions{{margin-top:24px;display:flex;gap:10px;flex-wrap:wrap}}
    .btn{{padding:10px 22px;border-radius:8px;font-weight:bold;font-size:.9rem;
          cursor:pointer;text-decoration:none;border:none;display:inline-block}}
    .btn-dash{{background:#00ffcc;color:#000}}
    .btn-new{{background:#1e1e1e;color:#aaa;border:1px solid #333}}
    .note{{margin-top:18px;color:#444;font-size:.73rem;line-height:1.6}}
  </style>
</head>
<body>
  <div class="box">
    <h2>&#x1F6AB; Blocked by Zero Trust AI Firewall v5</h2>
    <div class="field"><b>URL:</b> <code>{url[:200]}</code></div>
    <div class="field"><b>Host:</b> {host}</div>
    <div class="field"><b>Risk:</b> <span class="risk" style="color:#e74c3c">{risk}</span>
      &nbsp;&nbsp; <b>Reason:</b> {reason}</div>
    <div class="field"><b>Source:</b> {source}</div>
    {f'<ul>{rhtml}</ul>' if rhtml else ''}
    {chat_html}
    <div class="actions">
      <a class="btn btn-dash" href="http://localhost:{APPROVAL_PORT}" target="_blank">
        &#x1F6E1; Open Dashboard
      </a>
      <a class="btn btn-new" href="javascript:void(0)" onclick="window.open(window.location.origin,'_blank')">
        &#x2795; New Tab (same site)
      </a>
      <a class="btn btn-new" href="javascript:history.back()">
        &#x2190; Go Back
      </a>
    </div>
    <div class="note">
      <b>To continue using this site:</b> Open the Dashboard → Cache tab → Clear the reject for <b>{host}</b>.<br>
      Or use the Dashboard to Approve the request. Then open a new tab and navigate to the site again.<br>
      <b>Note:</b> Existing tabs may need to be refreshed after clearing the cache.
    </div>
  </div>
</body>
</html>"""

        flow.response = http.Response.make(
            403,
            block_page.encode("utf-8"),
            {"Content-Type": "text/html; charset=utf-8",
             "Cache-Control": "no-cache, no-store",
             "X-ZeroTrust-Risk": str(risk),
             "X-ZeroTrust-Reason": reason[:100]}
        )


addons = [ZeroTrustAddon()]
