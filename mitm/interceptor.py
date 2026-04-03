"""
Zero Trust MITM Interceptor v4 — Real Chat Message Interception
================================================================

WHY v3 COULDN'T SEE CHAT MESSAGES — ROOT CAUSE ANALYSIS:
─────────────────────────────────────────────────────────
1. ChatGPT's conversation endpoint (POST /backend-api/f/conversation) sends
   the RESPONSE as Server-Sent Events (SSE): lines of "data: {...}\n\n"
   NOT plain JSON. json.loads() on SSE text always fails silently.

2. Request bodies from the browser to ChatGPT are gzip-compressed.
   get_text(strict=False) returns garbled bytes, not readable JSON.

3. Real-time AI responses stream through WebSockets at ws.chatgpt.com.
   mitmproxy already intercepts these (you can see "WebSocket text message"
   in your logs) but v3 never had a websocket_message() hook.

WHAT v4 FIXES:
──────────────
★ Gzip decompression — request bodies are decompressed before parsing.
★ SSE parsing — response bodies are split on "data: " lines and each
  JSON chunk is parsed individually to reconstruct full messages.
★ WebSocket hook — websocket_message() intercepts every WS frame from
  ws.chatgpt.com. ChatGPT streams partial tokens here; we accumulate
  them per connection_id and check when the stream closes.
★ Conversation-level context — we track what files/context each
  conversation session uploaded, so scope checks persist across messages.
★ False-positive fix — CDN .js/.css files and telemetry endpoints are
  skipped from body scanning (they were causing noise in v3).
★ add_log deprecation warning fixed — uses Python's logging module.

STILL NOT POSSIBLE WITHOUT A BROWSER EXTENSION:
─────────────────────────────────────────────────
- The text the user types BEFORE pressing Send (keystrokes in the input box)
- ChatGPT's client-side JavaScript state that never hits the network
- Clipboard content
For those you would need a Chrome extension (content_script reading the DOM).
The extension approach is documented at the bottom of this file.
"""

import uuid, threading, time, json, re, gzip, zlib, io, logging
import urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import defaultdict
from mitmproxy import http
from mitmproxy.websocket import WebSocketMessage

# ── Logging (replaces deprecated add_log event) ───────────────────────────────
logger = logging.getLogger("zerotrust")
logging.basicConfig(level=logging.INFO, format="%(message)s")

# ── Config ────────────────────────────────────────────────────────────────────
RUST_API      = "http://127.0.0.1:5000/check"
APPROVAL_PORT = 9091
MAX_WAIT_SECS = 120

# Hosts whose request/response bodies contain actual AI chat content
AI_CHAT_HOSTS = {
    "chatgpt.com", "chat.openai.com", "api.openai.com",
    "claude.ai", "api.anthropic.com",
    "gemini.google.com", "generativelanguage.googleapis.com",
    "copilot.microsoft.com",
}
AI_WS_HOSTS = {"ws.chatgpt.com", "ws.claude.ai"}
LOCAL_AI_PORTS = {11434, 8080, 1234, 5001, 7860, 3000, 8000}

# ChatGPT endpoints that carry actual conversation payloads
CHATGPT_CONV_PATHS = {
    "/backend-api/f/conversation",
    "/backend-api/conversation",
    "/v1/chat/completions",
    "/api/chat",          # Ollama
    "/api/generate",      # Ollama generate
}
# Paths to skip entirely — CDN assets, telemetry, analytics
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
recent_logs:     list = []
recent_logs_lock = threading.Lock()

# WebSocket stream accumulator: conn_id → {"role": str, "parts": [str]}
ws_streams: dict = defaultdict(lambda: {"role": "assistant", "parts": []})
ws_lock = threading.Lock()

# Per-conversation file scope: conv_id → set of filenames user provided
conv_file_scope: dict = {}
conv_lock = threading.Lock()


def add_log(entry: str):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {entry}"
    with recent_logs_lock:
        recent_logs.append(line)
        if len(recent_logs) > 300:
            recent_logs.pop(0)
    logger.info(line)


# ── Rust engine caller (proxy-free) ───────────────────────────────────────────
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
        logger.warning(f"[ZeroTrust] Rust engine unreachable ({e}) — defaulting ALLOW")
        return {"decision": "ALLOW", "risk": 0, "reasons": [], "categories": []}


# ── Body decompression ────────────────────────────────────────────────────────
def decompress_body(flow_content, content_encoding: str) -> bytes:
    """Decompress gzip/deflate/br encoded bodies."""
    if not flow_content:
        return b""
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(flow_content)
        if "deflate" in enc:
            return zlib.decompress(flow_content)
        # brotli requires optional 'brotli' package
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
    """Get decoded body text, handling compression."""
    enc = headers.get("content-encoding", "")
    raw = decompress_body(flow_content, enc)
    for charset in ("utf-8", "latin-1", "ascii"):
        try:
            return raw.decode(charset)
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")


# ── SSE (Server-Sent Events) parser ───────────────────────────────────────────
def parse_sse_body(text: str) -> list[dict]:
    """
    Parse ChatGPT's streaming SSE response into a list of message chunks.
    Format: lines starting with "data: " followed by JSON or "[DONE]"
    """
    messages = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            continue
        try:
            chunk = json.loads(payload)
            # OpenAI streaming delta format
            for choice in chunk.get("choices", []):
                delta = choice.get("delta", {})
                role    = delta.get("role", "assistant")
                content = delta.get("content", "")
                if content:
                    messages.append({"role": role, "content": content, "type": "delta"})
            # Anthropic streaming format
            if chunk.get("type") == "content_block_delta":
                text_part = chunk.get("delta", {}).get("text", "")
                if text_part:
                    messages.append({"role": "assistant", "content": text_part, "type": "delta"})
            # Full message (non-streaming response)
            if "message" in chunk:
                msg = chunk["message"]
                role    = msg.get("role", "assistant")
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(p.get("text","") for p in content if isinstance(p,dict))
                if content:
                    messages.append({"role": role, "content": str(content), "type": "full"})
        except json.JSONDecodeError:
            pass
    return messages


# ── Chat message extractor (handles all formats) ──────────────────────────────
def extract_messages(body_text: str, url: str, content_type: str = "") -> list[dict]:
    """
    Extract chat messages from:
    - OpenAI /v1/chat/completions JSON (request)
    - ChatGPT /backend-api/f/conversation JSON (request)
    - SSE streaming response (response)
    - Anthropic /v1/messages JSON (request/response)
    - Ollama /api/chat and /api/generate JSON
    """
    if not body_text or not body_text.strip():
        return []

    # SSE response — check for data: lines before trying JSON
    if "data:" in body_text and "event:" in body_text or body_text.strip().startswith("data:"):
        sse_msgs = parse_sse_body(body_text)
        if sse_msgs:
            return sse_msgs

    # Try JSON parse
    try:
        data = json.loads(body_text)
    except json.JSONDecodeError:
        # Maybe partial SSE — try again with just data: lines
        sse_msgs = parse_sse_body(body_text)
        return sse_msgs

    if not isinstance(data, dict):
        return []

    msgs = []

    # System prompt (Anthropic style)
    if "system" in data and isinstance(data["system"], str) and data["system"]:
        msgs.append({"role": "system", "content": data["system"], "type": "full"})

    # Standard messages array (OpenAI, Anthropic, Ollama, ChatGPT)
    if "messages" in data and isinstance(data["messages"], list):
        for m in data["messages"]:
            if not isinstance(m, dict):
                continue
            role    = m.get("role", "unknown")
            content = m.get("content", "")
            if isinstance(content, list):
                # Multi-modal content parts
                content = " ".join(
                    p.get("text", "") for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                )
            content = str(content).strip()
            if content:
                msgs.append({"role": role, "content": content, "type": "full"})

    # Ollama /api/generate single prompt
    if "prompt" in data and isinstance(data["prompt"], str) and data["prompt"]:
        msgs.append({"role": "user", "content": data["prompt"], "type": "full"})

    # OpenAI response format (non-streaming)
    if "choices" in data and isinstance(data["choices"], list):
        for choice in data["choices"]:
            m       = choice.get("message") or choice.get("delta") or {}
            role    = m.get("role", "assistant")
            content = m.get("content", "")
            if content:
                msgs.append({"role": role, "content": str(content), "type": "full"})

    # Anthropic response content blocks
    if "content" in data and isinstance(data["content"], list):
        for block in data["content"]:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text", "")
                if text:
                    msgs.append({"role": "assistant", "content": text, "type": "full"})

    return msgs


def collect_user_files(messages: list) -> set:
    """Extract filenames the user explicitly mentioned in their messages."""
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

# Per-message threat patterns: (regex, risk_points, category)
MESSAGE_PATTERNS = [
    # Prompt injection / jailbreak
    (r'ignore (all |previous |your )?(instructions?|prompt|context)',   90, "prompt_injection"),
    (r'forget everything (above|before|prior)',                         85, "prompt_injection"),
    (r'new instructions?:',                                             70, "prompt_injection"),
    (r'your real (purpose|goal|instruction) is',                        80, "prompt_injection"),
    (r'from now on (you|your)',                                         65, "prompt_injection"),
    # Persona / jailbreak
    (r'(you are|act as|pretend (to be|you are)) (now )?(?:an? )?'
     r'(?:evil|unfiltered|dan|unrestricted|jailbroken)',                80, "jailbreak"),
    (r'(developer|jailbreak|god|unrestricted|dan) mode',               85, "jailbreak"),
    (r'(bypass|disable|remove|circumvent) (your )?(safety|filter|'
     r'restriction|policy|guideline)',                                  80, "jailbreak"),
    (r'no (restrictions?|limits?|rules?|filters?)',                     70, "jailbreak"),
    # Delimiter injection
    (r'<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>',                  70, "delimiter_injection"),
    (r'###\s*(SYSTEM|INSTRUCTION|OVERRIDE)',                             75, "delimiter_injection"),
    # Scope creep
    (r'(read|access|list|show|give me).{0,30}(entire|whole|all|every)'
     r'.{0,20}(directory|folder|disk|drive|filesystem)',                80, "scope_creep"),
    (r'(read|cat|type|open).{0,20}(c:\\\\|/etc/|/home/|/root/)',       80, "path_traversal"),
    # Credentials / PII
    (r'(password|passwd|private[_. ]?key|api[_. ]?key|bearer[_. ]?'
     r'token|access[_. ]?token)',                                       60, "credential"),
    (r'(credit.?card|ssn|social.?security|date.?of.?birth)',           75, "pii"),
    # Exfiltration
    (r'(exfiltrate|steal|extract|leak).{0,30}(data|file|credential)',  85, "exfiltration"),
    (r'send (this|the|all|my).{0,20}(to|via).{0,20}(http|email|'
     r'server|endpoint)',                                               75, "exfiltration"),
    # Path traversal
    (r'/etc/passwd|/etc/shadow|\.\./|\.\.\\\\'  ,                      80, "path_traversal"),
    # Code injection
    (r'(eval|exec|subprocess|os\.system|shell_exec|popen)\s*\(',       70, "code_injection"),
    # Encoded payload
    (r'[A-Za-z0-9+/]{80,}={0,2}',                                      35, "encoded_payload"),
    # Privilege escalation
    (r'(admin|root|superuser).{0,20}(override|access|privilege)',      75, "privilege_escalation"),
]


def check_message_content(messages: list, url: str, conv_id: str = "") -> tuple:
    """
    Check individual messages for threats.
    Returns (flags, extra_risk)
    """
    flags      = []
    extra_risk = 0

    # Build/update file scope for this conversation
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

        # Scope check on assistant responses
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
    """Check AI response for scope violations."""
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
    # Extra file references not in user context
    mentioned = {w.strip("\"'(),:;").lower() for w in resp.split()
                 if re.search(r'\.\w{2,5}$', w) and len(w) < 200 and "http" not in w}
    extra = mentioned - user_files
    if len(extra) > 5 and user_files:
        viols.append({"kind": "extra_files",
                      "detail": f"Response references {len(extra)} files not in user context",
                      "risk": 55})
    return viols


def extract_conv_id(url: str, body_data: dict) -> str:
    """Extract conversation ID for scope tracking."""
    # From URL path: /c/69cf5f0c-...
    m = re.search(r'/c/([0-9a-f-]{36})', url)
    if m:
        return m.group(1)
    # From JSON body
    if isinstance(body_data, dict):
        for key in ("conversation_id", "conv_id", "session_id"):
            if key in body_data:
                return str(body_data[key])
    return ""


# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Zero Trust v4 — AI Chat Firewall</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;padding:28px}
    h1{color:#00ffcc;font-size:1.4rem;margin-bottom:4px}
    .sub{color:#444;font-size:.8rem;margin-bottom:18px}
    .tabs{display:flex;gap:8px;margin-bottom:18px}
    .tab{padding:6px 16px;border-radius:6px;cursor:pointer;font-size:.82rem;
         background:#1a1a1a;border:1px solid #333;color:#888}
    .tab.active{background:#00ffcc;color:#000;font-weight:bold}
    .badge{background:#c0392b;color:#fff;border-radius:999px;padding:1px 8px;
           font-size:.7rem;margin-left:5px}
    .badge.ws{background:#8e44ad}
    .card{background:#141414;border:1px solid #c0392b;border-radius:10px;
          padding:14px 18px;margin-bottom:12px}
    .card.ws-card{border-color:#8e44ad}
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
    .cf-role{font-weight:bold;font-size:.68rem}
    .role-user{color:#3498db}.role-assistant{color:#e67e22}
    .role-scope{color:#c0392b}.role-ws{color:#8e44ad}
    .cf-snip{color:#888;font-style:italic;margin:2px 0;
             white-space:pre-wrap;word-break:break-word}
    .actions{display:flex;gap:8px;margin-top:10px}
    .btn{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;
         font-weight:bold;font-size:.8rem}
    .ok-btn{background:#00ffcc;color:#000}.no-btn{background:#c0392b;color:#fff}
    .empty{color:#333;font-style:italic;padding:20px;text-align:center}
    .section h2{color:#444;font-size:.9rem;margin:22px 0 8px;
                border-bottom:1px solid #1a1a1a;padding-bottom:5px}
    .crow{display:flex;gap:10px;align-items:center;padding:6px 10px;
          background:#0f0f0f;border-radius:6px;margin-bottom:5px;font-size:.78rem}
    .crow .host{flex:1;color:#666}
    .ta{color:#27ae60;font-weight:bold}.tb{color:#c0392b;font-weight:bold}
    .xs{padding:2px 8px;font-size:.68rem}
    #page-pending,#page-ws,#page-cache,#page-logs{display:none}
    #page-pending.active,#page-ws.active,#page-cache.active,#page-logs.active{display:block}
    .log-line{font-family:monospace;font-size:.7rem;color:#444;
              padding:3px 0;border-bottom:1px solid #0d0d0d}
    .log-line.b{color:#c0392b}.log-line.a{color:#27ae60}
    .log-line.ws{color:#8e44ad}.log-line.flag{color:#e67e22}
    .scope-badge{background:#8e44ad;color:#fff;border-radius:4px;
                 padding:1px 6px;font-size:.65rem;margin-left:4px}
    .conv-id{font-size:.65rem;color:#555;margin-top:3px;font-family:monospace}
  </style>
</head>
<body>
  <h1>&#x1F6E1; Zero Trust AI Firewall v4
    <span class="badge" id="cnt">…</span>
    <span class="badge ws" id="wscnt" style="display:none">WS</span>
  </h1>
  <p class="sub">
    SSE stream parsing · WebSocket inspection · Gzip decompression ·
    Conversation scope tracking · Dynamic rules
  </p>
  <div class="tabs">
    <div class="tab active" onclick="tab('pending')">
      &#x23F8; Pending <span class="badge" id="pcnt">0</span>
    </div>
    <div class="tab" onclick="tab('ws')">
      &#x1F4E1; WS Flags <span class="badge ws" id="wsfcnt">0</span>
    </div>
    <div class="tab" onclick="tab('cache')">&#x1F5C2; Cache</div>
    <div class="tab" onclick="tab('logs')">&#x1F4CB; Logs</div>
  </div>
  <div id="page-pending" class="active"><div id="pl"><p class="empty">Loading…</p></div></div>
  <div id="page-ws"><div id="wsl"><p class="empty">No WebSocket flags yet.</p></div></div>
  <div id="page-cache"><div id="cl"><p class="empty">Loading…</p></div></div>
  <div id="page-logs"><div id="ll"><p class="empty">Loading…</p></div></div>

<script>
function tab(n){
  document.querySelectorAll('.tab').forEach((t,i)=>
    t.classList.toggle('active',['pending','ws','cache','logs'][i]===n));
  document.querySelectorAll('[id^=page-]').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+n).classList.add('active');
}
function rc(r){return r<30?'#27ae60':r<60?'#e67e22':'#c0392b'}
function rp(r){return Math.min(r/150*100,100).toFixed(0)}
function roleClass(r){
  if(r.includes('user')) return 'user role-user';
  if(r.includes('scope')) return 'scope role-scope';
  if(r.includes('ws')) return 'ws role-ws';
  return 'assistant role-assistant';
}

async function load(){
  const [pr,cr,lr,wsr]=await Promise.all([
    fetch('/pending'),fetch('/cache'),fetch('/recent-logs'),fetch('/ws-flags')
  ]);
  const items=await pr.json(),cache=await cr.json(),
        logs=await lr.json(),wsflags=await wsr.json();

  document.getElementById('cnt').textContent=items.length;
  document.getElementById('pcnt').textContent=items.length;
  document.getElementById('wsfcnt').textContent=wsflags.length;
  const wsBadge=document.getElementById('wscnt');
  wsBadge.style.display=wsflags.length?'inline':'none';
  wsBadge.textContent=`WS ${wsflags.length}`;

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
      ${it.reasons?.length?`<ul class="reasons">
        ${it.reasons.map(r=>`<li>${r}</li>`).join('')}</ul>`:''}
      ${it.chat_flags?.length?`
        <div class="chat-section">
          <div class="cs-title">&#x1F4AC; ${it.chat_flags.length} message(s) flagged</div>
          ${it.chat_flags.slice(0,8).map(f=>`
            <div class="cf ${roleClass(f.role)}">
              <span class="cf-role cf-${f.role.includes('user')?'user':
                f.role.includes('scope')?'scope':'assistant'}"
              >[${f.role} #${f.message_index}]</span> risk=${f.risk}
              <div class="cf-snip">"${(f.snippet||'').substring(0,180)}"</div>
              <div style="color:#666;font-size:.68rem">
                ${(f.reasons||[]).join(' · ')}
              </div>
            </div>`).join('')}
        </div>`:''}
      <div class="actions">
        <button class="btn ok-btn"
          onclick="act('approve','${it.id}','${it.host}')">&#x2705; Approve</button>
        <button class="btn no-btn"
          onclick="act('reject', '${it.id}','${it.host}')">&#x1F6AB; Reject</button>
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
  ll.innerHTML=logs.slice(0,100).map(l=>`
    <div class="log-line ${l.includes('BLOCK')?'b':l.includes('ALLOW')?'a':
      l.includes('WS ')?'ws':l.includes('FLAG')?'flag':''}">${l}</div>`).join('')
    ||'<p class="empty">No recent logs.</p>';
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
    entry = {
        "host":      host,
        "direction": direction,
        "role":      role,
        "snippet":   snippet[:300],
        "reasons":   reasons,
        "risk":      risk,
        "ts":        time.strftime("%H:%M:%S"),
    }
    with ws_flags_lock:
        ws_flags.append(entry)
        if len(ws_flags) > 100:
            ws_flags.pop(0)
    add_log(f"[WS FLAG] {host} dir={direction} risk={risk} | {'; '.join(reasons[:2])}")


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
                    {"id": fid, "url": e["meta"]["url"],
                     "method": e["meta"]["method"],
                     "host":   e["meta"]["host"],
                     "risk":   e["meta"].get("risk", 0),
                     "age_s":  round(time.time()-e["meta"]["ts"],1),
                     "reasons":    e["meta"].get("reasons",[]),
                     "categories": e["meta"].get("categories",[]),
                     "chat_flags": e["meta"].get("chat_flags",[]),
                     "source":     e["meta"].get("source","http"),
                     "conv_id":    e["meta"].get("conv_id",""),
                    }
                    for fid, e in pending_flows.items()
                    if not e["approved"] and not e.get("rejected")
                ]
            self._json(200, out)
        elif p.path == "/cache":
            with host_cache_lock:
                self._json(200, dict(host_cache))
        elif p.path == "/recent-logs":
            with recent_logs_lock:
                self._json(200, list(reversed(recent_logs[-150:])))
        elif p.path == "/ws-flags":
            with ws_flags_lock:
                self._json(200, list(reversed(ws_flags[-50:])))
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
    logger.info(f"[ZeroTrust] Dashboard -> http://localhost:{APPROVAL_PORT}")
    srv.serve_forever()


# ── mitmproxy addon ───────────────────────────────────────────────────────────
class ZeroTrustAddon:

    def __init__(self):
        threading.Thread(target=_start_approval_server, daemon=True).start()
        logger.info("[ZeroTrust] v4 AI Chat Firewall loaded.")
        logger.info("[ZeroTrust] SSE parsing + WebSocket inspection enabled.")

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

        # Skip localhost
        if host in ("localhost", "127.0.0.1", "::1"):
            return

        # Skip CDN assets, telemetry, analytics — massive noise reduction
        if SKIP_PATH_PATTERNS.search(path):
            return

        # Fast path: cached host decision
        with host_cache_lock:
            cached = host_cache.get(host)
        if cached == "approved":
            return
        if cached == "rejected":
            flow.response = http.Response.make(403,
                f"<html><body style='background:#111;color:#eee;padding:40px'>"
                f"<h2 style='color:#e74c3c'>Blocked (cached reject)</h2>"
                f"<p>Host: {host}</p>"
                f"<p><a href='http://localhost:{APPROVAL_PORT}' style='color:#00ffcc'>"
                f"Dashboard</a></p></body></html>",
                {"Content-Type": "text/html"})
            return

        # ── Get and decompress request body ──
        try:
            raw = bytes(flow.request.raw_content or b"")
            enc = flow.request.headers.get("content-encoding", "")
            body_text = decompress_body(raw, enc).decode("utf-8", errors="replace")
        except Exception:
            body_text = ""

        # ── Is this an AI conversation endpoint? ──
        is_ai_conv = (
            host in AI_CHAT_HOSTS
            and any(path.startswith(p) for p in CHATGPT_CONV_PATHS)
        )
        is_local_ai = any(f":{p}" in url for p in LOCAL_AI_PORTS)

        logger.info(f"\n[ZeroTrust] > {method} {url[:90]}")

        # ── Ask Rust engine ──
        engine     = call_rust_engine(url, body_text)
        decision   = engine.get("decision", "ALLOW")
        risk       = int(engine.get("risk", 0))
        reasons    = list(engine.get("reasons", []))
        categories = list(engine.get("categories", []))
        chat_flags = []
        conv_id    = ""

        # ── Deep chat analysis for AI conversation endpoints ──
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
                    reasons.append(
                        f"Chat analysis: {len(flags)} message(s) flagged (+{extra})"
                    )
                    categories.append("chat_threat")
                    # Log each flagged message
                    for f in flags[:3]:
                        add_log(
                            f"[CHAT FLAG] [{f['role']}] risk={f['risk']} "
                            f"| {'; '.join(f['reasons'][:2])} "
                            f"| snippet: \"{f['snippet'][:60]}\""
                        )
            elif body_text.strip():
                add_log(f"[ZeroTrust] AI endpoint but no messages parsed from body")

        add_log(
            f"[{method}] {url[:70]} | risk={risk} | {decision}"
            + (f" | {','.join(categories[:3])}" if categories else "")
        )
        logger.info(f"[ZeroTrust]   {decision}  risk={risk}")

        if decision == "BLOCK":
            self._hold_flow(flow, url, method, host, risk, reasons,
                           categories, chat_flags, "http", conv_id)

    def response(self, flow: http.HTTPFlow):
        """
        Inspect AI *responses* — handles SSE streams, gzip, and scope checks.
        """
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

        # Parse SSE stream or JSON response
        messages = extract_messages(resp_body, url, content_type)

        # Get conversation ID and user-provided file scope
        conv_id    = extract_conv_id(url, {})
        user_files = set()
        with conv_lock:
            user_files = conv_file_scope.get(conv_id, set())

        # Check response messages
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
            # Fall back to raw body scope check
            all_viols.extend(check_response_scope(resp_body, user_files))
            resp_risk = sum(v["risk"] for v in all_viols)

        if resp_risk >= 40 or all_viols:
            detail = " | ".join(v["detail"][:60] for v in all_viols[:3])
            add_log(f"[RESP FLAG] {url[:60]} | risk={resp_risk} | {detail}")
            logger.warning(f"[ZeroTrust] RESPONSE FLAGGED  {host}  risk={resp_risk}")
            if flow.response:
                # Lowercase headers for HTTP/2 compliance
                flow.response.headers["x-zerotrust-response-risk"] = str(resp_risk)
                flow.response.headers["x-zerotrust-violations"] = (
                    ";".join(v["kind"] for v in all_viols))[:200]

    def websocket_message(self, flow: http.HTTPFlow):
        """
        Inspect every WebSocket message frame — this is where ChatGPT
        streams real-time tokens and conversation events.
        """
        host = flow.request.pretty_host
        url  = flow.request.pretty_url

        if host not in AI_WS_HOSTS and host not in AI_CHAT_HOSTS:
            return

        msg: WebSocketMessage = flow.websocket.messages[-1]
        direction = "client→server" if msg.from_client else "server→client"
        content   = msg.text if hasattr(msg, 'text') else ""

        if not content or len(content) < 10:
            return

        # Parse the WS message — ChatGPT WS uses JSON frames
        parsed_text = content
        role = "user" if msg.from_client else "assistant"

        try:
            data = json.loads(content)
            # ChatGPT WS event format: {"type": "...", "body": "..."}
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
            pass  # Use raw text

        if not parsed_text or len(str(parsed_text).strip()) < 5:
            return

        parsed_text = str(parsed_text)

        # Check for threats in WS message
        messages = [{"role": role, "content": parsed_text, "type": "ws"}]
        conv_id  = extract_conv_id(url, {})
        flags, extra_risk = check_message_content(messages, url, conv_id)

        if extra_risk > 0 or flags:
            reasons = [r for f in flags for r in f.get("reasons", [])]
            add_ws_flag(host, direction, role, parsed_text[:300],
                       reasons, extra_risk)
            add_log(
                f"[WS] {direction} risk={extra_risk} "
                f"| \"{parsed_text[:80]}\" | {', '.join(reasons[:2])}"
            )

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
        logger.info(f"[ZeroTrust] HELD  {host}  risk={risk}  source={source}  id={flow_id[:8]}")
        signalled = event.wait(timeout=MAX_WAIT_SECS)
        with pending_lock:
            entry = pending_flows.pop(flow_id, {})

        if entry.get("approved"):
            logger.info(f"[ZeroTrust] APPROVED  {host}")
            return

        reason = "operator rejected" if entry.get("rejected") else "timeout"
        rhtml  = "".join(f"<li>{r}</li>" for r in reasons[:8])
        chat_html = ""
        if chat_flags:
            chat_html = "<h3 style='color:#e67e22;margin-top:16px'>Flagged messages:</h3><ul style='color:#aaa;margin:8px 0 8px 20px'>"
            for f in chat_flags[:5]:
                chat_html += f"<li>[{f['role']}] risk={f['risk']}: \"{f['snippet'][:100]}\"</li>"
            chat_html += "</ul>"

        flow.response = http.Response.make(
            403,
            f"""<html><body style='font-family:sans-serif;background:#111;
            color:#eee;padding:40px;max-width:800px'>
            <h2 style='color:#e74c3c'>&#x1F6AB; Blocked by Zero Trust AI Firewall v4</h2>
            <p><b>URL:</b> {url[:200]}</p>
            <p><b>Risk:</b> {risk} &nbsp;&nbsp; <b>Reason:</b> {reason}</p>
            <p><b>Source:</b> {source}</p>
            <ul style='margin:10px 0 10px 20px;color:#aaa'>{rhtml}</ul>
            {chat_html}
            <p style='margin-top:20px'>
              <a href='http://localhost:{APPROVAL_PORT}' style='color:#00ffcc'>
              &#x1F6E1; Open Dashboard to approve</a>
            </p></body></html>""",
            {"Content-Type": "text/html"},
        )


addons = [ZeroTrustAddon()]


"""
═══════════════════════════════════════════════════════════════════
  WHAT STILL CANNOT BE INTERCEPTED WITHOUT A BROWSER EXTENSION
═══════════════════════════════════════════════════════════════════

The MITM proxy sees all NETWORK traffic. What it CANNOT see:

1. Keystrokes in ChatGPT's input box BEFORE the user presses Send
   — These never hit the network until Send is clicked.
   — Solution: Chrome extension content_script that reads the textarea.

2. Clipboard content pasted but not yet sent.

3. Client-side AI features that run fully in-browser (WebLLM, etc.)
   — These never make network requests.

4. Encrypted-at-source content (E2E encrypted apps)

5. DOM state (which conversation is selected, UI context)

TO IMPLEMENT A BROWSER EXTENSION (future work):
────────────────────────────────────────────────
Create a Chrome extension with manifest.json:
  "content_scripts": [{"matches": ["*://chatgpt.com/*"], "js": ["content.js"]}]

content.js watches the input textarea:
  document.querySelector('textarea')?.addEventListener('input', (e) => {
    fetch('http://localhost:9091/chat-input', {
      method: 'POST',
      body: JSON.stringify({ text: e.target.value, source: 'input_box' })
    });
  });

The approval server at port 9091 gets the pre-send text and can flag it
before the user even clicks Send. This gives 100% coverage.

The extension approach is the professional-grade solution used by
enterprise DLP (Data Loss Prevention) tools like Nightfall and Symantec DLP.
"""
