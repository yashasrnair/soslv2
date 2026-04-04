/**
 * Zero Trust AI Firewall v5 — Chrome Extension Content Script
 * ============================================================
 *
 * What this does:
 *   1. Watches the AI chat input textarea/div for user keystrokes
 *   2. Sends the current text to the Zero Trust firewall (port 9091)
 *      on a debounced interval — NOT on every keystroke (too noisy)
 *   3. If the firewall returns a HIGH risk score (>= 70), it shows
 *      a visible warning banner inside the chat UI
 *   4. The "Send" button is NOT blocked by default (the firewall
 *      is advisory here) — blocking requires the MITM proxy layer
 *
 * Supported sites:
 *   - chatgpt.com / chat.openai.com
 *   - claude.ai
 *   - gemini.google.com
 *   - copilot.microsoft.com
 */

const FIREWALL_URL = "http://localhost:9091/chat-input";
const DEBOUNCE_MS  = 1500;   // send after 1.5s of no typing
const WARN_RISK    = 70;     // risk score that triggers visible warning
const MIN_LENGTH   = 20;     // ignore inputs shorter than this

let debounceTimer = null;
let lastSentText  = "";
let warningBanner = null;

// ── Input selector map per site ────────────────────────────────────────────
function getInputSelector() {
  const host = window.location.hostname;
  if (host.includes("chatgpt.com") || host.includes("openai.com")) {
    // ChatGPT uses a contenteditable div
    return 'div#prompt-textarea, textarea[data-id="root"], div[contenteditable="true"][data-testid]';
  }
  if (host.includes("claude.ai")) {
    return 'div[contenteditable="true"].ProseMirror, div[contenteditable="true"]';
  }
  if (host.includes("gemini.google.com")) {
    return 'div[contenteditable="true"].ql-editor, rich-textarea div[contenteditable]';
  }
  if (host.includes("copilot.microsoft.com")) {
    return 'textarea[id*="userInput"], div[contenteditable="true"]';
  }
  return 'textarea, div[contenteditable="true"]';
}

// ── Warning banner ─────────────────────────────────────────────────────────
function showWarning(risk, reasons) {
  removeWarning();
  warningBanner = document.createElement("div");
  warningBanner.id = "zt-warning-banner";
  warningBanner.style.cssText = `
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%);
    background: #1a0000;
    border: 2px solid #e74c3c;
    border-radius: 10px;
    padding: 12px 20px;
    z-index: 999999;
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
    color: #e0e0e0;
    max-width: 500px;
    width: 90%;
    box-shadow: 0 4px 24px rgba(0,0,0,0.6);
    display: flex;
    align-items: flex-start;
    gap: 10px;
  `;

  const icon = document.createElement("span");
  icon.textContent = "🚫";
  icon.style.fontSize = "20px";

  const content = document.createElement("div");
  content.style.flex = "1";

  const title = document.createElement("div");
  title.style.cssText = "font-weight:bold;color:#e74c3c;margin-bottom:4px";
  title.textContent = `Zero Trust Warning — Risk Score: ${risk}`;

  const detail = document.createElement("div");
  detail.style.cssText = "font-size:12px;color:#aaa;line-height:1.5";
  detail.textContent = reasons.slice(0, 3).join(" · ") || "Potential threat detected in prompt";

  const dashLink = document.createElement("a");
  dashLink.href = "http://localhost:9091";
  dashLink.target = "_blank";
  dashLink.style.cssText = "color:#00ffcc;font-size:11px;margin-top:6px;display:inline-block";
  dashLink.textContent = "→ Open Dashboard";

  const closeBtn = document.createElement("button");
  closeBtn.textContent = "✕";
  closeBtn.style.cssText = `
    background: none; border: none; color: #555;
    cursor: pointer; font-size: 16px; padding: 0; margin-left: 8px;
    flex-shrink: 0;
  `;
  closeBtn.onclick = removeWarning;

  content.appendChild(title);
  content.appendChild(detail);
  content.appendChild(dashLink);
  warningBanner.appendChild(icon);
  warningBanner.appendChild(content);
  warningBanner.appendChild(closeBtn);
  document.body.appendChild(warningBanner);

  // Auto-dismiss after 8 seconds
  setTimeout(removeWarning, 8000);
}

function removeWarning() {
  if (warningBanner && warningBanner.parentNode) {
    warningBanner.parentNode.removeChild(warningBanner);
  }
  warningBanner = null;
}

// ── Send text to firewall ──────────────────────────────────────────────────
async function sendToFirewall(text) {
  if (text === lastSentText) return;
  if (text.trim().length < MIN_LENGTH) return;
  lastSentText = text;

  try {
    const res = await fetch(FIREWALL_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text:   text,
        source: window.location.hostname,
        url:    window.location.href,
      }),
    });
    const data = await res.json();

    if (data.risk >= WARN_RISK) {
      showWarning(data.risk, data.reasons || []);
    } else {
      // Clear warning if risk dropped (user edited their message)
      removeWarning();
    }
  } catch (e) {
    // Firewall not running — silently ignore (proxy still protects at network level)
    console.debug("[ZeroTrust Extension] Firewall unreachable:", e.message);
  }
}

// ── Input text extractor ───────────────────────────────────────────────────
function getInputText(el) {
  if (el.tagName === "TEXTAREA") return el.value;
  // contenteditable div — get innerText
  return el.innerText || el.textContent || "";
}

// ── Watch for input elements (handles SPA navigation) ─────────────────────
function attachListeners() {
  const selector = getInputSelector();
  const inputs   = document.querySelectorAll(selector);

  inputs.forEach(el => {
    if (el._zt_attached) return;  // already watching
    el._zt_attached = true;

    const handler = () => {
      const text = getInputText(el);
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => sendToFirewall(text), DEBOUNCE_MS);
    };

    el.addEventListener("input",   handler, { passive: true });
    el.addEventListener("keydown", handler, { passive: true });
    el.addEventListener("paste",   handler, { passive: true });
  });
}

// ── Observe DOM for new input elements (ChatGPT creates them dynamically) ──
const observer = new MutationObserver(() => attachListeners());
observer.observe(document.body, { childList: true, subtree: true });

// Initial attach
attachListeners();
setTimeout(attachListeners, 2000);  // retry after SPA hydration

console.log("[ZeroTrust v5] Content script loaded on", window.location.hostname);
