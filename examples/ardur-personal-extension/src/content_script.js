(() => {
  if (window.__ARDUR_PERSONAL_ACTIVE) {
    return;
  }
  window.__ARDUR_PERSONAL_ACTIVE = true;

  const EVENT_TYPE = "ardur.observed_event.v0.1";
  const SOURCE = "content_script";
  const MAX_TEXT_CHARS = 12000;
  const MAX_SNAPSHOT_TEXT_CHARS = 9000;
  const MAX_TEXT_EXCERPT_CHARS = 1800;
  const MAX_MESSAGE_CHARS = 1200;
  const MAX_MESSAGES = 12;
  const OBSERVE_DELAY_MS = 1200;
  const tabSessionId = crypto.randomUUID();
  let pendingTimer = 0;
  let lastDigest = "";

  async function sha256Hex(text) {
    const encoded = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", encoded);
    return [...new Uint8Array(digest)]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
  }

  function selectedText() {
    const root = document.querySelector("main") || document.body;
    const text = (root?.innerText || "").replace(/\s+/g, " ").trim();
    return text.slice(0, MAX_TEXT_CHARS);
  }

  function normalizedText(element) {
    return (element?.innerText || element?.textContent || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function clip(value, maxChars) {
    return value.length <= maxChars ? value : `${value.slice(0, maxChars - 3)}...`;
  }

  function detectProvider() {
    const host = location.hostname.toLowerCase();
    const providers = [
      [/(\.|^)grok\.com$/, "Grok"],
      [/(\.|^)claude\.ai$/, "Claude"],
      [/(\.|^)(chatgpt\.com|chat\.openai\.com)$/, "ChatGPT"],
      [/(\.|^)codex\.openai\.com$/, "Codex"],
      [/(\.|^)(kimi\.com|kimi\.moonshot\.cn|moonshot\.cn)$/, "Kimi"]
    ];
    const match = providers.find(([pattern]) => pattern.test(host));
    return match ? match[1] : "Generic AI Website";
  }

  function roleFromElement(element) {
    const explicitRole = element.getAttribute("data-message-author-role");
    if (["user", "assistant", "tool", "system"].includes(explicitRole)) {
      return explicitRole;
    }
    const descriptor = [
      element.getAttribute("data-testid"),
      element.getAttribute("aria-label"),
      element.getAttribute("data-role"),
      element.className
    ].join(" ").toLowerCase();
    if (/\b(user|human|prompt|composer)\b/.test(descriptor)) {
      return "user";
    }
    if (/\b(assistant|answer|response|model|bot|completion)\b/.test(descriptor)) {
      return "assistant";
    }
    return "unknown";
  }

  function messageCandidates() {
    const selectors = [
      "[data-message-author-role]",
      "[data-testid*='message']",
      "[data-testid*='response']",
      "[data-testid*='answer']",
      "[data-testid*='conversation']",
      "article",
      "main [role='listitem']"
    ];
    const candidates = [];
    for (const selector of selectors) {
      document.querySelectorAll(selector).forEach((element) => candidates.push(element));
    }
    return candidates;
  }

  async function extractMessages() {
    const messages = [];
    const seen = new Set();
    for (const element of messageCandidates()) {
      const text = normalizedText(element);
      if (text.length < 8 || text.length > MAX_SNAPSHOT_TEXT_CHARS) {
        continue;
      }
      const digest = await sha256Hex(text);
      if (seen.has(digest)) {
        continue;
      }
      seen.add(digest);
      messages.push({
        role: roleFromElement(element),
        text_digest: `sha-256:${digest}`,
        text_excerpt: clip(text, MAX_MESSAGE_CHARS),
        source: element.tagName.toLowerCase()
      });
    }
    if (messages.length > 0) {
      return messages.slice(-MAX_MESSAGES);
    }
    const rootText = normalizedText(document.querySelector("main") || document.body);
    const chunks = rootText
      .split(/(?<=[.!?])\s+|\n{2,}/)
      .map((value) => value.trim())
      .filter((value) => value.length >= 16)
      .slice(-MAX_MESSAGES);
    for (const chunk of chunks) {
      const digest = await sha256Hex(chunk);
      messages.push({
        role: "unknown",
        text_digest: `sha-256:${digest}`,
        text_excerpt: clip(chunk, MAX_MESSAGE_CHARS),
        source: "visible_text"
      });
    }
    return messages;
  }

  async function capturePolicy() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "ardur.personal.get_capture_policy",
        origin: location.origin
      });
      return { captureSnapshots: response?.ok && response.captureSnapshots === true };
    } catch {
      return { captureSnapshots: false };
    }
  }

  async function buildReviewSnapshot(text, reason, digest) {
    const policy = await capturePolicy();
    const includeText = policy.captureSnapshots === true;
    const snapshot = {
      schema_version: "ardur.personal.visible_session_snapshot.v0.1",
      provider: detectProvider(),
      origin: location.origin,
      title: clip(document.title || "", 160),
      boundary_reason: reason,
      capture_mode: includeText ? "structured_visible_text" : "digest_only",
      text_snapshot_included: includeText,
      visible_text_digest: `sha-256:${digest}`,
      visible_text_excerpt: "",
      messages: [],
      collected_at: new Date().toISOString()
    };
    if (!includeText) {
      return snapshot;
    }
    snapshot.visible_text_excerpt = clip(text.slice(0, MAX_SNAPSHOT_TEXT_CHARS), MAX_TEXT_EXCERPT_CHARS);
    snapshot.messages = await extractMessages();
    return snapshot;
  }

  async function emitObservation(reason) {
    const text = selectedText();
    if (!text) {
      return;
    }
    const digest = await sha256Hex(text);
    if (digest === lastDigest) {
      return;
    }
    const review = await buildReviewSnapshot(text, reason, digest);
    await chrome.runtime.sendMessage({
      type: EVENT_TYPE,
      source: SOURCE,
      origin: location.origin,
      tab_session_id: tabSessionId,
      frame_id: 0,
      observed_at: new Date().toISOString(),
      event: {
        kind: "dom_observed",
        action_class: "observe",
        target: reason,
        content_digest: `sha-256:${digest}`,
        raw_content_included: false
      },
      review
    });
    lastDigest = digest;
  }

  function scheduleObservation(reason) {
    clearTimeout(pendingTimer);
    pendingTimer = setTimeout(() => {
      emitObservation(reason).catch(() => {});
    }, OBSERVE_DELAY_MS);
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "ardur.personal.collect_now") {
      return false;
    }
    emitObservation("manual_collect")
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  });

  scheduleObservation("initial_page_state");
  const observer = new MutationObserver(() => scheduleObservation("dom_mutation"));
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true
  });
})();
