const EVENT_TYPE = "ardur.observed_event.v0.1";
const SETTINGS_KEY = "ardur_personal_settings";
const HISTORY_KEY = "ardur_personal_hub_history";
const MAX_HISTORY = 200;
const DEFAULT_HUB_URL = "http://127.0.0.1:8765";

chrome.runtime.onInstalled.addListener(() => {
  initializeStorage().catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") {
    return;
  }
  maybeInjectEnabledTab(tabId, tab?.url).catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((result) => sendResponse(result))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

async function handleMessage(message, sender) {
  switch (message?.type) {
    case EVENT_TYPE:
      return handleObservedEvent(message, sender);
    case "ardur.personal.get_state":
      return popupState(message);
    case "ardur.personal.enable_origin":
      return enableOrigin(message.origin);
    case "ardur.personal.disable_origin":
      return disableOrigin(message.origin);
    case "ardur.personal.get_capture_policy":
      return capturePolicy(message.origin);
    case "ardur.personal.set_capture_snapshots":
      return setCaptureSnapshots(message.origin, message.enabled);
    case "ardur.personal.set_hub_token":
      return setHubToken(message.token);
    case "ardur.personal.export_receipts":
      return hubGet("/v1/export");
    case "ardur.personal.hub_status":
      return hubGet("/v1/status");
    default:
      return { ok: false, error: "unsupported message type" };
  }
}

async function initializeStorage() {
  const settings = await loadSettings();
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function popupState(message) {
  const settings = await loadSettings();
  const history = await loadHistory();
  const origin = normalizeOrigin(message?.origin || "");
  const originHistory = origin
    ? history.filter((item) => item.origin === origin).slice(-25).reverse()
    : history.slice(-25).reverse();
  const hub = await hubGet("/v1/status");
  return {
    ok: true,
    origin,
    enabled: origin ? settings.enabledOrigins.includes(origin) : false,
    captureSnapshots: origin ? settings.captureSnapshotsOrigins.includes(origin) : false,
    settings,
    hub,
    receipts: originHistory.map((item) => item.receipt).filter(Boolean),
    sessionReviews: originHistory.map((item) => item.session_review).filter(Boolean),
    latestReview: originHistory.find((item) => item.session_review)?.session_review || null
  };
}

async function enableOrigin(origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) {
    return { ok: false, error: "invalid origin" };
  }
  const settings = await loadSettings();
  if (!settings.enabledOrigins.includes(normalized)) {
    settings.enabledOrigins.push(normalized);
  }
  await saveSettings(settings);
  return { ok: true, settings };
}

async function disableOrigin(origin) {
  const normalized = normalizeOrigin(origin);
  const settings = await loadSettings();
  settings.enabledOrigins = settings.enabledOrigins.filter((item) => item !== normalized);
  settings.captureSnapshotsOrigins = settings.captureSnapshotsOrigins.filter(
    (item) => item !== normalized
  );
  await saveSettings(settings);
  return { ok: true, settings };
}

async function capturePolicy(origin) {
  const normalized = normalizeOrigin(origin);
  const settings = await loadSettings();
  return {
    ok: true,
    origin: normalized,
    captureSnapshots: normalized
      ? settings.captureSnapshotsOrigins.includes(normalized)
      : false
  };
}

async function setCaptureSnapshots(origin, enabledValue) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) {
    return { ok: false, error: "invalid origin" };
  }
  const settings = await loadSettings();
  const enabled = enabledValue === true;
  if (enabled && !settings.enabledOrigins.includes(normalized)) {
    return { ok: false, error: "enable the site before capturing text snapshots" };
  }
  if (enabled && !settings.captureSnapshotsOrigins.includes(normalized)) {
    settings.captureSnapshotsOrigins.push(normalized);
  }
  if (!enabled) {
    settings.captureSnapshotsOrigins = settings.captureSnapshotsOrigins.filter(
      (item) => item !== normalized
    );
  }
  await saveSettings(settings);
  return { ok: true, settings };
}

async function setHubToken(tokenValue) {
  const settings = await loadSettings();
  settings.hubToken = String(tokenValue || "").trim();
  await saveSettings(settings);
  return { ok: true, settings };
}

async function handleObservedEvent(message, sender) {
  const validation = await validateObservedEvent(message, sender);
  if (!validation.ok) {
    return validation;
  }
  const hubEvent = buildHubEvent(message);
  const response = await hubPost("/v1/events/observe", hubEvent);
  if (!response.ok) {
    return response;
  }
  const history = await loadHistory();
  history.push({
    observed_at: new Date().toISOString(),
    origin: message.origin,
    receipt: response.receipt,
    session_review: response.session_review,
    policy: response.policy
  });
  await chrome.storage.local.set({ [HISTORY_KEY]: history.slice(-MAX_HISTORY) });
  return {
    ok: true,
    receipt_id: response.receipt?.receipt_id,
    verdict: response.policy?.verdict,
    hub: true
  };
}

function buildHubEvent(message) {
  const review = message.review || {};
  return {
    schema_version: "ardur.personal.event.v0.1",
    source: {
      type: "browser",
      app: review.provider || providerFromOrigin(message.origin),
      origin: message.origin
    },
    session: {
      id: `${message.origin}:${message.tab_session_id}`,
      title: review.title || ""
    },
    event: {
      kind: "browser_visible_observation",
      action_class: message.event.action_class || "observe",
      target: message.event.target || "browser",
      capture_mode: review.capture_mode || "digest_only",
      content_digest: message.event.content_digest,
      raw_content_included: false,
      text_snapshot_included: review.text_snapshot_included === true,
      text_excerpt: review.visible_text_excerpt || "",
      messages: Array.isArray(review.messages) ? review.messages : [],
      consent: { visible_text: review.text_snapshot_included === true }
    }
  };
}

async function validateObservedEvent(message, sender) {
  if (message.source !== "content_script") {
    return { ok: false, error: "invalid source" };
  }
  const origin = normalizeOrigin(message.origin);
  if (!origin) {
    return { ok: false, error: "invalid origin" };
  }
  const senderOrigin = normalizeOrigin(sender?.url || sender?.tab?.url || "");
  if (senderOrigin && senderOrigin !== origin) {
    return { ok: false, error: "origin mismatch" };
  }
  const settings = await loadSettings();
  if (!settings.enabledOrigins.includes(origin)) {
    return { ok: false, error: "origin is not enabled" };
  }
  if (!Number.isInteger(message.frame_id) || message.frame_id < 0) {
    return { ok: false, error: "invalid frame id" };
  }
  if (typeof message.tab_session_id !== "string" || !message.tab_session_id) {
    return { ok: false, error: "invalid tab session id" };
  }
  if (Number.isNaN(Date.parse(message.observed_at || ""))) {
    return { ok: false, error: "invalid observed_at" };
  }
  const event = message.event || {};
  if (event.kind !== "dom_observed") {
    return { ok: false, error: "invalid event kind" };
  }
  if (!/^sha-256:[0-9a-f]{64}$/.test(event.content_digest || "")) {
    return { ok: false, error: "invalid content digest" };
  }
  if (event.raw_content_included !== false) {
    return { ok: false, error: "raw content is never sent by the browser adapter" };
  }
  const review = message.review;
  if (review?.text_snapshot_included === true) {
    if (!settings.captureSnapshotsOrigins.includes(origin)) {
      return { ok: false, error: "text snapshot was sent without user consent" };
    }
  }
  return { ok: true };
}

async function maybeInjectEnabledTab(tabId, url) {
  const origin = normalizeOrigin(url || "");
  if (!origin) {
    return;
  }
  const settings = await loadSettings();
  if (!settings.enabledOrigins.includes(origin)) {
    return;
  }
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["src/content_script.js"]
  });
}

async function hubGet(path) {
  const settings = await loadSettings();
  try {
    const response = await fetch(`${settings.hubUrl}${path}`, {
      headers: hubHeaders(settings)
    });
    return await response.json();
  } catch (error) {
    return { ok: false, error: `Hub unavailable: ${error.message || error}` };
  }
}

async function hubPost(path, payload) {
  const settings = await loadSettings();
  try {
    const response = await fetch(`${settings.hubUrl}${path}`, {
      method: "POST",
      headers: hubHeaders(settings, { "content-type": "application/json" }),
      body: JSON.stringify(payload)
    });
    return await response.json();
  } catch (error) {
    return { ok: false, error: `Hub unavailable: ${error.message || error}` };
  }
}

async function loadSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return {
    enabledOrigins: [],
    captureSnapshotsOrigins: [],
    hubUrl: DEFAULT_HUB_URL,
    hubToken: "",
    ...stored[SETTINGS_KEY]
  };
}

async function saveSettings(settings) {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function loadHistory() {
  const stored = await chrome.storage.local.get(HISTORY_KEY);
  return Array.isArray(stored[HISTORY_KEY]) ? stored[HISTORY_KEY] : [];
}

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function hubHeaders(settings, extra = {}) {
  const headers = { ...extra };
  const token = String(settings.hubToken || "").trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
    headers["X-Ardur-Hub-Token"] = token;
  }
  return headers;
}

function providerFromOrigin(origin) {
  const host = new URL(origin).hostname.toLowerCase();
  if (host.endsWith("grok.com")) return "Grok";
  if (host.endsWith("claude.ai")) return "Claude";
  if (host.endsWith("chatgpt.com") || host.endsWith("chat.openai.com")) return "ChatGPT";
  if (host.endsWith("codex.openai.com")) return "Codex";
  if (host.endsWith("kimi.com") || host.endsWith("moonshot.cn")) return "Kimi";
  return "Generic AI Website";
}
