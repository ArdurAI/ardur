let currentOrigin = "";
let enabled = false;

document.addEventListener("DOMContentLoaded", () => {
  bind("toggle-origin", toggleOrigin);
  bind("collect", collectNow);
  bind("export", exportReceipts);
  bind("hub", hubStatus);
  bind("dashboard", openDashboard);
  bind("save-hub-token", saveHubToken);
  document
    .getElementById("capture-snapshots")
    .addEventListener("change", toggleCaptureSnapshots);
  refresh().catch(showError);
});

function bind(id, handler) {
  document.getElementById(id).addEventListener("click", () => {
    handler().catch(showError);
  });
}

async function refresh() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentOrigin = normalizeOrigin(tab?.url || "");
  const state = await chrome.runtime.sendMessage({
    type: "ardur.personal.get_state",
    origin: currentOrigin
  });
  if (!state.ok) {
    throw new Error(state.error || "state unavailable");
  }
  enabled = Boolean(state.enabled);
  renderState(state);
}

function renderState(state) {
  document.getElementById("origin").textContent = state.origin || "-";
  document.getElementById("hub-state").textContent = state.hub?.ok
    ? `Running: ${state.hub.session_reviews || 0} reviews`
    : "Not running";
  const toggle = document.getElementById("toggle-origin");
  toggle.textContent = state.enabled ? "Disable" : "Enable";
  toggle.dataset.enabled = String(state.enabled);
  document.getElementById("collect").disabled = !state.enabled || !state.hub?.ok;
  document.getElementById("hub-token").value = state.settings?.hubToken || "";
  const capture = document.getElementById("capture-snapshots");
  capture.checked = Boolean(state.captureSnapshots);
  capture.disabled = !state.enabled;
  document.getElementById("capture-mode").textContent = state.captureSnapshots
    ? "Review text"
    : "Digest only";
  document.getElementById("count").textContent = String(state.receipts.length);
  document.getElementById("timeline").replaceChildren(...state.receipts.map(receiptItem));
  renderReview(state.latestReview);
}

function receiptItem(receipt) {
  const item = document.createElement("li");
  const head = document.createElement("div");
  head.className = "receipt-head";

  const id = document.createElement("span");
  id.className = "receipt-id";
  id.textContent = String(receipt.receipt_id || "receipt").slice(0, 16);

  const verdict = document.createElement("span");
  verdict.className = `verdict ${receipt.verdict || "unknown"}`;
  verdict.textContent = receipt.verdict || "unknown";

  const target = document.createElement("p");
  target.textContent = receipt.tool || receipt.target || "Ardur Hub receipt";

  const digest = document.createElement("p");
  digest.className = "digest";
  digest.textContent = receipt.receipt_hash ? receipt.receipt_hash.slice(0, 24) : "";

  head.append(id, verdict);
  item.append(head, target, digest);
  return item;
}

function renderReview(review) {
  document.getElementById("review-provider").textContent = review?.provider || "-";
  document.getElementById("review-summary").textContent = review?.summary || "No review yet.";
  document
    .getElementById("review-labels")
    .replaceChildren(...(review?.policy_labels || []).map(labelItem));
  document
    .getElementById("actions")
    .replaceChildren(...(review?.actions || []).slice(-5).reverse().map(actionItem));
}

function labelItem(value) {
  const item = document.createElement("span");
  item.className = `policy-label ${value}`;
  item.textContent = value;
  return item;
}

function actionItem(action) {
  const item = document.createElement("li");
  item.className = "action";

  const kind = document.createElement("span");
  kind.className = "action-kind";
  kind.textContent = String(action.kind || "action").replace(/_/g, " ");

  const summary = document.createElement("p");
  summary.textContent = action.summary || "";

  item.append(kind, summary);
  return item;
}

async function toggleOrigin() {
  if (!currentOrigin) {
    throw new Error("current site is unavailable");
  }
  if (enabled) {
    await chrome.runtime.sendMessage({
      type: "ardur.personal.disable_origin",
      origin: currentOrigin
    });
    await refresh();
    setStatus("Disabled");
    return;
  }
  const granted = await chrome.permissions.request({
    origins: [`${currentOrigin}/*`]
  });
  if (!granted) {
    setStatus("Not enabled");
    return;
  }
  await chrome.runtime.sendMessage({
    type: "ardur.personal.enable_origin",
    origin: currentOrigin
  });
  await injectContentScript();
  await refresh();
  setStatus("Enabled");
}

async function toggleCaptureSnapshots(event) {
  if (!currentOrigin || !enabled) {
    event.target.checked = false;
    throw new Error("enable the site first");
  }
  const response = await chrome.runtime.sendMessage({
    type: "ardur.personal.set_capture_snapshots",
    origin: currentOrigin,
    enabled: event.target.checked
  });
  if (!response.ok) {
    throw new Error(response.error || "capture setting failed");
  }
  await refresh();
  setStatus(event.target.checked ? "Review text on" : "Digest only");
}

async function saveHubToken() {
  const token = document.getElementById("hub-token").value;
  const response = await chrome.runtime.sendMessage({
    type: "ardur.personal.set_hub_token",
    token
  });
  if (!response.ok) {
    throw new Error(response.error || "Hub token save failed");
  }
  await refresh();
  setStatus("Hub token saved");
}

async function collectNow() {
  await injectContentScript();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  await chrome.tabs.sendMessage(tab.id, { type: "ardur.personal.collect_now" });
  setTimeout(() => refresh().catch(showError), 700);
}

async function injectContentScript() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    throw new Error("active tab unavailable");
  }
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["src/content_script.js"]
  });
}

async function exportReceipts() {
  const exported = await chrome.runtime.sendMessage({
    type: "ardur.personal.export_receipts"
  });
  if (!exported.ok) {
    throw new Error(exported.error || "export failed");
  }
  const blob = new Blob([JSON.stringify(exported, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  await chrome.tabs.create({ url });
}

async function hubStatus() {
  const response = await chrome.runtime.sendMessage({ type: "ardur.personal.hub_status" });
  if (!response.ok) {
    throw new Error(response.error || "Hub unavailable");
  }
  setStatus("Hub running");
  await refresh();
}

async function openDashboard() {
  const state = await chrome.runtime.sendMessage({
    type: "ardur.personal.get_state",
    origin: currentOrigin
  });
  const settings = state.settings || {};
  const hubUrl = settings.hubUrl || "http://127.0.0.1:8765";
  const token = String(settings.hubToken || "").trim();
  const url = token
    ? `${hubUrl}/dashboard?token=${encodeURIComponent(token)}`
    : `${hubUrl}/dashboard`;
  await chrome.tabs.create({ url });
}

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function setStatus(value) {
  document.getElementById("status").textContent = value;
}

function showError(error) {
  setStatus(error.message || String(error));
}
