import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const contentScript = readFileSync(
  resolve("examples/ardur-personal-extension/src/content_script.js"),
  "utf8"
);

const sendIndex = contentScript.indexOf("await chrome.runtime.sendMessage({");
const digestIndex = contentScript.indexOf("lastDigest = digest;");

if (sendIndex < 0 || digestIndex < 0) {
  console.error("FAIL: content script digest/send wiring not found");
  process.exit(1);
}

if (digestIndex < sendIndex) {
  console.error("FAIL: lastDigest is updated before sendMessage succeeds");
  process.exit(1);
}

console.log("PASS: content script marks digest after observation send succeeds");
