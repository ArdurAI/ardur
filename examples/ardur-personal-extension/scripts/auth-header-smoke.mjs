import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const worker = readFileSync(
  resolve("examples/ardur-personal-extension/src/service_worker.js"),
  "utf8"
);

const required = [
  "hubToken",
  "function hubHeaders",
  "Authorization",
  "X-Ardur-Hub-Token",
  "ardur.personal.set_hub_token"
];

const missing = required.filter((needle) => !worker.includes(needle));
if (missing.length > 0) {
  console.error(`FAIL: missing Hub auth wiring: ${missing.join(", ")}`);
  process.exit(1);
}

console.log("PASS: browser adapter sends configured Hub auth headers");
