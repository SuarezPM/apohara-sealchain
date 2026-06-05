// Node smoke test: load the wasm-pack `web` build of sealchain-wasm and verify a
// known-good receipt (content + Ed25519 + C2PA must pass; HMAC honestly not
// checkable) plus a tampered artifact (content must fail). No network.
//
// Usage:
//   node web/smoke.mjs <artifact> <receipt.seal.json>
//
// Exit 0 on success, non-zero on any failed assertion.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import init, { verify_receipt } from "./pkg/sealchain_wasm.js";

const here = dirname(fileURLToPath(import.meta.url));

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exit(1);
  }
  console.log("ok  :", msg);
}

const [artifactPath, receiptPath] = process.argv.slice(2);
if (!artifactPath || !receiptPath) {
  console.error("usage: node web/smoke.mjs <artifact> <receipt.seal.json>");
  process.exit(2);
}

// Instantiate the wasm by handing the binary bytes to the init function (no fetch).
const wasmBytes = await readFile(join(here, "pkg", "sealchain_wasm_bg.wasm"));
await init({ module_or_path: wasmBytes });

const fileBytes = new Uint8Array(await readFile(artifactPath));
const receiptText = await readFile(receiptPath, "utf8");

// --- Good case ---
const good = verify_receipt(fileBytes, receiptText);
console.log("\n[good receipt]");
console.log(JSON.stringify(good, null, 2));

assert(!good.error, "good: no structural error");
const layer = (name) => good.layers.find((l) => l.name === name);
assert(layer("content")?.ok === true, "good: content layer verified");
assert(layer("ed25519")?.ok === true, "good: ed25519 layer verified");
assert(layer("c2pa")?.ok === true, "good: c2pa layer verified");
assert(layer("hmac")?.ok === false, "good: hmac NOT claimed (honest)");
assert(
  layer("hmac")?.reason.includes("hmac key not available in browser"),
  "good: hmac reason is honest"
);
assert(good.ok === true, "good: overall verdict is VERIFIED");

// --- Tampered case: flip one byte of the artifact ---
const tampered = new Uint8Array(fileBytes);
tampered[0] = tampered[0] ^ 0xff;
const bad = verify_receipt(tampered, receiptText);
console.log("\n[tampered artifact]");
console.log(JSON.stringify(bad, null, 2));

assert(!bad.error, "tampered: not a structural error");
const badContent = bad.layers.find((l) => l.name === "content");
assert(badContent?.ok === false, "tampered: content layer FAILS");
assert(bad.ok === false, "tampered: overall verdict is NOT VERIFIED");

console.log("\nALL SMOKE ASSERTIONS PASSED");
