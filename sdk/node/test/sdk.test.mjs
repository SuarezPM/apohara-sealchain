/**
 * SDK round-trip tests against the real apohara-sealchain binary.
 *
 * Build-binary-aware: if no binary can be resolved (no SEALCHAIN_BIN, not on
 * PATH, no in-repo release build), the tests skip rather than fail. Run with:
 *
 *   SEALCHAIN_BIN=<repo>/target/release/apohara-sealchain node --test
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { seal, verify, show, resolveBin, SealchainError } from "../index.mjs";

function binaryAvailable() {
  const bin = resolveBin();
  // resolveBin may return the bare "sealchain"; probe it before relying on it.
  const probe = spawnSync(bin, ["--version"], { encoding: "utf8" });
  return !probe.error;
}

const skip = binaryAvailable()
  ? false
  : "apohara-sealchain binary not found (set SEALCHAIN_BIN or build the release binary)";

function workdir() {
  return mkdtempSync(path.join(tmpdir(), "sealchain-node-"));
}

test("seal + verify + show round-trip", { skip }, () => {
  const dir = workdir();
  const artifact = path.join(dir, "doc.txt");
  writeFileSync(artifact, "sealchain node sdk roundtrip\n");

  // Default offline seal: HMAC + Ed25519 + C2PA sidecar, no network.
  const receipt = seal(artifact);
  assert.ok(receipt, "seal returns a receipt path");

  const verdict = verify(artifact, receipt);
  assert.equal(verdict.ok, true);
  const names = new Set(verdict.layers.map((l) => l.name));
  for (const expected of ["content", "hmac", "ed25519", "c2pa"]) {
    assert.ok(names.has(expected), `verdict includes ${expected} layer`);
  }

  const trail = show(receipt);
  assert.equal(typeof trail, "string");
  assert.match(trail, /apohara-seal-v1/);
});

test("verify detects tamper without throwing", { skip }, () => {
  const dir = workdir();
  const artifact = path.join(dir, "doc.txt");
  writeFileSync(artifact, "original content\n");
  const receipt = seal(artifact);

  // Mutate after sealing: verification reports ok=false (exit 1 is a verdict).
  writeFileSync(artifact, "tampered content\n");
  const verdict = verify(artifact, receipt);
  assert.equal(verdict.ok, false);
});

test("seal honors out and sealedAt", { skip }, () => {
  const dir = workdir();
  const artifact = path.join(dir, "doc.txt");
  writeFileSync(artifact, "pinned timestamp\n");
  const out = path.join(dir, "custom.seal.json");

  const receipt = seal(artifact, {
    out,
    sealedAt: "2026-01-01T00:00:00+00:00",
  });
  assert.equal(receipt, out);
  assert.ok(existsSync(out));

  const trail = show(receipt);
  assert.match(trail, /2026-01-01T00:00:00\+00:00/);
});

test("seal throws on missing artifact", { skip }, () => {
  const dir = workdir();
  const missing = path.join(dir, "nope.txt");
  assert.throws(() => seal(missing), (err) => {
    assert.ok(err instanceof SealchainError);
    assert.notEqual(err.exitCode, 0);
    return true;
  });
});
