/**
 * Thin Node SDK over the `apohara-sealchain` CLI.
 *
 * This package does not reimplement any cryptography. It shells out to the real
 * `apohara-sealchain` binary (the same one built from `crates/apohara-sealchain`) and parses its
 * output. The binary is the single source of truth; this module only marshals
 * arguments and JSON.
 *
 * Binary resolution order:
 *   1. SEALCHAIN_BIN environment variable, if set.
 *   2. `apohara-sealchain` on PATH.
 *   3. The in-repo release build at <repo>/target/release/apohara-sealchain.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

/** Raised when the apohara-sealchain binary exits non-zero. */
export class SealchainError extends Error {
  constructor(message, { exitCode, stderr }) {
    super(message);
    this.name = "SealchainError";
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

/**
 * Resolve the apohara-sealchain binary path.
 *
 * Honors SEALCHAIN_BIN, then PATH (by deferring to the spawn lookup), then the
 * in-repo release build. Returns the resolved path or the bare command name.
 * Throws if a repo fallback was the only option and it does not exist.
 */
export function resolveBin() {
  const envBin = process.env.SEALCHAIN_BIN;
  if (envBin) {
    return envBin;
  }

  // This file lives at sdk/node/index.mjs, so the repo root is two parents up.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..");
  const candidate = path.join(repoRoot, "target", "release", "sealchain");
  if (existsSync(candidate)) {
    return candidate;
  }

  // Fall back to PATH resolution performed by the OS at spawn time.
  return "apohara-sealchain";
}

function run(args) {
  const bin = resolveBin();
  const proc = spawnSync(bin, args, { encoding: "utf8" });
  if (proc.error) {
    // ENOENT here means neither SEALCHAIN_BIN, PATH, nor the repo build resolved.
    throw new SealchainError(
      `apohara-sealchain binary not found (${bin}): ${proc.error.message}. ` +
        "Set SEALCHAIN_BIN, put `apohara-sealchain` on PATH, or build it with " +
        "`cargo build --release -p apohara-sealchain`.",
      { exitCode: -1, stderr: String(proc.error.message ?? "") },
    );
  }
  return proc;
}

/**
 * Seal `filePath` into a receipt and return the receipt path.
 *
 * Mirrors `apohara-sealchain seal`. The default is fully offline (HMAC + Ed25519 + C2PA
 * sidecar). `tsa`/`rekor`/`all` add network-backed layers that need
 * connectivity at seal time.
 *
 * @param {string} filePath Artifact to seal.
 * @param {object} [opts]
 * @param {boolean} [opts.c2pa=true] Emit the offline C2PA sidecar; false -> --no-c2pa.
 * @param {boolean} [opts.embed=false] Embed the C2PA manifest in-file (supported media).
 * @param {string|null} [opts.tsa] Add a TSA layer; "" uses the default authority, a URL overrides.
 * @param {string|null} [opts.rekor] Add a Rekor layer; "" uses the default shard, a URL overrides.
 * @param {boolean} [opts.all=false] Seal all layers real-or-abort.
 * @param {string|null} [opts.sealedAt] Fixed RFC 3339 timestamp.
 * @param {string|null} [opts.out] Receipt output path (default `<path>.seal.json`).
 * @returns {string} The receipt path reported by the binary.
 */
export function seal(filePath, opts = {}) {
  const {
    c2pa = true,
    embed = false,
    tsa = null,
    rekor = null,
    all = false,
    sealedAt = null,
    out = null,
  } = opts;

  const args = ["seal", filePath];
  if (!c2pa) {
    args.push("--no-c2pa");
  }
  if (embed) {
    args.push("--embed");
  }
  if (tsa !== null && tsa !== undefined) {
    args.push("--tsa");
    if (tsa) {
      args.push(tsa);
    }
  }
  if (rekor !== null && rekor !== undefined) {
    args.push("--rekor");
    if (rekor) {
      args.push(rekor);
    }
  }
  if (all) {
    args.push("--all");
  }
  if (sealedAt !== null && sealedAt !== undefined) {
    args.push("--sealed-at", sealedAt);
  }
  if (out !== null && out !== undefined) {
    args.push("--out", out);
  }
  args.push("--json");

  const proc = run(args);
  if (proc.status !== 0) {
    throw new SealchainError(`apohara-sealchain seal failed (exit ${proc.status})`, {
      exitCode: proc.status,
      stderr: (proc.stderr ?? "").trim(),
    });
  }
  // `seal --json` emits a batch envelope: {"sealed","failed","files":[{...,"receipt_path"}]}.
  // (A single path is a batch of one.)
  const parsed = JSON.parse(proc.stdout);
  if (parsed.failed) {
    throw new SealchainError(`apohara-sealchain seal reported ${parsed.failed} failure(s)`, {
      exitCode: proc.status,
      stderr: (proc.stderr ?? "").trim(),
    });
  }
  const files = parsed.files ?? [];
  if (files.length > 0) return files[0].receipt_path;
  if (parsed.receipt_path) return parsed.receipt_path;
  throw new SealchainError("apohara-sealchain seal produced no receipt path in --json output", {
    exitCode: proc.status,
    stderr: (proc.stderr ?? "").trim(),
  });
}

/**
 * Verify `filePath` against `receipt` and return the verdict.
 *
 * Mirrors `apohara-sealchain verify --json`. Returns `{ ok, layers }`. A failed
 * verification (tamper/mismatch, exit 1) is NOT an error: it returns the verdict
 * with `ok: false`. Only structural failures (bad receipt, exit 3) throw.
 *
 * @param {string} filePath Artifact path.
 * @param {string} receipt Receipt JSON path.
 * @returns {{ok: boolean, layers: Array<{name: string, ok: boolean, reason: string}>}}
 */
export function verify(filePath, receipt) {
  const proc = run(["verify", filePath, receipt, "--json"]);
  // Exit 0 = pass, 1 = verification failed; both produce a JSON verdict.
  if (proc.status !== 0 && proc.status !== 1) {
    throw new SealchainError(`apohara-sealchain verify failed (exit ${proc.status})`, {
      exitCode: proc.status,
      stderr: (proc.stderr ?? "").trim(),
    });
  }
  return JSON.parse(proc.stdout);
}

/**
 * Return the human-readable chain trail for `receipt`.
 *
 * Mirrors `apohara-sealchain show`.
 *
 * @param {string} receipt Receipt JSON path.
 * @returns {string}
 */
export function show(receipt) {
  const proc = run(["show", receipt]);
  if (proc.status !== 0) {
    throw new SealchainError(`apohara-sealchain show failed (exit ${proc.status})`, {
      exitCode: proc.status,
      stderr: (proc.stderr ?? "").trim(),
    });
  }
  return proc.stdout;
}

export default { seal, verify, show, resolveBin, SealchainError };
