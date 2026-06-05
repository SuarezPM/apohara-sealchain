#!/usr/bin/env node
"use strict";

// Postinstall: download the prebuilt `apohara-sealchain` binary that matches this
// platform/arch from the GitHub Release whose tag is `v<package.version>`, place
// it in npx/bin/, and chmod +x. Standard prebuilt-binary npm wrapper pattern.
//
// Asset names MUST match those produced by .github/workflows/release.yml.

const fs = require("fs");
const path = require("path");
const https = require("https");

const REPO = "SuarezPM/apohara-sealchain";
const pkg = require("./package.json");
const TAG = `v${pkg.version}`;

// Map Node's process.platform/process.arch to the release asset name + local
// binary filename. Keys are `${platform}-${arch}`.
const ASSETS = {
  "linux-x64": {
    asset: "apohara-sealchain-x86_64-unknown-linux-gnu",
    binName: "apohara-sealchain",
  },
  "darwin-arm64": {
    asset: "apohara-sealchain-aarch64-apple-darwin",
    binName: "apohara-sealchain",
  },
  "win32-x64": {
    asset: "apohara-sealchain-x86_64-pc-windows-msvc.exe",
    binName: "apohara-sealchain.exe",
  },
};

function fail(msg) {
  console.error(`[apohara-sealchain] install failed: ${msg}`);
  process.exit(1);
}

function download(url, dest, redirectsLeft) {
  return new Promise((resolve, reject) => {
    if (redirectsLeft < 0) {
      reject(new Error("too many redirects"));
      return;
    }
    const req = https.get(
      url,
      { headers: { "User-Agent": "apohara-sealchain-installer" } },
      (res) => {
        // GitHub Release asset downloads redirect to a CDN.
        if (
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          res.resume();
          resolve(download(res.headers.location, dest, redirectsLeft - 1));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        const out = fs.createWriteStream(dest);
        res.pipe(out);
        out.on("finish", () => out.close(resolve));
        out.on("error", reject);
      }
    );
    req.on("error", reject);
  });
}

async function main() {
  const key = `${process.platform}-${process.arch}`;
  const entry = ASSETS[key];
  if (!entry) {
    fail(
      `unsupported platform/arch: ${key}. ` +
        `Supported: ${Object.keys(ASSETS).join(", ")}. ` +
        `Build from source: https://github.com/${REPO}`
    );
  }

  const binDir = path.join(__dirname, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const dest = path.join(binDir, entry.binName);

  const url = `https://github.com/${REPO}/releases/download/${TAG}/${entry.asset}`;
  console.error(`[apohara-sealchain] downloading ${url}`);

  try {
    await download(url, dest, 5);
  } catch (err) {
    fail(`could not download binary: ${err.message}`);
  }

  if (process.platform !== "win32") {
    try {
      fs.chmodSync(dest, 0o755);
    } catch (err) {
      fail(`could not chmod binary: ${err.message}`);
    }
  }

  console.error(`[apohara-sealchain] installed ${dest}`);
}

main();
