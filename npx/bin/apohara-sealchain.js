#!/usr/bin/env node
"use strict";

// Thin shim: exec the downloaded `apohara-sealchain` binary, defaulting to the `mcp`
// subcommand so `npx @apohara/sealchain` starts the MCP stdio server. Any extra args
// are forwarded verbatim; if the caller passes their own subcommand we do not
// inject `mcp`. stdio is fully inherited so the MCP transport works.

const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const binName = process.platform === "win32" ? "apohara-sealchain.exe" : "apohara-sealchain";
const binPath = path.join(__dirname, binName);

if (!fs.existsSync(binPath)) {
  console.error(
    `[apohara-sealchain] binary not found at ${binPath}. ` +
      `Reinstall the package so postinstall can download it.`
  );
  process.exit(1);
}

// Default to `mcp` only when no arguments were given.
const forwarded = process.argv.slice(2);
const args = forwarded.length === 0 ? ["mcp"] : forwarded;

const child = spawn(binPath, args, { stdio: "inherit" });

child.on("error", (err) => {
  console.error(`[apohara-sealchain] failed to start binary: ${err.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
