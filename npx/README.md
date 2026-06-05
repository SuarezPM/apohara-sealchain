# apohara-sealchain

`npx @apohara/sealchain` downloads the prebuilt `apohara-sealchain` binary for your platform and starts the MCP stdio server (`apohara-sealchain mcp`). To use it from an MCP client (e.g. Claude Desktop / Claude Code), add a server entry that runs the command via npx — for example `{ "command": "npx", "args": ["-y", "@apohara/sealchain"] }` — which exposes the `seal_artifact`, `verify_receipt`, and `show_chain` tools over stdio. You can also pass CLI subcommands directly (`npx @apohara/sealchain seal <file>`); when no arguments are given it defaults to `mcp`.
