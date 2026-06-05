//! apohara-sealchain — single binary: CLI (seal/verify/show/keygen) + MCP stdio server.

mod cli;
mod mcp;

fn main() {
    std::process::exit(cli::run());
}
