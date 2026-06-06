// These tests drive the MCP server over a child-process stdio transport, which
// is unix-oriented; the harness is unreliable on Windows CI runners (pipe/EOF
// timing). The MCP server itself is cross-platform — this skips only the test
// harness, not the product. Verified on Linux and macOS.
#![cfg(not(windows))]

//! MCP server integration test: a real client round-trip.
//!
//! Spawns the built `apohara-sealchain mcp` binary as a child process, connects with the
//! rmcp client over the child-process stdio transport, and exercises the full
//! protocol: initialize -> list_tools (assert exactly 3) -> seal_artifact ->
//! verify_receipt (assert ok:true).
//!
//! Strategy: real client round-trip via `rmcp::transport::TokioChildProcess`.
//! The resolved rmcp (1.7.0) exposes both a client and the child-process
//! transport, so the heavier `assert_cmd` JSON-RPC fallback is not needed.

use std::collections::BTreeSet;

use rmcp::model::CallToolRequestParams;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::ServiceExt;
use serde_json::{json, Map, Value};
use tempfile::tempdir;

/// Build a `TokioChildProcess` running `apohara-sealchain mcp`.
fn spawn_server() -> TokioChildProcess {
    let bin = assert_cmd::cargo::cargo_bin("apohara-sealchain");
    TokioChildProcess::new(tokio::process::Command::new(bin).configure(|cmd| {
        cmd.arg("mcp");
    }))
    .expect("spawn apohara-sealchain mcp")
}

/// Convert a serde_json object into the `JsonObject` (Map) call arguments.
fn args(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("object args")
}

#[tokio::test]
async fn mcp_round_trip_lists_three_tools_and_seals() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    std::fs::write(&artifact, b"apohara-sealchain mcp round trip").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    let client = ().serve(spawn_server()).await.expect("client connects");

    // --- list_tools: exactly seal_artifact / verify_receipt / show_chain ---
    let tools = client.list_all_tools().await.expect("list tools");
    let names: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let expected: BTreeSet<String> = ["seal_artifact", "verify_receipt", "show_chain"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(names, expected, "exactly the three expected tools");
    assert_eq!(tools.len(), 3, "no extra tools exposed");

    // --- seal_artifact ---
    let seal = client
        .call_tool(
            CallToolRequestParams::new("seal_artifact")
                .with_arguments(args(json!({ "path": artifact.to_string_lossy() }))),
        )
        .await
        .expect("seal_artifact call");
    assert_ne!(seal.is_error, Some(true), "seal must not error");
    let seal_out = seal.structured_content.expect("seal structured content");
    assert_eq!(seal_out["ok"], json!(true), "seal ok");
    assert!(receipt.exists(), "receipt written next to artifact");
    // Every layer of the freshly sealed receipt verifies.
    let layers = seal_out["layers"].as_array().expect("layers array");
    assert!(
        layers.iter().all(|l| l["ok"] == json!(true)),
        "all seal layers ok: {layers:?}"
    );

    // --- verify_receipt ---
    let verify = client
        .call_tool(
            CallToolRequestParams::new("verify_receipt").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "receipt": receipt.to_string_lossy(),
            }))),
        )
        .await
        .expect("verify_receipt call");
    assert_ne!(verify.is_error, Some(true), "verify must not error");
    let verify_out = verify
        .structured_content
        .expect("verify structured content");
    assert_eq!(verify_out["ok"], json!(true), "verify ok:true");

    client.cancel().await.expect("clean shutdown");
}

#[tokio::test]
async fn mcp_seal_accepts_seal_mode_params_and_aborts_without_partial_receipt() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    std::fs::write(&artifact, b"apohara-sealchain mcp seal modes").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    let client = ().serve(spawn_server()).await.expect("client connects");

    // The tool accepts the new params; a default (no network params) call still
    // round-trips fully offline.
    let seal = client
        .call_tool(
            CallToolRequestParams::new("seal_artifact").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "c2pa": false,
            }))),
        )
        .await
        .expect("offline seal call");
    assert_ne!(seal.is_error, Some(true), "offline seal must not error");
    assert!(receipt.exists(), "offline receipt written");
    std::fs::remove_file(&receipt).expect("clear receipt");

    // An unreachable TSA aborts with an error result and NO partial receipt.
    let aborted = client
        .call_tool(
            CallToolRequestParams::new("seal_artifact").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "tsa": "http://127.0.0.1:9/x",
            }))),
        )
        .await;
    // rmcp surfaces a tool error as Err on the client side; either way no
    // receipt may exist.
    let errored = match aborted {
        Ok(result) => result.is_error == Some(true),
        Err(_) => true,
    };
    assert!(errored, "unreachable TSA must abort, not succeed");
    assert!(
        !receipt.exists(),
        "no partial/faked receipt on aborted MCP seal"
    );

    client.cancel().await.expect("clean shutdown");
}

/// A minimal valid 1x1 RGBA PNG (real, c2pa-embeddable).
fn tiny_png() -> Vec<u8> {
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240,
        31, 0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
}

#[tokio::test]
async fn mcp_embed_param_embeds_in_file_and_verifies() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("photo.png");
    std::fs::write(&artifact, tiny_png()).expect("write png");
    let receipt = dir.path().join("photo.png.seal.json");

    let client = ().serve(spawn_server()).await.expect("client connects");

    // seal_artifact with embed=true: the manifest goes INTO the PNG.
    let seal = client
        .call_tool(
            CallToolRequestParams::new("seal_artifact").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "embed": true,
            }))),
        )
        .await
        .expect("embed seal call");
    assert_ne!(seal.is_error, Some(true), "embed seal must not error");
    assert!(receipt.exists(), "receipt written next to artifact");

    // The receipt records the embedded mode and the PNG was rewritten.
    let body = std::fs::read_to_string(&receipt).expect("read receipt");
    assert!(body.contains("\"c2paEmbedded\""), "c2paEmbedded recorded");
    assert!(!body.contains("\"c2paManifest\""), "no sidecar manifest");
    assert_ne!(
        std::fs::read(&artifact).expect("read png"),
        tiny_png(),
        "file rewritten with embedded manifest"
    );

    // verify_receipt round-trips: content + embedded c2pa both ok.
    let verify = client
        .call_tool(
            CallToolRequestParams::new("verify_receipt").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "receipt": receipt.to_string_lossy(),
            }))),
        )
        .await
        .expect("verify_receipt call");
    let verify_out = verify
        .structured_content
        .expect("verify structured content");
    assert_eq!(verify_out["ok"], json!(true), "embedded verify ok:true");

    client.cancel().await.expect("clean shutdown");
}

/// verify_receipt with an optional `profile` enforces a named attestation
/// profile: the cryptographic `ok` stays separate from the `policy` report.
#[tokio::test]
async fn mcp_verify_with_profile_reports_policy() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    std::fs::write(&artifact, b"apohara-sealchain mcp profile").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    let client = ().serve(spawn_server()).await.expect("client connects");

    // Seal the default offline receipt (hmac + ed25519 + c2pa).
    let seal = client
        .call_tool(
            CallToolRequestParams::new("seal_artifact")
                .with_arguments(args(json!({ "path": artifact.to_string_lossy() }))),
        )
        .await
        .expect("seal_artifact call");
    assert_ne!(seal.is_error, Some(true), "seal must not error");
    assert!(receipt.exists(), "receipt written");

    // profile=full: crypto ok, but the policy fails (offline receipt has no tsa/rekor).
    let verify = client
        .call_tool(
            CallToolRequestParams::new("verify_receipt").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "receipt": receipt.to_string_lossy(),
                "profile": "full",
            }))),
        )
        .await
        .expect("verify_receipt call");
    let out = verify
        .structured_content
        .expect("verify structured content");
    assert_eq!(out["ok"], json!(true), "crypto verdict stays ok");
    assert_eq!(
        out["policy"]["passed"],
        json!(false),
        "full profile not met offline: {out:?}"
    );
    assert_eq!(out["policy"]["profile"], json!("full"));
    assert!(
        out["policy"]["violations"]
            .as_array()
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "violations listed: {out:?}"
    );

    // offline-basic IS satisfied by the offline receipt.
    let ok_profile = client
        .call_tool(
            CallToolRequestParams::new("verify_receipt").with_arguments(args(json!({
                "path": artifact.to_string_lossy(),
                "receipt": receipt.to_string_lossy(),
                "profile": "offline-basic",
            }))),
        )
        .await
        .expect("verify_receipt offline-basic");
    let out2 = ok_profile
        .structured_content
        .expect("offline-basic structured content");
    assert_eq!(out2["policy"]["passed"], json!(true), "offline-basic met");

    client.cancel().await.expect("clean shutdown");
}

/// B-4: the same server, served over **streamable-HTTP** (`mcp --http`), is
/// reachable by a real HTTP MCP client and exposes the same three tools. This
/// exercises the transport end-to-end (bind -> connect -> initialize ->
/// list_tools) over a child process, alongside the default stdio path above.
#[tokio::test]
async fn mcp_streamable_http_round_trip_lists_tools() {
    use rmcp::transport::StreamableHttpClientTransport;

    // Reserve a free loopback port, then hand it to the child server.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port();
    let addr = format!("127.0.0.1:{port}");

    let bin = assert_cmd::cargo::cargo_bin("apohara-sealchain");
    let mut child = tokio::process::Command::new(bin)
        .args(["mcp", "--http", &addr])
        .kill_on_drop(true)
        .spawn()
        .expect("spawn mcp --http");

    // Wait for the server to accept connections (up to ~5s).
    let mut ready = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ready, "streamable-HTTP server did not start on {addr}");

    let transport = StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
    let client = ().serve(transport).await.expect("http client connects");

    let tools = client.list_all_tools().await.expect("list tools over http");
    let names: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let expected: BTreeSet<String> = ["seal_artifact", "verify_receipt", "show_chain"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(
        names, expected,
        "the three tools are exposed over streamable-HTTP"
    );

    client.cancel().await.expect("clean shutdown");
    let _ = child.kill().await;
}
