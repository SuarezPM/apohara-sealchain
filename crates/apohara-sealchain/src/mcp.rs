//! MCP stdio server.
//!
//! Exposes the sync `apohara-sealchain-core` engine as three MCP tools over stdio,
//! using the official Rust SDK (`rmcp`):
//!
//! * `seal_artifact` — seal a file, write `<path>.seal.json`, return the
//!   verify-of-what-we-just-sealed layer results.
//! * `verify_receipt` — verify a file against a receipt file on disk.
//! * `show_chain` — render a receipt's human-readable audit trail.
//!
//! The default receipt produced here is the offline HMAC + Ed25519 + C2PA record the
//! CLI emits (with an optional offline C2PA sidecar via `c2pa=true`). The
//! `tsa`/`rekor`/`all` parameters add the network-backed layers and require
//! connectivity at seal time; `all=true` is real-or-abort (any unproducible
//! layer errors the call with no receipt written). The core is synchronous, so
//! every call into it runs on a blocking thread via [`tokio::task::spawn_blocking`]
//! to keep the async runtime responsive.

use std::path::PathBuf;

use apohara_sealchain_core::{
    default_receipt_path, evaluate_policy_now, load_or_generate, profile_names, render_chain,
    seal_artifact, verify_artifact, LayerResult, Policy, SealedRecord, DEFAULT_REKOR_V2_URL,
    DEFAULT_TSA_URL,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

/// Arguments for `seal_artifact`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SealParams {
    /// Path to the artifact to seal.
    pub path: String,
    /// Emit a real C2PA sidecar manifest (offline, signed with the seal's
    /// Ed25519 key via a self-signed cert) bound to the payload hash. **Defaults
    /// to true**, matching the CLI's offline default (HMAC + Ed25519 + C2PA).
    /// Set false to seal HMAC + Ed25519 only.
    #[serde(default = "default_true")]
    pub c2pa: bool,
    /// Embed the C2PA manifest IN the artifact file (native in-file hard binding)
    /// for supported media (JPEG, PNG, TIFF/DNG, WEBP, AVIF/HEIF, MP4/MOV, GIF,
    /// SVG, WAV, MP3, FLAC, JXL). The file is rewritten with the embedded asset
    /// and the receipt records `c2paEmbedded` instead of the sidecar manifest. An
    /// unsupported format errors the call (no receipt written) — it never falls
    /// back to the sidecar. Requires c2pa=true. Defaults to false.
    #[serde(default)]
    pub embed: bool,
    /// Add a real RFC 3161 TSA timestamp layer (network at seal time). Provide a
    /// TSA URL, or the empty string to use the default authority. Omit for none.
    #[serde(default)]
    pub tsa: Option<String>,
    /// Add a real Sigstore Rekor v2 transparency layer (network at seal time).
    /// Provide a shard URL, or the empty string to use the default shard. Omit
    /// for none.
    #[serde(default)]
    pub rekor: Option<String>,
    /// Seal all configured layers (HMAC+Ed25519+C2PA+TSA+Rekor) real-or-abort:
    /// if any requested layer cannot be produced, the call errors and no receipt
    /// is written. Implies tsa+rekor at their default endpoints. Defaults to
    /// false.
    #[serde(default)]
    pub all: bool,
}

fn default_true() -> bool {
    true
}

/// Arguments for `verify_receipt`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyParams {
    /// Path to the artifact.
    pub path: String,
    /// Path to the receipt JSON.
    pub receipt: String,
    /// Optional named attestation profile to enforce after verification (e.g.
    /// `offline-basic`, `transparency`, `legal-grade`, `full`). When set, the
    /// result gains a `policy` object {passed, profile, violations}. The overall
    /// `ok` stays the cryptographic verdict; policy compliance is reported
    /// separately. Omit to skip policy enforcement.
    #[serde(default)]
    pub profile: Option<String>,
}

/// Arguments for `show_chain`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ShowParams {
    /// Path to the receipt JSON.
    pub receipt: String,
}

/// The MCP server: a thin async shell over the sync core.
#[derive(Clone, Default)]
pub struct SealchainServer;

/// Map layer results into the wire JSON array used by both tools.
fn layers_json(results: &[LayerResult]) -> Vec<Value> {
    results
        .iter()
        .map(|r| json!({ "name": r.name, "ok": r.ok, "reason": r.reason }))
        .collect()
}

/// Turn an error string into a structured MCP tool error.
fn tool_error(message: String) -> ErrorData {
    ErrorData::internal_error(message, None)
}

/// A successful tool result carrying both structured JSON and a short text
/// summary for clients that only render unstructured content.
fn structured_with_text(value: Value, summary: String) -> CallToolResult {
    let mut result = CallToolResult::structured(value);
    // Replace the default JSON-blob text with a concise human summary.
    result.content = vec![Content::text(summary)];
    result
}

#[tool_router]
impl SealchainServer {
    /// Construct the server.
    pub fn new() -> Self {
        Self
    }

    /// Seal a file with the default keystore (HMAC + Ed25519 + C2PA) into a
    /// `<path>.seal.json` receipt and return the result of verifying what was
    /// just sealed.
    #[tool(
        description = "Seal a file into a tamper-evident receipt. The default is fully offline \
(HMAC + Ed25519 + C2PA); set c2pa=false to seal HMAC + Ed25519 only. The C2PA \
sidecar manifest is real and offline-verifiable, signed with the seal's Ed25519 \
key via a self-signed cert, bound to the payload hash. The tsa, \
rekor, and all parameters add network-backed layers that REQUIRE connectivity at \
seal time: tsa adds an RFC 3161 timestamp, rekor adds a Sigstore Rekor v2 \
transparency entry (each takes a URL, or empty string for the default endpoint), \
and all=true seals every configured layer real-or-abort — if any requested layer \
cannot be produced the call errors and NO receipt is written. Writes \
<path>.seal.json next to the artifact and returns the layer results of verifying \
the freshly sealed receipt."
    )]
    pub async fn seal_artifact(
        &self,
        Parameters(params): Parameters<SealParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = PathBuf::from(params.path);
        let c2pa = params.c2pa;
        let embed = params.embed;
        // Resolve the seal mode: `all` implies tsa+rekor at their defaults; an
        // explicit param uses its URL, or the default when given empty.
        let resolve = |value: Option<String>, default: &str| -> Option<String> {
            if params.all {
                return Some(default.to_string());
            }
            value.map(|v| if v.is_empty() { default.to_string() } else { v })
        };
        let tsa = resolve(params.tsa, DEFAULT_TSA_URL);
        let rekor = resolve(params.rekor, DEFAULT_REKOR_V2_URL);
        // Core is sync (file IO + crypto): run it off the async runtime.
        let outcome = tokio::task::spawn_blocking(move || -> Result<Value, String> {
            let keys = load_or_generate(None).map_err(|e| e.to_string())?;
            // A requested-but-unproducible network layer is an Err here, so the
            // receipt write below is never reached: no partial/faked receipt.
            let record = seal_artifact(
                &path,
                &keys,
                None,
                c2pa,
                embed,
                tsa.as_deref(),
                rekor.as_deref(),
            )
            .map_err(|e| e.to_string())?;

            let receipt_path = default_receipt_path(&path);
            let serialized = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
            std::fs::write(&receipt_path, serialized)
                .map_err(|e| format!("write receipt {}: {e}", receipt_path.display()))?;

            // Layers = verifying exactly what we just sealed, with the secret
            // available, so the HMAC layer is fully checked.
            let results =
                verify_artifact(&path, &record, Some(&keys.hmac)).map_err(|e| e.to_string())?;

            Ok(json!({
                "ok": true,
                "receipt_path": receipt_path.to_string_lossy(),
                "sealed_at": record.seal.sealed_at,
                "layers": layers_json(&results),
            }))
        })
        .await
        .map_err(|e| tool_error(format!("seal task panicked: {e}")))?
        .map_err(tool_error)?;

        let summary = format!(
            "Sealed -> {} (sealedAt {})",
            outcome["receipt_path"].as_str().unwrap_or(""),
            outcome["sealed_at"].as_str().unwrap_or("")
        );
        Ok(structured_with_text(outcome, summary))
    }

    /// Verify a file against a receipt on disk. Without the shared HMAC secret,
    /// the HMAC layer attests preimage integrity only; the content and Ed25519
    /// layers are fully checked.
    #[tool(
        description = "Verify an artifact against its receipt file. Checks the content hash and \
the Ed25519 signature (via the receipt's embedded public key). The HMAC layer \
attests preimage integrity only, since the shared secret is not provided here. \
Pass an optional `profile` (offline-basic, transparency, legal-grade, full) to \
also enforce that named attestation profile: the result gains a `policy` object \
{passed, profile, violations}, while `ok` stays the cryptographic verdict."
    )]
    pub async fn verify_receipt(
        &self,
        Parameters(params): Parameters<VerifyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = PathBuf::from(params.path);
        let receipt = PathBuf::from(params.receipt);
        let profile = params.profile;
        let outcome = tokio::task::spawn_blocking(move || -> Result<Value, String> {
            let text = std::fs::read_to_string(&receipt)
                .map_err(|e| format!("read receipt {}: {e}", receipt.display()))?;
            let record: SealedRecord =
                serde_json::from_str(&text).map_err(|e| format!("parse receipt: {e}"))?;

            let results = verify_artifact(&path, &record, None).map_err(|e| e.to_string())?;
            let ok = results.iter().all(|r| r.ok);
            let mut out = json!({ "ok": ok, "layers": layers_json(&results) });

            // Optional named-profile enforcement (present-and-verified semantics).
            if let Some(name) = profile {
                let policy = Policy::from_profile(&name).ok_or_else(|| {
                    format!(
                        "unknown profile '{name}' (available: {})",
                        profile_names().join(", ")
                    )
                })?;
                let mut report = evaluate_policy_now(&policy, &record, &results);
                report.profile = Some(name);
                out["policy"] = json!({
                    "passed": report.passed,
                    "profile": report.profile,
                    "violations": report.violations,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| tool_error(format!("verify task panicked: {e}")))?
        .map_err(tool_error)?;

        let ok = outcome["ok"].as_bool().unwrap_or(false);
        let mut summary = if ok { "PASS" } else { "FAIL" }.to_string();
        if let Some(policy) = outcome.get("policy") {
            let passed = policy
                .get("passed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            summary.push_str(&format!(
                " · policy {}",
                if passed { "PASS" } else { "FAIL" }
            ));
        }
        Ok(structured_with_text(outcome, summary))
    }

    /// Render a receipt's human-readable audit trail.
    #[tool(
        description = "Print a receipt's human-readable audit trail: method, sealedAt, artifact, \
and the present layers."
    )]
    pub async fn show_chain(
        &self,
        Parameters(params): Parameters<ShowParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let receipt = PathBuf::from(params.receipt);
        let trail = tokio::task::spawn_blocking(move || -> Result<String, String> {
            let text = std::fs::read_to_string(&receipt)
                .map_err(|e| format!("read receipt {}: {e}", receipt.display()))?;
            let record: SealedRecord =
                serde_json::from_str(&text).map_err(|e| format!("parse receipt: {e}"))?;
            Ok(render_chain(&record))
        })
        .await
        .map_err(|e| tool_error(format!("show task panicked: {e}")))?
        .map_err(tool_error)?;

        Ok(CallToolResult::success(vec![Content::text(trail)]))
    }
}

#[tool_handler]
impl ServerHandler for SealchainServer {
    fn get_info(&self) -> ServerInfo {
        // ProtocolVersion::default() is LATEST; only tools capability is enabled.
        // Report this crate's identity, not the SDK's (from_build_env resolves to
        // rmcp's build env, which would mislabel the server).
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "apohara-sealchain: verifiable, tamper-evident receipts for AI artifacts. \
Tools: seal_artifact, verify_receipt, show_chain. Sealing is offline by default \
(HMAC + Ed25519, plus an optional offline C2PA sidecar); the tsa/rekor/all \
parameters add network-backed layers (real-or-abort under all).",
            )
    }
}
