//! Wire schema for `apohara-seal-v1` records and schema detection.
//!
//! A sealed record is `{ "payload": {...}, "seal": {...} }`. The seal block
//! carries the method tag, the timestamp, the canonical preimage (as
//! `0x`-hex), and one entry per active layer. The opt-in extension layers (TSA,
//! Rekor, C2PA) are preserved as opaque `Value`s / hex strings so a record can
//! be round-tripped without loss.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::SealError;

/// Detected schema generation of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaVersion {
    /// Current schema: timestamp lives at `seal.sealedAt`.
    V4,
}

/// HMAC layer descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacLayer {
    /// Algorithm identifier, e.g. `HMAC-SHA256`.
    pub alg: String,
    /// Key identifier.
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// `0x`-prefixed hex signature.
    pub sig: String,
}

/// Ed25519 layer descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Layer {
    /// Key identifier.
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// `0x`-prefixed hex signature.
    pub sig: String,
}

/// The seal block attached to a payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealBlock {
    /// Seal method tag, always `apohara-seal-v1` for this engine.
    pub method: String,
    /// RFC 3339 timestamp the seal was produced at.
    #[serde(rename = "sealedAt")]
    pub sealed_at: String,
    /// `0x`-prefixed hex of the canonical preimage bytes.
    pub preimage: String,
    /// Mandatory HMAC layer.
    pub hmac: HmacLayer,
    /// Optional Ed25519 layer.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ed25519: Option<Ed25519Layer>,
    /// Optional embedded Ed25519 public key (SPKI PEM) making the receipt
    /// self-verifiable. It is a *sibling* of the layers and is NOT part of the
    /// preimage, so adding it never changes the seal.
    #[serde(
        rename = "ed25519PublicKey",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub ed25519_public_key: Option<String>,
    /// Opaque TSA layer (not yet verifiable).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tsa: Option<Value>,
    /// Optional Sigstore Rekor v2 transparency anchor: the mapped DSSE log entry
    /// (logIndex, logId, inclusionProof, canonicalizedBody, envelope, verifier)
    /// produced by [`crate::layers::rekor`]. Like `ed25519PublicKey`, it is a
    /// sibling of the layers and NOT part of the preimage, so adding it never
    /// changes the seal. Verified offline (RFC 6962 Merkle inclusion + checkpoint
    /// signature against a pinned shard key).
    #[serde(
        rename = "rekorAnchor",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub rekor_anchor: Option<Value>,
    /// Optional C2PA sidecar manifest: `0x`-hex of the real JUMBF manifest-store
    /// bytes produced by [`crate::layers::c2pa`]. Like `ed25519PublicKey`, it is a
    /// sibling of the layers and NOT part of the preimage, so adding it never
    /// changes the seal.
    #[serde(
        rename = "c2paManifest",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub c2pa_manifest: Option<String>,
    /// Optional flag marking that the C2PA manifest is embedded **in the artifact
    /// file** (native in-file hard binding) rather than carried as a sidecar in
    /// `c2paManifest`. When `Some(true)`, the C2PA layer is verified by reading
    /// the manifest from the file itself, not from `c2paManifest` (the two are
    /// mutually exclusive). Like the other siblings it is NOT part of the
    /// preimage, so it never changes the seal.
    #[serde(
        rename = "c2paEmbedded",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub c2pa_embedded: Option<bool>,
}

/// A full sealed record: the payload and its seal block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedRecord {
    /// Application payload (the data that was sealed).
    pub payload: Value,
    /// The attached seal.
    pub seal: SealBlock,
}

/// Determine the schema version of a raw record value.
///
/// * `seal.sealedAt` present and a string → [`SchemaVersion::V4`].
/// * top-level `sealedAt` present (legacy v3) with no `seal.sealedAt` →
///   [`SealError::UnsupportedSchemaV3`].
/// * anything else → [`SealError::Malformed`].
pub fn detect_schema(record: &Value) -> Result<SchemaVersion, SealError> {
    let obj = record
        .as_object()
        .ok_or_else(|| SealError::Malformed("record is not a JSON object".into()))?;

    if let Some(seal) = obj.get("seal").and_then(Value::as_object) {
        if seal.get("sealedAt").and_then(Value::as_str).is_some() {
            return Ok(SchemaVersion::V4);
        }
    }

    if obj.get("sealedAt").and_then(Value::as_str).is_some() {
        return Err(SealError::UnsupportedSchemaV3);
    }

    Err(SealError::Malformed(
        "no seal.sealedAt and no top-level sealedAt".into(),
    ))
}
