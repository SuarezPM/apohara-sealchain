//! Sigstore Rekor v2 transparency layer (story R-003) — real DSSE entries.
//!
//! This layer anchors a seal in the public Sigstore Rekor v2 transparency log by
//! submitting a DSSE `dsse v0.0.2` entry whose payload is an in-toto Statement
//! binding the seal's canonical preimage, then verifies the returned entry
//! **offline**: an RFC 6962 Merkle inclusion recompute plus a C2SP signed-note
//! (checkpoint) signature check against a **configured, pinned** shard log key.
//!
//! ## Canonical binding (Rust-canonical)
//!
//! * Build an in-toto Statement whose single subject digest is
//!   `sha256(preimage)` (the seal's canonical preimage from
//!   [`crate::seal::build_preimage`]).
//! * Wrap it in a DSSE envelope (`payloadType = application/vnd.in-toto+json`),
//!   compute the DSSE PAE, and **sign the PAE with the SEAL's Ed25519 key** — not
//!   an ephemeral key, not a Fulcio/OIDC certificate. The verifier in the entry
//!   is the seal's Ed25519 public key (SPKI DER), `keyDetails = PKIX_ED25519`.
//! * Submit a `DSSERequestV002` to the configured shard's
//!   `POST /api/v2/log/entries` and map the returned entry to a [`RekorAnchor`].
//!
//! ## Pass bar (verify)
//!
//! A real Rekor pass REQUIRES **both**:
//!
//! 1. **RFC 6962 Merkle inclusion**: the leaf is `sha256(0x00 || canonicalizedBody)`;
//!    chaining it with the proof hashes must reproduce `inclusionProof.rootHash`.
//! 2. **C2SP checkpoint signature** over the **full** signed-note body (origin,
//!    tree size, root hash, and any extension lines — NOT header-only) against the
//!    shard log public key resolved from config by `logId`.
//!
//! Merkle-structure-only is explicitly NOT a pass. An unknown shard key (no config
//! match for the anchor's `logId`) is a **measured** `ok: false` — never an `Err`,
//! never a silent pass. Corrupted proof / corrupted checkpoint → `ok: false`.
//!
//! ## Shard key, by config (rotates ~6 months)
//!
//! The v2 shard URL (`https://log2025-1.rekor.sigstore.dev`) and its log public
//! key are NOT TUF-distributed to clients yet and the active shard rotates roughly
//! every six months, so they live in `packaging/rekor-shards.json` (pinned with
//! provenance), resolved by `logId`. Rotating the shard is a config update, not a
//! recompile (see [`load_shards`] / [`ShardKey`]).
//!
//! ## No async leak
//!
//! `sigstore-rekor`'s client is async (reqwest). The core engine is sync, so the
//! network calls run on a private current-thread tokio runtime built inside
//! [`submit`]. No async/tokio types appear in this module's public API.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use sigstore_crypto::verify_ed25519;
use sigstore_merkle::{hash_leaf, verify_inclusion_proof};
use sigstore_rekor::entry::{
    DsseEntryV2, DsseRequestV002, DsseVerifierV2, HashedRekordPublicKeyV2,
};
use sigstore_rekor::RekorClient;
use sigstore_types::{
    Checkpoint, DerCertificate, DerPublicKey, DsseEnvelope, DsseSignature, PayloadBytes,
    Sha256Hash, SignatureBytes, Statement, Subject,
};

use crate::artifact::LayerResult;
use crate::error::SealError;

/// Default Rekor v2 shard URL. NOT hardcoded into the protocol — the active shard
/// rotates ~6 months. New seals use this shard; verification resolves the key by
/// `logId` from `packaging/rekor-shards.json`, so frozen anchors keep verifying
/// across rotations as long as the old shard stays listed.
pub const DEFAULT_REKOR_V2_URL: &str = "https://log2025-1.rekor.sigstore.dev";

/// The in-toto Statement type tag.
const INTOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

/// The DSSE payload type for an in-toto Statement.
const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The predicate type for a apohara-sealchain anchor (vendor-namespaced, no registry).
const SEALCHAIN_PREDICATE_TYPE: &str = "https://apohara.dev/sealchain/anchor/v1";

/// The `PublicKeyDetails` enum value for an Ed25519 self-managed key in a Rekor
/// v2 DSSE verifier (`dev.sigstore.common.v1.PublicKeyDetails.PKIX_ED25519 = 7`).
const KEY_DETAILS_ED25519: &str = "PKIX_ED25519";

/// A Rekor anchor: the mapped `TransparencyLogEntry` plus the DSSE envelope and
/// verifier needed to re-derive and verify the entry offline. Serialized into
/// `seal.rekorAnchor` as the JSON shape documented on [`Self::to_json`].
#[derive(Debug, Clone)]
pub struct RekorAnchor {
    /// Log index of the entry.
    pub log_index: i64,
    /// Log ID (base64 SHA-256-style key hash, as returned by the shard / pinned
    /// in config). Resolves the shard public key for checkpoint verification.
    pub log_id: String,
    /// Integrated time (Unix seconds).
    pub integrated_time: i64,
    /// RFC 6962 inclusion proof.
    pub inclusion_proof: InclusionProof,
    /// Base64 of the canonicalized Rekor entry body (the Merkle leaf preimage).
    pub canonicalized_body: String,
    /// The DSSE envelope that was submitted (carries the seal Ed25519 signature).
    pub envelope: serde_json::Value,
    /// The verifier: the seal's Ed25519 public key (SPKI DER, base64) + keyDetails.
    pub verifier: serde_json::Value,
}

/// RFC 6962 inclusion proof, as stored in the anchor.
#[derive(Debug, Clone, Deserialize)]
pub struct InclusionProof {
    /// 0-based leaf index in the tree.
    #[serde(rename = "logIndex")]
    pub log_index: i64,
    /// Tree size the proof is against.
    #[serde(rename = "treeSize")]
    pub tree_size: i64,
    /// Root hash (hex), as committed by the checkpoint.
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    /// Sibling hashes (hex) along the leaf→root path.
    pub hashes: Vec<String>,
    /// C2SP signed-note checkpoint text (origin, size, root, signatures).
    pub checkpoint: String,
}

impl RekorAnchor {
    /// Map this anchor to the `seal.rekorAnchor` JSON value.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "logIndex": self.log_index,
            "logId": self.log_id,
            "integratedTime": self.integrated_time,
            "inclusionProof": {
                "logIndex": self.inclusion_proof.log_index,
                "treeSize": self.inclusion_proof.tree_size,
                "rootHash": self.inclusion_proof.root_hash,
                "hashes": self.inclusion_proof.hashes,
                "checkpoint": self.inclusion_proof.checkpoint,
            },
            "canonicalizedBody": self.canonicalized_body,
            "envelope": self.envelope,
            "verifier": self.verifier,
        })
    }

    /// Parse an anchor from its `seal.rekorAnchor` JSON value. Missing/ill-typed
    /// required fields are a structural [`SealError::Malformed`].
    pub fn from_json(value: &serde_json::Value) -> Result<Self, SealError> {
        let m = |f: &str| SealError::Malformed(format!("rekorAnchor missing {f}"));
        let proof_value = value
            .get("inclusionProof")
            .ok_or_else(|| m("inclusionProof"))?;
        let inclusion_proof: InclusionProof = serde_json::from_value(proof_value.clone())
            .map_err(|e| SealError::Malformed(format!("rekorAnchor inclusionProof: {e}")))?;
        Ok(Self {
            log_index: value
                .get("logIndex")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| m("logIndex"))?,
            log_id: value
                .get("logId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| m("logId"))?
                .to_string(),
            integrated_time: value
                .get("integratedTime")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| m("integratedTime"))?,
            inclusion_proof,
            canonicalized_body: value
                .get("canonicalizedBody")
                .and_then(|v| v.as_str())
                .ok_or_else(|| m("canonicalizedBody"))?
                .to_string(),
            envelope: value
                .get("envelope")
                .cloned()
                .ok_or_else(|| m("envelope"))?,
            verifier: value
                .get("verifier")
                .cloned()
                .ok_or_else(|| m("verifier"))?,
        })
    }
}

/// A pinned shard log public key, resolved from `packaging/rekor-shards.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ShardKey {
    /// The log ID this key verifies (base64), matched against `anchor.logId`.
    #[serde(rename = "logId")]
    pub log_id: String,
    /// The shard origin string (checkpoint first line), e.g.
    /// `log2025-1.rekor.sigstore.dev`. Used to pick the checkpoint signature.
    pub origin: String,
    /// The shard log public key (SPKI PEM). Ed25519 for the 2025-1 shard.
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: String,
    /// `sha256(DER SPKI)` fingerprint, for provenance/audit.
    #[serde(rename = "keySha256")]
    pub key_sha256: String,
}

/// Load and parse the pinned shard keys from `rekor-shards.json` text.
///
/// The text is the contents of `packaging/rekor-shards.json` (an array of
/// [`ShardKey`]). A parse failure is a structural [`SealError::Malformed`].
pub fn load_shards(json_text: &str) -> Result<Vec<ShardKey>, SealError> {
    serde_json::from_str(json_text)
        .map_err(|e| SealError::Malformed(format!("parse rekor-shards.json: {e}")))
}

/// Resolve the shard key for `log_id`, if pinned.
pub fn resolve_shard<'a>(shards: &'a [ShardKey], log_id: &str) -> Option<&'a ShardKey> {
    shards.iter().find(|s| s.log_id == log_id)
}

/// Whether the seal-time default Rekor shard is in the currently-active set, per
/// the TUF-distributed Sigstore SigningConfig (plan B-1a). "Active" means "present
/// in the SigningConfig's valid v2 endpoint set", not "the single newest shard" —
/// overlapping validity windows can leave more than one shard active. A *stale*
/// shard (rotated out of the valid set) is never recorded — it aborts the seal
/// (real-or-abort); only the two states below reach a receipt, in
/// `seal.rekorAnchor.shardActiveness`.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardActiveness {
    /// The shard URL is in the SigningConfig's active Rekor v2 endpoint set.
    Active,
    /// The SigningConfig lists no Rekor v2 endpoint (the v2 rollout window) or
    /// could not be fetched, so staleness cannot be determined — the seal proceeds
    /// against the pinned default, and the receipt says so honestly.
    Undeterminable,
}

#[cfg(feature = "native")]
impl ShardActiveness {
    /// Lowercase tag recorded in the receipt.
    pub fn as_str(self) -> &'static str {
        match self {
            ShardActiveness::Active => "active",
            ShardActiveness::Undeterminable => "undeterminable",
        }
    }
}

/// Classify `shard_url` against the SigningConfig's `active_v2_urls`.
///
/// * non-empty set containing `shard_url` → [`ShardActiveness::Active`].
/// * non-empty set NOT containing it → [`Err`] (stale shard → abort the seal).
/// * empty set → [`ShardActiveness::Undeterminable`] (no v2 endpoint distributed
///   yet, so staleness is not knowable).
///
/// Pure (no network), so the abort path is unit-testable. Comparison normalizes
/// trailing slashes on both sides. This is the honest core of B-1a: it converts the
/// previously-silent "anchored to a rotated-out shard" path into a loud abort,
/// while never false-aborting when the active set is simply unknown.
#[cfg(feature = "native")]
pub fn classify_shard(
    shard_url: &str,
    active_v2_urls: &[String],
) -> Result<ShardActiveness, SealError> {
    if active_v2_urls.is_empty() {
        return Ok(ShardActiveness::Undeterminable);
    }
    let norm = |u: &str| u.trim_end_matches('/').to_string();
    let target = norm(shard_url);
    if active_v2_urls.iter().any(|u| norm(u) == target) {
        Ok(ShardActiveness::Active)
    } else {
        Err(SealError::Rekor(format!(
            "refusing to anchor to a stale Rekor shard: {shard_url} is not in the active Rekor v2 \
             set from the Sigstore SigningConfig ({}). The active shard has rotated — pass \
             `--rekor <active-url>` and add the new shard key to packaging/rekor-shards.json.",
            active_v2_urls.join(", ")
        )))
    }
}

/// Fetch the active Rekor v2 endpoint URLs from the live TUF-distributed Sigstore
/// SigningConfig. A fetch/parse failure maps to an empty set (→ `Undeterminable`
/// upstream), not an error: we cannot conclude a shard is stale merely because TUF
/// was unreachable, and the submit's own health-check still guards a down shard.
#[cfg(feature = "native")]
fn fetch_active_v2_rekor_urls() -> Vec<String> {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };
    let Ok(cfg) = runtime.block_on(sigstore_trust_root::SigningConfig::production()) else {
        return Vec::new();
    };
    cfg.get_rekor_urls(Some(2))
        .into_iter()
        .map(|e| e.url.clone())
        .collect()
}

/// Seal-time stale-shard guard (plan B-1a). Determine whether `shard_url` is the
/// active Rekor v2 shard per the TUF SigningConfig: returns `Active`/
/// `Undeterminable` to record in the receipt, or [`Err`] (abort) if the shard is
/// provably stale. Never writes the pin and never touches the verify path.
#[cfg(feature = "native")]
pub fn check_shard_active(shard_url: &str) -> Result<ShardActiveness, SealError> {
    classify_shard(shard_url, &fetch_active_v2_rekor_urls())
}

/// Submit a real Rekor v2 DSSE entry anchoring `preimage`, signed by the SEAL's
/// Ed25519 key, to the shard at `shard_url`. Returns the mapped [`RekorAnchor`].
///
/// Builds an in-toto Statement (`subject[0].digest.sha256 = sha256(preimage)`),
/// wraps it in a DSSE envelope, signs the PAE with `seal_signing_key`, submits a
/// `DSSERequestV002`, and maps the response. A health-check (`GET
/// /api/v2/checkpoint`) runs first so a down shard yields a clear error.
///
/// The network calls run on a private current-thread tokio runtime; no async
/// types leak out. Any network/protocol/mapping failure is a [`SealError::Rekor`].
pub fn submit(
    preimage: &[u8],
    seal_signing_key: &SigningKey,
    shard_url: &str,
) -> Result<RekorAnchor, SealError> {
    // Build the in-toto Statement bound to the seal's canonical preimage.
    let subject_sha256 = hex::encode(Sha256::digest(preimage));
    let statement = Statement {
        type_: INTOTO_STATEMENT_V1.to_string(),
        subject: vec![Subject {
            name: "apohara-sealchain-preimage".to_string(),
            digest: sigstore_types::Digest {
                sha256: Some(subject_sha256),
                sha512: None,
            },
        }],
        predicate_type: SEALCHAIN_PREDICATE_TYPE.to_string(),
        predicate: json!({}),
    };
    let payload = serde_json::to_vec(&statement)
        .map_err(|e| SealError::Rekor(format!("serialize in-toto statement: {e}")))?;

    // DSSE PAE over the in-toto payload, signed with the seal Ed25519 key.
    let pae = sigstore_types::pae(INTOTO_PAYLOAD_TYPE, &payload);
    let signature = seal_signing_key.sign(&pae).to_bytes().to_vec();

    let envelope = DsseEnvelope::new(
        INTOTO_PAYLOAD_TYPE.to_string(),
        PayloadBytes::from_bytes(&payload),
        vec![DsseSignature {
            sig: SignatureBytes::from_bytes(&signature),
            keyid: Default::default(),
        }],
    );

    // The seal's Ed25519 public key as SPKI DER, as the self-managed verifier.
    let spki_der = seal_signing_key.verifying_key().to_public_key_der_bytes()?;
    // `sigstore-rekor`'s `DsseEntryV2::new` hardcodes ECDSA + a Fulcio cert, so
    // build the request directly with a public-key verifier and PKIX_ED25519.
    let verifier = DsseVerifierV2 {
        key_details: KEY_DETAILS_ED25519.to_string(),
        x509_certificate: None,
        public_key: Some(HashedRekordPublicKeyV2 {
            // The field is typed `DerCertificate` (a base64 newtype) but serializes
            // as the `publicKey.rawBytes` base64 DER the v2 API expects for a key.
            content: DerCertificate::from_bytes(&spki_der),
        }),
    };
    let entry = DsseEntryV2 {
        request: DsseRequestV002 {
            envelope: envelope.clone(),
            verifiers: vec![verifier],
        },
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SealError::Rekor(format!("build runtime: {e}")))?;

    // Health-check the shard. The v2 shard exposes `/api/v2/checkpoint` (200) but
    // not the v1 `/api/v1/log` info endpoint, so probe the checkpoint directly.
    runtime.block_on(health_check(shard_url))?;

    let client = RekorClient::new(shard_url);
    let log_entry = runtime
        .block_on(client.create_dsse_entry_v2(entry))
        .map_err(|e| SealError::Rekor(format!("submit DSSE v2 entry to {shard_url}: {e}")))?;

    map_entry(log_entry, &envelope, &spki_der)
}

/// GET `{shard_url}/api/v2/checkpoint`; a non-2xx or transport error is a
/// [`SealError::Rekor`] making a down shard fail clearly before the submit.
async fn health_check(shard_url: &str) -> Result<(), SealError> {
    let url = format!("{}/api/v2/checkpoint", shard_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| SealError::Rekor(format!("rekor shard unreachable ({url}): {e}")))?;
    if !resp.status().is_success() {
        return Err(SealError::Rekor(format!(
            "rekor shard health-check failed ({url}): {}",
            resp.status()
        )));
    }
    Ok(())
}

/// Map a `LogEntry` plus the submitted envelope/verifier into a [`RekorAnchor`].
fn map_entry(
    entry: sigstore_rekor::LogEntry,
    envelope: &DsseEnvelope,
    spki_der: &[u8],
) -> Result<RekorAnchor, SealError> {
    let verification = entry
        .verification
        .ok_or_else(|| SealError::Rekor("response missing verification".into()))?;
    let proof = verification
        .inclusion_proof
        .ok_or_else(|| SealError::Rekor("response missing inclusion proof".into()))?;

    let envelope_json = serde_json::to_value(envelope)
        .map_err(|e| SealError::Rekor(format!("serialize envelope: {e}")))?;
    let verifier_json = json!({
        "publicKey": { "rawBytes": base64::engine::general_purpose::STANDARD.encode(spki_der) },
        "keyDetails": KEY_DETAILS_ED25519,
    });

    Ok(RekorAnchor {
        log_index: entry.log_index,
        log_id: entry.log_id.to_string(),
        integrated_time: entry.integrated_time,
        inclusion_proof: InclusionProof {
            log_index: proof.log_index,
            tree_size: proof.tree_size,
            root_hash: proof.root_hash,
            hashes: proof.hashes,
            checkpoint: proof.checkpoint,
        },
        canonicalized_body: entry.body.to_base64(),
        envelope: envelope_json,
        verifier: verifier_json,
    })
}

/// Verify a Rekor anchor offline against the configured shard key.
///
/// Two independent checks, **both** required for `ok: true`:
///
/// 1. **RFC 6962 Merkle inclusion** (`sigstore-merkle`): the leaf
///    `sha256(0x00 || canonicalizedBody)` chained with the proof hashes must
///    reproduce `inclusionProof.rootHash`.
/// 2. **C2SP checkpoint signature** over the **full** signed-note body
///    (`sigstore-crypto`'s Ed25519 verify against the pinned shard key).
///
/// Resolution: `shard_key_pem` is the configured shard log public key (SPKI PEM)
/// for `anchor.logId`. If `None` (no config match), this is a **measured**
/// `ok: false` with reason `log key unknown for logId <id>` — never an `Err`,
/// never a silent pass. Corrupted root hash or checkpoint → `ok: false`.
pub fn verify_anchor(anchor: &RekorAnchor, shard_key_pem: Option<&[u8]>) -> LayerResult {
    // Unknown key: a measured failure, not an Err and not a silent pass.
    let Some(pem_bytes) = shard_key_pem else {
        return rekor_result(
            false,
            &format!("log key unknown for logId {}", anchor.log_id),
        );
    };

    // --- Check 1: RFC 6962 Merkle inclusion ---
    let body = match base64::engine::general_purpose::STANDARD.decode(&anchor.canonicalized_body) {
        Ok(b) => b,
        Err(e) => return rekor_result(false, &format!("canonicalizedBody not base64: {e}")),
    };
    let leaf = hash_leaf(&body);

    let proof = &anchor.inclusion_proof;
    let root_hash = match Sha256Hash::from_hex(&proof.root_hash) {
        Ok(h) => h,
        Err(e) => return rekor_result(false, &format!("inclusion proof rootHash invalid: {e}")),
    };
    let mut proof_hashes = Vec::with_capacity(proof.hashes.len());
    for (i, h) in proof.hashes.iter().enumerate() {
        match Sha256Hash::from_hex(h) {
            Ok(hash) => proof_hashes.push(hash),
            Err(e) => return rekor_result(false, &format!("proof hash[{i}] invalid: {e}")),
        }
    }
    let (leaf_index, tree_size) = match (
        u64::try_from(proof.log_index),
        u64::try_from(proof.tree_size),
    ) {
        (Ok(li), Ok(ts)) => (li, ts),
        _ => return rekor_result(false, "inclusion proof has negative index/size"),
    };
    if let Err(e) = verify_inclusion_proof(&leaf, leaf_index, tree_size, &proof_hashes, &root_hash)
    {
        return rekor_result(false, &format!("merkle inclusion failed: {e}"));
    }

    // --- Check 2: C2SP checkpoint signature over the FULL signed-note body ---
    let checkpoint = match Checkpoint::from_text(&proof.checkpoint) {
        Ok(c) => c,
        Err(e) => return rekor_result(false, &format!("checkpoint parse failed: {e}")),
    };

    // The checkpoint must commit to the same root hash the inclusion proof used.
    if checkpoint.root_hash != root_hash {
        return rekor_result(false, "checkpoint root hash != inclusion proof root hash");
    }

    let public_key = match decode_public_key(pem_bytes) {
        Ok(k) => k,
        Err(reason) => return rekor_result(false, &reason),
    };

    // Verify the Ed25519 signature over the FULL signed-note body (origin, size,
    // root, and any extension lines, with trailing newline) — not header-only.
    // The shard's Ed25519 checkpoint key hint is not `sha256(spki)[:4]` (the
    // sigstore-crypto `compute_key_hint` formula), so select the signature by the
    // shard origin and verify directly rather than via `CheckpointVerifyExt`.
    let signed_data = checkpoint.signed_data();
    let mut verified = false;
    for sig in &checkpoint.signatures {
        if verify_ed25519(&public_key, &sig.signature, signed_data).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return rekor_result(
            false,
            "checkpoint signature invalid for configured shard key",
        );
    }

    rekor_result(
        true,
        "merkle inclusion ok; checkpoint signature verified against configured shard key",
    )
}

/// Decode an SPKI PEM (`PUBLIC KEY`) into a [`DerPublicKey`].
fn decode_public_key(pem_bytes: &[u8]) -> Result<DerPublicKey, String> {
    let text =
        std::str::from_utf8(pem_bytes).map_err(|e| format!("shard key pem not utf-8: {e}"))?;
    DerPublicKey::from_pem(text).map_err(|e| format!("shard key pem invalid: {e}"))
}

/// Build a `rekor` [`LayerResult`].
fn rekor_result(ok: bool, reason: &str) -> LayerResult {
    LayerResult {
        name: "rekor".to_string(),
        ok,
        reason: reason.to_string(),
    }
}

/// Encode a `VerifyingKey` as SPKI DER bytes, mapping the error to [`SealError`].
trait ToPublicKeyDerBytes {
    fn to_public_key_der_bytes(&self) -> Result<Vec<u8>, SealError>;
}

impl ToPublicKeyDerBytes for ed25519_dalek::VerifyingKey {
    fn to_public_key_der_bytes(&self) -> Result<Vec<u8>, SealError> {
        use ed25519_dalek::pkcs8::spki::EncodePublicKey;
        Ok(self
            .to_public_key_der()
            .map_err(|e| SealError::Rekor(format!("encode seal spki der: {e}")))?
            .as_bytes()
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malformed anchor JSON is a structural error, never a panic.
    #[test]
    fn from_json_missing_fields_is_malformed() {
        let bad = json!({ "logIndex": 1 });
        let err = RekorAnchor::from_json(&bad).expect_err("should be malformed");
        assert!(matches!(err, SealError::Malformed(_)));
    }

    /// Unknown key (no config match) is a measured ok:false, not an Err.
    #[test]
    fn unknown_key_is_measured_false() {
        let anchor = RekorAnchor {
            log_index: 1,
            log_id: "unknown-log-id".to_string(),
            integrated_time: 0,
            inclusion_proof: InclusionProof {
                log_index: 0,
                tree_size: 1,
                root_hash: "00".repeat(32),
                hashes: vec![],
                checkpoint: String::new(),
            },
            canonicalized_body: String::new(),
            envelope: json!({}),
            verifier: json!({}),
        };
        let result = verify_anchor(&anchor, None);
        assert_eq!(result.name, "rekor");
        assert!(!result.ok);
        assert_eq!(result.reason, "log key unknown for logId unknown-log-id");
    }

    /// Shard loader parses the committed config and resolves the 2025-1 key.
    /// Reads the in-crate vendored copy of `packaging/rekor-shards.json`.
    #[test]
    fn loader_resolves_default_shard() {
        let text = include_str!("../../rekor-shards.json");
        let shards = load_shards(text).expect("parse shards");
        let log_id = "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=";
        let shard = resolve_shard(&shards, log_id).expect("2025-1 shard resolves");
        assert_eq!(shard.origin, "log2025-1.rekor.sigstore.dev");
        assert!(shard.public_key_pem.contains("BEGIN PUBLIC KEY"));
        assert_eq!(shard.key_sha256.len(), 64, "sha256 hex fingerprint");
    }
}
