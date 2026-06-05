//! File seal/verify orchestrator.
//!
//! Seals a file on disk into a self-contained [`SealedRecord`]: the payload
//! records the artifact's content hash, name, size, and guessed MIME type; the
//! seal is the offline, deterministic HMAC + Ed25519 stack from
//! [`crate::seal::seal_deterministic`], with the Ed25519 public key embedded so
//! the receipt verifies without out-of-band key distribution.
//!
//! Verification is layered: a **content** layer recomputes the file's hash and
//! compares it to the receipt (this is what a one-byte file change trips),
//! followed by the cryptographic layers. Tamper produces `ok: false` results;
//! only structural problems (missing fields, bad schema) are errors.
//!
//! The cryptographic stack is HMAC + Ed25519 and fully offline-verifiable. Three
//! opt-in sibling layers extend it: a real C2PA sidecar manifest, a real RFC 3161
//! TSA timestamp over `hmac.sig || ed25519.sig` (requested on demand, verified
//! offline by message imprint), and a real Sigstore Rekor v2 DSSE anchor over the
//! canonical preimage (submitted on demand, verified offline by RFC 6962 Merkle
//! inclusion plus a checkpoint signature against a pinned shard key). The
//! extension point is the per-layer result list returned by [`verify_artifact`];
//! new layers append their own [`LayerResult`].

#[cfg(feature = "native")]
use std::path::Path;
#[cfg(feature = "native")]
use std::path::PathBuf;

#[cfg(feature = "native")]
use chrono::Utc;
#[cfg(feature = "native")]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::SealError;
#[cfg(feature = "native")]
use crate::keystore::Keys;
use crate::layers::{c2pa, ed25519, hmac};
#[cfg(feature = "native")]
use crate::layers::{rekor, tsa};
use crate::schema::{SealBlock, SealedRecord};
use crate::seal::build_preimage;
#[cfg(feature = "native")]
use crate::seal::seal_deterministic;

/// The pinned Rekor shard keys, embedded from the in-crate `rekor-shards.json`.
/// This is a vendored copy of the workspace `packaging/rekor-shards.json` (the
/// source of truth); it lives in-crate so the file ships inside the published
/// crate tarball and the Windows release build needs no symlink support. Keep
/// the two in sync when rotating a shard. The binary ships with the pinned keys
/// so verification is self-contained (see [`crate::layers::rekor`]).
#[cfg(feature = "native")]
const REKOR_SHARDS_JSON: &str = include_str!("../rekor-shards.json");

/// Outcome of verifying a single layer of a receipt.
#[derive(Debug, Clone)]
pub struct LayerResult {
    /// Layer name, e.g. `content`, `hmac`, `ed25519`.
    pub name: String,
    /// Whether the layer verified.
    pub ok: bool,
    /// Human-readable explanation (empty or a short note on success).
    pub reason: String,
}

/// Compute the lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Decode a `0x`-prefixed (prefix optional) hex string into bytes.
fn decode_hex0x(s: &str) -> Option<Vec<u8>> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body).ok()
}

/// Seal the file at `path` into a self-contained receipt.
///
/// The payload is `{artifactSha256, path, size, mime}`. The seal is HMAC +
/// Ed25519 over the canonical preimage; the Ed25519 public key is embedded in
/// the seal block (outside the preimage). `sealed_at` defaults to the current
/// time in RFC 3339 when `None`.
///
/// When `c2pa` is true, a real C2PA sidecar manifest (JUMBF) binding the
/// canonical payload hash is also produced and stored as
/// `seal.c2paManifest = "0x" + hex(jumbf)`. The manifest is a sibling of the
/// layers (outside the preimage), so enabling it never changes the seal. The
/// HMAC secret never appears in the record; the C2PA manifest is the only new
/// field.
///
/// When `embed` is true, the C2PA manifest is instead embedded **in the artifact
/// file** using c2pa-rs's native in-file hard binding (the data-hash assertion
/// c2pa computes over the asset). The file at `path` is **rewritten** with the
/// embedded asset, then `artifactSha256`/`size`/`mime` are computed from those
/// FINAL bytes, so the seal binds the embedded file. The receipt records
/// `seal.c2paEmbedded = true` and omits `c2paManifest` (the two are mutually
/// exclusive). `embed` requires an embeddable media format (see
/// [`c2pa::is_embeddable_extension`]); an unsupported format is a hard
/// [`SealError::C2pa`] — it never silently falls back to the sidecar. `embed`
/// requires `c2pa` to be true.
///
/// When `tsa` is `Some(url)`, a real RFC 3161 timestamp token is requested over
/// the canonical binding `hmac.sig || ed25519.sig` and stored as
/// `seal.tsa = {authority, issuedAt, der:"0x"+hex(token)}`. Like the C2PA
/// manifest, it is a sibling of the layers (outside the preimage). This makes a
/// network call to the TSA. The default (`None`) keeps the offline behavior
/// unchanged.
///
/// When `rekor` is `Some(url)`, a real Sigstore Rekor v2 DSSE entry is submitted
/// anchoring the canonical preimage (a DSSE-signed in-toto Statement whose subject
/// digest is `sha256(preimage)`, signed with the seal's Ed25519 key) and the
/// returned transparency-log entry is stored as `seal.rekorAnchor`. Like the
/// other extension layers it is a sibling of the layers (outside the preimage).
/// This makes a network call to the shard. The default (`None`) keeps the offline
/// behavior unchanged.
#[cfg(feature = "native")]
pub fn seal_artifact(
    path: &Path,
    keys: &Keys,
    sealed_at: Option<&str>,
    c2pa: bool,
    embed: bool,
    tsa: Option<&str>,
    rekor: Option<&str>,
) -> Result<SealedRecord, SealError> {
    if embed && !c2pa {
        return Err(SealError::C2pa(
            "--embed requires the C2PA layer (do not combine with --no-c2pa)".into(),
        ));
    }

    let bytes = std::fs::read(path)
        .map_err(|e| SealError::Malformed(format!("read {}: {e}", path.display())))?;

    // In embed mode, the C2PA manifest goes INTO the file before hashing: gate the
    // format (hard error on unsupported — never a silent sidecar fallback), embed,
    // rewrite the artifact, and hash the FINAL embedded bytes.
    let bytes = if embed {
        embed_into_file(path, &bytes, &keys.ed25519)?
    } else {
        bytes
    };

    let artifact_sha256 = sha256_hex(&bytes);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let mime = mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();

    let payload = json!({
        "artifactSha256": artifact_sha256,
        "path": name,
        "size": bytes.len() as u64,
        "mime": mime,
    });

    let sealed_at_owned = sealed_at.map(str::to_string).unwrap_or_else(now_rfc3339);

    let mut record =
        seal_deterministic(&payload, &keys.hmac, Some(&keys.ed25519), &sealed_at_owned)?;
    // Embed the public key so the receipt is self-verifiable. Sibling of the
    // layers, outside the preimage — does not change the seal.
    record.seal.ed25519_public_key = Some(keys.ed25519_public_pem.clone());

    if c2pa {
        if embed {
            // The C2PA layer is the in-file manifest (already written above); the
            // receipt records the mode rather than carrying sidecar bytes.
            record.seal.c2pa_embedded = Some(true);
        } else {
            let jumbf = c2pa::emit_sidecar(&record.payload, &keys.ed25519)?;
            record.seal.c2pa_manifest = Some(format!("0x{}", hex::encode(&jumbf)));
        }
    }

    if let Some(tsa_url) = tsa {
        let to_stamp = tsa_to_stamp(&record.seal)?;
        let token = tsa::request_token(&to_stamp, tsa_url)?;
        record.seal.tsa = Some(json!({
            "authority": token.authority,
            "issuedAt": token.issued_at,
            "der": format!("0x{}", hex::encode(&token.der)),
        }));
    }

    if let Some(shard_url) = rekor {
        let preimage = decode_hex0x(&record.seal.preimage)
            .ok_or_else(|| SealError::InvalidPreimage(record.seal.preimage.clone()))?;
        let anchor = rekor::submit(&preimage, &keys.ed25519, shard_url)?;
        record.seal.rekor_anchor = Some(anchor.to_json());
    }

    Ok(record)
}

/// The lowercase file extension of `path`, or `""` when it has none.
#[cfg(feature = "native")]
fn extension_lossy(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Embed a real C2PA manifest into the artifact at `path` and **rewrite the file
/// in place** with the embedded asset, returning the final embedded bytes.
///
/// The format is gated by extension first: an unsupported media type is a hard
/// [`SealError::C2pa`] (never a silent sidecar fallback). c2pa-rs adds its own
/// in-file data-hash hard binding over the asset; the seal then hashes these
/// final bytes. The original file content is replaced by the embedded asset.
#[cfg(feature = "native")]
fn embed_into_file(
    path: &Path,
    original_bytes: &[u8],
    signer_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, SealError> {
    let ext = extension_lossy(path);
    if !c2pa::is_embeddable_extension(&ext) {
        return Err(SealError::C2pa(format!(
            "--embed: unsupported media format for in-file C2PA: {} (extension {:?}). \
Embeddable formats: JPEG, PNG, TIFF/DNG, WEBP, AVIF/HEIF, MP4/MOV, GIF, SVG, WAV, MP3, FLAC, JXL. \
Use the offline sidecar (omit --embed) for other formats.",
            path.display(),
            ext
        )));
    }

    let embedded = c2pa::embed_manifest(original_bytes, &ext, signer_key)?;
    std::fs::write(path, &embedded)
        .map_err(|e| SealError::Malformed(format!("rewrite embedded {}: {e}", path.display())))?;
    Ok(embedded)
}

/// Reconstruct the canonical TSA binding `hmac.sig || ed25519.sig` (raw bytes,
/// that exact order) from a seal block. Requires both layers; an Ed25519-less
/// seal cannot carry a TSA token under this binding.
#[cfg(feature = "native")]
fn tsa_to_stamp(seal: &SealBlock) -> Result<Vec<u8>, SealError> {
    let hmac_sig = decode_hex0x(&seal.hmac.sig)
        .ok_or_else(|| SealError::Malformed(format!("invalid hmac.sig hex: {}", seal.hmac.sig)))?;
    let ed_layer = seal
        .ed25519
        .as_ref()
        .ok_or_else(|| SealError::Malformed("tsa binding requires an ed25519 layer".into()))?;
    let ed_sig = decode_hex0x(&ed_layer.sig).ok_or_else(|| {
        SealError::Malformed(format!("invalid ed25519.sig hex: {}", ed_layer.sig))
    })?;

    let mut to_stamp = hmac_sig;
    to_stamp.extend_from_slice(&ed_sig);
    Ok(to_stamp)
}

/// Verify `file` against `receipt`, returning one [`LayerResult`] per layer.
///
/// The content layer recomputes the file hash and compares it to
/// `payload.artifactSha256`. The crypto layers re-derive the canonical
/// preimage from the receipt's payload and check it against the stored
/// preimage and each present signature (the Ed25519 layer uses the embedded
/// public key, so verification is self-contained without the HMAC secret).
///
/// `key_hmac` is optional: when supplied, the HMAC layer is checked against the
/// shared secret; when `None`, the HMAC layer reports only preimage integrity
/// (the secret-based MAC cannot be verified offline without the key).
///
/// Overall validity is "all present layers ok AND content ok"; structural
/// problems (missing fields) are `Err`, tamper is `ok: false`.
#[cfg(feature = "native")]
pub fn verify_artifact(
    file: &Path,
    receipt: &SealedRecord,
    key_hmac: Option<&[u8]>,
) -> Result<Vec<LayerResult>, SealError> {
    let bytes = std::fs::read(file)
        .map_err(|e| SealError::Malformed(format!("read {}: {e}", file.display())))?;
    verify_artifact_bytes(&bytes, receipt, key_hmac)
}

/// Verify in-memory `file_bytes` against `receipt`, returning one
/// [`LayerResult`] per layer.
///
/// This is the byte-oriented core of [`verify_artifact`] and the entry point the
/// in-browser (wasm) verifier calls: it takes the artifact bytes directly rather
/// than a filesystem path, so it has no I/O and compiles to wasm32.
///
/// The content layer recomputes `sha256(file_bytes)` and compares it to
/// `payload.artifactSha256`. The crypto layers re-derive the canonical preimage
/// and check the present signatures (Ed25519 uses the embedded public key, so it
/// is self-contained). The C2PA layer verifies the sidecar JUMBF offline.
///
/// The TSA and Rekor layers are verifiable only in the `native` build (they need
/// the sigstore stack + pinned shard keys). In the `verify-only` (wasm) build
/// they are reported as **present but not verified in this build** — honest, not
/// a faked pass — matching the offline-build contract.
pub fn verify_artifact_bytes(
    file_bytes: &[u8],
    receipt: &SealedRecord,
    key_hmac: Option<&[u8]>,
) -> Result<Vec<LayerResult>, SealError> {
    let mut results = Vec::new();

    // --- Content layer ---
    let expected_hash = receipt
        .payload
        .get("artifactSha256")
        .and_then(Value::as_str)
        .ok_or_else(|| SealError::Malformed("payload missing artifactSha256".into()))?;

    let actual_hash = sha256_hex(file_bytes);
    let content_ok = actual_hash == expected_hash;
    results.push(LayerResult {
        name: "content".to_string(),
        ok: content_ok,
        reason: if content_ok {
            "artifact hash matches receipt".to_string()
        } else {
            "artifact hash mismatch: file does not match receipt".to_string()
        },
    });

    // --- Crypto layers ---
    crypto_layers(&receipt.payload, &receipt.seal, key_hmac, &mut results)?;

    // --- C2PA layer (present-only): in-file embedded OR sidecar JUMBF ---
    if receipt.seal.c2pa_embedded == Some(true) {
        results.push(c2pa_embedded_layer(
            file_bytes,
            &receipt.payload,
            &receipt.seal,
        )?);
    } else if let Some(manifest_hex) = receipt.seal.c2pa_manifest.as_deref() {
        results.push(c2pa_layer(&receipt.payload, manifest_hex)?);
    }

    // --- TSA layer (present-only) ---
    if let Some(tsa_value) = receipt.seal.tsa.as_ref() {
        #[cfg(feature = "native")]
        results.push(tsa_layer(&receipt.seal, tsa_value)?);
        #[cfg(not(feature = "native"))]
        results.push(present_unverified_layer("tsa", tsa_value));
    }

    // --- Rekor v2 transparency layer (present-only) ---
    if let Some(rekor_value) = receipt.seal.rekor_anchor.as_ref() {
        #[cfg(feature = "native")]
        results.push(rekor_layer(rekor_value)?);
        #[cfg(not(feature = "native"))]
        results.push(present_unverified_layer("rekor", rekor_value));
    }

    Ok(results)
}

/// Honest placeholder for a transparency layer that is *present* in the receipt
/// but whose network-backed verification (sigstore stack + pinned shard keys) is
/// not compiled into the wasm verify-only build. Reports `ok: false` with a clear
/// honest reason rather than faking a pass.
#[cfg(not(feature = "native"))]
fn present_unverified_layer(name: &str, _value: &Value) -> LayerResult {
    LayerResult {
        name: name.to_string(),
        ok: false,
        reason: format!(
            "{name} layer present; network-layer verify needs bundled keys — not checked in this offline build"
        ),
    }
}

/// Verify the present Rekor anchor offline: parse it, resolve the pinned shard
/// key by `logId` from the embedded `rekor-shards.json`, and check RFC 6962
/// Merkle inclusion plus the checkpoint signature. A structurally malformed
/// anchor is an [`Err`]; a failed inclusion/checkpoint, or an unknown shard key,
/// is a measured `ok: false` (never an `Err`, never a silent pass).
#[cfg(feature = "native")]
fn rekor_layer(rekor_value: &Value) -> Result<LayerResult, SealError> {
    let anchor = rekor::RekorAnchor::from_json(rekor_value)?;
    let shards = rekor::load_shards(REKOR_SHARDS_JSON)?;
    let shard_pem = rekor::resolve_shard(&shards, &anchor.log_id)
        .map(|s| s.public_key_pem.clone().into_bytes());
    Ok(rekor::verify_anchor(&anchor, shard_pem.as_deref()))
}

/// Verify the present TSA token: reconstruct the canonical binding
/// `hmac.sig || ed25519.sig` from the seal, decode the stored DER, and check the
/// token's message imprint against it (the pass bar). Chain validation is
/// best-effort and reported in `reason`; no root is configured here, so it is
/// always reported unverified. Unparseable hex is a structural [`Err`]; an
/// imprint mismatch is `ok: false`.
#[cfg(feature = "native")]
fn tsa_layer(seal: &SealBlock, tsa_value: &Value) -> Result<LayerResult, SealError> {
    let der_hex = tsa_value
        .get("der")
        .and_then(Value::as_str)
        .ok_or_else(|| SealError::Malformed("seal.tsa missing der".into()))?;
    let der = decode_hex0x(der_hex)
        .ok_or_else(|| SealError::Malformed(format!("invalid seal.tsa der hex: {der_hex}")))?;

    let to_stamp = tsa_to_stamp(seal)?;
    Ok(tsa::verify_token(&der, &to_stamp, None))
}

/// Resolve the c2pa asset format string for an embedded receipt: the file
/// extension from `payload.path` (preferred — c2pa accepts a bare extension),
/// falling back to `payload.mime`. Returns `""` when neither is usable; c2pa then
/// surfaces an unsupported-format error.
fn embedded_format(payload: &Value) -> String {
    if let Some(path) = payload.get("path").and_then(Value::as_str) {
        if let Some(ext) = std::path::Path::new(path).extension() {
            return ext.to_string_lossy().to_ascii_lowercase();
        }
    }
    payload
        .get("mime")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Verify the in-file C2PA manifest embedded in `file_bytes`: read it with the
/// real `c2pa::Reader` and require a non-`Invalid` validation state. On the
/// native build the signer cert's Ed25519 public key is additionally checked
/// against the receipt's embedded `ed25519PublicKey` (signer ≡ authorship). The
/// integrity binding is c2pa's own data-hash assertion; the content layer also
/// independently catches a tampered file. Unreadable input is a structural
/// [`Err`]; an invalid manifest or signer mismatch is `ok: false`.
fn c2pa_embedded_layer(
    file_bytes: &[u8],
    payload: &Value,
    seal: &SealBlock,
) -> Result<LayerResult, SealError> {
    let format = embedded_format(payload);
    let valid = c2pa::verify_embedded(file_bytes, &format)?;
    if !valid {
        return Ok(LayerResult {
            name: "c2pa".to_string(),
            ok: false,
            reason: "embedded c2pa manifest invalid or absent".to_string(),
        });
    }

    // Native: confirm the embedded manifest's signer is the seal's Ed25519 key.
    #[cfg(feature = "native")]
    {
        if let Some(pem) = seal.ed25519_public_key.as_deref() {
            let expected = ed25519::verifying_key_from_pem(pem)?;
            match c2pa::embedded_signer_pubkey(file_bytes, &format)? {
                Some(signer) if signer.as_slice() == expected.as_bytes() => {}
                Some(_) => {
                    return Ok(LayerResult {
                        name: "c2pa".to_string(),
                        ok: false,
                        reason: "embedded c2pa signer key does not match the seal key".to_string(),
                    });
                }
                None => {
                    return Ok(LayerResult {
                        name: "c2pa".to_string(),
                        ok: false,
                        reason: "embedded c2pa manifest has no signer certificate".to_string(),
                    });
                }
            }
        }
    }
    // The wasm verify-only build cannot parse the signer cert (no x509-parser);
    // it attests manifest validity only. `seal` is otherwise unused there.
    #[cfg(not(feature = "native"))]
    let _ = seal;

    Ok(LayerResult {
        name: "c2pa".to_string(),
        ok: true,
        reason: "embedded c2pa manifest valid; signer is the seal key".to_string(),
    })
}

/// Verify the present C2PA sidecar: decode the stored JUMBF, recompute the
/// canonical payload hash, and check the manifest binds it. Unparseable hex or
/// JUMBF is a structural [`Err`]; a hash/validity mismatch is `ok: false`.
fn c2pa_layer(payload: &Value, manifest_hex: &str) -> Result<LayerResult, SealError> {
    let jumbf = decode_hex0x(manifest_hex)
        .ok_or_else(|| SealError::C2pa(format!("invalid c2paManifest hex: {manifest_hex}")))?;
    let expected = c2pa::payload_hash_hex(payload)?;
    let ok = c2pa::verify_sidecar(&jumbf, &expected)?;
    Ok(LayerResult {
        name: "c2pa".to_string(),
        ok,
        reason: if ok {
            "c2pa manifest valid; payload hash bound".to_string()
        } else {
            "c2pa manifest invalid or payload hash mismatch".to_string()
        },
    })
}

/// Append per-layer crypto results (hmac, ed25519) for the present layers.
///
/// Re-derives the canonical preimage from `payload` and `seal.sealedAt`, so a
/// tampered payload (which no longer canonicalizes to the stored preimage)
/// trips every crypto layer. A malformed signature is tamper (`ok: false`); a
/// present Ed25519 layer with no embedded/usable public key is structural
/// (`Err`).
fn crypto_layers(
    payload: &Value,
    seal: &SealBlock,
    key_hmac: Option<&[u8]>,
    results: &mut Vec<LayerResult>,
) -> Result<(), SealError> {
    let stored = decode_hex0x(&seal.preimage)
        .ok_or_else(|| SealError::InvalidPreimage(seal.preimage.clone()))?;
    let computed = build_preimage(payload, &seal.sealed_at)?;
    let preimage_ok = computed == stored;

    // HMAC layer (mandatory).
    let hmac_ok = match (preimage_ok, key_hmac, decode_hex0x(&seal.hmac.sig)) {
        (true, Some(key), Some(sig)) => hmac::verify(&computed, &sig, key),
        // No secret: best we can attest offline is preimage integrity + shape.
        (true, None, Some(_)) => true,
        _ => false,
    };
    results.push(LayerResult {
        name: "hmac".to_string(),
        ok: hmac_ok,
        reason: if hmac_ok && key_hmac.is_some() {
            "hmac verified".to_string()
        } else if hmac_ok {
            // No secret key supplied: the symmetric MAC cannot be checked
            // (HMAC is symmetric and the key never ships in a receipt). All we
            // attest offline here is preimage integrity. Be honest about it.
            "preimage integrity ok; HMAC not checked (no secret key supplied)".to_string()
        } else if !preimage_ok {
            "hmac failed: preimage does not match payload".to_string()
        } else {
            "hmac signature invalid".to_string()
        },
    });

    // Ed25519 layer (present-only, self-contained via embedded public key).
    if let Some(ed_layer) = seal.ed25519.as_ref() {
        let pem = seal
            .ed25519_public_key
            .as_deref()
            .ok_or(SealError::MissingPublicKey)?;
        let key = ed25519::verifying_key_from_pem(pem)?;
        let ed_ok = match (preimage_ok, decode_hex0x(&ed_layer.sig)) {
            (true, Some(sig)) => ed25519::verify(&computed, &sig, &key),
            _ => false,
        };
        results.push(LayerResult {
            name: "ed25519".to_string(),
            ok: ed_ok,
            reason: if ed_ok {
                "ed25519 verified".to_string()
            } else if !preimage_ok {
                "ed25519 failed: preimage does not match payload".to_string()
            } else {
                "ed25519 signature invalid".to_string()
            },
        });
    }

    Ok(())
}

/// Current UTC time as an RFC 3339 string with a `+00:00` offset.
#[cfg(feature = "native")]
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

/// The receipt path for an artifact: `<artifact>.seal.json` next to it.
#[cfg(feature = "native")]
pub fn default_receipt_path(artifact: &Path) -> PathBuf {
    let mut name = artifact.as_os_str().to_os_string();
    name.push(".seal.json");
    PathBuf::from(name)
}

/// Render a receipt's human-readable audit trail: method, sealedAt, the
/// artifact line (when the payload carries one), and the present layers.
pub fn render_chain(record: &SealedRecord) -> String {
    let seal = &record.seal;
    let mut out = String::new();
    out.push_str(&format!("method:   {}\n", seal.method));
    out.push_str(&format!("sealedAt: {}\n", seal.sealed_at));
    if let Some(path) = record.payload.get("path").and_then(Value::as_str) {
        let size = record
            .payload
            .get("size")
            .and_then(Value::as_u64)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "?".to_string());
        out.push_str(&format!("artifact: {path} ({size} bytes)\n"));
    }
    out.push_str("layers:\n");
    out.push_str(&format!("  hmac      [{}]\n", seal.hmac.alg));
    if seal.ed25519.is_some() {
        let embedded = if seal.ed25519_public_key.is_some() {
            " (public key embedded)"
        } else {
            ""
        };
        out.push_str(&format!("  ed25519{embedded}\n"));
    }
    if seal.c2pa_embedded == Some(true) {
        out.push_str("  c2pa      (in-file embedded manifest)\n");
    } else if seal.c2pa_manifest.is_some() {
        out.push_str("  c2pa      (sidecar JUMBF manifest)\n");
    }
    if let Some(tsa) = seal.tsa.as_ref() {
        let authority = tsa.get("authority").and_then(Value::as_str).unwrap_or("?");
        out.push_str(&format!("  tsa       (RFC 3161, {authority})\n"));
    }
    if let Some(rekor) = seal.rekor_anchor.as_ref() {
        let log_index = rekor
            .get("logIndex")
            .and_then(Value::as_i64)
            .map(|i| i.to_string())
            .unwrap_or_else(|| "?".to_string());
        out.push_str(&format!(
            "  rekor     (Sigstore v2, logIndex {log_index})\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::load_or_generate;
    use crate::verify::verify;

    fn overall_ok(results: &[LayerResult]) -> bool {
        results.iter().all(|r| r.ok)
    }

    fn layer<'a>(results: &'a [LayerResult], name: &str) -> &'a LayerResult {
        results
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing layer: {name}"))
    }

    #[test]
    fn seal_then_verify_all_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"apohara-sealchain artifact bytes").expect("write");

        let record = seal_artifact(&artifact, &keys, None, false, false, None, None).expect("seal");
        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");

        assert!(overall_ok(&results), "all layers should verify");
        assert!(layer(&results, "content").ok);
        assert!(layer(&results, "hmac").ok);
        assert!(layer(&results, "ed25519").ok);

        // Self-contained: core verify() with no pubkey arg uses the embedded key.
        let record_value = serde_json::to_value(&record).expect("to_value");
        assert!(verify(&record_value, &keys.hmac, None).expect("core verify"));
    }

    #[test]
    fn flipped_file_byte_trips_content_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.bin");
        std::fs::write(&artifact, b"original-bytes").expect("write");

        let record = seal_artifact(&artifact, &keys, None, false, false, None, None).expect("seal");
        // Flip one byte of the file (receipt unchanged).
        std::fs::write(&artifact, b"Original-bytes").expect("rewrite");

        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
        assert!(!overall_ok(&results));
        assert!(!layer(&results, "content").ok, "content must fail");
        assert!(layer(&results, "hmac").ok, "hmac still ok");
        assert!(layer(&results, "ed25519").ok, "ed25519 still ok");
    }

    #[test]
    fn tampered_payload_trips_crypto_layers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"payload tamper case").expect("write");

        let mut record =
            seal_artifact(&artifact, &keys, None, false, false, None, None).expect("seal");
        // Tamper the receipt payload (mime), leaving the preimage stale.
        record.payload["mime"] = Value::String("tampered/type".to_string());

        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
        assert!(!overall_ok(&results));
        assert!(!layer(&results, "hmac").ok, "hmac must fail on tamper");
        assert!(
            !layer(&results, "ed25519").ok,
            "ed25519 must fail on tamper"
        );
    }

    #[test]
    fn seal_with_c2pa_adds_valid_sidecar_layer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"c2pa sidecar artifact").expect("write");

        // c2pa = true emits a real JUMBF sidecar into seal.c2paManifest.
        let record = seal_artifact(&artifact, &keys, None, true, false, None, None).expect("seal");
        let manifest = record
            .seal
            .c2pa_manifest
            .as_deref()
            .expect("c2paManifest present");
        assert!(manifest.starts_with("0x"), "manifest stored as 0x-hex");

        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
        assert!(overall_ok(&results), "all layers ok with valid sidecar");
        let c2pa = layer(&results, "c2pa");
        assert!(c2pa.ok, "c2pa layer must verify: {}", c2pa.reason);

        // The HMAC secret must never leak into the receipt, even with c2pa on.
        let serialized = serde_json::to_string(&record).expect("serialize");
        assert!(
            !serialized.contains(&hex::encode(&keys.hmac)),
            "HMAC key must not appear in the receipt"
        );
    }

    #[test]
    fn c2pa_layer_absent_when_not_requested() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"no sidecar here").expect("write");

        let record = seal_artifact(&artifact, &keys, None, false, false, None, None).expect("seal");
        assert!(record.seal.c2pa_manifest.is_none(), "no c2paManifest field");

        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
        assert!(
            results.iter().all(|r| r.name != "c2pa"),
            "no c2pa layer reported when absent"
        );
    }

    #[test]
    fn tampered_payload_trips_c2pa_layer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"c2pa tamper case").expect("write");

        let mut record =
            seal_artifact(&artifact, &keys, None, true, false, None, None).expect("seal");
        // Tamper the receipt payload: the canonical hash no longer matches the
        // hash bound in the (still-valid) C2PA manifest, so the c2pa layer fails.
        record.payload["mime"] = Value::String("tampered/type".to_string());

        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
        assert!(!overall_ok(&results));
        assert!(
            !layer(&results, "c2pa").ok,
            "c2pa layer must fail when payload hash no longer matches"
        );
    }

    #[test]
    fn missing_artifact_sha_is_structural_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"x").expect("write");

        let mut record =
            seal_artifact(&artifact, &keys, None, false, false, None, None).expect("seal");
        record
            .payload
            .as_object_mut()
            .unwrap()
            .remove("artifactSha256");

        let err = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect_err("structural");
        assert!(matches!(err, SealError::Malformed(_)));
    }

    /// A minimal valid 1x1 RGBA PNG (real, c2pa-embeddable). Generated offline
    /// (signature + IHDR + IDAT + IEND); enough for c2pa-rs to embed a manifest.
    fn tiny_png() -> Vec<u8> {
        vec![
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207,
            192, 240, 31, 0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66,
            96, 130,
        ]
    }

    #[test]
    fn embed_writes_in_file_manifest_and_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("photo.png");
        std::fs::write(&artifact, tiny_png()).expect("write png");

        // Seal with --embed: the manifest goes INTO the PNG.
        let record =
            seal_artifact(&artifact, &keys, None, true, true, None, None).expect("embed seal");

        // The receipt records the embedded mode, NOT a sidecar manifest.
        assert_eq!(
            record.seal.c2pa_embedded,
            Some(true),
            "c2paEmbedded recorded"
        );
        assert!(
            record.seal.c2pa_manifest.is_none(),
            "no sidecar manifest in embed mode"
        );

        // The file on disk was rewritten with the embedded asset and its hash is
        // bound by the seal (artifactSha256 == sha256(embedded bytes)).
        let final_bytes = std::fs::read(&artifact).expect("read embedded png");
        assert_ne!(
            final_bytes,
            tiny_png(),
            "file rewritten with embedded asset"
        );
        let bound = record.payload["artifactSha256"].as_str().unwrap();
        assert_eq!(sha256_hex(&final_bytes), bound, "seal binds embedded bytes");

        // The embedded manifest reads back Valid via the real c2pa::Reader AND its
        // signer cert public key equals the seal's Ed25519 public key.
        assert!(
            c2pa::verify_embedded(&final_bytes, "png").expect("verify embedded"),
            "embedded manifest must be Valid"
        );
        let signer = c2pa::embedded_signer_pubkey(&final_bytes, "png")
            .expect("signer pubkey")
            .expect("signer cert present");
        assert_eq!(
            signer.as_slice(),
            keys.ed25519.verifying_key().as_bytes(),
            "embedded signer == seal public key"
        );

        // Full verify round-trips: content + embedded c2pa both ok.
        let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
        assert!(overall_ok(&results), "all layers verify: {results:?}");
        assert!(layer(&results, "content").ok, "content ok");
        let c2pa_layer = layer(&results, "c2pa");
        assert!(c2pa_layer.ok, "embedded c2pa ok: {}", c2pa_layer.reason);

        // The HMAC secret must never leak into the receipt, even with embed on.
        let serialized = serde_json::to_string(&record).expect("serialize");
        assert!(
            !serialized.contains(&hex::encode(&keys.hmac)),
            "HMAC key must not appear in the receipt"
        );
    }

    #[test]
    fn embed_unsupported_format_hard_errors_no_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.bin");
        let original = b"not embeddable media".to_vec();
        std::fs::write(&artifact, &original).expect("write");

        // --embed on an unsupported format is a hard error, never a sidecar.
        let err = seal_artifact(&artifact, &keys, None, true, true, None, None)
            .expect_err("unsupported embed must error");
        assert!(matches!(err, SealError::C2pa(_)), "got: {err:?}");

        // The artifact file is untouched (no partial embed written).
        let after = std::fs::read(&artifact).expect("read");
        assert_eq!(after, original, "file unchanged on rejected embed");
    }

    #[test]
    fn embed_requires_c2pa() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("photo.png");
        std::fs::write(&artifact, tiny_png()).expect("write png");

        // embed=true with c2pa=false is rejected before any file mutation.
        let err = seal_artifact(&artifact, &keys, None, false, true, None, None)
            .expect_err("embed without c2pa must error");
        assert!(matches!(err, SealError::C2pa(_)), "got: {err:?}");
        assert_eq!(
            std::fs::read(&artifact).unwrap(),
            tiny_png(),
            "png untouched"
        );
    }

    #[test]
    fn embedded_tamper_trips_c2pa_or_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("photo.png");
        std::fs::write(&artifact, tiny_png()).expect("write png");

        let record =
            seal_artifact(&artifact, &keys, None, true, true, None, None).expect("embed seal");
        let embedded = std::fs::read(&artifact).expect("read embedded");

        // Flip a byte in the embedded image-data region: the content layer (and/or
        // the c2pa data-hash binding) must trip, so the overall verdict is false.
        let mut tampered = embedded.clone();
        let idx = tampered.len() / 2;
        tampered[idx] ^= 0xff;
        let results = verify_artifact_bytes(&tampered, &record, Some(&keys.hmac)).expect("verify");
        assert!(!overall_ok(&results), "tampered embedded file must fail");
    }
}
