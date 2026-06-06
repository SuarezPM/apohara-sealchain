//! C2PA sidecar layer — real, offline-verifiable JUMBF manifests.
//!
//! This layer produces a genuine C2PA manifest store (JUMBF bytes) that binds
//! the seal's canonical payload hash, and reads it back with the real
//! `c2pa::Reader`. There is **no JSON fallback**: the bytes stored in
//! `seal.c2paManifest` are a true manifest store that `c2pa::Reader` parses and
//! cryptographically validates.
//!
//! ## What is bound
//!
//! The Rust engine is authoritative for the binding: the manifest carries a
//! **custom** assertion `apohara.seal.payloadHash` with
//! `{ "alg": "sha256", "hash": <hex> }`, where `<hex>` is
//! `sha256(JCS(strip_excluded(payload)))` — the exact same hash on emit and
//! verify. We deliberately do NOT use the reserved `c2pa.hash.data` /
//! `c2pa.hash` hard-binding assertions: those bind *asset bytes*, not our JSON
//! payload, and misusing them would be dishonest. Our label lives in the
//! `apohara.*` namespace, which the C2PA spec reserves for vendor assertions.
//!
//! ## Signer (seal-bound, TEST-trust disclosed)
//!
//! Signing ties the manifest to the **seal's own Ed25519 key**: the COSE
//! signature is produced with the seal's private key via a
//! [`CallbackSigner`], and the signing certificate is a self-signed X.509
//! certificate whose subject public key is the seal's Ed25519 public key
//! (generated with `rcgen`). The end-entity cert that verifies the COSE
//! signature therefore carries the *same* identity that authored the seal —
//! signer ≡ authorship.
//!
//! The certificate is self-signed (not anchored to a trust list), so
//! verification runs with `verify_trust = false`: we assert the manifest is
//! cryptographically **Valid** (well-formed + signature integrity), not
//! **Trusted**. This is the documented v0.1 posture; a production trust list is
//! a later story. The HMAC secret is never involved in C2PA signing.
//!
//! ## Offline guarantee
//!
//! The crate is built without the `fetch_remote_manifests` feature, so the
//! reader cannot fetch a remote manifest even if asked. We additionally set
//! `remote_manifest_fetch = false` and use the sidecar (`no_embed`) path with
//! an in-memory asset stream, so no media file and no network are ever touched.

#[cfg(feature = "native")]
use c2pa::{Builder, BuilderIntent, CallbackSigner, DigitalSourceType, SigningAlg};
use c2pa::{Reader, Settings};
#[cfg(feature = "native")]
use ed25519_dalek::SigningKey;
#[cfg(feature = "native")]
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
#[cfg(feature = "native")]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::SealError;
use crate::excluded::strip_excluded;
use crate::jcs;

/// Common name for the seal's self-signed signing certificate.
#[cfg(feature = "native")]
const SIGNER_CERT_CN: &str = "apohara-seal.local";

/// Organization (O=) for the signing certificate's subject. c2pa-rs requires
/// the signing cert's subject to carry an Organization attribute: on read it
/// reads `subject.iter_organization().last()` for `issuer_org` and errors with
/// `MissingSigningCertificateChain` if absent. A bare CN is not enough.
#[cfg(feature = "native")]
const SIGNER_CERT_ORG: &str = "Apohara Seal (self-signed, LOCAL USE ONLY)";

/// Fixed 16-byte DER prefix of a canonical PKCS#8 **v1** OneAsymmetricKey for
/// Ed25519: `SEQUENCE { INTEGER 0, AlgorithmIdentifier(1.3.101.112),
/// OCTET STRING { OCTET STRING(32 bytes) } }`. The 32-byte raw key follows.
/// c2pa's [`CallbackSigner::ed25519_sign`] parses the PEM and reads the key as
/// `contents[16..]`, so we must hand it this exact v1 layout (ed25519-dalek's
/// own PKCS#8 encoder emits the longer v2 form, which would break that offset).
#[cfg(feature = "native")]
const PKCS8_V1_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE (46 bytes)
    0x02, 0x01, 0x00, // INTEGER 0 (version v1)
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: id-Ed25519
    0x04, 0x22, // OCTET STRING (34 bytes)
    0x04, 0x20, // inner OCTET STRING (32-byte private key)
];

/// Custom assertion label binding the seal's canonical payload hash. Lives in
/// the vendor-reserved `apohara.*` namespace; intentionally NOT a reserved
/// `c2pa.hash*` hard binding (those bind asset bytes, not our JSON payload).
const PAYLOAD_HASH_LABEL: &str = "apohara.seal.payloadHash";

/// MIME used for the in-memory sidecar asset. `application/unknown` has no
/// format handler, which forces the sidecar (`no_embed`) path: the manifest
/// store is returned as standalone JUMBF rather than embedded into media.
const SIDECAR_FORMAT: &str = "application/unknown";

/// File extensions c2pa-rs 0.85 can **embed** a manifest into (its `CAIWriter`
/// set, not the broader reader set). Vetted against the writer handlers
/// registered in `c2pa::jumbf_io`'s `CAI_WRITERS` map (BMFF, JPEG, JPEG-XL, PNG,
/// RIFF, SVG, TIFF, MP3, FLAC, GIF). TIFF's writer accepts only the subset in its
/// `SUPPORTED_WRITER_TYPES` (`tif`/`tiff`/`dng`), so the non-writable TIFF
/// variants (`arw`, `nef`) are intentionally excluded here. A format outside this
/// set must hard-error under `--embed` rather than silently fall back to sidecar.
#[cfg(feature = "native")]
const EMBEDDABLE_EXTENSIONS: &[&str] = &[
    // BMFF (ISO base media): MP4/MOV/HEIF/AVIF family.
    "avif", "heif", "heic", "mp4", "m4a", "mov", "m4v", //
    // JPEG / JPEG-XL.
    "jpg", "jpeg", "jxl", //
    // PNG.
    "png", //
    // RIFF: WebP, WAV, AVI.
    "avi", "wav", "webp", //
    // SVG / XML family.
    "svg", "xhtml", "xml", //
    // TIFF (writer subset only).
    "tif", "tiff", "dng", //
    // Audio: MP3, FLAC.
    "mp3", "flac", //
    // GIF.
    "gif",
];

/// Placeholder asset bytes the sidecar manifest is signed against. The hard
/// binding to our payload lives in the custom assertion, not in this asset, so
/// the asset content is irrelevant (a non-empty stream is required by the SDK).
const SIDECAR_ASSET: &[u8] = b"apohara-seal-c2pa-sidecar";

/// Build the JSON settings that keep the c2pa pipeline fully offline and accept
/// the seal's self-signed (untrusted) signer: trust checking and remote fetch
/// are off. `verify_after_sign` is on so [`emit_sidecar`] fails loudly if the
/// signature it just produced does not validate, rather than emitting a manifest
/// that only fails on read (the default is off outside c2pa's own test build).
fn offline_settings() -> Result<Settings, SealError> {
    Settings::new()
        .with_json(
            r#"{
                "verify": {
                    "verify_trust": false,
                    "verify_timestamp_trust": false,
                    "remote_manifest_fetch": false,
                    "ocsp_fetch": false,
                    "verify_after_sign": true
                }
            }"#,
        )
        .map_err(|e| SealError::C2pa(format!("settings: {e}")))
}

/// Compute the canonical payload hash hex: `sha256(JCS(strip_excluded(payload)))`.
pub fn payload_hash_hex(payload: &Value) -> Result<String, SealError> {
    let canonical = jcs::canonicalize(&strip_excluded(payload))?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}

/// Encode `signer_key` as a canonical PKCS#8 **v1** PEM (`PRIVATE KEY`) — the
/// 48-byte layout c2pa's [`CallbackSigner::ed25519_sign`] and rcgen's ring
/// backend both accept. Built from the 32-byte seed plus a fixed v1 prefix
/// rather than ed25519-dalek's PKCS#8 encoder (which emits the v2 form).
#[cfg(feature = "native")]
fn seal_pkcs8_v1_pem(signer_key: &SigningKey) -> String {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&PKCS8_V1_ED25519_PREFIX);
    der.extend_from_slice(&signer_key.to_bytes());
    pem::Pem::new("PRIVATE KEY", der).to_string()
}

/// Build a self-signed end-entity X.509 certificate (PEM) whose subject public
/// key is `signer_key`'s Ed25519 public key, signed by `signer_key` itself.
///
/// The certificate carries the v3 extensions c2pa-rs's certificate-profile
/// check requires for a signer: BasicConstraints (cA=FALSE), KeyUsage
/// (digitalSignature), ExtendedKeyUsage (emailProtection — an allowed C2PA
/// signing EKU), plus SubjectKeyIdentifier and AuthorityKeyIdentifier. Because
/// the certificate is self-signed, its SPKI equals the seal's public key and
/// the COSE signature (made with the seal's private key) verifies against it —
/// proving signer ≡ authorship.
#[cfg(feature = "native")]
fn build_signer_cert_pem(signer_key: &SigningKey) -> Result<String, SealError> {
    let pkcs8_pem = seal_pkcs8_v1_pem(signer_key);
    // Reuse the *exact* seal key material so the cert SPKI == seal public key.
    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8_pem, &PKCS_ED25519)
        .map_err(|e| SealError::C2pa(format!("rcgen key from seal pkcs8: {e}")))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, SIGNER_CERT_CN);
    dn.push(DnType::OrganizationName, SIGNER_CERT_ORG);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    // End-entity (cA=FALSE) — c2pa rejects a CA cert as the signing credential.
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // emailProtection is one of the EKUs c2pa-rs accepts for a signer; the
    // ephemeral signer's `anyExtendedKeyUsage` is explicitly rejected.
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    // c2pa's certificate profile requires an AuthorityKeyIdentifier extension.
    params.use_authority_key_identifier_extension = true;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| SealError::C2pa(format!("self-sign signer cert: {e}")))?;
    Ok(cert.pem())
}

/// The IPTC digital source type recorded for **AI-generated media** in the C2PA
/// created action: `trainedAlgorithmicMedia` (C2PA 2.x / IPTC Digital Source
/// Types). Pinned so the emitted label is stable and round-trip-testable; emitted
/// only when the caller opts in via `ai_generated` (the `--ai-generated` flag).
pub const AI_GENERATED_SOURCE_TYPE: &str =
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia";

/// The created-manifest digital source type for a seal: AI-generated media
/// ([`AI_GENERATED_SOURCE_TYPE`]) when `ai_generated`, else `Empty` (no claim
/// about how the content was produced — the honest default).
#[cfg(feature = "native")]
fn created_source_type(ai_generated: bool) -> DigitalSourceType {
    if ai_generated {
        DigitalSourceType::TrainedAlgorithmicMedia
    } else {
        DigitalSourceType::Empty
    }
}

/// Emit a real C2PA sidecar manifest (JUMBF bytes) binding `payload`'s
/// canonical hash, signed with the **seal's own Ed25519 key**.
///
/// `signer_key` is the seal's Ed25519 [`SigningKey`]. The COSE signature is
/// produced with that key via a [`CallbackSigner`], and the signing certificate
/// is a self-signed cert carrying the same key's public part (see
/// `build_signer_cert_pem`). The HMAC secret is never involved. `ai_generated`
/// records the created action's digital source type as AI-generated media
/// ([`AI_GENERATED_SOURCE_TYPE`]) instead of `Empty`.
#[cfg(feature = "native")]
pub fn emit_sidecar(
    payload: &Value,
    signer_key: &SigningKey,
    ai_generated: bool,
) -> Result<Vec<u8>, SealError> {
    let hash_hex = payload_hash_hex(payload)?;
    let assertion = json!({ "alg": "sha256", "hash": hash_hex });

    let context = c2pa::Context::new()
        .with_settings(offline_settings()?)
        .map_err(|e| SealError::C2pa(format!("context: {e}")))?;

    let mut builder = Builder::from_context(context);
    // A standalone sidecar with no parent asset: a "created" manifest. The digital
    // source type is AI-generated media when the caller opts in, else empty (the
    // placeholder asset is not the real subject).
    builder.set_intent(BuilderIntent::Create(created_source_type(ai_generated)));
    // Sidecar mode: return the standalone manifest store, do not embed in media.
    builder.set_no_embed(true);
    builder
        .add_assertion(PAYLOAD_HASH_LABEL, &assertion)
        .map_err(|e| SealError::C2pa(format!("add assertion: {e}")))?;

    let cert_pem = build_signer_cert_pem(signer_key)?;
    // PKCS#8 v1 PEM of the seal's private key; `CallbackSigner::ed25519_sign`
    // parses it and signs the COSE to-be-signed bytes with the seal key. The
    // closure owns this so it lives as long as the signer.
    let seal_priv_pem = seal_pkcs8_v1_pem(signer_key);
    let signer = CallbackSigner::new(
        move |_context, data: &[u8]| CallbackSigner::ed25519_sign(data, seal_priv_pem.as_bytes()),
        SigningAlg::Ed25519,
        cert_pem.into_bytes(),
    );

    let mut source = std::io::Cursor::new(SIDECAR_ASSET);
    let jumbf = builder
        .sign(&signer, SIDECAR_FORMAT, &mut source, &mut std::io::empty())
        .map_err(|e| SealError::C2pa(format!("sign: {e}")))?;

    Ok(jumbf)
}

/// Return `true` when c2pa-rs can **embed** a manifest into a file with this
/// extension (case-insensitive), per `EMBEDDABLE_EXTENSIONS`. Used to gate
/// `--embed`: an unsupported format must hard-error, never silently sidecar.
#[cfg(feature = "native")]
pub fn is_embeddable_extension(ext: &str) -> bool {
    let ext = ext.to_ascii_lowercase();
    EMBEDDABLE_EXTENSIONS.contains(&ext.as_str())
}

/// Embed a real C2PA manifest **into** `media_bytes** and return the new asset
/// bytes (the original media augmented with an in-file JUMBF store).
///
/// Unlike [`emit_sidecar`], this uses c2pa-rs's **native in-file hard binding**:
/// the manifest carries the C2PA data-hash assertion c2pa computes over the asset
/// (excluding the manifest region), so the embedded file's integrity is proven by
/// c2pa itself. We do **not** add the `apohara.seal.payloadHash` assertion here —
/// binding the apohara-sealchain payload hash would be circular (the payload hash is over
/// `artifactSha256`, which is itself `sha256(embedded bytes)`). The seal's
/// payload hash is still produced and signed by the surrounding HMAC/Ed25519
/// layers over the FINAL embedded file.
///
/// `format` is the asset MIME or extension (e.g. `image/png` or `png`); it must
/// be embeddable (see [`is_embeddable_extension`]) — callers gate on the
/// extension before reaching here. `signer_key` is the seal's Ed25519 key; the
/// COSE signature and the self-signed cert are produced exactly as in
/// [`emit_sidecar`], so signer ≡ authorship holds for the embedded manifest too.
#[cfg(feature = "native")]
pub fn embed_manifest(
    media_bytes: &[u8],
    format: &str,
    signer_key: &SigningKey,
    ai_generated: bool,
) -> Result<Vec<u8>, SealError> {
    let context = c2pa::Context::new()
        .with_settings(offline_settings()?)
        .map_err(|e| SealError::C2pa(format!("context: {e}")))?;

    let mut builder = Builder::from_context(context);
    // A manifest created for this asset; c2pa adds its own data-hash hard binding
    // over the asset bytes (the integrity proof for the embedded file). The digital
    // source type is AI-generated media when the caller opts in, else empty.
    builder.set_intent(BuilderIntent::Create(created_source_type(ai_generated)));
    // Embed mode: write the manifest into the output asset stream.
    builder.set_no_embed(false);

    let cert_pem = build_signer_cert_pem(signer_key)?;
    let seal_priv_pem = seal_pkcs8_v1_pem(signer_key);
    let signer = CallbackSigner::new(
        move |_context, data: &[u8]| CallbackSigner::ed25519_sign(data, seal_priv_pem.as_bytes()),
        SigningAlg::Ed25519,
        cert_pem.into_bytes(),
    );

    let mut source = std::io::Cursor::new(media_bytes);
    let mut dest = std::io::Cursor::new(Vec::new());
    builder
        .sign(&signer, format, &mut source, &mut dest)
        .map_err(|e| SealError::C2pa(format!("embed sign: {e}")))?;

    Ok(dest.into_inner())
}

/// Verify the in-file C2PA manifest embedded in `media_bytes`: parse it with the
/// real `c2pa::Reader` over the asset stream and require a non-`Invalid`
/// validation state. Returns `Ok(true)` when valid, `Ok(false)` when the reader
/// reports `Invalid` or no manifest is present. Unparseable input is an [`Err`].
///
/// `format` is the asset MIME or extension. The integrity binding is c2pa's own
/// data-hash assertion over the asset bytes, so a tampered embedded file fails
/// here (the content layer also independently catches it via `artifactSha256`).
pub fn verify_embedded(media_bytes: &[u8], format: &str) -> Result<bool, SealError> {
    let context = c2pa::Context::new()
        .with_settings(offline_settings()?)
        .map_err(|e| SealError::C2pa(format!("context: {e}")))?;

    let mut source = std::io::Cursor::new(media_bytes);
    let reader = Reader::from_context(context)
        .with_stream(format, &mut source)
        .map_err(|e| SealError::C2pa(format!("read embedded manifest: {e}")))?;

    if reader.validation_state() == c2pa::ValidationState::Invalid {
        return Ok(false);
    }
    Ok(reader.active_manifest().is_some())
}

/// Extract the end-entity signing certificate's Ed25519 SPKI public key from the
/// C2PA manifest embedded in `media_bytes`, as raw 32-byte key. Returns `None`
/// when no manifest, no signature info, or the cert cannot be parsed. Used to
/// confirm the embedded manifest's signer ≡ the seal's Ed25519 public key.
#[cfg(feature = "native")]
pub fn embedded_signer_pubkey(
    media_bytes: &[u8],
    format: &str,
) -> Result<Option<Vec<u8>>, SealError> {
    let context = c2pa::Context::new()
        .with_settings(offline_settings()?)
        .map_err(|e| SealError::C2pa(format!("context: {e}")))?;

    let mut source = std::io::Cursor::new(media_bytes);
    let reader = Reader::from_context(context)
        .with_stream(format, &mut source)
        .map_err(|e| SealError::C2pa(format!("read embedded manifest: {e}")))?;

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => return Ok(None),
    };
    let sig_info = match manifest.signature_info() {
        Some(s) => s,
        None => return Ok(None),
    };
    let cert_chain_pem = sig_info.cert_chain();
    if cert_chain_pem.is_empty() {
        return Ok(None);
    }
    Ok(spki_ed25519_from_cert_pem(cert_chain_pem))
}

/// Parse the first PEM `CERTIFICATE` in `cert_chain_pem` and return its SPKI
/// public-key bytes (raw Ed25519 key). `None` on any parse failure.
#[cfg(feature = "native")]
fn spki_ed25519_from_cert_pem(cert_chain_pem: &str) -> Option<Vec<u8>> {
    use x509_parser::prelude::FromDer;

    let pem = pem::parse(cert_chain_pem).ok()?;
    if pem.tag() != "CERTIFICATE" {
        return None;
    }
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(pem.contents()).ok()?;
    // `subject_public_key.data` is a `Cow<'_, [u8]>`; bind the borrow to `&[u8]`
    // explicitly so `as_ref` is unambiguous (a transitive dep — typed_path — adds a
    // second `AsRef` impl on `Cow<[u8]>` in scope, which otherwise trips E0283).
    let spki: &[u8] = cert.public_key().subject_public_key.data.as_ref();
    Some(spki.to_vec())
}

/// Parse `manifest_bytes` with the real `c2pa::Reader`, require the manifest to
/// be cryptographically **Valid**, and check that the `apohara.seal.payloadHash`
/// assertion's `hash` equals `expected_payload_hash_hex` (case-insensitive).
///
/// Returns `Ok(true)` only when the manifest is valid *and* the bound hash
/// matches; `Ok(false)` on any mismatch or non-valid state. A structural
/// failure (bytes that cannot be parsed at all) is an [`Err`].
pub fn verify_sidecar(
    manifest_bytes: &[u8],
    expected_payload_hash_hex: &str,
) -> Result<bool, SealError> {
    let context = c2pa::Context::new()
        .with_settings(offline_settings()?)
        .map_err(|e| SealError::C2pa(format!("context: {e}")))?;

    let mut source = std::io::Cursor::new(SIDECAR_ASSET);
    let reader = Reader::from_context(context)
        .with_manifest_data_and_stream(manifest_bytes, SIDECAR_FORMAT, &mut source)
        .map_err(|e| SealError::C2pa(format!("read manifest: {e}")))?;

    // Require cryptographic validity. Ephemeral (untrusted) certs cannot reach
    // `Trusted`, so `Valid` (well-formed + signature integrity) is the bar.
    if reader.validation_state() == c2pa::ValidationState::Invalid {
        return Ok(false);
    }

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => return Ok(false),
    };

    for assertion in manifest.assertions() {
        if assertion.label() == PAYLOAD_HASH_LABEL {
            let value = assertion
                .value()
                .map_err(|e| SealError::C2pa(format!("assertion value: {e}")))?;
            let bound = value.get("hash").and_then(Value::as_str).unwrap_or("");
            return Ok(bound.eq_ignore_ascii_case(expected_payload_hash_hex));
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn sample_payload() -> Value {
        json!({
            "artifactSha256": "deadbeef",
            "path": "doc.txt",
            "size": 42,
            "mime": "text/plain"
        })
    }

    #[test]
    fn emit_then_verify_round_trip_ok() {
        let key = SigningKey::generate(&mut OsRng);
        let payload = sample_payload();

        let jumbf = emit_sidecar(&payload, &key, false).expect("emit");
        let expected = payload_hash_hex(&payload).expect("hash");

        // The manifest is REAL JUMBF: the Reader parses it and it is Valid.
        assert!(
            verify_sidecar(&jumbf, &expected).expect("verify"),
            "round trip must verify"
        );
    }

    #[test]
    fn manifest_is_real_jumbf_reader_parses_valid() {
        let key = SigningKey::generate(&mut OsRng);
        let payload = sample_payload();
        let jumbf = emit_sidecar(&payload, &key, false).expect("emit");

        let context = c2pa::Context::new()
            .with_settings(offline_settings().unwrap())
            .unwrap();
        let mut source = std::io::Cursor::new(SIDECAR_ASSET);
        let reader = Reader::from_context(context)
            .with_manifest_data_and_stream(&jumbf, SIDECAR_FORMAT, &mut source)
            .expect("reader parses real JUMBF");
        assert_ne!(
            reader.validation_state(),
            c2pa::ValidationState::Invalid,
            "validation state must be Valid (or better), not Invalid"
        );
        assert!(
            reader.active_manifest().is_some(),
            "an active manifest must be present"
        );
    }

    #[test]
    fn wrong_expected_hash_returns_false() {
        let key = SigningKey::generate(&mut OsRng);
        let payload = sample_payload();
        let jumbf = emit_sidecar(&payload, &key, false).expect("emit");

        let wrong = "00".repeat(32);
        assert!(
            !verify_sidecar(&jumbf, &wrong).expect("verify"),
            "wrong expected hash must not verify"
        );
    }

    #[test]
    fn case_insensitive_hash_match() {
        let key = SigningKey::generate(&mut OsRng);
        let payload = sample_payload();
        let jumbf = emit_sidecar(&payload, &key, false).expect("emit");

        let expected = payload_hash_hex(&payload).expect("hash").to_uppercase();
        assert!(
            verify_sidecar(&jumbf, &expected).expect("verify"),
            "uppercase expected hash must still match"
        );
    }

    #[test]
    fn garbage_bytes_are_structural_error() {
        let err = verify_sidecar(b"not a manifest at all", "deadbeef");
        assert!(err.is_err(), "unparseable bytes are a structural error");
    }

    /// The S4 signer ≡ authorship proof: the manifest is **Valid** AND the
    /// end-entity certificate's public key equals the seal's Ed25519 public key.
    /// Valid means the COSE signature verified against that cert's SPKI; since
    /// the COSE was signed with the seal key and the cert wraps the same key,
    /// the seal key both signed the manifest and is the certified identity.
    #[test]
    fn signer_identity_equals_seal_public_key() {
        use x509_parser::prelude::FromDer;

        let key = SigningKey::generate(&mut OsRng);
        let payload = sample_payload();
        let jumbf = emit_sidecar(&payload, &key, false).expect("emit");

        // 1. The manifest must reach Valid (well-formed + signature integrity).
        let context = c2pa::Context::new()
            .with_settings(offline_settings().unwrap())
            .unwrap();
        let mut source = std::io::Cursor::new(SIDECAR_ASSET);
        let reader = Reader::from_context(context)
            .with_manifest_data_and_stream(&jumbf, SIDECAR_FORMAT, &mut source)
            .expect("reader parses real JUMBF");
        assert_eq!(
            reader.validation_state(),
            c2pa::ValidationState::Valid,
            "manifest must be Valid (signature verified against the EE cert)"
        );

        // 2. Extract the end-entity cert's Ed25519 SPKI public key and assert it
        //    equals the seal's public key.
        let manifest = reader.active_manifest().expect("active manifest");
        let sig_info = manifest.signature_info().expect("signature info");
        let cert_chain_pem = sig_info.cert_chain();
        assert!(
            !cert_chain_pem.is_empty(),
            "cert chain PEM must be present in the signature info"
        );

        let pem = pem::parse(cert_chain_pem).expect("parse cert PEM");
        assert_eq!(pem.tag(), "CERTIFICATE", "cert chain must be a CERTIFICATE");
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(pem.contents()).expect("parse DER");
        let spki_pubkey: &[u8] = cert.public_key().subject_public_key.data.as_ref();

        let seal_pubkey = key.verifying_key();
        assert_eq!(
            spki_pubkey,
            seal_pubkey.as_bytes(),
            "the signing cert's SPKI public key must equal the seal's Ed25519 public key"
        );
    }

    /// A minimal valid 1x1 RGBA PNG (c2pa-embeddable), mirroring the artifact-test
    /// fixture — enough for c2pa-rs to embed a manifest.
    fn tiny_png() -> Vec<u8> {
        vec![
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207,
            192, 240, 31, 0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66,
            96, 130,
        ]
    }

    /// Read a standalone sidecar JUMBF back and return its manifest-store JSON.
    fn sidecar_manifest_json(jumbf: &[u8]) -> String {
        let context = c2pa::Context::new()
            .with_settings(offline_settings().unwrap())
            .unwrap();
        let mut source = std::io::Cursor::new(SIDECAR_ASSET);
        Reader::from_context(context)
            .with_manifest_data_and_stream(jumbf, SIDECAR_FORMAT, &mut source)
            .expect("reader parses JUMBF")
            .json()
    }

    /// Read an in-file embedded manifest back and return its manifest-store JSON.
    fn embedded_manifest_json(media: &[u8], format: &str) -> String {
        let context = c2pa::Context::new()
            .with_settings(offline_settings().unwrap())
            .unwrap();
        let mut source = std::io::Cursor::new(media);
        Reader::from_context(context)
            .with_stream(format, &mut source)
            .expect("reader parses embedded manifest")
            .json()
    }

    /// B-3: `ai_generated` records the IPTC trainedAlgorithmicMedia source type in
    /// the SIDECAR manifest; the default does not claim AI-generated.
    #[test]
    fn ai_generated_records_trained_algorithmic_media_sidecar() {
        let key = SigningKey::generate(&mut OsRng);
        let payload = sample_payload();

        let ai = emit_sidecar(&payload, &key, true).expect("emit ai");
        assert!(
            sidecar_manifest_json(&ai).contains(AI_GENERATED_SOURCE_TYPE),
            "ai_generated sidecar must record the trainedAlgorithmicMedia source type"
        );

        let plain = emit_sidecar(&payload, &key, false).expect("emit plain");
        assert!(
            !sidecar_manifest_json(&plain).contains(AI_GENERATED_SOURCE_TYPE),
            "default sidecar must NOT claim AI-generated"
        );
    }

    /// B-3: the same holds for the EMBEDDED (in-file) manifest — the anti-circularity
    /// exclusion of the payload-hash assertion does not apply to the AI source type,
    /// so it is present in both modes.
    #[test]
    fn ai_generated_records_trained_algorithmic_media_embedded() {
        let key = SigningKey::generate(&mut OsRng);

        let ai = embed_manifest(&tiny_png(), "png", &key, true).expect("embed ai");
        assert!(
            embedded_manifest_json(&ai, "png").contains(AI_GENERATED_SOURCE_TYPE),
            "ai_generated embedded must record the trainedAlgorithmicMedia source type"
        );

        let plain = embed_manifest(&tiny_png(), "png", &key, false).expect("embed plain");
        assert!(
            !embedded_manifest_json(&plain, "png").contains(AI_GENERATED_SOURCE_TYPE),
            "default embedded must NOT claim AI-generated"
        );
    }
}
