//! RFC 3161 Time-Stamp Authority (TSA) layer — real timestamp tokens.
//!
//! This layer requests a genuine RFC 3161 timestamp token from a public TSA and
//! verifies it offline. The TSA timestamps the **canonical binding**
//! `hmac.sig || ed25519.sig` (raw bytes, that exact order): the message imprint
//! inside the token is `sha256(hmac.sig || ed25519.sig)`. We store the result as
//!
//! ```json
//! { "authority": <label>, "issuedAt": <ISO8601>, "der": "0x" + hex(token) }
//! ```
//!
//! where `der` is the full DER-encoded `TimeStampResp` returned by the TSA.
//!
//! ## Canonical pass bar vs. best-effort chain
//!
//! The **pass bar** is the message imprint: the token's
//! `TstInfo.messageImprint.hashedMessage` must equal `sha256(to_stamp)`. A
//! mismatch is the only thing that makes [`verify_token`] report `ok: false`.
//! The `sigstore-tsa` verifier checks the imprint *before* any CMS-signature or
//! certificate work and surfaces a distinct `HashMismatch` error, so the imprint
//! failure is cleanly isolated.
//!
//! Certificate-chain validation is **best-effort**: only when a trust root is
//! supplied (`root_pem`) is the chain validated, and an unverifiable chain is
//! reported in `reason` — it never flips an imprint-valid token to `ok: false`.
//! With no root (the default) the chain is reported unverified and the imprint
//! remains the pass bar. This is the documented v0.1 posture, mirroring the
//! C2PA layer's "Valid, not Trusted" stance.
//!
//! ## No async leak
//!
//! The `sigstore-tsa` client is async (reqwest). The core engine is sync, so the
//! single network call runs on a private current-thread tokio runtime built
//! inside [`request_token`]. No async/tokio types appear in this module's public
//! API.

use sigstore_tsa::{verify_timestamp_response, Error as TsaError, TimestampClient, VerifyOpts};
use sigstore_types::SignatureBytes;

use crate::artifact::LayerResult;
use crate::error::SealError;

/// Default TSA endpoint. Sigstore's public TSA is reachable and embeds its
/// signing chain in the token (`cert_req = true` by default), so a freshly
/// requested token verifies its imprint offline without out-of-band certs.
pub const DEFAULT_TSA_URL: &str = "https://timestamp.sigstore.dev/api/v1/timestamp";

/// A stored RFC 3161 timestamp token: the authority label, the issuance time
/// (ISO 8601 / RFC 3339, seconds precision, `Z`), and the raw DER token.
#[derive(Debug, Clone)]
pub struct TsaToken {
    /// Human-readable label for the TSA the token came from.
    pub authority: String,
    /// Token issuance time from `TstInfo.genTime`, as RFC 3339.
    pub issued_at: String,
    /// Raw DER bytes of the `TimeStampResp` (stored as `0x`+hex in the seal).
    pub der: Vec<u8>,
}

/// Map a TSA URL to a short, stable authority label. Known public TSAs get a
/// friendly name; anything else falls back to the URL's host (or the full URL).
fn authority_label(url: &str) -> String {
    match url {
        "https://timestamp.sigstore.dev/api/v1/timestamp" => "sigstore".to_string(),
        "https://freetsa.org/tsr" => "freetsa".to_string(),
        other => host_of(other).unwrap_or_else(|| other.to_string()),
    }
}

/// Extract the host portion of an `http(s)://host[/...]` URL without pulling in
/// a URL-parsing dependency.
fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', ':']).next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Request a real RFC 3161 timestamp token over `to_stamp` from `tsa_url`.
///
/// `to_stamp` is the canonical binding `hmac.sig || ed25519.sig`. The TSA client
/// hashes it with SHA-256 and timestamps that digest, so the token's message
/// imprint is exactly `sha256(to_stamp)`. The returned [`TsaToken`] carries the
/// authority label, the token's `genTime` as `issued_at`, and the full DER.
///
/// The network call runs on a private current-thread tokio runtime; no async
/// types leak out. A network/protocol failure is a [`SealError::Tsa`].
pub fn request_token(to_stamp: &[u8], tsa_url: &str) -> Result<TsaToken, SealError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SealError::Tsa(format!("build runtime: {e}")))?;

    let signature = SignatureBytes::from_bytes(to_stamp);
    let client = TimestampClient::new(tsa_url);

    let token = runtime
        .block_on(client.timestamp_signature(&signature))
        .map_err(|e| SealError::Tsa(format!("request timestamp from {tsa_url}: {e}")))?;
    let der = token.into_bytes();

    // Extract genTime by verifying the imprint (no roots → no chain check). This
    // both confirms the freshly issued token binds our `to_stamp` and yields the
    // issuance time from `TstInfo.genTime`.
    let result = verify_timestamp_response(&der, to_stamp, VerifyOpts::new())
        .map_err(|e| SealError::Tsa(format!("parse issued token: {e}")))?;
    // sigstore-tsa 0.8 returns `result.time` as a `jiff::Timestamp` (was chrono).
    // Format it as second-precision RFC 3339 in UTC to match the prior output.
    let issued_at = result.time.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();

    Ok(TsaToken {
        authority: authority_label(tsa_url),
        issued_at,
        der,
    })
}

/// Verify a stored RFC 3161 token against `to_stamp`.
///
/// **Pass bar (imprint):** the token's message imprint must equal
/// `sha256(to_stamp)`. A mismatch is the only `ok: false` outcome. Structural
/// garbage (unparseable DER) is also `ok: false` — never a panic.
///
/// **Best-effort (chain):** when `root_pem` is supplied, the TSA certificate
/// chain is validated to that root and the outcome is noted in `reason`; an
/// unverifiable chain does NOT flip an imprint-valid token to `ok: false`. With
/// `root_pem = None` (the default) the chain is reported unverified.
pub fn verify_token(der: &[u8], to_stamp: &[u8], root_pem: Option<&[u8]>) -> LayerResult {
    // Pass bar: imprint check with no roots (chain validation is skipped when
    // `roots` is empty). The imprint is checked before any signature/cert work,
    // so a `HashMismatch` cleanly isolates an imprint failure.
    match verify_timestamp_response(der, to_stamp, VerifyOpts::new()) {
        Ok(_) => {}
        Err(TsaError::HashMismatch { .. }) => {
            return tsa_result(false, "tsa imprint mismatch");
        }
        Err(e) => {
            // Unparseable/garbage token or a CMS-signature problem: we could not
            // confirm the imprint, so this is not a pass.
            return tsa_result(false, &format!("tsa token unverifiable: {e}"));
        }
    }

    // Imprint verified. Best-effort chain validation when a root is configured.
    let Some(root_pem) = root_pem else {
        return tsa_result(true, "imprint ok; chain unverified (no root)");
    };

    match decode_roots(root_pem) {
        Ok(opts) => match verify_timestamp_response(der, to_stamp, opts) {
            Ok(_) => tsa_result(true, "imprint ok; chain verified"),
            // Chain failure must NOT flip an imprint-valid token to ok:false.
            Err(e) => tsa_result(true, &format!("imprint ok; chain unverified ({e})")),
        },
        Err(reason) => tsa_result(true, &format!("imprint ok; chain unverified ({reason})")),
    }
}

/// Build [`VerifyOpts`] with the PEM-encoded root certificate(s) in `root_pem`
/// as trust roots, so [`verify_timestamp_response`] validates the chain.
fn decode_roots(root_pem: &[u8]) -> Result<VerifyOpts<'static>, String> {
    use rustls_pki_types::CertificateDer;

    let text = std::str::from_utf8(root_pem).map_err(|e| format!("root pem not utf-8: {e}"))?;
    let mut roots: Vec<CertificateDer<'static>> = Vec::new();
    for block in pem::parse_many(text).map_err(|e| format!("parse root pem: {e}"))? {
        if block.tag() == "CERTIFICATE" {
            roots.push(CertificateDer::from(block.into_contents()));
        }
    }
    if roots.is_empty() {
        return Err("no CERTIFICATE block in root pem".to_string());
    }
    Ok(VerifyOpts::new().with_roots(roots))
}

/// Build a `tsa` [`LayerResult`] with the given outcome and reason.
fn tsa_result(ok: bool, reason: &str) -> LayerResult {
    LayerResult {
        name: "tsa".to_string(),
        ok,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Garbage DER must be handled structurally (ok:false, no panic).
    #[test]
    fn garbage_der_is_ok_false_not_panic() {
        let result = verify_token(b"not a real timestamp token", b"to-stamp", None);
        assert_eq!(result.name, "tsa");
        assert!(!result.ok, "garbage DER must not verify");
    }

    #[test]
    fn authority_label_known_and_fallback() {
        assert_eq!(authority_label(DEFAULT_TSA_URL), "sigstore");
        assert_eq!(authority_label("https://freetsa.org/tsr"), "freetsa");
        assert_eq!(
            authority_label("https://tsa.example.com:8443/ts"),
            "tsa.example.com"
        );
    }

    /// The imprint a token must bind is `sha256(to_stamp)`; this documents the
    /// canonical binding used by the offline vector test.
    #[test]
    fn imprint_is_sha256_of_to_stamp() {
        let to_stamp = b"hmac-sig-bytes||ed25519-sig-bytes";
        let imprint = Sha256::digest(to_stamp);
        assert_eq!(imprint.len(), 32);
    }
}
