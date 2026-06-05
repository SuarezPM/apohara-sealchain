//! Ed25519 layer.
//!
//! Ed25519 (RFC 8032) is deterministic: signing the same preimage with the
//! same key always yields the same 64-byte signature, so a re-sign reproduces
//! the stored vector signatures exactly. Keys are parsed from PKCS#8 (private)
//! and SPKI (public) PEM via `ed25519-dalek`'s pkcs8/pem features.

use crate::error::SealError;
use ed25519_dalek::pkcs8::spki::DecodePublicKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Parse an Ed25519 signing key from a PKCS#8 PEM document.
pub fn signing_key_from_pem(pem: &str) -> Result<SigningKey, SealError> {
    SigningKey::from_pkcs8_pem(pem).map_err(|e| SealError::KeyError(e.to_string()))
}

/// Parse an Ed25519 verifying key from an SPKI PEM document.
pub fn verifying_key_from_pem(pem: &str) -> Result<VerifyingKey, SealError> {
    VerifyingKey::from_public_key_pem(pem).map_err(|e| SealError::KeyError(e.to_string()))
}

/// Sign `preimage` with `key`, returning the raw 64-byte signature.
pub fn sign(preimage: &[u8], key: &SigningKey) -> Vec<u8> {
    key.sign(preimage).to_bytes().to_vec()
}

/// Verify that `sig` is a valid Ed25519 signature over `preimage` for `key`.
///
/// Returns `false` for both wrong-length signatures and genuine mismatches;
/// callers treat either as tamper, never as a structural error.
pub fn verify(preimage: &[u8], sig: &[u8], key: &VerifyingKey) -> bool {
    let bytes: [u8; 64] = match sig.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&bytes);
    key.verify(preimage, &signature).is_ok()
}
