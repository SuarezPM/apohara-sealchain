//! HMAC-SHA256 layer.
//!
//! Algorithm identifier `HMAC-SHA256`, key id `hmac-default` in the vectors.
//! Verification is constant-time via the `hmac` crate's `verify_slice`.

use crate::error::SealError;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The algorithm string recorded in the seal block.
pub const ALG: &str = "HMAC-SHA256";

/// Compute the HMAC-SHA256 tag over `preimage` with `key`.
///
/// HMAC accepts keys of any length, so `new_from_slice` does not fail for
/// `Hmac<Sha256>`; the error is surfaced as [`SealError`] rather than panicked
/// to keep the library panic-free on untrusted input.
pub fn sign(preimage: &[u8], key: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| SealError::KeyError(format!("hmac key: {e}")))?;
    mac.update(preimage);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Constant-time check that `sig` is the valid HMAC-SHA256 tag for `preimage`.
pub fn verify(preimage: &[u8], sig: &[u8], key: &[u8]) -> bool {
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(preimage);
    mac.verify_slice(sig).is_ok()
}
