//! Error taxonomy for the seal engine.
//!
//! The crate draws a hard line between *structural* failures and *content
//! mismatches*. Structural failures (malformed records, unsupported schemas,
//! key parsing errors) surface as [`SealError`]. A tamper / signature mismatch
//! is **not** an error: it is a successful verification that returns
//! `Ok(false)`. See [`crate::verify::verify`] for the full contract.

use thiserror::Error;

/// Errors raised while building or verifying a seal.
///
/// These represent conditions where verification *could not be performed*, as
/// opposed to a verification that completed and found the record invalid.
#[derive(Debug, Error)]
pub enum SealError {
    /// A required field was missing or had the wrong JSON type.
    #[error("malformed record: {0}")]
    Malformed(String),

    /// The record uses the legacy v3 schema (top-level `sealedAt`, no
    /// `seal.sealedAt`), which this engine does not support.
    #[error("unsupported legacy v3 schema")]
    UnsupportedSchemaV3,

    /// The `seal.preimage` field was present but not valid `0x`-prefixed hex.
    #[error("invalid preimage encoding: {0}")]
    InvalidPreimage(String),

    /// An Ed25519 layer is present but no public key was supplied to verify it.
    #[error("ed25519 layer present but no public key provided")]
    MissingPublicKey,

    /// An Ed25519 key (PEM/DER) could not be parsed.
    #[error("ed25519 key error: {0}")]
    KeyError(String),

    /// The encrypted keystore could not be decrypted. The common cause is a
    /// wrong passphrase (the AEAD authentication tag did not match); it may also
    /// be a corrupted or truncated blob. This is **never** a panic and never a
    /// silent fallback to a different key — decryption either authenticates or
    /// returns this error.
    #[error("decrypt keystore: {0}")]
    Decrypt(String),

    /// JSON canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),

    /// A C2PA sidecar operation (build, sign, or read) failed structurally. A
    /// *mismatched* manifest is not this error — that is `Ok(false)` from
    /// [`crate::layers::c2pa::verify_sidecar`].
    #[error("c2pa error: {0}")]
    C2pa(String),

    /// A TSA operation (network request, runtime, or token parse) failed
    /// structurally. A *mismatched* imprint is not this error — that is
    /// `ok: false` from [`crate::layers::tsa::verify_token`].
    #[error("tsa error: {0}")]
    Tsa(String),

    /// A Rekor operation (network submit, runtime, or response mapping) failed
    /// structurally. A *failed* inclusion or checkpoint verification is not this
    /// error — that is `ok: false` from [`crate::layers::rekor::verify_anchor`],
    /// including the measured `ok: false` for an unknown shard log key.
    #[error("rekor error: {0}")]
    Rekor(String),

    /// The local receipt index (sqlite) could not be opened, migrated, or
    /// queried. The index is a convenience/discovery layer, never a source of
    /// truth (it is rebuildable from the receipts on disk), so an index failure
    /// does not invalidate a receipt.
    #[error("index error: {0}")]
    Index(String),
}
