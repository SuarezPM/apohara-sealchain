//! Cryptographic layers stacked on the shared preimage.
//!
//! Each layer signs the *same* canonical preimage independently. The v1 wire
//! format mandates HMAC; Ed25519 is optional. The C2PA layer is an opt-in
//! sidecar (real, offline-verifiable JUMBF); the TSA layer is an opt-in RFC 3161
//! timestamp over `hmac.sig || ed25519.sig`; the Rekor layer is an opt-in
//! Sigstore Rekor v2 DSSE transparency anchor over the canonical preimage.

pub mod c2pa;
pub mod ed25519;
pub mod hmac;
// The transparency layers are network clients (sigstore + reqwest + tokio) and
// are native-only; the wasm verify-only build excludes them.
#[cfg(feature = "native")]
pub mod rekor;
#[cfg(feature = "native")]
pub mod tsa;
