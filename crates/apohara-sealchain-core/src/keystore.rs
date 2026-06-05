//! Key material loading, generation, encryption at rest, and rotation.
//!
//! A [`Keys`] bundle is the HMAC secret plus the Ed25519 signing key (and its
//! public SPKI PEM, kept alongside for embedding in receipts). Keys are loaded
//! from a config directory or generated on first use. On unix, generated key
//! files are written with mode `0600` so a fresh install does not leak secrets
//! to other local users.
//!
//! The HMAC key is a secret: it is never serialized into a receipt. Only the
//! Ed25519 *public* key is ever embedded (see [`crate::artifact`]).
//!
//! # Storage modes
//!
//! A keystore lives in one of two on-disk shapes inside the config dir:
//!
//! * **Plaintext** (the default, backward-compatible): `ed25519.pem` (PKCS#8)
//!   plus `hmac.key` (raw 32 bytes). Loaded with no passphrase.
//! * **Encrypted at rest**: a single `keystore.enc` blob holding the private
//!   material (Ed25519 PKCS#8 PEM + HMAC key) sealed with XChaCha20-Poly1305
//!   under a scrypt-derived key, plus `ed25519.pub.pem` (the *public* SPKI PEM)
//!   in the clear. A passphrase (CLI `--passphrase` or `SEALCHAIN_PASSPHRASE`)
//!   is required to read it; a wrong passphrase yields [`SealError::Decrypt`],
//!   never a panic and never a silently-wrong key.
//!
//! The mode is detected by file presence: if `keystore.enc` exists the keystore
//! is encrypted, otherwise the plaintext pair is used.
//!
//! # Rotation
//!
//! [`rotate`] archives the active material under `archive/<ISO8601>/` (preserving
//! its mode) and generates a fresh keypair in the same mode. Receipts embed their
//! own Ed25519 public key, so receipts sealed with an archived key still verify
//! after rotation — no keyring lookup is needed.
//!
//! # KMS / HSM (future, gated — NOT implemented)
//!
//! Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) and hardware HSM/PKCS#11 backends
//! are an intentional extension point, not a stub. They require network/hardware
//! access that this offline crate deliberately avoids, so they are documented as
//! future work (see `docs/key-management.md`) rather than faked. A real KMS/HSM
//! backend would implement the same "produce/consume Ed25519 PKCS#8 + HMAC bytes"
//! contract the local file functions in this module do, behind its own feature
//! flag, keeping the seal/verify engine unchanged.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SealError;

/// Number of random bytes in a generated HMAC key.
const HMAC_KEY_LEN: usize = 32;

/// File name for the Ed25519 private key (PKCS#8 PEM) inside the config dir
/// (plaintext mode).
const ED25519_FILE: &str = "ed25519.pem";

/// File name for the raw HMAC key (32 bytes) inside the config dir (plaintext mode).
const HMAC_FILE: &str = "hmac.key";

/// File name for the encrypted private-material blob (encrypted mode).
const ENC_FILE: &str = "keystore.enc";

/// File name for the public Ed25519 SPKI PEM kept in the clear (encrypted mode).
const PUBLIC_FILE: &str = "ed25519.pub.pem";

/// Subdirectory under the config dir holding rotated (archived) key material.
const ARCHIVE_DIR: &str = "archive";

/// Magic header (4 bytes) identifying a apohara-sealchain encrypted-keystore blob v1.
const ENC_MAGIC: &[u8; 4] = b"SCK1";

/// scrypt cost parameter `log2(N)`. 15 => N = 32768 (RFC 7914 interactive tier).
const SCRYPT_LOG_N: u8 = 15;
/// scrypt block-size parameter `r`.
const SCRYPT_R: u32 = 8;
/// scrypt parallelization parameter `p`.
const SCRYPT_P: u32 = 1;
/// Salt length for the scrypt KDF, in bytes.
const SALT_LEN: usize = 16;
/// Derived-key length (XChaCha20-Poly1305 key), in bytes.
const KEY_LEN: usize = 32;

/// The key material used to seal and verify records.
pub struct Keys {
    /// Shared HMAC-SHA256 secret. Never serialized into a receipt.
    pub hmac: Vec<u8>,
    /// Ed25519 signing (private) key.
    pub ed25519: SigningKey,
    /// SPKI PEM of the Ed25519 public key, for embedding in receipts.
    pub ed25519_public_pem: String,
    /// Directory the keys were loaded from / persisted to. `None` when the
    /// bundle was built from in-memory overrides (nothing was written).
    config_dir: Option<PathBuf>,
}

impl Keys {
    /// Build a [`Keys`] from an in-memory signing key and HMAC secret,
    /// deriving the public PEM from the signing key. `config_dir` is the
    /// directory the material lives in, or `None` for in-memory overrides.
    fn from_parts(
        hmac: Vec<u8>,
        ed25519: SigningKey,
        config_dir: Option<PathBuf>,
    ) -> Result<Self, SealError> {
        let ed25519_public_pem = ed25519
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| SealError::KeyError(format!("encode public pem: {e}")))?;
        Ok(Self {
            hmac,
            ed25519,
            ed25519_public_pem,
            config_dir,
        })
    }

    /// The resolved directory the keys were loaded from / persisted to, if any.
    /// `None` for bundles built from in-memory overrides.
    pub fn config_dir(&self) -> Option<&Path> {
        self.config_dir.as_deref()
    }

    /// SHA-256 fingerprint of the Ed25519 public SPKI DER, lowercase hex.
    ///
    /// Stable identifier for the active public key, printed by `key show` /
    /// `key list` so an operator can tell which key sealed a given receipt.
    pub fn fingerprint(&self) -> Result<String, SealError> {
        fingerprint_from_signing(&self.ed25519)
    }
}

/// SHA-256 fingerprint (lowercase hex) of a signing key's public SPKI DER.
fn fingerprint_from_signing(signing: &SigningKey) -> Result<String, SealError> {
    let der = signing
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| SealError::KeyError(format!("encode public der: {e}")))?;
    Ok(fingerprint_from_spki_der(der.as_bytes()))
}

/// SHA-256 fingerprint (lowercase hex) of public SPKI DER bytes.
fn fingerprint_from_spki_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

/// SHA-256 fingerprint (lowercase hex) computed from a public SPKI PEM string.
fn fingerprint_from_public_pem(pem: &str) -> Result<String, SealError> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    let vk = ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
        .map_err(|e| SealError::KeyError(format!("parse public pem: {e}")))?;
    let der = vk
        .to_public_key_der()
        .map_err(|e| SealError::KeyError(format!("encode public der: {e}")))?;
    Ok(fingerprint_from_spki_der(der.as_bytes()))
}

/// Resolve the config directory: explicit arg, else `$XDG_CONFIG_HOME/apohara-sealchain`,
/// else `$HOME/.config/apohara-sealchain`.
fn resolve_config_dir(config_dir: Option<&Path>) -> Result<PathBuf, SealError> {
    if let Some(dir) = config_dir {
        return Ok(dir.to_path_buf());
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("apohara-sealchain"));
        }
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| SealError::KeyError("cannot resolve config dir: $HOME unset".into()))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("apohara-sealchain"))
}

/// On-disk header for an encrypted keystore blob (JSON after the magic bytes).
///
/// Holds only KDF parameters, the salt, and the AEAD nonce — all public. The
/// ciphertext follows the header. None of these fields reveal the passphrase or
/// the private key material.
#[derive(Serialize, Deserialize)]
struct EncHeader {
    /// KDF identifier. Always `"scrypt"` for v1.
    kdf: String,
    /// scrypt `log2(N)` cost parameter.
    log_n: u8,
    /// scrypt block-size parameter `r`.
    r: u32,
    /// scrypt parallelization parameter `p`.
    p: u32,
    /// KDF salt, lowercase hex.
    salt: String,
    /// XChaCha20-Poly1305 nonce (24 bytes), lowercase hex.
    nonce: String,
}

/// The private material that gets encrypted (serialized to JSON before sealing).
#[derive(Serialize, Deserialize)]
struct Secret {
    /// Ed25519 private key as a PKCS#8 PEM string.
    ed25519_pkcs8_pem: String,
    /// HMAC secret, lowercase hex.
    hmac_hex: String,
}

/// Whether an encrypted keystore is present in `dir`.
fn is_encrypted(dir: &Path) -> bool {
    dir.join(ENC_FILE).is_file()
}

/// Derive the AEAD key from a passphrase + salt via scrypt.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], SealError> {
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, KEY_LEN)
        .map_err(|e| SealError::Decrypt(format!("scrypt params: {e}")))?;
    let mut key = [0u8; KEY_LEN];
    scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|e| SealError::Decrypt(format!("scrypt kdf: {e}")))?;
    Ok(key)
}

/// Encode the secret material into an encrypted blob: `MAGIC || header_len(LE u32)
/// || header_json || ciphertext`.
fn encrypt_secret(secret: &Secret, passphrase: &str) -> Result<Vec<u8>, SealError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| SealError::Decrypt(format!("aead key: {e}")))?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

    let plaintext = serde_json::to_vec(secret)
        .map_err(|e| SealError::KeyError(format!("serialize secret: {e}")))?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| SealError::Decrypt(format!("aead encrypt: {e}")))?;

    let header = EncHeader {
        kdf: "scrypt".to_string(),
        log_n: SCRYPT_LOG_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
    };
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| SealError::KeyError(format!("serialize header: {e}")))?;

    let mut out = Vec::with_capacity(4 + 4 + header_json.len() + ciphertext.len());
    out.extend_from_slice(ENC_MAGIC);
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an encrypted-keystore blob with `passphrase`. A wrong passphrase (or a
/// corrupt/truncated blob) returns [`SealError::Decrypt`], never a panic.
fn decrypt_secret(blob: &[u8], passphrase: &str) -> Result<Secret, SealError> {
    if blob.len() < 8 || &blob[..4] != ENC_MAGIC {
        return Err(SealError::Decrypt(
            "not a apohara-sealchain encrypted keystore (bad magic)".into(),
        ));
    }
    let header_len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    let header_start: usize = 8;
    let header_end = header_start
        .checked_add(header_len)
        .filter(|&end| end <= blob.len())
        .ok_or_else(|| SealError::Decrypt("truncated keystore header".into()))?;

    let header: EncHeader = serde_json::from_slice(&blob[header_start..header_end])
        .map_err(|e| SealError::Decrypt(format!("parse header: {e}")))?;
    if header.kdf != "scrypt" {
        return Err(SealError::Decrypt(format!("unknown kdf: {}", header.kdf)));
    }
    let params = ScryptParams::new(header.log_n, header.r, header.p, KEY_LEN)
        .map_err(|e| SealError::Decrypt(format!("scrypt params: {e}")))?;
    let salt =
        hex::decode(&header.salt).map_err(|e| SealError::Decrypt(format!("decode salt: {e}")))?;
    let nonce_bytes =
        hex::decode(&header.nonce).map_err(|e| SealError::Decrypt(format!("decode nonce: {e}")))?;
    if nonce_bytes.len() != 24 {
        return Err(SealError::Decrypt("bad nonce length".into()));
    }

    let mut key = [0u8; KEY_LEN];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut key)
        .map_err(|e| SealError::Decrypt(format!("scrypt kdf: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| SealError::Decrypt(format!("aead key: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = &blob[header_end..];
    // A wrong passphrase fails the Poly1305 tag check here -> Err, never a panic
    // and never a silently-wrong key.
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SealError::Decrypt("wrong passphrase or corrupted keystore".into()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| SealError::Decrypt(format!("parse decrypted secret: {e}")))
}

/// Load existing keys from `config_dir`, or generate and persist a fresh pair.
///
/// Plaintext mode (no passphrase, backward-compatible): both `ed25519.pem`
/// (PKCS#8) and `hmac.key` (raw 32 bytes) must exist to be loaded; if either is
/// missing, a new pair is generated and written (mode `0600` on unix).
///
/// This is the legacy plaintext entry point retained for existing callers. To
/// read or create an *encrypted* keystore, use [`load_or_generate_with_passphrase`].
pub fn load_or_generate(config_dir: Option<&Path>) -> Result<Keys, SealError> {
    load_or_generate_with_passphrase(config_dir, None)
}

/// Load existing keys, or generate and persist a fresh pair, honoring the
/// keystore's storage mode and an optional passphrase.
///
/// Mode resolution:
/// * If an encrypted keystore (`keystore.enc`) exists, a `passphrase` is
///   required; absent => [`SealError::KeyError`], wrong => [`SealError::Decrypt`].
/// * Else if a plaintext keystore exists, it is loaded (passphrase ignored —
///   plaintext has nothing to decrypt).
/// * Else a fresh pair is generated: encrypted when a passphrase is provided,
///   plaintext otherwise (plaintext stays the default with no passphrase).
pub fn load_or_generate_with_passphrase(
    config_dir: Option<&Path>,
    passphrase: Option<&str>,
) -> Result<Keys, SealError> {
    let dir = resolve_config_dir(config_dir)?;

    if is_encrypted(&dir) {
        return load_encrypted(&dir, passphrase);
    }

    let ed_path = dir.join(ED25519_FILE);
    let hmac_path = dir.join(HMAC_FILE);
    if ed_path.is_file() && hmac_path.is_file() {
        return load_plaintext(&dir);
    }

    // Generate fresh material in the requested mode.
    let signing = SigningKey::generate(&mut OsRng);
    let mut hmac = vec![0u8; HMAC_KEY_LEN];
    OsRng.fill_bytes(&mut hmac);
    fs::create_dir_all(&dir)
        .map_err(|e| SealError::KeyError(format!("create {}: {e}", dir.display())))?;

    match passphrase {
        Some(pass) => write_encrypted(&dir, &signing, &hmac, pass)?,
        None => write_plaintext(&dir, &signing, &hmac)?,
    }
    Keys::from_parts(hmac, signing, Some(dir))
}

/// Load a plaintext keystore (both files known to exist by the caller).
fn load_plaintext(dir: &Path) -> Result<Keys, SealError> {
    let ed_path = dir.join(ED25519_FILE);
    let hmac_path = dir.join(HMAC_FILE);
    let pem = fs::read_to_string(&ed_path)
        .map_err(|e| SealError::KeyError(format!("read {}: {e}", ed_path.display())))?;
    let signing = SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| SealError::KeyError(format!("parse ed25519 pem: {e}")))?;
    let hmac = fs::read(&hmac_path)
        .map_err(|e| SealError::KeyError(format!("read {}: {e}", hmac_path.display())))?;
    Keys::from_parts(hmac, signing, Some(dir.to_path_buf()))
}

/// Load an encrypted keystore, requiring a passphrase.
fn load_encrypted(dir: &Path, passphrase: Option<&str>) -> Result<Keys, SealError> {
    let pass = passphrase.ok_or_else(|| {
        SealError::KeyError(
            "keystore is encrypted: provide --passphrase or set SEALCHAIN_PASSPHRASE".into(),
        )
    })?;
    let enc_path = dir.join(ENC_FILE);
    let blob = fs::read(&enc_path)
        .map_err(|e| SealError::KeyError(format!("read {}: {e}", enc_path.display())))?;
    let secret = decrypt_secret(&blob, pass)?;
    let signing = SigningKey::from_pkcs8_pem(&secret.ed25519_pkcs8_pem)
        .map_err(|e| SealError::KeyError(format!("parse ed25519 pem: {e}")))?;
    let hmac = hex::decode(&secret.hmac_hex)
        .map_err(|e| SealError::KeyError(format!("decode hmac: {e}")))?;
    Keys::from_parts(hmac, signing, Some(dir.to_path_buf()))
}

/// Write a plaintext keystore (`ed25519.pem` + `hmac.key`) into `dir` (0600).
fn write_plaintext(dir: &Path, signing: &SigningKey, hmac: &[u8]) -> Result<(), SealError> {
    let pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| SealError::KeyError(format!("encode pkcs8 pem: {e}")))?;
    write_private(&dir.join(ED25519_FILE), pem.as_bytes())?;
    write_private(&dir.join(HMAC_FILE), hmac)?;
    Ok(())
}

/// Write an encrypted keystore (`keystore.enc` 0600 + `ed25519.pub.pem` clear).
fn write_encrypted(
    dir: &Path,
    signing: &SigningKey,
    hmac: &[u8],
    passphrase: &str,
) -> Result<(), SealError> {
    let pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| SealError::KeyError(format!("encode pkcs8 pem: {e}")))?;
    let secret = Secret {
        ed25519_pkcs8_pem: pem.to_string(),
        hmac_hex: hex::encode(hmac),
    };
    let blob = encrypt_secret(&secret, passphrase)?;
    write_private(&dir.join(ENC_FILE), &blob)?;

    // The public key is public: store it in the clear so `key list/show` and any
    // tooling can read the active fingerprint without the passphrase.
    let public_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| SealError::KeyError(format!("encode public pem: {e}")))?;
    fs::write(dir.join(PUBLIC_FILE), public_pem.as_bytes()).map_err(|e| {
        SealError::KeyError(format!("write {}: {e}", dir.join(PUBLIC_FILE).display()))
    })?;
    Ok(())
}

/// Build keys from explicit overrides (CLI `--hmac-key` / `--key`, env).
///
/// When an override is absent the corresponding material is generated in
/// memory (not persisted) so the caller always gets a usable bundle.
pub fn from_overrides(
    hmac_key: Option<&[u8]>,
    ed_pem_path: Option<&Path>,
) -> Result<Keys, SealError> {
    let signing = match ed_pem_path {
        Some(path) => {
            let pem = fs::read_to_string(path)
                .map_err(|e| SealError::KeyError(format!("read {}: {e}", path.display())))?;
            SigningKey::from_pkcs8_pem(&pem)
                .map_err(|e| SealError::KeyError(format!("parse ed25519 pem: {e}")))?
        }
        None => SigningKey::generate(&mut OsRng),
    };

    let hmac = match hmac_key {
        Some(bytes) => bytes.to_vec(),
        None => {
            let mut buf = vec![0u8; HMAC_KEY_LEN];
            OsRng.fill_bytes(&mut buf);
            buf
        }
    };

    Keys::from_parts(hmac, signing, None)
}

/// Convert a plaintext keystore in `config_dir` into an encrypted one.
///
/// Reads the plaintext pair, writes `keystore.enc` (+ `ed25519.pub.pem`), then
/// removes the plaintext files. Errors if the keystore is already encrypted or
/// if no plaintext keystore exists. The returned [`Keys`] is the (unchanged) key
/// material, now backed by the encrypted store.
pub fn encrypt_keystore(config_dir: Option<&Path>, passphrase: &str) -> Result<Keys, SealError> {
    let dir = resolve_config_dir(config_dir)?;
    if is_encrypted(&dir) {
        return Err(SealError::KeyError("keystore is already encrypted".into()));
    }
    let ed_path = dir.join(ED25519_FILE);
    let hmac_path = dir.join(HMAC_FILE);
    if !ed_path.is_file() || !hmac_path.is_file() {
        return Err(SealError::KeyError(format!(
            "no plaintext keystore to encrypt in {}",
            dir.display()
        )));
    }
    let keys = load_plaintext(&dir)?;
    write_encrypted(&dir, &keys.ed25519, &keys.hmac, passphrase)?;
    // Remove the now-redundant plaintext secrets.
    fs::remove_file(&ed_path)
        .map_err(|e| SealError::KeyError(format!("remove {}: {e}", ed_path.display())))?;
    fs::remove_file(&hmac_path)
        .map_err(|e| SealError::KeyError(format!("remove {}: {e}", hmac_path.display())))?;
    Ok(keys)
}

/// Convert an encrypted keystore in `config_dir` back into a plaintext one.
///
/// Decrypts with `passphrase`, writes the plaintext pair (0600), then removes
/// `keystore.enc` and `ed25519.pub.pem`. A wrong passphrase yields
/// [`SealError::Decrypt`].
pub fn decrypt_keystore(config_dir: Option<&Path>, passphrase: &str) -> Result<Keys, SealError> {
    let dir = resolve_config_dir(config_dir)?;
    if !is_encrypted(&dir) {
        return Err(SealError::KeyError(
            "keystore is not encrypted (nothing to decrypt)".into(),
        ));
    }
    let keys = load_encrypted(&dir, Some(passphrase))?;
    write_plaintext(&dir, &keys.ed25519, &keys.hmac)?;
    let enc_path = dir.join(ENC_FILE);
    fs::remove_file(&enc_path)
        .map_err(|e| SealError::KeyError(format!("remove {}: {e}", enc_path.display())))?;
    let pub_path = dir.join(PUBLIC_FILE);
    if pub_path.is_file() {
        fs::remove_file(&pub_path)
            .map_err(|e| SealError::KeyError(format!("remove {}: {e}", pub_path.display())))?;
    }
    Ok(keys)
}

/// Rotate the active keypair: archive the current material under
/// `archive/<ISO8601>/`, then generate a fresh keypair in the same storage mode.
///
/// Old receipts embed their own Ed25519 public key, so they still verify after
/// rotation — no keyring lookup is needed. Returns the new active [`Keys`].
///
/// `passphrase` is required when the keystore is (or will be) encrypted, and is
/// ignored for a plaintext keystore.
pub fn rotate(config_dir: Option<&Path>, passphrase: Option<&str>) -> Result<Keys, SealError> {
    let dir = resolve_config_dir(config_dir)?;
    let encrypted = is_encrypted(&dir);

    // The files that make up the active keystore, by mode.
    let active_files: &[&str] = if encrypted {
        &[ENC_FILE, PUBLIC_FILE]
    } else {
        &[ED25519_FILE, HMAC_FILE]
    };
    let present = active_files.iter().any(|name| dir.join(name).is_file());
    if !present {
        return Err(SealError::KeyError(format!(
            "no active keystore to rotate in {}",
            dir.display()
        )));
    }
    if encrypted && passphrase.is_none() {
        return Err(SealError::KeyError(
            "encrypted keystore: provide --passphrase to rotate".into(),
        ));
    }

    // Archive the current material into a timestamped subdir.
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let archive = dir.join(ARCHIVE_DIR).join(&stamp);
    fs::create_dir_all(&archive)
        .map_err(|e| SealError::KeyError(format!("create {}: {e}", archive.display())))?;
    for name in active_files {
        let src = dir.join(name);
        if src.is_file() {
            let dst = archive.join(name);
            fs::rename(&src, &dst).map_err(|e| {
                SealError::KeyError(format!(
                    "archive {} -> {}: {e}",
                    src.display(),
                    dst.display()
                ))
            })?;
        }
    }

    // Generate a fresh keypair in the same mode.
    let signing = SigningKey::generate(&mut OsRng);
    let mut hmac = vec![0u8; HMAC_KEY_LEN];
    OsRng.fill_bytes(&mut hmac);
    match (encrypted, passphrase) {
        (true, Some(pass)) => write_encrypted(&dir, &signing, &hmac, pass)?,
        _ => write_plaintext(&dir, &signing, &hmac)?,
    }
    Keys::from_parts(hmac, signing, Some(dir))
}

/// A summary of one archived (rotated-out) keypair.
#[derive(Debug, Clone, Serialize)]
pub struct ArchivedKey {
    /// Archive timestamp (the `archive/<ISO8601>` subdir name).
    pub archived_at: String,
    /// SHA-256 fingerprint (lowercase hex) of the archived public key, if its
    /// public material could be recovered without a passphrase.
    pub fingerprint: Option<String>,
}

/// Summary of the active keystore plus its archived keys, for `key list`/`show`.
#[derive(Debug, Clone, Serialize)]
pub struct KeystoreInfo {
    /// Resolved config directory.
    pub config_dir: String,
    /// Whether the active keystore is encrypted at rest.
    pub encrypted: bool,
    /// SHA-256 fingerprint (lowercase hex) of the active public key, if readable
    /// without a passphrase (always readable: the public PEM is in the clear).
    pub active_fingerprint: Option<String>,
    /// Archived keys, newest-timestamp first.
    pub archived: Vec<ArchivedKey>,
}

/// Gather a [`KeystoreInfo`] for the keystore in `config_dir` without needing a
/// passphrase: the active and archived public fingerprints are read from the
/// clear public PEM (encrypted mode) or derived from the plaintext key.
pub fn info(config_dir: Option<&Path>) -> Result<KeystoreInfo, SealError> {
    let dir = resolve_config_dir(config_dir)?;
    let encrypted = is_encrypted(&dir);

    let active_fingerprint = active_fingerprint(&dir, encrypted)?;
    let archived = list_archived(&dir)?;

    Ok(KeystoreInfo {
        config_dir: dir.to_string_lossy().into_owned(),
        encrypted,
        active_fingerprint,
        archived,
    })
}

/// Fingerprint of the active public key, read without a passphrase.
fn active_fingerprint(dir: &Path, encrypted: bool) -> Result<Option<String>, SealError> {
    if encrypted {
        let pub_path = dir.join(PUBLIC_FILE);
        if pub_path.is_file() {
            let pem = fs::read_to_string(&pub_path)
                .map_err(|e| SealError::KeyError(format!("read {}: {e}", pub_path.display())))?;
            return Ok(Some(fingerprint_from_public_pem(&pem)?));
        }
        return Ok(None);
    }
    let ed_path = dir.join(ED25519_FILE);
    if ed_path.is_file() {
        let pem = fs::read_to_string(&ed_path)
            .map_err(|e| SealError::KeyError(format!("read {}: {e}", ed_path.display())))?;
        let signing = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| SealError::KeyError(format!("parse ed25519 pem: {e}")))?;
        return Ok(Some(fingerprint_from_signing(&signing)?));
    }
    Ok(None)
}

/// List archived keypairs under `archive/`, newest first. The fingerprint is read
/// from a clear public PEM when present, derived from a plaintext key otherwise,
/// or left `None` for an encrypted archive (its public key needs no passphrase
/// only when `ed25519.pub.pem` was archived alongside it — which it is).
fn list_archived(dir: &Path) -> Result<Vec<ArchivedKey>, SealError> {
    let archive_root = dir.join(ARCHIVE_DIR);
    if !archive_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries = fs::read_dir(&archive_root)
        .map_err(|e| SealError::KeyError(format!("read {}: {e}", archive_root.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| SealError::KeyError(format!("read archive entry: {e}")))?;
        if !entry.path().is_dir() {
            continue;
        }
        let archived_at = entry.file_name().to_string_lossy().into_owned();
        let fingerprint = archived_fingerprint(&entry.path())?;
        out.push(ArchivedKey {
            archived_at,
            fingerprint,
        });
    }
    // Newest first (timestamp names sort lexicographically == chronologically).
    out.sort_by(|a, b| b.archived_at.cmp(&a.archived_at));
    Ok(out)
}

/// Recover an archived key's public fingerprint without a passphrase: from the
/// clear public PEM (encrypted archive) or the plaintext PEM (plaintext archive).
fn archived_fingerprint(archive_dir: &Path) -> Result<Option<String>, SealError> {
    let pub_path = archive_dir.join(PUBLIC_FILE);
    if pub_path.is_file() {
        let pem = fs::read_to_string(&pub_path)
            .map_err(|e| SealError::KeyError(format!("read {}: {e}", pub_path.display())))?;
        return Ok(Some(fingerprint_from_public_pem(&pem)?));
    }
    let ed_path = archive_dir.join(ED25519_FILE);
    if ed_path.is_file() {
        let pem = fs::read_to_string(&ed_path)
            .map_err(|e| SealError::KeyError(format!("read {}: {e}", ed_path.display())))?;
        let signing = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| SealError::KeyError(format!("parse ed25519 pem: {e}")))?;
        return Ok(Some(fingerprint_from_signing(&signing)?));
    }
    Ok(None)
}

/// Write `bytes` to `path`, restricting the file to owner read/write on unix.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SealError> {
    fs::write(path, bytes)
        .map_err(|e| SealError::KeyError(format!("write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| SealError::KeyError(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::seal_artifact;

    #[test]
    fn generates_into_tempdir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("generate");
        assert_eq!(keys.hmac.len(), HMAC_KEY_LEN);
        assert!(dir.path().join(ED25519_FILE).is_file());
        assert!(dir.path().join(HMAC_FILE).is_file());
        assert!(keys.ed25519_public_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn reloads_same_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = load_or_generate(Some(dir.path())).expect("generate");
        let second = load_or_generate(Some(dir.path())).expect("reload");
        assert_eq!(first.hmac, second.hmac);
        assert_eq!(
            first.ed25519.to_bytes(),
            second.ed25519.to_bytes(),
            "reloaded signing key must match"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        load_or_generate(Some(dir.path())).expect("generate");
        for name in [ED25519_FILE, HMAC_FILE] {
            let meta = fs::metadata(dir.path().join(name)).expect("metadata");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} must be mode 0600, got {mode:o}");
        }
    }

    #[test]
    fn override_pem_path_is_honored() {
        // Generate a pair, then point from_overrides at the written PEM.
        let dir = tempfile::tempdir().expect("tempdir");
        let generated = load_or_generate(Some(dir.path())).expect("generate");
        let ed_path = dir.path().join(ED25519_FILE);

        let custom_hmac = b"override-hmac-key";
        let keys = from_overrides(Some(custom_hmac), Some(&ed_path)).expect("overrides");
        assert_eq!(keys.hmac, custom_hmac);
        assert_eq!(
            keys.ed25519.to_bytes(),
            generated.ed25519.to_bytes(),
            "override must load the PEM at the given path"
        );
    }

    #[test]
    fn hmac_key_never_appears_in_receipt() {
        // Seal a real artifact and assert the HMAC key hex is absent from the
        // serialized receipt.
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("generate");

        let artifact = dir.path().join("artifact.txt");
        fs::write(&artifact, b"hello apohara-sealchain").expect("write artifact");

        let record = seal_artifact(
            &artifact,
            &keys,
            Some("2026-01-01T00:00:00+00:00"),
            false,
            false,
            None,
            None,
        )
        .expect("seal artifact");
        let serialized = serde_json::to_string(&record).expect("serialize receipt");

        let hmac_hex = hex::encode(&keys.hmac);
        assert!(
            !serialized.contains(&hmac_hex),
            "HMAC key hex must NOT appear in the receipt"
        );
    }

    #[test]
    fn encrypted_roundtrip_right_passphrase() {
        // Generate an encrypted keystore, reload it with the right passphrase;
        // the keys must match bit-for-bit.
        let dir = tempfile::tempdir().expect("tempdir");
        let first = load_or_generate_with_passphrase(Some(dir.path()), Some("correct horse"))
            .expect("generate encrypted");
        assert!(
            dir.path().join(ENC_FILE).is_file(),
            "encrypted blob present"
        );
        assert!(
            dir.path().join(PUBLIC_FILE).is_file(),
            "public pem in the clear"
        );
        assert!(
            !dir.path().join(ED25519_FILE).is_file(),
            "no plaintext private pem"
        );
        assert!(!dir.path().join(HMAC_FILE).is_file(), "no plaintext hmac");

        let second = load_or_generate_with_passphrase(Some(dir.path()), Some("correct horse"))
            .expect("reload encrypted");
        assert_eq!(first.hmac, second.hmac);
        assert_eq!(first.ed25519.to_bytes(), second.ed25519.to_bytes());
    }

    #[test]
    fn wrong_passphrase_is_clear_error_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        load_or_generate_with_passphrase(Some(dir.path()), Some("right"))
            .expect("generate encrypted");
        // `Keys` deliberately does not implement Debug (it holds secret
        // material), so we match on the Result instead of using expect_err.
        let err = match load_or_generate_with_passphrase(Some(dir.path()), Some("WRONG")) {
            Err(e) => e,
            Ok(_) => panic!("wrong passphrase must error"),
        };
        assert!(matches!(err, SealError::Decrypt(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("wrong passphrase"), "clear message: {msg}");
    }

    #[test]
    fn encrypted_missing_passphrase_is_clear_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        load_or_generate_with_passphrase(Some(dir.path()), Some("pass")).expect("generate");
        let err = match load_or_generate_with_passphrase(Some(dir.path()), None) {
            Err(e) => e,
            Ok(_) => panic!("must require passphrase"),
        };
        assert!(matches!(err, SealError::KeyError(_)), "got {err:?}");
        assert!(err.to_string().contains("encrypted"));
    }

    #[test]
    fn encrypted_file_has_no_raw_private_bytes() {
        // The encrypted blob must NOT contain the raw Ed25519 private key bytes
        // nor the raw HMAC key bytes.
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate_with_passphrase(Some(dir.path()), Some("scan-pass"))
            .expect("generate encrypted");
        let blob = fs::read(dir.path().join(ENC_FILE)).expect("read blob");

        let priv_bytes = keys.ed25519.to_bytes();
        assert!(
            !contains_subslice(&blob, &priv_bytes),
            "raw Ed25519 private key bytes must NOT be in the encrypted file"
        );
        assert!(
            !contains_subslice(&blob, &keys.hmac),
            "raw HMAC key bytes must NOT be in the encrypted file"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn encrypt_then_decrypt_keystore_preserves_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = load_or_generate(Some(dir.path())).expect("generate plaintext");

        let encrypted = encrypt_keystore(Some(dir.path()), "convert-pass").expect("encrypt");
        assert_eq!(original.ed25519.to_bytes(), encrypted.ed25519.to_bytes());
        assert!(dir.path().join(ENC_FILE).is_file());
        assert!(!dir.path().join(ED25519_FILE).is_file());

        let decrypted = decrypt_keystore(Some(dir.path()), "convert-pass").expect("decrypt");
        assert_eq!(original.ed25519.to_bytes(), decrypted.ed25519.to_bytes());
        assert_eq!(original.hmac, decrypted.hmac);
        assert!(dir.path().join(ED25519_FILE).is_file());
        assert!(!dir.path().join(ENC_FILE).is_file());
    }

    #[test]
    fn rotate_plaintext_archives_and_generates_new_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = load_or_generate(Some(dir.path())).expect("generate");
        let original_fp = original.fingerprint().expect("fp");

        let rotated = rotate(Some(dir.path()), None).expect("rotate");
        let rotated_fp = rotated.fingerprint().expect("fp");
        assert_ne!(original_fp, rotated_fp, "rotation yields a new key");

        // The archive holds exactly one entry whose fingerprint == the old key.
        let info = info(Some(dir.path())).expect("info");
        assert_eq!(info.archived.len(), 1);
        assert_eq!(
            info.archived[0].fingerprint.as_deref(),
            Some(original_fp.as_str())
        );
        assert_eq!(
            info.active_fingerprint.as_deref(),
            Some(rotated_fp.as_str())
        );
    }

    #[test]
    fn rotate_encrypted_requires_passphrase_and_keeps_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        load_or_generate_with_passphrase(Some(dir.path()), Some("rot-pass")).expect("generate");

        // Missing passphrase => clear KeyError, not a panic.
        let err = match rotate(Some(dir.path()), None) {
            Err(e) => e,
            Ok(_) => panic!("must require passphrase"),
        };
        assert!(matches!(err, SealError::KeyError(_)));

        let rotated = rotate(Some(dir.path()), Some("rot-pass")).expect("rotate encrypted");
        assert!(dir.path().join(ENC_FILE).is_file(), "stays encrypted");
        // The new key loads with the same passphrase.
        let reloaded =
            load_or_generate_with_passphrase(Some(dir.path()), Some("rot-pass")).expect("reload");
        assert_eq!(rotated.ed25519.to_bytes(), reloaded.ed25519.to_bytes());
    }

    #[test]
    fn info_reports_active_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("generate");
        let info = info(Some(dir.path())).expect("info");
        assert!(!info.encrypted);
        assert_eq!(
            info.active_fingerprint.as_deref(),
            Some(keys.fingerprint().expect("fp").as_str())
        );
        assert!(info.archived.is_empty());
    }
}
