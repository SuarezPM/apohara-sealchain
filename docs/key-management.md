# Key management

apohara-sealchain's signing/HMAC material lives in a config-dir keystore. This document
covers the on-disk formats, the passphrase-encrypted-at-rest mode, key rotation,
and the (deliberately unimplemented) KMS/HSM extension point.

All key-management code is **native-only** (gated behind the `native` feature).
The wasm verify-only build never compiles it: verification is self-contained
because every receipt embeds its own Ed25519 public key.

## Config directory

Resolution order (`crates/apohara-sealchain-core/src/keystore.rs::resolve_config_dir`):

1. an explicit `--config-dir`,
2. `$XDG_CONFIG_HOME/apohara-sealchain`,
3. `$HOME/.config/apohara-sealchain`.

## Storage modes

A keystore is in exactly one of two on-disk shapes, auto-detected by file
presence (`keystore.enc` present ⇒ encrypted, else plaintext):

### Plaintext (default, backward-compatible)

| File          | Contents                              | Mode |
|---------------|---------------------------------------|------|
| `ed25519.pem` | Ed25519 private key, PKCS#8 PEM        | 0600 |
| `hmac.key`    | raw 32-byte HMAC secret               | 0600 |

This is the original format; existing keystores keep loading with no passphrase.

### Encrypted at rest

| File             | Contents                                       | Mode |
|------------------|------------------------------------------------|------|
| `keystore.enc`   | encrypted private material (see format below)  | 0600 |
| `ed25519.pub.pem`| Ed25519 **public** SPKI PEM, in the clear      | 0644 |

The public key is public, so it is stored unencrypted: `key list` / `key show`
read the active fingerprint without a passphrase. Only the *private* material
(Ed25519 PKCS#8 + HMAC key) is sealed.

## Encrypted-file format (`keystore.enc`, v1)

```
"SCK1"                       4-byte magic
header_len                   u32, little-endian
header_json                  header_len bytes (JSON, see below)
ciphertext                   XChaCha20-Poly1305 output (incl. 16-byte auth tag)
```

`header_json` (all values public — they reveal neither passphrase nor key):

```json
{ "kdf": "scrypt", "log_n": 15, "r": 8, "p": 1,
  "salt": "<16-byte hex>", "nonce": "<24-byte hex>" }
```

- **KDF**: scrypt (RFC 7914), `N = 2^15 = 32768`, `r = 8`, `p = 1`, 32-byte output.
  Salt is 16 random bytes per write.
- **AEAD**: XChaCha20-Poly1305 with a 24-byte random nonce. The plaintext is a
  JSON object `{ "ed25519_pkcs8_pem": "...", "hmac_hex": "..." }`.

A **wrong passphrase** fails the Poly1305 authentication tag and returns
`SealError::Decrypt("wrong passphrase or corrupted keystore")` — never a panic,
and never a silently-wrong key. The CLI maps this to exit code `4`.

## CLI

```sh
# Create a keystore (plaintext by default; encrypted if a passphrase is set)
apohara-sealchain keygen [--config-dir DIR] [--passphrase PASS]

# Convert between modes
apohara-sealchain key encrypt [--config-dir DIR] --passphrase PASS   # plaintext -> encrypted
apohara-sealchain key decrypt [--config-dir DIR] --passphrase PASS   # encrypted -> plaintext

# Rotate the active key (mode-preserving)
apohara-sealchain key rotate  [--config-dir DIR] [--passphrase PASS] [--json]

# Inspect fingerprints
apohara-sealchain key list    [--config-dir DIR] [--json]
apohara-sealchain key show    [--config-dir DIR] [--json]            # alias of list

# Seal with the default keystore (passphrase required if it is encrypted)
apohara-sealchain seal FILE [--passphrase PASS]
```

The passphrase is read from `--passphrase` or, when absent, the
`SEALCHAIN_PASSPHRASE` environment variable. With no passphrase the keystore
stays plaintext (the documented default). Sealing against an encrypted keystore
with no/ wrong passphrase fails cleanly with exit `4`.

`verify` never needs the keystore passphrase: receipts embed their Ed25519
public key, and the HMAC layer (if checked) takes its key from `--hmac-key`.

## Rotation and archive layout

`key rotate` archives the current active material under a timestamped subdir and
generates a fresh keypair in the **same** storage mode:

```
<config-dir>/
  ed25519.pem | keystore.enc        # the NEW active key
  ed25519.pub.pem                   # (encrypted mode) NEW public key
  archive/
    20260605T142530Z/               # ISO-8601 UTC timestamp
      ed25519.pem | keystore.enc    # the rotated-out key (mode preserved)
      ed25519.pub.pem               # (encrypted mode) old public key, in clear
```

Rotation does **not** break old receipts: each receipt embeds the Ed25519 public
key it was sealed with (`seal.ed25519PublicKey`), so verification is fully
self-contained and needs no keyring lookup. `key list` reports each archived
key's fingerprint (read from the clear public PEM, so no passphrase is needed).

## Fingerprints

A key's fingerprint is the lowercase-hex SHA-256 of its Ed25519 public SPKI DER.
It is stable across plaintext/encrypted conversions and lets an operator match a
receipt's embedded public key to an active or archived key.

## KMS / HSM backends — future, gated, NOT faked

Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) and hardware HSM/PKCS#11 backends
are an intentional **extension point**, not a working feature and not a stub.
They require network and/or hardware access that this offline-first crate
deliberately avoids, so they are documented here rather than implemented behind a
flag that would pretend to work.

The seam is the local-file keystore functions in `keystore.rs`
(`load_or_generate_with_passphrase`, `rotate`, `encrypt_keystore`,
`decrypt_keystore`). A real KMS/HSM backend would implement the same contract
they do — "produce/consume Ed25519 PKCS#8 + HMAC bytes" — keeping the seal/verify
engine unchanged. Adding one is future work:

- it must be feature-gated (e.g. `kms-aws`, `hsm-pkcs11`) so the default offline
  build pulls no cloud/hardware dependencies;
- signing may move *into* the backend (the private key never leaving the HSM),
  which would extend the `Keys` abstraction to a "signer" trait rather than an
  in-memory `SigningKey`. That refactor is out of scope for the file backend.
