# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-06

### Added

- **HuggingFace seal Action** (`.github/actions/huggingface-seal`): a composite
  Action that seals a model file, **verifies the receipt locally**, and uploads the
  `.seal.json` to the model repo — but only when an `hf_token` is supplied;
  otherwise it is a dry-run (seal + verify, no publish). Reproducible offline via
  `examples/huggingface/hf-action-dryrun.sh`.
- **MCP streamable-HTTP transport** (`mcp --http <host:port>`): serve the MCP
  server over streamable-HTTP (endpoint `/mcp`) for remote/CI use, alongside the
  default stdio transport. Adds the rmcp `transport-streamable-http-server` feature
  and an `axum` dependency. **No authentication** — the default config restricts the
  `Host` header to loopback (DNS-rebinding mitigation); bind only to a trusted
  address or front it with an authenticating reverse proxy.
- **C2PA AI-generated disclosure** (`seal --ai-generated`, MCP `ai_generated`): records
  the IPTC `trainedAlgorithmicMedia` digital source type (C2PA 2.x) in the created
  action of the C2PA manifest, in **both** sidecar and embedded modes — for AI-content
  disclosure (e.g. EU AI Act Art. 50). Opt-in; without the flag the source type stays
  `empty` (no claim about how the content was produced).
- **Model-transparency interop for `provenance`**: `provenance --format model-signing`
  emits an in-toto Statement in the model-transparency / OpenSSF Model Signing shape
  (`predicateType https://model_signing/signature/v1.0`, subject = the artifact's
  `(path, sha256)`), so ML-signing-ecosystem consumers can match the artifact digest.
  The default `--format apohara` keeps the native `apohara.dev/sealchain/provenance/v1`
  predicate (never renamed to `slsa.dev`). The interop predicate cross-links to the
  native one rather than restating it. Vendored shape descriptor:
  `packaging/model-signing-schema.json`.
- **Seal-time stale-shard guard for Rekor v2** (`--rekor`): before submitting, the
  seal compares the target shard against the **active** Rekor v2 endpoints in the
  TUF-distributed Sigstore `SigningConfig`. A shard that has rotated out of the
  active set **aborts** the seal (real-or-abort) instead of silently anchoring to a
  deprecated shard; an undeterminable active set proceeds and records
  `seal.rekorAnchor.shardActiveness = "undeterminable"`. New dependency
  `sigstore-trust-root` (same sigstore-* 0.6.6 family; default `tuf` feature pulls
  the `tough` TUF client), native/seal-time only — never linked into the offline
  verify path.

### Security

- **CI now enforces the offline-verify invariant**: a `verify-offline-isolation`
  job asserts the `verify-only` build links no network client
  (reqwest/tokio/sigstore/tough), so `verify` cannot make a network call by
  accident.

### Changed

- `deny.toml`: allow `MPL-2.0` for the transitive `option-ext` crate (pulled via
  `tough -> directories -> dirs-sys`); file-level weak copyleft, not modified, so
  no obligation on this project's own MIT/Apache-2.0 source. MSRV is unchanged
  (1.88; the new TUF deps declare lower floors).

## [0.1.0] - 2026-06-05

Initial release of **apohara-sealchain** — verifiable, tamper-evident receipts for AI
artifacts, exposed as both a CLI and an MCP (Model Context Protocol) server.

### Added

- **5-layer `apohara-seal-v1` receipt engine** (`apohara-sealchain-core`): content hash,
  HMAC integrity, Ed25519 authorship, C2PA manifest, and Sigstore transparency
  (TSA timestamp + Rekor v2 inclusion) layers, all canonicalized with JCS
  (RFC 8785).
- **CLI** (`apohara-sealchain`): `seal` and `verify` subcommands over the filesystem,
  with deterministic receipt paths and a human-readable verification chain.
- **MCP server** (`apohara-sealchain mcp`): stdio transport exposing the seal/verify
  engine as MCP tools for agent integration.
- **WASM verifier** (`sealchain-wasm`): the offline verify path
  (content, HMAC, Ed25519, C2PA verify) compiled to
  `wasm32-unknown-unknown` for in-browser verification, with no network or
  filesystem dependencies.
- **npx wrapper** (`apohara-sealchain`): downloads the prebuilt platform binary
  from the GitHub Release and runs the MCP server via `npx @apohara/sealchain`.
- **Passphrase-encrypted keystore at rest + key rotation** (native only): the
  private material (Ed25519 PKCS#8 + HMAC key) can be stored encrypted with
  scrypt (KDF) + XChaCha20-Poly1305 (AEAD); a wrong passphrase fails cleanly
  (exit 4) instead of panicking or using a wrong key. New `key` CLI group:
  `key rotate` (mode-preserving, archives the old key so prior receipts still
  verify via their embedded public key), `key list`/`key show` (active +
  archived fingerprints), and `key encrypt`/`key decrypt` (convert between
  plaintext and encrypted modes). Plaintext stays the backward-compatible
  default; the passphrase is read from `--passphrase` or `SEALCHAIN_PASSPHRASE`.
  KMS/HSM backends are a documented future extension point (see
  `docs/key-management.md`), not faked.
- **Canonical trust profile** (`packaging/trust-profile.json`): a machine-readable
  single source of truth for what each layer combination proves, the named
  profiles (`offline-basic`, `transparency`, `legal-grade`, `full`), and the
  qualified-TSA host allowlist. The crate embeds a byte-identical copy;
  `docs/TRUST-PROFILE.md` is its human-readable rendering.
- **Attestation policies**: `apohara-sealchain verify --policy <file.toml>` /
  `--profile <name>` enforces a declarative bar *after* verification. New exit
  code `5` = crypto verified but policy not satisfied (a tampered receipt still
  exits `1`). A layer counts only if present **and** verified; `require_qualified_tsa`
  is an honest host-allowlist match, not eIDAS proof. The MCP `verify_receipt`
  tool gains an optional `profile` param. Examples in `examples/policies/`.
- **Transparency dashboard**: `apohara-sealchain dashboard` renders a self-contained,
  **offline** HTML report (no network references at all) from the local index or
  a `--from-dir` scan — one row per receipt with layers, an honest verify status,
  and an optional policy-compliance column.
- **Dual license**: MIT OR Apache-2.0.

[Unreleased]: https://github.com/SuarezPM/apohara-sealchain/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuarezPM/apohara-sealchain/releases/tag/v0.1.0
