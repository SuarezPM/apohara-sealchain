# Assurance Case

This is apohara-sealchain's **assurance case**: a structured argument for *why its
security requirements are met*. It states the security requirements, the threat
model and trust boundaries, the secure-design principles applied, and how common
implementation weaknesses are countered — each with pointers to the code, tests,
and CI that back the claim. It consolidates [`SECURITY.md`](../SECURITY.md) (threat
model), [`docs/TRUST-PROFILE.md`](TRUST-PROFILE.md) (what each layer proves), and
[`SPEC.md`](../SPEC.md) (wire format + verify semantics); where those disagree with
this document, the more specific one wins (SPEC for wire format, TRUST-PROFILE for
proof claims).

## 1. Security requirements (what we promise)

apohara-sealchain produces and verifies `apohara-seal-v1` receipts for files. Its
security requirements:

1. **Tamper-evidence of the artifact.** A verifier detects any change to the
   sealed bytes (one flipped byte fails verification).
2. **Tamper-evidence of the receipt.** A verifier detects any change to the
   receipt; no layer reports a pass it did not cryptographically re-derive.
3. **Offline, self-contained verification.** `verify` requires only the artifact
   and the receipt — no network, no key server — and never makes a network call.
4. **Real-or-abort production.** A requested layer is produced for real or the
   seal aborts; no partial or faked receipt is written.
5. **No over-claiming.** Each layer's guarantee is stated narrowly and honestly;
   the tool never asserts trust it cannot prove (see TRUST-PROFILE).

Non-requirements (explicitly out of scope, documented so they are not over-read):
real-world **identity** binding (Ed25519 proves key-holding, not who), **legal
qualification** of the default timestamp (not eIDAS-qualified), and
**third-party-trust-anchored** C2PA (v0.1/v0.2 is self-signed). See
[`SECURITY.md`](../SECURITY.md#threat-model--what-a-receipt-protects-and-what-it-does-not).

## 2. Threat model and trust boundaries

### Actors and assets
- **Sealer** (trusted): holds the Ed25519 private key + HMAC secret, runs `seal`.
- **Distributor/registry** (untrusted): hosts the artifact + receipt (HF Hub, a
  bucket, a PR). May tamper in transit or at rest.
- **Verifier** (the relying party): runs `verify` with only the artifact +
  receipt (+ optionally the HMAC secret).
- **Assets:** artifact integrity, authorship authenticity, the receipt's bindings,
  and the sealer's private key material.

### Trust boundaries
- **Boundary A — the receipt.** Everything a third party trusts must be inside the
  receipt or pinned in the verifier binary. The embedded Ed25519 public key, the
  C2PA manifest, and the TSA/Rekor material travel in the receipt; the Rekor shard
  keys are pinned at compile time in the verifier
  ([`artifact.rs` `REKOR_SHARDS_JSON`](../crates/apohara-sealchain-core/src/artifact.rs)).
  No trust is placed in the distributor.
- **Boundary B — the verify process.** `verify` consumes only attacker-influenced
  bytes (the artifact + receipt) and trusted pinned data; it performs **no network
  I/O** and so cannot be redirected, downgraded, or have keys substituted by a
  network adversary. This boundary is **CI-enforced** (see §4).
- **Boundary C — the sealer's secrets.** The HMAC secret and Ed25519 private key
  live in the keystore, separate from receipts and (optionally) encrypted at rest;
  they never appear in a receipt.
- **Outside the boundary at seal time only:** TSA and Rekor submission make
  network calls *during `seal`* (opt-in); a network adversary there can cause a
  seal to *fail* (real-or-abort) but cannot forge a passing receipt.

### Threats considered and mitigations
| Threat | Mitigation |
|--------|------------|
| Artifact tampered in transit/at rest | content layer binds `sha256(file)`; mismatch ⇒ `verify` exits non-zero |
| Receipt tampered | every crypto layer re-derives the canonical preimage; edit ⇒ all layers `ok:false` |
| Forged authorship | Ed25519 signature over the canonical preimage, checked against the embedded public key |
| Network adversary at verify time | `verify` makes **no** network calls (Boundary B, CI-enforced); Rekor key is pinned, not fetched |
| Stale/rotated Rekor shard at seal time | seal-time guard compares the shard against the TUF SigningConfig active set and **aborts** a rotated-out shard ([rekor.rs `check_shard_active`](../crates/apohara-sealchain-core/src/layers/rekor.rs)) |
| Unknown Rekor key at verify | measured `ok:false` ("log key unknown"), never a silent pass |
| Partial/faked layer | real-or-abort: `--all` writes nothing if any requested layer cannot be produced |
| Wrong-passphrase keystore | decrypt returns `Err` (AEAD tag), never a panic or wrong-key use |
| Supply-chain tampering of the binary | release binaries carry SLSA build provenance (Sigstore keyless); `gh attestation verify` checks them |

## 3. Secure-design principles applied

- **Measure, don't assert.** No layer hardcodes a pass; each re-derives and checks
  its own binding or reports `ok:false` with a reason. Enforced by the conformance
  vectors and per-layer tests ([`tests/conformance.rs`](../crates/apohara-sealchain-core/tests/conformance.rs),
  [`tests/rekor.rs`](../crates/apohara-sealchain-core/tests/rekor.rs)).
- **Least privilege / no ambient trust.** Verify trusts only the receipt + pinned
  keys; it has no filesystem-config or network surface to subvert.
- **Fail closed (real-or-abort).** The default is to abort rather than emit a weak
  or partial result.
- **Separation of secrets.** Private key material is isolated from receipts and
  encryptable at rest (scrypt + XChaCha20-Poly1305).
- **Memory safety by construction.** Pure safe Rust (the produced software has no
  memory-unsafe language); `unsafe` is not used in the shipped library paths.
- **Defense in depth.** Independent layers (content, HMAC, Ed25519, C2PA, TSA,
  Rekor) each bind the same canonical preimage, so a single layer's limitation
  does not collapse the others.

## 4. Common implementation weaknesses — countered

- **Input validation (untrusted input).** The receipt and artifact are treated as
  untrusted: structural problems are typed `Err` (verification not performed),
  tamper is a measured `ok:false`; malformed hex, bad base64, negative
  proof indices, and unknown schema versions are all handled explicitly, never
  panicking. (`verify_artifact_bytes` and the layer verifiers.)
- **No weak crypto.** SHA-256 + Ed25519 + HMAC-SHA256; no SHA-1/MD5/CBC-SSH. TLS
  (seal-time TSA/Rekor) uses `reqwest` + `rustls` with certificate verification on
  by default, TLS 1.2+.
- **No secrets in output.** The HMAC secret and private key never appear in a
  receipt; a CI **gitleaks** job scans for leaked secrets.
- **Offline-verify invariant cannot regress.** A CI job (`verify-offline-isolation`)
  asserts the `verify-only` build links no network client
  (reqwest/tokio/sigstore/tough), so `verify` cannot acquire a network surface by
  accident.
- **Dependency risk.** `cargo-deny` (licenses/bans/advisories) and `cargo-audit`
  (RUSTSEC) run in CI; documented, reviewed exceptions only.
- **Static analysis.** `clippy` with `-D warnings` on every change.
- **Honesty gate.** A CI check forbids over-claiming the provenance level
  (`provenance-honesty`): the literal "SLSA Build L3" may not appear without
  recorded verification evidence.

## 5. Residual risk (honest)

- **Identity is not bound.** Ed25519 proves key-holding, not real-world identity;
  out-of-band trust of the public key is required.
- **C2PA is self-signed** in this version ("Valid, not Trusted"); the CA-anchored
  upgrade path is documented in [`docs/c2pa-trust.md`](c2pa-trust.md).
- **Default timestamp is not eIDAS-qualified**; legal weight requires pointing
  `--tsa` at a QTSP.
- **HMAC is symmetric**; only a secret-holder can re-check it.

These are documented, intentional limitations, not undisclosed gaps — which is
itself part of the security posture.

## 6. Evidence index

| Claim | Evidence |
|-------|----------|
| Tamper-evidence | `crates/apohara-sealchain-core/tests/conformance.rs`, `crates/apohara-sealchain/tests/cli.rs` (flip-a-byte ⇒ exit 1), the README demo |
| Offline verify, CI-enforced | `.github/workflows/ci.yml` job `verify-offline-isolation`; `crates/apohara-sealchain-core/tests/rekor.rs` frozen-anchor tests |
| Real-or-abort | `crates/apohara-sealchain/tests/cli.rs` / `crates/apohara-sealchain/tests/mcp.rs` abort-without-partial-receipt tests |
| No weak crypto / no secrets leaked | dependency choices + CI `gitleaks`, `cargo-deny`, `cargo-audit` |
| Signed releases | `.github/workflows/release.yml` (attest-build-provenance); `gh attestation verify` |
| Test coverage | ~84% statement coverage (`cargo llvm-cov --workspace --summary-only`); see [`best-practices-silver.md`](best-practices-silver.md) |
