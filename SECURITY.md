# Security Policy

## Reporting a vulnerability

**Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/SuarezPM/apohara-sealchain/security/advisories/new).**
Do **not** open a public issue for a security problem.

GitHub Security Advisories gives us a private channel to triage, fix, and
coordinate disclosure with you. When you report, please include:

- the affected version (`apohara-sealchain --version`) and platform,
- a minimal reproduction (a sample artifact + receipt is ideal),
- the impact you observed (e.g. a forged receipt that verifies, a tampered
  artifact that passes, a panic, or a network call on the `verify` path).

We aim to acknowledge a report within **5 business days** and to agree on a
disclosure timeline with you. We credit reporters in the advisory unless you ask
us not to.

## Supported versions

apohara-sealchain is pre-1.0; only the latest released minor line receives
security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Threat model — what a receipt protects, and what it does not

A seal is **evidence, not a verdict**. Each layer answers a narrow question against
a specific trust anchor; over-reading one layer's presence is the most likely way
to be misled. The canonical, machine-readable statement of what each layer proves
lives in [`packaging/trust-profile.json`](packaging/trust-profile.json); the
human-readable rendering is [`docs/TRUST-PROFILE.md`](docs/TRUST-PROFILE.md). The
honesty caveats below are the security-relevant subset and are kept consistent with
that document.

### In scope (the tool defends these)

- **Tamper-evidence of the artifact.** The content layer binds `sha256(file)`; one
  flipped byte makes `verify` exit non-zero at the content layer.
- **Tamper-evidence of the receipt.** Every layer re-derives and re-checks its own
  binding at verify time, or reports `ok: false` with a reason — there is no
  hardcoded `verified=true` anywhere in the tree.
- **Offline verification with no trust-on-first-use.** `verify` performs **no**
  network calls; the Rekor shard key is pinned with provenance in the binary, never
  fetched from the thing being verified.
- **Real-or-abort sealing.** `--all` (and any requested layer) is produced for real
  or the seal aborts and writes nothing — no partial receipt is emitted.

### Out of scope / known limitations (do not over-read a seal)

These are intentional, documented postures, not hidden gaps:

- **HMAC is symmetric.** Only a holder of the shared secret can re-check the HMAC
  layer, and anyone holding that secret can forge it. A third party without the
  secret verifies content + Ed25519 + C2PA instead — the tools say so rather than
  fake a pass. HMAC alone proves local integrity, not authorship.
- **The v0.1 C2PA manifest is self-signed** with the seal's Ed25519 key (C2PA trust
  check disabled — "Valid, not Trusted"). It binds the payload but is **not** a
  third-party-trust-anchored C2PA credential, and is invisible-as-trusted in
  external C2PA viewers.
- **The default timestamp is not eIDAS-qualified.** The default RFC-3161 TSA
  produces a genuine token, but it is **not** a legally-qualified (court-admissible)
  **eIDAS** timestamp. For legal weight, point `--tsa` at a Qualified Trust Service
  Provider (your account to provide). `require_qualified_tsa` is a host-allowlist
  match, not cryptographic proof of qualification.
- **Transparency requires network at seal time.** The Rekor v2 transparency layer
  needs network to submit at seal time; it proves public, append-only inclusion, not
  identity or legal qualification. (Verification of the inclusion proof remains
  offline.)
- **Authorship ≠ identity.** Ed25519 proves the holder of a key signed the seal; it
  does **not** bind that key to a real-world identity (no PKI / OIDC identity).

## Build & supply-chain integrity

Release binaries carry a SLSA **build provenance (L2+)** attestation (Sigstore
keyless). Verify a downloaded asset before running it:

```sh
gh attestation verify <asset> --repo SuarezPM/apohara-sealchain
```

Prefer `cargo install apohara-sealchain` (build from source) when you can.
