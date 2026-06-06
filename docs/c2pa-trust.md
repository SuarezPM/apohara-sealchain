# C2PA trust anchor — from self-signed (v0.1) to a CA-issued credential

apohara-sealchain's C2PA layer is **real** — a genuine JUMBF manifest, cryptographically
bound to the seal's canonical payload hash, signed with the seal's own Ed25519 key
([`SPEC §3.5`](../SPEC.md)). What it is **not**, in v0.1, is *third-party-trust-anchored*:
the signing certificate is **self-signed**, so a C2PA viewer reports the manifest as
**"Valid, not Trusted."** This document explains why, and the concrete workflow to
upgrade to a CA-issued credential that external viewers (Adobe, LinkedIn, etc.) show
as trusted.

> **Honesty.** Nothing below is wired into the default build. v0.1 is self-signed by
> design and says so. A CA-issued credential is a maintainer action with real cost and
> a real trade-off (see [Ed25519 vs. the C2PA CA ecosystem](#ed25519-vs-the-c2pa-ca-ecosystem)).
> Do **not** claim "trusted" anywhere until a CA-issued cert is actually in use.

## Why self-signed is "Valid, not Trusted"

A C2PA validator does two things: (1) verify the manifest's signature and bindings
(cryptography), and (2) check that the signing certificate chains to a root on a
**C2PA Trust List** (trust). v0.1 passes (1) — the COSE signature verifies against the
embedded cert, and the cert's SPKI equals the seal's public key, so *signer ≡ authorship*.
It deliberately skips (2): the cert is self-signed and on no trust list, so
`offline_settings()` turns trust checking off
([`c2pa.rs` `offline_settings`](../crates/apohara-sealchain-core/src/layers/c2pa.rs)):

```jsonc
"verify": { "verify_trust": false, "verify_timestamp_trust": false, ... }
```

An external viewer that enforces (2) will render "Valid, not Trusted" — the binding is
sound, but the identity is not anchored to a recognized authority.

## What the signing certificate must carry

The current self-signed end-entity cert
([`c2pa.rs` `build_signer_cert_pem`](../crates/apohara-sealchain-core/src/layers/c2pa.rs))
already satisfies the c2pa-rs **certificate profile**, and a CA-issued cert must satisfy
the same profile:

- **End-entity** (`BasicConstraints cA=FALSE`) — c2pa rejects a CA cert as the signer.
- **KeyUsage** = `digitalSignature`.
- **ExtendedKeyUsage** = a C2PA-accepted signing EKU. We use `emailProtection`
  (`id-kp-emailProtection`); `anyExtendedKeyUsage` is explicitly rejected. C2PA also
  accepts document-signing EKUs — match what your CA issues against the C2PA spec's
  allowed set.
- **SubjectKeyIdentifier** + **AuthorityKeyIdentifier** extensions present.
- A non-empty **Organization (`O=`)** in the subject DN.

The differentiator for *trust* is the chain: the CA's issuing/root certificate must be
on a **C2PA Trust List** that the consuming viewer uses (the public C2PA trust list, or
Adobe's, etc.).

## The CA-issued workflow

1. **Choose a CA that issues C2PA / document-signing certificates** whose root is on the
   relevant C2PA trust list — e.g. **SSL.com** (C2PA / "Document Signing") or
   **DigiCert**. Confirm the issuing root is on the trust list your audience validates
   against before buying.
2. **Generate a CSR** for the key you will sign with, with the subject DN (include `O=`)
   and the EKU the CA supports for C2PA. (See the trade-off below before deciding the key
   algorithm.)
3. **Complete the CA's identity vetting** (organization validation) and receive the
   issued **end-entity certificate + intermediate chain** (PEM).
4. **Wire the issued chain into the signer.** The signer is a
   [`CallbackSigner`](../crates/apohara-sealchain-core/src/layers/c2pa.rs) constructed
   with `(sign_closure, SigningAlg, cert_chain_pem)`. Replace the self-signed
   `build_signer_cert_pem(...)` output with the CA-issued **full chain PEM**, and have
   the sign closure use the private key the CSR was made for. (This is the single
   integration point; today the chain is the self-signed cert.)
5. **Enable trust verification.** Flip `verify_trust` to `true` (and configure the trust
   anchors) in the c2pa `Settings` so the pipeline — and `verify_after_sign` — actually
   enforce the chain instead of accepting the self-signed cert.
6. **Verify in a real viewer.** Confirm an external C2PA viewer reports **"Trusted"**,
   not just "Valid", before updating any user-facing claim.

## Ed25519 vs. the C2PA CA ecosystem

This is the load-bearing trade-off, stated plainly:

- v0.1's strongest property is **signer ≡ seal key**: the C2PA cert's SPKI *is* the
  seal's Ed25519 public key, so the same key proves authorship across the Ed25519 layer
  and the C2PA manifest.
- The commercial C2PA CA ecosystem largely issues **ECDSA (P-256) or RSA** certificates;
  **Ed25519** issuance is not broadly available. So a CA-issued credential will, in
  practice, use a **different key/algorithm** than the seal's Ed25519 key.
- Consequences to choose between, honestly:
  - **(A) CA cert with its own ECDSA/RSA key** → the C2PA manifest becomes
    third-party-*trusted*, but the C2PA signer is **no longer the same key** as the seal's
    Ed25519 authorship key. The payload-hash assertion still binds the manifest to the
    seal's canonical payload, so the *binding* holds; the *signer ≡ seal key* property
    does not. Document this explicitly if adopted.
  - **(B) Wait for / require an Ed25519-issuing C2PA CA** → preserves signer ≡ seal key,
    at the cost of availability today.

There is no free lunch here: trusted-identity and single-key-authorship pull against each
other given current CA support. v0.1 chooses single-key-authorship + honest
"not trusted"; the production upgrade chooses trusted-identity, and must disclose the
key-separation if it goes with (A).

## Cost & gating

A CA-issued C2PA/document-signing certificate requires **organization vetting** and an
**annual fee**, and the credential is the maintainer's to provision and protect. Like the
[eIDAS QTSP path](TRUST-PROFILE.md#legal-grade-timestamps-eidas-qtsp), this is a **GATED**
manual step outside the tool: apohara-sealchain ships no CA credential and will not fake a
trusted signer.

## See also

- [`docs/TRUST-PROFILE.md`](TRUST-PROFILE.md) — what the C2PA layer proves and does not.
- [`SPEC.md`](../SPEC.md) — the C2PA layer binding and verify semantics.
- C2PA specification — conformance, trust lists, and the signer certificate profile.
