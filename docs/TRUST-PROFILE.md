# Trust Profile — what each apohara-sealchain layer (and combination) actually proves

This is the canonical reference for **what a apohara-sealchain receipt proves, and what it
does not**, layer by layer and in combination. It exists so that no one over-reads
a seal: each layer answers a narrow question and depends on a specific trust anchor.
For the wire format and verify semantics see [`SPEC.md`](../SPEC.md); for the candid
limitations see the **Honesty** section of the [root README](../README.md#honesty-read-this).

> **Canonical, machine-readable source.** This document is the human-readable
> rendering of [`packaging/trust-profile.json`](../packaging/trust-profile.json),
> which is the **single source of truth**: the named profiles, the proof matrix,
> and the qualified-TSA host allowlist all live there and are consumed directly by
> the attestation-policy engine (`verify --policy`/`--profile`) and the
> transparency dashboard (`apohara-sealchain dashboard`). The crate embeds a byte-identical
> copy; a dev test keeps the two in sync. If the prose here and the JSON ever
> disagree, **the JSON wins.**

> **The one-line rule.** A seal is *evidence*, not a verdict. It proves the
> properties of the layers it actually carries, against the trust anchors those
> layers require — nothing more. In particular, the **default** timestamp path is
> **not** a legally-qualified (eIDAS) timestamp; see
> [Legal-grade timestamps](#legal-grade-timestamps-eidas-qtsp) below.

## The five layers (one-liners)

| Layer | Question it answers |
|-------|---------------------|
| **HMAC-SHA256** | Has this receipt's preimage been altered, given the shared secret? |
| **Ed25519** | Did the holder of this private key author this seal? |
| **RFC-3161 TSA** | Did this content exist before a point in time, *according to that TSA*? |
| **Rekor v2** | Is this seal publicly recorded in an append-only transparency log? |
| **C2PA** | Is there a provenance manifest bound to this payload? |

## Proof matrix — layers and combinations

Each row is a *cumulative* seal: every later row includes the guarantees of the rows
above it (apohara-sealchain's preimage chains HMAC → Ed25519, and TSA/Rekor/C2PA are siblings
bound to that chain). "Proves" and "Does NOT prove" are stated narrowly on purpose.

| Seal combination | What it proves | What it does NOT prove | Trust anchor needed |
|------------------|----------------|------------------------|---------------------|
| **HMAC only** | Local integrity: anyone holding the shared secret can confirm the receipt's preimage is unmodified. | Authorship (anyone with the secret can forge it), existence-in-time, public record, provenance. | The **shared HMAC secret** (symmetric; verifier must already hold it). |
| **+ Ed25519** | Authorship by the key holder: the seal was signed by whoever controls that Ed25519 private key. The public key is embedded, so verification is offline. | *Who* that key holder is (no identity binding / PKI), *when* it was signed, public record, provenance. | The **Ed25519 keypair** (and out-of-band trust that the embedded public key really is the claimed author's). |
| **+ TSA (non-qualified, e.g. FreeTSA / Sigstore)** | Existence-before-a-point-in-time *as asserted by that TSA*: the `hmac.sig \|\| ed25519.sig` binding was timestamped, and the token's message imprint is re-checked offline. | A **legally-qualified / court-admissible** timestamp; identity; public record; provenance. The free TSA is credible but **not eIDAS-qualified**. | The **TSA's signing certificate** (imprint is the pass bar; chain validation is best-effort — "Valid, not Trusted", see [SPEC §3.3](../SPEC.md#33-rfc-3161-tsa--over-hmacsig--ed25519sig)). |
| **+ TSA (eIDAS QTSP, e.g. Actalis)** | A **qualified timestamp**: existence-before-time with legal effect under eIDAS (Art. 42) — presumed accurate and admissible across the EU. Same offline imprint check; the *legal weight* comes from the QTSP. | Authorship identity beyond the Ed25519 key, public record, provenance. (It does not turn an unqualified key into a qualified signature.) | A **qualified eIDAS TSA** under your own QTSP account — see [Legal-grade timestamps](#legal-grade-timestamps-eidas-qtsp). **GATED**: needs your credentials. |
| **+ Rekor v2 (public transparency)** | Public, append-only record: a DSSE-signed in-toto Statement anchoring the canonical preimage was admitted to a Sigstore Rekor v2 log, with an offline-verifiable inclusion proof + signed checkpoint. | Legal qualification, identity (the DSSE is signed by the seal key, not an OIDC identity), provenance. Transparency ≠ qualification. | The **Rekor log's public key**, pinned in [`packaging/rekor-shards.json`](../packaging/rekor-shards.json) (verified offline). |
| **+ C2PA (provenance manifest)** | A provenance manifest is cryptographically **bound to the payload** (sidecar JUMBF, or in-file hard binding with `--embed`): tooling can show the claimed origin/history. | A **third-party-trust-anchored** credential: in v0.1 the manifest is **self-signed** with the seal's Ed25519 key (C2PA trust check disabled — "Valid, not Trusted"). Not legal qualification, not identity. | A real **C2PA Signer certificate** for production provenance (v0.1 uses a self-signed cert) — see [`c2pa-trust.md`](c2pa-trust.md) for the CA-issued upgrade path. |
| **Full 5-layer (`--all`, real-or-abort)** | The union of all of the above, produced **real-or-abort** (if any requested layer can't be produced the seal aborts and writes nothing): integrity + authorship + timestamp + public transparency + provenance, each independently re-checked at verify time. | Anything no single layer proves: notably **legal-grade timestamping unless the TSA is a qualified eIDAS QTSP**, and third-party identity binding. `--all` uses the **default (non-qualified)** TSA. | All anchors above; for legal weight you must additionally point `--tsa` at an eIDAS QTSP (the default is not qualified). |

### Reading the matrix

- **Cumulative, not exclusive.** A higher row does not replace a lower one; it adds a
  property. An HMAC-only receipt is a complete, valid receipt (see SPEC's
  "present-layers-only" principle) — it simply proves less.
- **Each anchor is independent.** Ed25519 says nothing about *time*; the TSA says
  nothing about *identity*; Rekor says nothing about *legal qualification*. Do not let
  one layer's presence inflate another's claim.
- **"Valid, not Trusted."** Both the TSA chain (without a supplied root) and the v0.1
  C2PA manifest verify their *binding* offline but are not anchored to a third-party
  trust root by default. That is an intentional, documented posture, not a gap hidden
  from you.

## Named profiles & enforcement

The proof matrix above becomes *enforceable* through **named profiles** (defined
in [`packaging/trust-profile.json`](../packaging/trust-profile.json)) and the
attestation-policy engine. A profile is a bar a receipt must clear; it is checked
**after** cryptographic verification (a tampered receipt fails verification
outright).

| Profile | Requires | Use it for |
|---------|----------|------------|
| `offline-basic` | hmac + ed25519 + c2pa (all verified) | The fully-offline default seal: integrity + authorship + provenance. |
| `transparency` | ed25519 + rekor (all verified) | Publicly-recorded authorship (append-only Rekor v2 log). |
| `legal-grade` | ed25519 + tsa, with a **qualified QTSP** authority | An eIDAS-oriented timestamp (see below). |
| `full` | all five layers (all verified) | The maximal chain. |

Enforce one of these (or a custom TOML policy) at verify time, and surface
compliance across many receipts in the dashboard:

```sh
# Named profile — exit 0 = pass, 5 = crypto ok but policy failed, 1 = tamper
apohara-sealchain verify model.bin model.bin.seal.json --profile transparency

# Custom policy file (require_layers / min_layers / require_qualified_tsa /
# max_age_days / require_tsa_authority_in / forbid_layers)
apohara-sealchain verify model.bin model.bin.seal.json --policy examples/policies/legal-grade.toml

# Offline HTML transparency report with a per-row compliance column
apohara-sealchain dashboard --from-dir . --profile transparency -o report.html
```

A layer counts toward a profile only if it is **present AND verified** — there is
no asserted pass. See [`examples/policies/`](../examples/policies/) for the full
field reference, and [`docs/POSITIONING.md`](POSITIONING.md) for how the three
pieces fit together.

> **Honesty on `require_qualified_tsa`.** It is a **host-allowlist match** against
> the recorded `seal.tsa.authority` (the canonical `knownQualifiedTsaHosts`, or a
> per-policy `require_tsa_authority_in`). It does **not** cryptographically prove
> the eIDAS qualification of a token — that legal weight comes from using a real
> QTSP, per the next section.

## Legal-grade timestamps (eIDAS QTSP)

**The default timestamp is not legal-grade.** apohara-sealchain's default TSA is Sigstore's
public TSA (`https://timestamp.sigstore.dev/api/v1/timestamp`,
see [`tsa.rs:47`](../crates/apohara-sealchain-core/src/layers/tsa.rs#L47)), and FreeTSA is the
other commonly-used free endpoint. Both produce genuine RFC-3161 tokens and are fine
for integrity/credibility, but **neither is an eIDAS-qualified timestamp** — they are
**not** court-admissible as qualified timestamps under EU law.

A **qualified electronic timestamp** (eIDAS Regulation (EU) No 910/2014, Art. 42)
enjoys a legal presumption of accuracy of its date/time and the integrity of the data
it binds, and is recognised across all EU member states. To get one, the timestamp
must be issued by a **Qualified Trust Service Provider (QTSP)** that appears on an EU
Trusted List.

### How to get a qualified timestamp: point `--tsa` at a QTSP

There is **no code change required**. apohara-sealchain already passes an arbitrary RFC-3161
URL straight through to the TSA client — pointing it at a qualified TSA is the entire
mechanism:

```sh
# Qualified timestamp from an eIDAS QTSP (example: Actalis)
apohara-sealchain seal model.bin --tsa https://timestamp.actalis.it

# Combine with the rest of the chain (the default --all TSA is NOT qualified,
# so pass the QTSP URL explicitly alongside --rekor):
apohara-sealchain seal model.bin --tsa https://timestamp.actalis.it --rekor
```

The receipt records the QTSP under `seal.tsa.authority` (the host label, here
`timestamp.actalis.it`), and `verify` re-checks the token's message imprint offline
exactly as for any other TSA.

> **GATED — your responsibility.** A real QTSP timestamp requires **your own
> account/credentials with that provider** (Actalis, or another EU-Trusted-List QTSP).
> apohara-sealchain does **not** ship QTSP credentials and will **not** fake a qualified
> submission: if you do not configure a reachable QTSP endpoint you are authorised to
> use, you simply do not get a qualified timestamp. Provisioning the QTSP account is a
> manual human step outside this tool.

### Verifying the `--tsa` pass-through (code path)

The arbitrary TSA URL is honored with no allowlist and no validation — confirmed by
reading the code, not asserted:

1. **CLI flag** accepts any string:
   [`crates/apohara-sealchain/src/cli.rs:82-83`](../crates/apohara-sealchain/src/cli.rs#L82-L83)
   — `#[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_TSA_URL)] tsa: Option<String>`.
2. **CLI resolves and forwards** the value unchanged:
   [`crates/apohara-sealchain/src/cli.rs:230`](../crates/apohara-sealchain/src/cli.rs#L230)
   (`args.tsa.as_deref()`) →
   [`crates/apohara-sealchain/src/cli.rs:247`](../crates/apohara-sealchain/src/cli.rs#L247)
   (passed as the `tsa` argument to `seal_artifact`).
3. **Engine forwards** the URL to the TSA client:
   [`crates/apohara-sealchain-core/src/artifact.rs:181-183`](../crates/apohara-sealchain-core/src/artifact.rs#L181-L183)
   — `if let Some(tsa_url) = tsa { … tsa::request_token(&to_stamp, tsa_url)? }`.
4. **TSA client** opens an RFC-3161 request against exactly that URL:
   [`crates/apohara-sealchain-core/src/layers/tsa.rs:101`](../crates/apohara-sealchain-core/src/layers/tsa.rs#L101)
   — `let client = TimestampClient::new(tsa_url);`.

For an unrecognised host the authority label falls back to the URL's host
([`tsa.rs:63-69`](../crates/apohara-sealchain-core/src/layers/tsa.rs#L63-L69)), so a QTSP such
as Actalis is recorded as `timestamp.actalis.it` with no special-casing.

## Honesty cross-reference

This document is the long form of the README's commitments. See:

- [README — Honesty (read this)](../README.md#honesty-read-this) — FreeTSA is not a
  legally-qualified timestamp; the v0.1 C2PA manifest is self-signed; *measure, don't
  assert*.
- [SPEC §3.3 — RFC 3161 TSA](../SPEC.md#33-rfc-3161-tsa--over-hmacsig--ed25519sig) and
  [SPEC — Layer summary](../SPEC.md) — the "Valid, not Trusted" posture and the eIDAS
  QTSP note (point `--tsa` at a QTSP for legal weight).

**Measure, don't assert.** No layer hardcodes a pass; each re-derives and re-checks
its own binding at verify time, or reports `ok: false` with a reason. A qualified
timestamp is no exception — it is exactly the same offline imprint check, with legal
weight supplied by the QTSP you chose, not by apohara-sealchain.
