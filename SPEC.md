# `apohara-seal-v1` — Receipt Format Specification

Version: **v1** (`method = "apohara-seal-v1"`)
Status: stable for the v0.1 release; **this format may evolve** (see [Versioning & changelog](#versioning--changelog)).
Authoritative implementation: `crates/apohara-sealchain-core` (Rust). Where this document and the code disagree, the code wins; please file a fix.

A **receipt** (`<artifact>.seal.json`) is a tamper-evident credential for an arbitrary artifact. It records the artifact's content hash plus a stack of independently-verifiable cryptographic and transparency layers, all bound to a single canonical *preimage*.

---

## 1. Overview & design goals

A receipt is a JSON object `{ "payload": {...}, "seal": {...} }`. The `payload` describes the artifact; the `seal` block carries the canonical preimage and one entry per active layer.

Design goals, in priority order:

1. **Measure, don't assert.** Every layer genuinely produces and verifies its own artifact (a real HMAC tag, a real Ed25519 signature, a real RFC 3161 token, a real Rekor v2 entry with inclusion proof, a real C2PA JUMBF manifest). There is no hardcoded `verified = true` anywhere in the verify path. A layer either re-derives and checks its binding, or it reports `ok: false` with a reason.
2. **Per-layer results.** Verification returns one result per layer (`{name, ok, reason}`), not a single boolean. A consumer sees exactly which layer failed and why.
3. **Present-layers-only verification.** A receipt is valid when *every layer that is present* verifies. An HMAC-only receipt is a complete, valid receipt; it is not penalized for lacking Ed25519, TSA, Rekor, or C2PA. Verification never demands a layer the receipt does not carry.
4. **Structural error vs. tamper.** A structural problem (not an object, missing required field, unsupported legacy schema, unparseable key) is an *error* — verification could not be performed. A content/signature mismatch (tamper) is *not* an error: it is a completed verification that returns "invalid". See [§7](#7-verify-semantics).
5. **Self-contained verification.** The Ed25519 public key is embedded in the receipt (`seal.ed25519PublicKey`), and the Rekor shard keys are pinned in `packaging/rekor-shards.json`, so signature, timestamp, C2PA, and Rekor-inclusion verification all run **offline** from the receipt alone. The HMAC layer is the one exception: it needs the shared secret (see [§7](#7-verify-semantics)).

---

## 2. The preimage (the thing every crypto layer signs)

All cryptographic layers bind the same canonical byte string, the **preimage**. It is computed as:

```
preimage = JCS({
  "method":   "apohara-seal-v1",
  "sealedAt": <RFC 3339 timestamp>,
  "payload":  strip_excluded(payload)
})
```

and stored in the receipt as `seal.preimage`, `0x`-hex encoded.

- **JCS = RFC 8785** (JSON Canonicalization Scheme). Object keys are sorted lexicographically by UTF-16 code units, numbers use the ECMAScript `Number.prototype.toString` algorithm (e.g. `-0.0` collapses to `0`), strings carry the minimal mandated escaping, and the output is UTF-8 with no insignificant whitespace. The Rust engine uses the `serde_jcs` crate and is validated byte-for-byte against the Python reference (see [§10](#10-conformance-vectors)).
- **Key ordering note.** Although the envelope is constructed as `{method, sealedAt, payload}`, JCS sorts the keys, so the serialized preimage object is ordered `method`, `payload`, `sealedAt`. Payload object keys are likewise sorted recursively.
- **`0x`-hex encoding.** The preimage bytes, every signature, the C2PA manifest, and the TSA token are all stored as a `0x` prefix followed by lowercase hex. (Decoders accept the prefix as optional, but the engine always emits it.)

### 2.1 Excluded keys (`strip_excluded`)

Before canonicalization the payload is deep-copied with a fixed set of volatile / observability keys removed from **every** nested object (arrays are traversed element-wise; scalars pass through). This keeps the seal stable across replays where only runtime noise differs. The **6 excluded keys** are:

```
kg_status, kg_latency_ms, surface_status, truncated, charsSeen, lowConfidenceTier
```

This mirrors the Python reference's `excluded.py`. The same `strip_excluded(payload)` is also the input to the C2PA payload-hash binding ([§3.5](#35-c2pa-sidecar-jumbf--rust-canonical)).

### 2.2 Worked example

For the payload `{"artifactSha256":"dfc1…8043","path":"example.txt","size":32,"mime":"text/plain"}` sealed at `2026-01-01T00:00:00+00:00`, the decoded preimage bytes are exactly:

```json
{"method":"apohara-seal-v1","payload":{"artifactSha256":"dfc1d7644e9c4dddab91fc20548a7aaa27bbe28068ce7f207327460d67798043","mime":"text/plain","path":"example.txt","size":32},"sealedAt":"2026-01-01T00:00:00+00:00"}
```

Note the sorted keys (`method`, `payload`, `sealedAt`; and within payload `artifactSha256`, `mime`, `path`, `size`) and the absence of whitespace — this is the RFC 8785 canonical form, and it is what each layer below binds.

---

## 3. Per-layer binding

Each layer below documents *exactly* what bytes it binds. Two layers (C2PA, Rekor) are explicitly **Rust-canonical**: the Rust engine defines the authoritative behavior because the Python reference is internally inconsistent there, and no Python round-trip is claimed for them (see [§9](#9-interoperability-scope)).

### 3.1 HMAC-SHA256 — over the preimage

- **Binds:** the canonical preimage bytes.
- **Algorithm:** HMAC-SHA256 (`alg = "HMAC-SHA256"`).
- **Output:** the 32-byte tag, `0x`-hex (64 hex chars).
- **Receipt:** `seal.hmac = { "alg": "HMAC-SHA256", "keyId": "hmac-default", "sig": "0x…" }`.
- **Always present.** HMAC is the one mandatory layer.
- **Verification** is constant-time and requires the shared HMAC secret — it is *not* browser-verifiable without the key (see [§7](#7-verify-semantics)).

### 3.2 Ed25519 — over the preimage; embedded public key

- **Binds:** the same canonical preimage bytes (not a hash of them — the raw preimage).
- **Algorithm:** Ed25519 (RFC 8032), deterministic: the same preimage + key always yields the same 64-byte signature.
- **Output:** the 64-byte signature, `0x`-hex (128 hex chars).
- **Receipt:** `seal.ed25519 = { "keyId": "default", "sig": "0x…" }`.
- **Embedded public key:** `seal.ed25519PublicKey` holds the Ed25519 **SPKI public key as PEM**. It is a *sibling* of the layers and is **NOT part of the preimage**, so adding it never changes the seal. Its presence makes the receipt self-verifiable without out-of-band key distribution. (Conformance vectors omit it and pass the key explicitly; artifact receipts embed it.)
- **Optional but default-on** for artifact receipts.

### 3.3 RFC 3161 TSA — over `hmac.sig || ed25519.sig`

- **Binds:** the **canonical binding** `hmac.sig || ed25519.sig` — the *raw* signature bytes (after `0x`-hex decode) concatenated in **that exact order**. The TSA hashes this with SHA-256, so the token's message imprint is `sha256(hmac.sig || ed25519.sig)`. (An Ed25519-less seal cannot carry a TSA token under this binding.)
- **Output:** the full DER-encoded `TimeStampResp` token.
- **Receipt:** `seal.tsa = { "authority": <label>, "issuedAt": <RFC 3339 genTime>, "der": "0x…" }`.
  - `authority` is a short label (`sigstore`, `freetsa`, or the URL host).
  - `issuedAt` is the token's `TstInfo.genTime`.
  - `der` is `0x` + hex of the raw token bytes.
- **Sibling layer, NOT part of the preimage** — adding it never changes the seal.
- **Pass bar (imprint):** the token's `TstInfo.messageImprint.hashedMessage` must equal `sha256(hmac.sig || ed25519.sig)`. An imprint mismatch is the only `ok: false`; unparseable DER is also `ok: false` (never a panic).
- **Best-effort chain:** certificate-chain validation runs only when a trust root is supplied; an unverifiable chain is reported in `reason` and never flips an imprint-valid token to `ok: false`. With no root (the default) the chain is reported unverified. This is the documented "Valid, not Trusted" posture — the free path is not a legally-qualified timestamp.
- **Network:** requested on demand (`--tsa`), verified offline by message imprint.

### 3.4 Rekor v2 transparency — **Rust-canonical**

> **Rust-canonical.** The Rekor binding below is the authoritative apohara behavior. The Python reference's Rekor handling (notably its signed-checkpoint verification) is internally inconsistent; the Rust engine defines the canonical shape and verify rule, and **no Python round-trip is claimed**.

- **What is anchored:** an in-toto Statement whose single subject digest is `sha256(preimage)` (the canonical preimage from [§2](#2-the-preimage-the-thing-every-crypto-layer-signs)), wrapped in a DSSE envelope (`payloadType = application/vnd.in-toto+json`). The DSSE **PAE is signed with the seal's own Ed25519 key** — not an ephemeral key, not a Fulcio/OIDC certificate. The verifier recorded in the entry is the seal's Ed25519 public key (SPKI DER, base64) with `keyDetails = PKIX_ED25519`.
- **Submission:** a `DSSERequestV002` to the configured shard's `POST /api/v2/log/entries`.
- **Receipt:** `seal.rekorAnchor = { logIndex, logId, integratedTime, inclusionProof{ logIndex, treeSize, rootHash, hashes[], checkpoint }, canonicalizedBody, envelope, verifier }`.
  - `canonicalizedBody` is base64 of the canonicalized Rekor entry body (the Merkle leaf preimage).
  - `envelope` is the submitted DSSE envelope (`payloadType`, base64 `payload`, `signatures[]`).
  - `verifier` is `{ publicKey: { rawBytes: <base64 SPKI DER> }, keyDetails: "PKIX_ED25519" }`.
- **Sibling layer, NOT part of the preimage** — adding it never changes the seal.
- **Offline pass bar (BOTH required):**
  1. **RFC 6962 Merkle inclusion** — the leaf is `sha256(0x00 || canonicalizedBody)`; chaining it with the proof `hashes` must reproduce `inclusionProof.rootHash`. Merkle-structure-only is **not** a pass.
  2. **C2SP checkpoint signature** — the Ed25519 signature over the **full** signed-note body (origin, tree size, root hash, and any extension lines — not header-only) must verify against the **pinned shard log key** resolved by `logId`. The checkpoint's root hash must also equal the inclusion proof's root hash.
- **Config-driven shard key:** the v2 shard URL and its log public key are **not** TUF-distributed to clients yet and the active shard rotates roughly every six months, so they live in `packaging/rekor-shards.json` (pinned with provenance), resolved by `logId`. Rotating a shard is a **config update + rebuild**, not a protocol change; frozen anchors keep verifying across rotations as long as the old shard's entry stays listed.
- **Unknown shard key** (no config match for the anchor's `logId`) → a **measured** `ok: false` with reason `log key unknown for logId <id>` — never an `Err`, never a silent pass.
- **Network:** submitted on demand (`--rekor`), verified offline from the bundled proof + pinned key.

### 3.5 C2PA sidecar (JUMBF) — **Rust-canonical**

> **Rust-canonical.** The C2PA payload-hash binding below is the authoritative apohara behavior. The Python reference's C2PA hash input is internally inconsistent (and the Python path can fall back to a non-real-C2PA JSON); the Rust engine emits a **real** JUMBF manifest store and defines the canonical bound hash. **No Python round-trip is claimed.**

- **Binds:** a **custom** assertion `apohara.seal.payloadHash = { "alg": "sha256", "hash": <hex> }`, where `<hex> = sha256(JCS(strip_excluded(payload)))`. This is the same `strip_excluded` from [§2.1](#21-excluded-keys-strip_excluded), and the *exact same hash* is computed on emit and on verify.
  - The label lives in the vendor-reserved `apohara.*` namespace. The reserved `c2pa.hash.data` / `c2pa.hash` hard-binding assertions are **deliberately not used**: those bind *asset bytes*, not our JSON payload, and misusing them would be dishonest.
- **Signer = seal key via certificate.** The COSE signature is produced with the **seal's own Ed25519 key**, and the signing certificate is a self-signed X.509 cert whose subject public key *is* the seal's Ed25519 public key. So signer ≡ authorship: the same identity that authored the seal authored the manifest.
  - The cert is self-signed (not anchored to a trust list), so verification runs with `verify_trust = false`: the manifest is asserted cryptographically **Valid** (well-formed + signature integrity), not **Trusted**. This is the documented v0.1 posture.
- **Output:** the real C2PA manifest-store JUMBF bytes.
- **Receipt:** `seal.c2paManifest = "0x" + hex(JUMBF bytes)`.
- **Sibling layer, NOT part of the preimage** — adding it never changes the seal.
- **Offline guarantee:** built without remote-manifest fetch; the sidecar (`no_embed`) path uses an in-memory asset, so no media file and no network are touched on emit or verify.
- **Pass bar:** the `c2pa::Reader` must parse the JUMBF, reach a non-`Invalid` validation state, and the bound `apohara.seal.payloadHash.hash` must equal the recomputed `sha256(JCS(strip_excluded(payload)))` (case-insensitive). Unparseable bytes are a structural error; a hash/validity mismatch is `ok: false`.

#### 3.5.1 C2PA in-file embedding (`--embed`) — supported media

When `--embed` is used (CLI) or `embed=true` (MCP), the C2PA manifest is embedded **inside the artifact file** instead of carried as a sidecar. This uses c2pa-rs's **native in-file hard binding** — the `c2pa.hash.data` assertion c2pa computes over the asset bytes (excluding the manifest region) — which is what proves the embedded file's integrity. The `apohara.seal.payloadHash` assertion is **not** added in embed mode: binding it would be circular, since the seal's payload hash is over `artifactSha256`, which is itself `sha256(embedded bytes)`. The apohara-sealchain payload is still produced and signed by the surrounding HMAC/Ed25519 (and optional TSA/Rekor) layers over the **final embedded file**.

- **Order of operations:** (1) read the original media; (2) embed the manifest (`no_embed=false`) signed with the seal key (same `CallbackSigner` + self-signed cert as the sidecar), writing the embedded asset; (3) **rewrite the artifact file in place** with the embedded bytes; (4) compute `artifactSha256/size/mime` from the **final embedded file**; (5) run HMAC/Ed25519 (and any requested TSA/Rekor) over that payload; (6) write the `.seal.json` sidecar.
- **Receipt:** `seal.c2paEmbedded = true` (and **no** `c2paManifest` — the two are mutually exclusive). The in-file manifest is read directly from the artifact on verify.
- **Format gating:** the embeddable set is what c2pa-rs's `CAIWriter` handlers can write — JPEG, PNG, TIFF/DNG, WEBP, AVIF/HEIF, MP4/MOV/M4A/M4V, GIF, SVG, WAV, MP3, FLAC, JXL. An **unsupported** format with `--embed` is a **hard error** (CLI exit 2; `SealError::C2pa` from the engine) — it **never** silently falls back to the sidecar. `--embed` requires the C2PA layer (cannot be combined with `--no-c2pa`).
- **Pass bar (verify):** the content layer checks `sha256(file) == artifactSha256` (the embedded file). The C2PA layer reads the manifest from the **file** with `c2pa::Reader`, requires a non-`Invalid` validation state, and (native build) checks the signer cert's Ed25519 public key equals the receipt's embedded `ed25519PublicKey` (signer ≡ authorship). A tampered embedded file trips the content layer and/or c2pa's data-hash binding.

---

## 4. Content layer (file-hash binding)

Beyond the crypto layers, an artifact receipt carries a **content** layer that is checked by `verify_artifact` / `verify_artifact_bytes`:

- The payload records `artifactSha256 = sha256(file bytes)` (lowercase hex, no `0x`).
- On verify, the file's hash is recomputed and compared to `payload.artifactSha256`.
- A one-byte change to the *file* trips the **content** layer (and only that layer) — the crypto layers still verify because the *receipt* is unchanged. Conversely, tampering the *receipt payload* trips the crypto layers (the recomputed preimage no longer matches the stored one) — see [§7](#7-verify-semantics).
- A missing `artifactSha256` is a **structural error**, not `ok: false`.

---

## 5. Receipt JSON structure

Every field, with type and example (drawn from a real default receipt and the frozen TSA/Rekor captures). The authoritative schema is `packaging/receipt.schema.json` (JSON Schema draft 2020-12).

```jsonc
{
  "payload": {                       // object — the artifact descriptor
    "artifactSha256": "dfc1…8043",   // string, 64-hex (no 0x) — sha256(file bytes). REQUIRED by verify.
    "path": "example.txt",           // string — artifact basename
    "size": 32,                      // integer ≥ 0 — file size in bytes
    "mime": "text/plain"             // string — guessed MIME (application/octet-stream if unknown)
  },
  "seal": {
    "method": "apohara-seal-v1",     // string, const — the method tag. REQUIRED.
    "sealedAt": "2026-01-01T00:00:00+00:00", // string, RFC 3339 — part of the preimage. REQUIRED.
    "preimage": "0x7b226d…7d",       // 0x-hex — canonical preimage bytes (§2). REQUIRED.

    "hmac": {                        // object — mandatory HMAC layer. REQUIRED.
      "alg": "HMAC-SHA256",          // string, const
      "keyId": "hmac-default",       // string
      "sig": "0xf817…3b52"           // 0x-hex, 32 bytes / 64 hex chars — over the preimage
    },

    "ed25519": {                     // object — OPTIONAL Ed25519 layer
      "keyId": "default",            // string
      "sig": "0xa0c1…7a…"            // 0x-hex, 64 bytes / 128 hex chars — over the preimage
    },
    "ed25519PublicKey": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
                                     // string (SPKI PEM) — OPTIONAL; sibling, NOT in preimage

    "c2paManifest": "0x00002ee76a756d62…",
                                     // 0x-hex of real JUMBF (SIDECAR mode) — OPTIONAL; sibling, NOT in preimage
    "c2paEmbedded": true,            // bool (EMBED mode) — manifest is in the file, not a sidecar;
                                     // mutually exclusive with c2paManifest. OPTIONAL; sibling, NOT in preimage

    "tsa": {                         // object — OPTIONAL RFC 3161 layer; sibling, NOT in preimage
      "authority": "sigstore",       // string — TSA label
      "issuedAt": "2026-06-05T13:59:48Z", // string, RFC 3339 — token genTime
      "der": "0x308204ea…"           // 0x-hex — full DER TimeStampResp
    },

    "rekorAnchor": {                 // object — OPTIONAL Rekor v2 layer; sibling, NOT in preimage
      "logIndex": 4898979,           // integer
      "logId": "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=", // string (base64) — resolves shard key
      "integratedTime": 0,           // integer — Unix seconds
      "inclusionProof": {
        "logIndex": 4898979,         // integer — 0-based leaf index
        "treeSize": 4898980,         // integer
        "rootHash": "5fd8d43c…",     // string, hex
        "hashes": ["924539b9…", …],  // array of hex strings — leaf→root siblings
        "checkpoint": "log2025-1.rekor.sigstore.dev\n4898980\n…" // string — C2SP signed note
      },
      "canonicalizedBody": "eyJhcGlW…", // string (base64) — Merkle leaf preimage
      "envelope": {                  // the submitted DSSE envelope
        "payloadType": "application/vnd.in-toto+json",
        "payload": "eyJfdHlwZSI6…",  // base64 of the in-toto Statement (subject = sha256(preimage))
        "signatures": [ { "sig": "PjV4AEXQ…" } ] // base64 Ed25519 over the DSSE PAE
      },
      "verifier": {
        "publicKey": { "rawBytes": "MCowBQYDK2VwAyEA…" }, // base64 SPKI DER of the seal Ed25519 key
        "keyDetails": "PKIX_ED25519"
      }
    }
  }
}
```

**Required vs. optional.** Top-level `payload` and `seal` are required. Inside `seal`: `method`, `sealedAt`, `preimage`, and `hmac` are required; `ed25519`, `ed25519PublicKey`, `c2paManifest`, `c2paEmbedded`, `tsa`, `rekorAnchor` are optional and serialized only when present. `c2paManifest` (sidecar) and `c2paEmbedded` (in-file) are mutually exclusive — a receipt carries at most one C2PA mode. Inside `payload`, only `artifactSha256` is required by the verifier's content layer (the seal engine itself will canonicalize any JSON object payload).

---

## 6. Seal modes

Sealing is mode-based (CLI: `apohara-sealchain seal <file> [flags]`):

| Mode | Layers | Network | Failure behavior |
|------|--------|---------|------------------|
| **default** (offline) | HMAC + Ed25519 + C2PA | none | always succeeds offline |
| `--tsa[=URL]` | + RFC 3161 TSA | TSA at seal time | a layer that can't be produced **aborts** the seal (exit 1, no receipt written) |
| `--rekor[=URL]` | + Rekor v2 | Rekor shard at seal time | aborts on failure (exit 1, no receipt) |
| `--all` | HMAC + Ed25519 + C2PA + TSA + Rekor | TSA + Rekor at seal time | **real-or-abort**: any configured layer that cannot be produced aborts the seal; nothing is faked, nothing partial is written |
| `--no-c2pa` | drops C2PA from the default set | — | — |
| `--embed` | C2PA manifest embedded **in the artifact file** (replaces the sidecar `c2paManifest`) | none | supported media only; **unsupported format ⇒ hard error (exit 2)**, never a silent sidecar. Requires the C2PA layer (not `--no-c2pa`) |

Rationale for modes (vs. a strict always-all-5): the Rekor v2 public shard rotates ~6 months, so making every seal network-bound is fragile. The default seal is fully offline and deterministic; `--all` preserves the strict "5-real-or-fail" guarantee on demand. **No theater**: a requested layer is either produced for real or the seal aborts — there is no fake/stub layer.

`--embed` (in-file C2PA embedding) is supported for embeddable media (see [§3.5.1](#351-c2pa-in-file-embedding---embed--supported-media)): the manifest is written **into** the artifact file and the receipt records `c2paEmbedded` instead of the sidecar `c2paManifest`. An **unsupported** format with `--embed` is a **hard error** (exit 2) — never a silent sidecar fallback. Without `--embed`, the offline sidecar manifest is produced as before.

---

## 7. Verify semantics

Verification returns **one result per present layer** (`{name, ok, reason}`) and an overall verdict of "all present layers ok". Two distinct verify entry points exist:

- **`verify(record, key_hmac, pubkey_pem?)`** — the core record verifier. Returns `Ok(true)` / `Ok(false)` / `Err(SealError)`.
- **`verify_artifact` / `verify_artifact_bytes`** — the artifact verifier. Returns the per-layer `Vec<LayerResult>`, adding the **content** layer ([§4](#4-content-layer-file-hash-binding)) and the present-only C2PA / TSA / Rekor layers.

Rules:

1. **Present-layers-only.** Only layers that appear in the receipt are checked. An HMAC-only receipt is valid if its preimage recomputes and its HMAC checks out.
2. **Structural error vs. tamper.**
   - *Structural* (`Err(SealError)`): not a JSON object, missing `seal`/`payload`, a seal block that won't deserialize, missing `artifactSha256`, an Ed25519 layer present with no usable public key, an unparseable preimage hex, a legacy v3 schema. Verification *could not be performed*.
   - *Tamper* (`Ok(false)` / `ok: false`): the recomputed preimage differs from the stored one, an HMAC/Ed25519 signature does not verify, a malformed signature hex, a TSA imprint mismatch, a failed Merkle/checkpoint check, a C2PA hash/validity mismatch. Verification *completed and found the record invalid*.
3. **Tamper trips the right layers.** Editing the *receipt payload* changes the recomputed preimage, so it no longer equals the stored preimage — every crypto layer reports `ok: false` (and, for C2PA, the bound payload hash no longer matches). Editing the *file* trips only the content layer.
4. **Unknown-Rekor-key is measured, not error.** A Rekor anchor whose `logId` has no pinned shard key is a measured `ok: false` (reason: `log key unknown for logId <id>`), never an `Err` and never a silent pass.
5. **HMAC needs the secret.** HMAC verification requires the shared HMAC key. In the artifact verifier, when no HMAC key is supplied (e.g. the in-browser verify-only build), the HMAC layer reports only *preimage integrity* (`ok: true` if the preimage matches and the signature is well-formed hex) — it is **not** a full MAC check and is **not** browser-verifiable without the key. Ed25519, C2PA, and Rekor-inclusion remain fully verifiable offline from the embedded/pinned keys.
6. **Schema gate.** `detect_schema` requires `seal.sealedAt` (a string) → schema V4 (the `apohara-seal-v1` shape). A legacy v3 record (top-level `sealedAt`, no `seal.sealedAt`) is a hard error (`UnsupportedSchemaV3`). Anything else is `Malformed`.
7. **Build-dependent layers (wasm).** In the `verify-only` (wasm) browser build, TSA and Rekor verification (which need the sigstore stack + pinned keys) are reported as **present but not verified in this build** — an honest `ok: false` with a clear reason, not a faked pass. Content, HMAC (preimage-integrity), Ed25519, and C2PA verify in the browser.

---

## 8. What each layer proves (honest framing)

- **HMAC-SHA256** — integrity + authenticity to any holder of the shared secret. Not publicly verifiable.
- **Ed25519** — authorship by the holder of the seal's private key; publicly verifiable with the embedded public key.
- **RFC 3161 TSA** — existence-before-time, per the TSA. The free FreeTSA/Sigstore path is **not a legally-qualified timestamp**; point `--tsa` at an eIDAS QTSP for legal weight.
- **Rekor v2** — public transparency-log inclusion (the entry is in a tamper-evident append-only log), verifiable offline from the bundled proof + pinned shard key.
- **C2PA** — an embedded, signed provenance manifest binding the canonical payload hash; **Valid** (self-signed) in v0.1, not anchored to a production trust list.

---

## 9. Interoperability scope

| Layer | Interop scope |
|-------|---------------|
| **HMAC-SHA256** | **Bidirectional** with the Python `core/seal` reference — byte-compatible. A Python-sealed record verifies in Rust and vice versa. |
| **Ed25519** | **Bidirectional** with the Python reference — byte-compatible (same preimage, same RFC 8032 signature). |
| **RFC 3161 TSA** | **Rust-canonical.** No Python round-trip claimed; verified offline against frozen real captures. |
| **Rekor v2** | **Rust-canonical** (the Python reference's checkpoint verification is inconsistent). No Python round-trip claimed; verified offline against frozen real captures + pinned shard key. |
| **C2PA** | **Rust-canonical** (real JUMBF; the Python path is inconsistent and can fall back to non-real C2PA). No Python round-trip claimed. |

JCS canonicalization itself is byte-identical to the Python reference — that is the shared foundation that makes the HMAC + Ed25519 layers bidirectional.

---

## 10. Conformance vectors

Three tiers, located under `crates/apohara-sealchain-core/tests/vectors/`:

- **Tier-A — deterministic corpus (26 records).** `vec_01`…`vec_26` plus `INDEX.json` and `keys.json` (fixed, non-secret test keys; pinned `sealed_at = 2026-01-01T00:00:00+00:00`). These cover HMAC-only and HMAC+Ed25519 across JCS edge cases (astral/CJK/combining/RTL unicode, number formatting incl. `-0.0`→`0`, int bounds, deep nesting, arrays of objects, empty containers, escapes, excluded-key stripping, JCS key sorting, artifact descriptors). With the fixed keys, the Rust engine reproduces every stored seal byte-for-byte.
- **Tier-B — Python interop (HMAC + Ed25519).** The bidirectional gate: a Python-sealed record verifies in Rust and a Rust-sealed record verifies in Python (`core.seal.verify`), with byte-identical JCS. Scope is exactly the two byte-compatible layers.
- **Tier-C — frozen real captures (TSA / Rekor).** Real, recorded artifacts verified offline: `tests/vectors/tsa/sigstore_token.json` (a real RFC 3161 token) and `tests/vectors/rekor/log2025-1_anchor.json` (a real Rekor v2 anchor with inclusion proof + checkpoint). These exercise the Rust-canonical layers without claiming a Python round-trip.

---

## 11. Versioning & changelog

**v1** — `method = "apohara-seal-v1"` (internally schema V4: timestamp at `seal.sealedAt`). Initial public specification covering the preimage, the 5 layers (HMAC, Ed25519, TSA, Rekor v2, C2PA), the content layer, verify semantics, seal modes, interop scope, and the conformance tiers above.

**Stability statement.** This format is stable for the v0.1 release and the `apohara-seal-v1` tag will not change meaning. That said, **this format may evolve**: future layers may be added (they would be optional siblings, outside the preimage, so existing receipts keep verifying), the pinned Rekor shard set in `packaging/rekor-shards.json` will be updated as shards rotate (a config change, not a format change), and any breaking change to the preimage or an existing layer's binding will ship under a new `method` tag with its own vectors. Schema detection already hard-errors on the legacy v3 shape; new generations will be detectable the same way.
