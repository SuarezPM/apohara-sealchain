# HuggingFace: seal your fine-tune and prove it's yours

This example takes real files from the HuggingFace Hub — a **model card** and a
**weights file** — seals each into a tamper-evident `<file>.seal.json` receipt,
verifies them, and emits an **in-toto/SLSA-style provenance Statement** — end to
end. Publish the receipts next to your model on the Hub and **anyone** can prove,
offline, that the files they downloaded are byte-for-byte the ones you sealed, and
that *you* (the holder of your Ed25519 key) sealed them.

No account, no SaaS, no `verified=true` hardcoded anywhere. Every layer either
produces and re-checks its own crypto, or the seal aborts.

- Script: [`seal-hf-model.sh`](./seal-hf-model.sh)
- Flow: **download → seal → verify → show → provenance**

## The trust story

When you ship weights to the Hub, a downloader has no way to know whether the
file was altered in transit, on a mirror, or by a malicious re-upload — and no
way to know *you* produced it. Sealing answers both:

| Layer | What a verifier learns | How |
|-------|------------------------|-----|
| `content` | the file is **byte-for-byte** the one you sealed | `sha256(file) == payload.artifactSha256` |
| `ed25519` | it was sealed by **the holder of your key** (authorship) | signature checked against the public key embedded in the receipt |
| `c2pa` | a real **provenance manifest** binds the payload hash | JUMBF sidecar parsed by `c2pa::Reader`, bound hash re-checked |
| `hmac` | a **private** local-integrity tag | symmetric — only *you* can re-check it; it is not a public-authorship claim |
| `tsa` *(optional)* | the seal **existed before a point in time** | RFC-3161 token from a timestamp authority |
| `rekor` *(optional)* | the seal is in a **public transparency log** | Sigstore Rekor v2 inclusion proof |

The first four are **fully offline** — no network at seal or verify time. The
last two (`--all` / `SEAL_ALL=1`) add public transparency and need network *at
seal time*.

Honest scope: Ed25519 proves *the key holder* sealed it. It does **not** by
itself bind that key to a real-world identity — that's what the optional
transparency layers (and, in a fuller deployment, a key you publish on your Hub
profile or sign with a known identity) are for. HMAC is symmetric: it is a
private integrity tag, not something a third party can verify without your
secret, and the verifier says so honestly instead of faking a pass.

## Provenance: an in-toto Statement, honestly typed

`apohara-sealchain provenance <receipt>` maps a receipt onto an **in-toto Statement v1**
so the seal plugs into the wider supply-chain ecosystem (cosign, policy engines,
attestation stores):

- `subject[0].digest.sha256` **is** the artifact's `artifactSha256` — edit the
  payload and the subject digest changes with it.
- `predicate` reflects the **real** present layers above (hmac/ed25519/c2pa, plus
  tsa/rekor when sealed with them), each with an honest `offlineVerifiable` flag.

The `predicateType` is **`https://apohara.dev/sealchain/provenance/v1`** — a
apohara-sealchain attestation predicate, SLSA-style (it reuses the in-toto envelope) but
deliberately **not** `slsa.dev/provenance`. SLSA Build provenance attests *how a
build system produced* an artifact; apohara-sealchain does not run or observe a build, it
**seals** an existing artifact. Claiming SLSA Build semantics would mis-state what
we can prove, so the predicate type names what this actually is.

## Run it

```sh
# from the repo root (builds apohara-sealchain if no release binary is present):
examples/huggingface/seal-hf-model.sh
```

Knobs (all optional, via env vars):

| Var | Effect |
|-----|--------|
| `HF_CARD_URL=<url>` | seal a different model card / metadata file (default: `gpt2/config.json`) |
| `HF_WEIGHTS_URL=<url>` | seal a different weights file (default: `hf-internal-testing/tiny-random-gpt2/model.safetensors`) |
| `SEAL_ALL=1` | also add the network-backed TSA + Rekor transparency layers (to the weights) |
| `SEAL_KEEP=1` | keep the temp workspace (prints its path) to inspect the receipts |
| `SEALCHAIN=/path/to/apohara-sealchain` | use an explicit binary instead of building |

The script uses a throwaway `XDG_CONFIG_HOME` under a temp dir that is removed on
exit, so **your real keystore is never touched**. Pass `SEAL_KEEP=1` if you want
to keep the generated keys and receipts.

### Which files?

The defaults are two **real** Hub files:

- **model card / metadata** — `gpt2`'s `config.json` (~665 bytes): tiny, public,
  stable, human-readable. A model card is just another artifact; you seal it the
  same way you seal weights.
- **weights** — a real ~443 KB `model.safetensors` from the stable test repo
  `hf-internal-testing/tiny-random-gpt2`. This is genuine `.safetensors` weight
  data: sealing weights is **identical** to sealing any other file — content +
  Ed25519 + C2PA bind the exact bytes; only the bytes differ.

The Hub serves any file at `https://huggingface.co/<repo>/resolve/main/<file>`,
so to seal a real fine-tune just point `HF_WEIGHTS_URL` at your repo's
`*.safetensors` (and `HF_CARD_URL` at its `config.json`/`README.md`). The flow is
identical; only the bytes change.

## Real captured output

> The transcript below is **real, captured output** from running
> `examples/huggingface/seal-hf-model.sh` against the live HuggingFace Hub on
> 2026-06-05. The `sealedAt` timestamp and the freshly generated key are why a
> re-run differs; the layers and the `PASS` verdict are stable. ANSI colors are
> stripped for readability.

```text
== 1. keygen — create an Ed25519 + HMAC key pair (in a throwaway keystore) ==
Keys ready in /tmp/.../cfg/apohara-sealchain
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw6UB7aEQsyPy6aKId0Irhd0fy59GGnmpOox46PaNlhc=
-----END PUBLIC KEY-----

== 2. download — fetch a real model card AND a real weights file ==
GET https://huggingface.co/gpt2/resolve/main/config.json
saved config.json (665 bytes)
GET https://huggingface.co/hf-internal-testing/tiny-random-gpt2/resolve/main/model.safetensors
saved model.safetensors (453864 bytes)

== 3. seal — produce an offline receipt for BOTH files (HMAC + Ed25519 + C2PA) ==
OK   /tmp/.../config.json -> /tmp/.../config.json.seal.json
       layers: hmac, ed25519, c2pa
OK   /tmp/.../model.safetensors -> /tmp/.../model.safetensors.seal.json
       layers: hmac, ed25519, c2pa
summary: 2 sealed, 0 failed

== 4. verify — every present layer checks out for BOTH files (PASS, exit 0) ==
-- model card --
PASS
  content  [ok] artifact hash matches receipt
  hmac     [ok] hmac verified
  ed25519  [ok] ed25519 verified
  c2pa     [ok] c2pa manifest valid; payload hash bound
-- weights --
PASS
  content  [ok] artifact hash matches receipt
  hmac     [ok] hmac verified
  ed25519  [ok] ed25519 verified
  c2pa     [ok] c2pa manifest valid; payload hash bound

== 5. show — human-readable chain trail of the weights receipt ==
method:   apohara-seal-v1
sealedAt: 2026-06-05T18:07:12+00:00
artifact: model.safetensors (453864 bytes)
layers:
  hmac      [HMAC-SHA256]
  ed25519 (public key embedded)
  c2pa      (sidecar JUMBF manifest)

== 6. provenance — in-toto/SLSA-style Statement for the weights ==
(subject digest == the artifact sha256; predicate = the real layers above;
 predicateType is an apohara-sealchain predicate, NOT slsa.dev build provenance)
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "model.safetensors",
      "digest": {
        "sha256": "8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500"
      }
    }
  ],
  "predicateType": "https://apohara.dev/sealchain/provenance/v1",
  "predicate": {
    "method": "apohara-seal-v1",
    "sealedAt": "2026-06-05T18:07:12+00:00",
    "attestations": [
      {
        "type": "hmac",
        "alg": "HMAC-SHA256",
        "keyId": "hmac-default",
        "offlineVerifiable": false,
        "note": "symmetric integrity tag; the secret is not in the receipt, so only the key holder can re-check it. Not a public-authorship claim."
      },
      {
        "type": "ed25519",
        "keyId": "default",
        "offlineVerifiable": true,
        "note": "signature over the canonical preimage; proves the key holder sealed this artifact (authorship), checkable offline.",
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAw6UB7aEQsyPy6aKId0Irhd0fy59GGnmpOox46PaNlhc=\n-----END PUBLIC KEY-----\n"
      },
      {
        "type": "c2pa",
        "mode": "sidecar",
        "offlineVerifiable": true,
        "note": "sidecar JUMBF manifest binding the payload hash; verified offline."
      }
    ]
  }
}

== done — sealed a real model card + weights, verified both, emitted provenance ==
Publish the .seal.json receipts next to the model on the Hub; anyone can
verify them offline with the apohara-sealchain CLI or the in-browser WASM verifier,
and consume the in-toto Statement in their supply-chain tooling.
```

`verify` exits `0` on the all-layers-pass path above. Flip a single byte of
either file and `verify` exits `1` with `content [FAIL] artifact hash mismatch` —
the tamper is caught. The provenance `subject.digest.sha256` is the artifact's own
`artifactSha256`, so editing the payload changes the subject digest with it.

## What the published receipt looks like

The `<file>.seal.json` you publish is self-contained JSON. Long crypto values
are truncated here for readability:

```jsonc
{
  "payload": {
    "artifactSha256": "0daed7749b4f02b8f76240d5…",  // sha256 of the file
    "path": "config.json",
    "size": 665,
    "mime": "application/json"
  },
  "seal": {
    "method": "apohara-seal-v1",
    "sealedAt": "2026-06-05T17:17:23+00:00",
    "preimage": "0x7b226d6574686f64223a22…",        // canonical signed bytes
    "hmac":    { "alg": "HMAC-SHA256", "keyId": "hmac-default", "sig": "0x…" },
    "ed25519": { "keyId": "default", "sig": "0x…" },
    "ed25519PublicKey": "-----BEGIN PUBLIC KEY-----…", // embedded, self-contained
    "c2paManifest": "0x00002ee76a756d62…"            // real JUMBF manifest
  }
}
```

Because the Ed25519 **public** key is embedded, a verifier needs nothing but the
file and this receipt to check `content`, `ed25519`, and `c2pa`. The HMAC `sig`
is present but only *you* can re-check it (the secret is never in the receipt).

## Publish it, then let a consumer verify

1. **Seal locally** (the script above). You get `config.json.seal.json`.
2. **Publish the receipt next to the model** on the Hub — upload
   `config.json.seal.json` to the same repo as the file it seals. Receipts are
   small JSON sidecars; they sit alongside the weights.
3. **A consumer verifies** with either path:

   **CLI** — download both files, then:

   ```sh
   apohara-sealchain verify config.json config.json.seal.json
   # PASS  (content + ed25519 + c2pa verify offline; add --hmac-key <hex>
   #        only if you also share the symmetric key, which is rarely the point)
   apohara-sealchain show config.json.seal.json   # print the chain
   ```

   Note: without `--hmac-key`, the CLI checks the offline public layers
   (content, ed25519, c2pa) and skips the symmetric HMAC — exactly the layers a
   third party *can* check.

   **In the browser (WASM)** — drag the file and its `.seal.json` onto the
   offline verifier in [`web/`](../../web/) (`python3 -m http.server
   --directory web 8000`, then open `http://localhost:8000/`). It verifies
   `content` + `ed25519` + `c2pa` fully offline in WebAssembly — no backend, no
   upload. HMAC shows as `—` (not checkable without the secret), never faked.
4. **A consumer (or CI gate) consumes the provenance** — emit the in-toto
   Statement and feed it to supply-chain tooling:

   ```sh
   apohara-sealchain provenance model.safetensors.seal.json          # pretty JSON
   apohara-sealchain provenance model.safetensors.seal.json --json   # compact (one line)
   ```

   The Statement's `subject.digest.sha256` is the weights' own `artifactSha256`,
   and its `predicate.attestations` mirror the receipt's real layers — so a
   policy engine can gate on "this digest was sealed by this key" without trusting
   the producer's prose.

## Optional: add public transparency (`SEAL_ALL=1`)

```sh
SEAL_ALL=1 examples/huggingface/seal-hf-model.sh
```

This re-seals with `--all`, adding two **network-backed** layers at seal time:

- **RFC-3161 TSA** — a timestamp authority signs that the seal existed before a
  point in time.
- **Sigstore Rekor v2** — the seal is recorded in a public transparency log.

`--all` is **real-or-abort**: if either layer cannot be produced (network down,
authority unreachable), the seal aborts and **no receipt is written** — there is
never a partial or faked receipt. These layers need connectivity *when you
seal*; once written, `content`/`ed25519`/`c2pa` still verify offline.

## Optional: enforce a policy & build a transparency dashboard

Once the receipts exist, you can **enforce a bar** and **survey them at a glance**
(both fully offline). Enforce a named profile or a custom policy at verify time:

```sh
# The default offline seal satisfies offline-basic (exit 0)
apohara-sealchain verify model.safetensors model.safetensors.seal.json --profile offline-basic

# Require public transparency: an offline receipt fails this (exit 5), a
# receipt sealed with SEAL_ALL=1 (which adds Rekor) passes.
apohara-sealchain verify model.safetensors model.safetensors.seal.json --profile transparency
```

`verify` exits `0` when the policy is met, `5` when the receipt is crypto-valid
but does not meet the policy, and `1` if the file was tampered. Then render a
self-contained, offline HTML report of every receipt in the workspace:

```sh
apohara-sealchain dashboard --from-dir . --profile offline-basic -o transparency.html
# open transparency.html — one row per receipt, layers, an honest verify status,
# and a per-row compliance column. No network, no server.
```

See [`docs/POSITIONING.md`](../../docs/POSITIONING.md) and
[`examples/policies/`](../policies/) for the full trust-profile → policy →
dashboard story.
