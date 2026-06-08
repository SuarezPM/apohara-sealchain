# apohara-sealchain — offline in-browser receipt verifier

A static, drag-and-drop web page that verifies a apohara-sealchain receipt
(`<artifact>.seal.json`) against its artifact **fully offline in the browser**.
No network: everything runs locally in WebAssembly compiled from
`crates/sealchain-wasm`.

**Hosted:** the verifier runs live at
<https://suarezpm.github.io/apohara-sealchain/>, deployed from `web/` by
[`.github/workflows/pages.yml`](../.github/workflows/pages.yml) (which builds the
wasm with wasm-pack — the compiled `.wasm` is not committed).

## What is verified in the browser

| Layer    | In-browser result | Why |
|----------|-------------------|-----|
| `content`  | **verifiable** | `sha256(file) == payload.artifactSha256` |
| `ed25519`  | **verifiable** | checked against the receipt's embedded `ed25519PublicKey` (self-contained) |
| `c2pa`     | **verifiable** | the JUMBF sidecar is parsed by the real `c2pa::Reader` and the bound payload hash is checked, fully offline |
| `hmac`     | **not checkable** | HMAC is symmetric; its secret key is never in the receipt and is never shipped to the browser. The verifier says so honestly (amber `—`) instead of faking a pass. |
| `tsa` / `rekor` | **present, not checked** | their network-layer verification needs the bundled sigstore keys. Reported as present-but-unverified, never faked. |

The overall `VERIFIED` verdict covers every *browser-checkable* layer (content +
Ed25519 + C2PA). A tampered artifact trips the `content` layer and flips the
verdict to `NOT VERIFIED`.

## Build the wasm

Requires the Rust toolchain with the `wasm32-unknown-unknown` target and
[`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```sh
rustup target add wasm32-unknown-unknown   # once
cargo install wasm-pack                     # once

# from the repo root:
wasm-pack build crates/sealchain-wasm --target web --out-dir ../../web/pkg --release
```

This generates `web/pkg/` (the `.wasm` binary, JS glue, and `.d.ts`). `web/pkg/`
is **git-ignored**: it is build output, regenerated locally or by the Pages
workflow, never committed (keeps the compiled `.wasm` out of the source repo).

## Serve

The page must be served over HTTP (ES modules + wasm do not load from
`file://`). Any static server works, e.g.:

```sh
python3 -m http.server --directory web 8000
# then open http://localhost:8000/
```

Or with Node: `npx serve web` (or any equivalent). No backend is required.

## Use

1. Drop the artifact and its `<artifact>.seal.json` onto the drop zone
   (or pick them with the two file inputs). A dropped `*.json` is routed to the
   receipt slot; any other file becomes the artifact.
2. Click **Verify offline**.
3. The per-layer chain renders green (verified), red (failed), or amber
   (`—`, not checkable in the browser, i.e. HMAC).

## Offline guarantee

`web/index.html` ships a Content-Security-Policy of `default-src 'none'` with
`connect-src 'self'` — the only fetch is the local `.wasm` binary from the same
origin. There are no third-party origins and no outbound connections.
