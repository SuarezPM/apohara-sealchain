# `seal-artifact` action

Reusable composite GitHub Action that seals a build artifact with the
[`apohara-sealchain`](https://github.com/SuarezPM/apohara-sealchain) CLI, producing a
tamper-evident `<artifact>.seal.json` receipt.

By default the seal is **fully offline** (HMAC + Ed25519 + C2PA, no network).
Pass `args: --all` (or `--tsa` / `--rekor`) to add the network-backed
RFC 3161 TSA and Sigstore Rekor transparency layers — those **require network
access at seal time**, and with `--all` any layer that cannot be produced aborts
the seal (no partial receipt is written).

## Inputs

| Input     | Required | Default    | Description |
|-----------|----------|------------|-------------|
| `path`    | yes      | —          | Path to the artifact to seal. |
| `args`    | no       | `""`       | Extra flags passed verbatim to `apohara-sealchain seal` (e.g. `--all`, `--no-c2pa`, `--embed`, `--tsa [url]`, `--rekor [url]`, `--sealed-at <ts>`). |
| `out`     | no       | `""`       | Receipt output path. Defaults to `<path>.seal.json` next to the artifact. |
| `version` | no       | `latest`   | Which apohara-sealchain release to use. `latest` resolves the newest published GitHub Release; otherwise a tag like `v0.1.0`. |

## Outputs

| Output    | Description |
|-----------|-------------|
| `receipt` | Path to the produced `.seal.json` receipt. |

## Binary acquisition

The action obtains the `apohara-sealchain` CLI binary (not the `apohara-sealchain` npx
wrapper, which is MCP-mode only) in this order:

1. If `apohara-sealchain` is already on `PATH`, it is used as-is.
2. If `cargo-binstall` is available, `cargo binstall apohara-sealchain` pulls the
   prebuilt binary (no compile). Best-effort; falls through on failure.
3. Otherwise `gh release download` fetches the release asset matching the
   runner OS (`apohara-sealchain-x86_64-unknown-linux-gnu`,
   `apohara-sealchain-aarch64-apple-darwin`, or
   `apohara-sealchain-x86_64-pc-windows-msvc.exe`) and puts it on `PATH`.

## Usage: seal release assets on tag

This workflow runs when a GitHub Release is published, downloads each release
asset, seals it (offline), and uploads the resulting `.seal.json` receipts back
to the same release.

```yaml
name: seal-release-assets

on:
  release:
    types: [published]

permissions:
  contents: write

jobs:
  seal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Pull the asset to seal (one per job step; use the matrix variant below
      # to fan out across every release asset).
      - name: Download release asset
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          mkdir -p dist
          gh release download "${{ github.event.release.tag_name }}" \
            --repo "${{ github.repository }}" \
            --pattern "apohara-sealchain-x86_64-unknown-linux-gnu" \
            --dir dist --clobber

      # Seal the artifact via this action.
      - name: Seal artifact
        id: seal
        uses: ./.github/actions/seal-artifact
        with:
          path: dist/apohara-sealchain-x86_64-unknown-linux-gnu
          # args: --all      # opt in to TSA + Rekor (needs network at seal time)

      # Upload the produced receipt back to the release.
      - name: Upload receipt to release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release upload "${{ github.event.release.tag_name }}" \
            "${{ steps.seal.outputs.receipt }}" \
            --repo "${{ github.repository }}" --clobber
```

### Matrix variant (seal every asset)

A composite action runs once per `uses:`, so to seal many assets either list a
step per asset or drive it with a matrix:

```yaml
jobs:
  seal:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        asset:
          - apohara-sealchain-x86_64-unknown-linux-gnu
          - apohara-sealchain-aarch64-apple-darwin
          - apohara-sealchain-x86_64-pc-windows-msvc.exe
    steps:
      - uses: actions/checkout@v4
      - name: Download asset
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download "${{ github.event.release.tag_name }}" \
            --repo "${{ github.repository }}" \
            --pattern "${{ matrix.asset }}" --dir dist --clobber
      - id: seal
        uses: ./.github/actions/seal-artifact
        with:
          path: dist/${{ matrix.asset }}
      - name: Upload receipt
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release upload "${{ github.event.release.tag_name }}" \
            "${{ steps.seal.outputs.receipt }}" \
            --repo "${{ github.repository }}" --clobber
```

## Verifying a sealed asset

Consumers verify a downloaded asset against its receipt with the same CLI:

```bash
apohara-sealchain verify ./apohara-sealchain-x86_64-unknown-linux-gnu \
  ./apohara-sealchain-x86_64-unknown-linux-gnu.seal.json
```
