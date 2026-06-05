#!/usr/bin/env bash
# Seal your fine-tune and prove it's yours — a HuggingFace end-to-end example.
#
# Flow: download real (small, stable) HF files — a model card AND a weights file
# — seal each offline (HMAC + Ed25519 + C2PA) -> verify (PASS) -> show the chain
# -> emit an in-toto/SLSA-style provenance Statement for the weights. Optionally,
# with SEAL_ALL=1, add the network-backed transparency layers (RFC-3161 TSA +
# Sigstore Rekor v2) in a real-or-abort seal.
#
# What this proves, honestly:
#   - content  : the published file is byte-for-byte the one you sealed (sha256).
#   - ed25519  : it was sealed by the holder of this key pair (authorship). The
#                public key travels inside the receipt, so anyone can check it.
#   - c2pa     : a real JUMBF provenance manifest binds the payload hash.
#   - hmac     : a local integrity tag (symmetric; only the key holder can
#                re-check it — it is NOT a public-authorship claim).
#   - tsa/rekor (only with SEAL_ALL=1): the seal existed before a point in time
#                (TSA) and is recorded in a public transparency log (Rekor).
#
# The `provenance` step maps the receipt onto an in-toto Statement v1 whose
# subject digest IS the artifact's sha256 and whose predicate reflects the real
# layers above. The predicateType is an apohara apohara-sealchain predicate — SLSA-style
# (in-toto envelope) but NOT slsa.dev build provenance: apohara-sealchain seals
# artifacts, it does not run builds, and the predicate says so.
#
# Isolation: keys live in a throwaway XDG_CONFIG_HOME under a temp dir that is
# removed on exit, so your real keystore is never touched. Set SEAL_KEEP=1 to
# keep the workspace (it prints the path) if you want to inspect the receipts.
#
# Usage:
#   examples/huggingface/seal-hf-model.sh          # offline seal+verify+show+provenance
#   SEAL_ALL=1 examples/huggingface/seal-hf-model.sh   # + TSA + Rekor (network)
#   SEAL_KEEP=1 examples/huggingface/seal-hf-model.sh  # keep the workspace
#   SEALCHAIN=/path/to/apohara-sealchain examples/huggingface/seal-hf-model.sh
#   HF_CARD_URL=<url> HF_WEIGHTS_URL=<url> examples/huggingface/seal-hf-model.sh

set -euo pipefail

# --- the HuggingFace artifacts -----------------------------------------------
# Two real files from the Hub, both tiny and stable:
#   * the model CARD / metadata — gpt2's config.json (~665 bytes), public and
#     human-readable. A model card is just another artifact: you seal it the same
#     way you seal weights.
#   * the WEIGHTS — a real ~443 KB `model.safetensors` from the stable test repo
#     `hf-internal-testing/tiny-random-gpt2`. Sealing weights is identical to
#     sealing any other file: only the bytes differ. Point HF_WEIGHTS_URL at your
#     own `*.safetensors` to seal a real fine-tune.
HF_CARD_URL="${HF_CARD_URL:-https://huggingface.co/gpt2/resolve/main/config.json}"
HF_WEIGHTS_URL="${HF_WEIGHTS_URL:-https://huggingface.co/hf-internal-testing/tiny-random-gpt2/resolve/main/model.safetensors}"

# --- locate the binary -------------------------------------------------------
# Script lives in examples/huggingface/, so the repo root is two levels up.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${SEALCHAIN:-}"
if [ -z "$BIN" ]; then
  if [ -x "$REPO_ROOT/target/release/apohara-sealchain" ]; then
    BIN="$REPO_ROOT/target/release/apohara-sealchain"
  elif command -v apohara-sealchain >/dev/null 2>&1; then
    BIN="$(command -v apohara-sealchain)"
  else
    echo "==> building apohara-sealchain (release)…"
    cargo build --release --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p apohara-sealchain
    BIN="$REPO_ROOT/target/release/apohara-sealchain"
  fi
fi

# --- isolated, self-cleaning workspace ---------------------------------------
WORK="$(mktemp -d)"
if [ "${SEAL_KEEP:-0}" = "1" ]; then
  echo "==> SEAL_KEEP=1: workspace kept at $WORK"
else
  trap 'rm -rf "$WORK"' EXIT
fi
export XDG_CONFIG_HOME="$WORK/cfg"
CONFIG_DIR="$XDG_CONFIG_HOME/apohara-sealchain"

# Name the local copies after the remote files so the receipts read naturally.
CARD="$WORK/$(basename "$HF_CARD_URL")"
WEIGHTS="$WORK/$(basename "$HF_WEIGHTS_URL")"
CARD_RECEIPT="$CARD.seal.json"
WEIGHTS_RECEIPT="$WEIGHTS.seal.json"

# A fixed HMAC key keeps the example self-contained. In real use this is YOUR
# secret — never publish it, and never commit it. The Ed25519 key is what proves
# authorship publicly; the HMAC key is a private local-integrity tag.
HMAC_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

say "1. keygen — create an Ed25519 + HMAC key pair (in a throwaway keystore)"
"$BIN" keygen --config-dir "$CONFIG_DIR"

say "2. download — fetch a real model card AND a real weights file"
echo "GET $HF_CARD_URL"
curl -fsSL "$HF_CARD_URL" -o "$CARD"
printf 'saved %s (%s bytes)\n' "$(basename "$CARD")" "$(wc -c < "$CARD")"
echo "GET $HF_WEIGHTS_URL"
curl -fsSL "$HF_WEIGHTS_URL" -o "$WEIGHTS"
printf 'saved %s (%s bytes)\n' "$(basename "$WEIGHTS")" "$(wc -c < "$WEIGHTS")"

say "3. seal — produce an offline receipt for BOTH files (HMAC + Ed25519 + C2PA)"
"$BIN" seal "$CARD" "$WEIGHTS" \
  --key "$CONFIG_DIR/ed25519.pem" \
  --hmac-key "$HMAC_KEY"

# Optional: add the network-backed transparency layers to the WEIGHTS. real-or-
# abort — if the TSA or Rekor cannot be reached, the seal aborts and no receipt
# is written.
if [ "${SEAL_ALL:-0}" = "1" ]; then
  say "3b. seal --all — add RFC-3161 TSA + Sigstore Rekor v2 to the weights (needs network)"
  echo "(real-or-abort: if a layer can't be produced, the seal aborts)"
  "$BIN" seal "$WEIGHTS" \
    --all \
    --key "$CONFIG_DIR/ed25519.pem" \
    --hmac-key "$HMAC_KEY"
fi

say "4. verify — every present layer checks out for BOTH files (PASS, exit 0)"
echo "-- model card --"
"$BIN" verify "$CARD" "$CARD_RECEIPT" --hmac-key "$HMAC_KEY"
echo "-- weights --"
"$BIN" verify "$WEIGHTS" "$WEIGHTS_RECEIPT" --hmac-key "$HMAC_KEY"

say "5. show — human-readable chain trail of the weights receipt"
"$BIN" show "$WEIGHTS_RECEIPT"

say "6. provenance — in-toto/SLSA-style Statement for the weights"
echo "(subject digest == the artifact sha256; predicate = the real layers above;"
echo " predicateType is an apohara apohara-sealchain predicate, NOT slsa.dev build provenance)"
"$BIN" provenance "$WEIGHTS_RECEIPT"

say "done — sealed a real model card + weights, verified both, emitted provenance"
echo "Publish the .seal.json receipts next to the model on the Hub; anyone can"
echo "verify them offline with the apohara-sealchain CLI or the in-browser WASM verifier,"
echo "and consume the in-toto Statement in their supply-chain tooling."
