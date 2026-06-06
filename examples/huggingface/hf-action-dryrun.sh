#!/usr/bin/env bash
# Dry-run of the `huggingface-seal` GitHub Action's local path (B-6): seal a model
# file and verify the receipt OFFLINE, with NO upload to the Hub — exactly what the
# action does when no `hf_token` is supplied. Proves the action's seal+verify
# contract end-to-end without touching HuggingFace or your real keystore.
#
# Usage:
#   examples/huggingface/hf-action-dryrun.sh
#   SEALCHAIN=/path/to/apohara-sealchain examples/huggingface/hf-action-dryrun.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${SEALCHAIN:-}"
if [ -z "$BIN" ]; then
  if [ -x "$REPO_ROOT/target/release/apohara-sealchain" ]; then
    BIN="$REPO_ROOT/target/release/apohara-sealchain"
  elif command -v apohara-sealchain >/dev/null 2>&1; then
    BIN="$(command -v apohara-sealchain)"
  else
    cargo build --release --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p apohara-sealchain
    BIN="$REPO_ROOT/target/release/apohara-sealchain"
  fi
fi

# Isolated, self-cleaning workspace (keys + model live under a temp dir).
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export XDG_CONFIG_HOME="$WORK/cfg"
MODEL="$WORK/model.safetensors"
# A stand-in "fine-tune" payload (the action seals whatever file you point it at).
head -c 4096 /dev/urandom > "$MODEL"

say() { printf '\n== %s ==\n' "$1"; }

say "1. acquire — using $BIN"
"$BIN" --version

say "2. keygen (throwaway keystore)"
"$BIN" keygen --config-dir "$XDG_CONFIG_HOME/apohara-sealchain" >/dev/null

say "3. seal the model (offline: HMAC + Ed25519 + C2PA)"
"$BIN" seal "$MODEL" \
  --key "$XDG_CONFIG_HOME/apohara-sealchain/ed25519.pem" \
  --hmac-key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
RECEIPT="$MODEL.seal.json"
test -f "$RECEIPT" || { echo "FAIL: no receipt produced"; exit 1; }

say "4. verify the receipt OFFLINE (the action aborts here on failure, before upload)"
"$BIN" verify "$MODEL" "$RECEIPT" \
  --hmac-key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

say "5. DRY-RUN — no hf_token, so nothing is uploaded to the Hub"
echo "sealed + verified locally: $RECEIPT"
echo "(set hf_token + repo_id on the action to upload this receipt to a model card)"

say "dry-run complete — sealed, verified, no upload"
