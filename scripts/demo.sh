#!/usr/bin/env bash
# Reproducible end-to-end demo / CI smoke test for apohara-sealchain.
#
# Flow: keygen -> seal (offline: HMAC+Ed25519+C2PA) -> verify (PASS) ->
# flip one byte -> verify (FAIL at the content layer) -> restore -> show.
#
# Deterministic by construction: a pinned `--sealed-at`, a fixed HMAC key, and an
# isolated temp `XDG_CONFIG_HOME` + temp workdir (both cleaned up on exit). The
# tamper step is *expected* to exit 1; that exit is captured here so the script
# itself exits 0 on the happy path, which is what lets it double as a CI smoke
# test. Any unexpected failure aborts via `set -e` and a non-zero exit.
#
# Usage:
#   scripts/demo.sh            # uses target/release/apohara-sealchain, builds if missing
#   SEALCHAIN=/path/to/bin scripts/demo.sh   # use an explicit binary

set -euo pipefail

# --- locate the binary -------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
trap 'rm -rf "$WORK"' EXIT
export XDG_CONFIG_HOME="$WORK/cfg"
CONFIG_DIR="$XDG_CONFIG_HOME/apohara-sealchain"
ARTIFACT="$WORK/model.bin"
RECEIPT="$ARTIFACT.seal.json"

# Pinned inputs so every run is byte-identical.
SEALED_AT="2026-01-01T00:00:00+00:00"
HMAC_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

say "1. keygen — create an Ed25519 + HMAC key pair"
"$BIN" keygen --config-dir "$CONFIG_DIR"

say "2. seal — produce an offline receipt (HMAC + Ed25519 + C2PA)"
printf 'hello apohara-sealchain demo' > "$ARTIFACT"
"$BIN" seal "$ARTIFACT" \
  --sealed-at "$SEALED_AT" \
  --key "$CONFIG_DIR/ed25519.pem" \
  --hmac-key "$HMAC_KEY"

say "3. verify — every present layer checks out (PASS, exit 0)"
"$BIN" verify "$ARTIFACT" "$RECEIPT" --hmac-key "$HMAC_KEY"

say "4. tamper — flip one byte, then verify (expected FAIL at content layer)"
printf 'hello apohara-sealchain dem!' > "$ARTIFACT"
# The tamper verify MUST fail (exit 1). Capture it so the demo stays exit-0.
set +e
"$BIN" verify "$ARTIFACT" "$RECEIPT" --hmac-key "$HMAC_KEY"
TAMPER_RC=$?
set -e
if [ "$TAMPER_RC" -ne 1 ]; then
  echo "DEMO ERROR: tampered verify returned $TAMPER_RC, expected 1" >&2
  exit 1
fi
echo "(verify exited $TAMPER_RC as expected — tamper detected)"

say "5. show — human-readable chain trail of the receipt"
printf 'hello apohara-sealchain demo' > "$ARTIFACT"  # restore (purely cosmetic)
"$BIN" show "$RECEIPT"

say "demo complete — sealed, verified, detected tamper, exited 0"
