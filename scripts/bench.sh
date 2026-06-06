#!/usr/bin/env bash
# Reproducible, honest micro-benchmark for apohara-sealchain (OFFLINE profile only).
#
# Measures, on the local machine, the throughput/latency of the fully-offline seal
# (HMAC + Ed25519 + C2PA) and offline verify. It prints a Markdown table to stdout
# (so it can regenerate BENCHMARK.md) and exits 0 on success — which also lets it
# double as a CI smoke test (assert exit 0 + a table was produced; NO throughput
# threshold is asserted, so it never flakes).
#
# It does NOT benchmark the network tiers (--tsa / --rekor): those are dominated by
# remote-service latency, not by this tool, and would not be reproducible.
#
# Usage:
#   scripts/bench.sh [N] [FILE_BYTES]   # defaults: N=1000 files, 1024 bytes each
#   N=20 scripts/bench.sh               # quick CI smoke
#   SEALCHAIN=/path/to/bin scripts/bench.sh
set -euo pipefail

N="${1:-${N:-1000}}"
FILE_BYTES="${2:-1024}"

# --- locate the binary (same resolution order as demo.sh) --------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SEALCHAIN:-}"
if [ -z "$BIN" ]; then
  if [ -x "$REPO_ROOT/target/release/apohara-sealchain" ]; then
    BIN="$REPO_ROOT/target/release/apohara-sealchain"
  elif command -v apohara-sealchain >/dev/null 2>&1; then
    BIN="$(command -v apohara-sealchain)"
  else
    echo "==> building apohara-sealchain (release)…" >&2
    cargo build --release --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p apohara-sealchain
    BIN="$REPO_ROOT/target/release/apohara-sealchain"
  fi
fi

# --- isolated, self-cleaning workspace ---------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export XDG_CONFIG_HOME="$WORK/cfg"
CONFIG_DIR="$XDG_CONFIG_HOME/apohara-sealchain"
export XDG_DATA_HOME="$WORK/data"   # keep the receipt index out of the real one
SEALED_AT="2026-01-01T00:00:00+00:00"
HMAC_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

"$BIN" keygen --config-dir "$CONFIG_DIR" >/dev/null
KEY="$CONFIG_DIR/ed25519.pem"

now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", b-a}'; }
per_sec() { awk -v n="$1" -v t="$2" 'BEGIN{ if (t>0) printf "%.0f", n/t; else printf "n/a" }'; }
ms_each() { awk -v n="$1" -v t="$2" 'BEGIN{ if (n>0) printf "%.1f", (t/n)*1000; else printf "n/a" }'; }

seal_one() { # $1 file, $2... extra flags
  local f="$1"; shift
  "$BIN" seal "$f" --sealed-at "$SEALED_AT" --key "$KEY" --hmac-key "$HMAC_KEY" "$@" >/dev/null
}

# --- single-file latency: default offline vs --no-c2pa (the C2PA delta) ------
SINGLE="$WORK/one.bin"
head -c "$FILE_BYTES" /dev/urandom > "$SINGLE"

t0=$(now); seal_one "$SINGLE";          t1=$(now)  # HMAC+Ed25519+C2PA
SEAL_FULL_MS=$(ms_each 1 "$(elapsed "$t0" "$t1")")
RECEIPT_BYTES=$(wc -c < "$SINGLE.seal.json")

t0=$(now); "$BIN" verify "$SINGLE" "$SINGLE.seal.json" --hmac-key "$HMAC_KEY" >/dev/null; t1=$(now)
VERIFY_MS=$(ms_each 1 "$(elapsed "$t0" "$t1")")

NOC2PA="$WORK/two.bin"
head -c "$FILE_BYTES" /dev/urandom > "$NOC2PA"
t0=$(now); seal_one "$NOC2PA" --no-c2pa; t1=$(now)  # HMAC+Ed25519 only
SEAL_NOC2PA_MS=$(ms_each 1 "$(elapsed "$t0" "$t1")")
# %+.1f carries its own sign (e.g. "+2.0" / "-0.5"), so the table must NOT prepend
# another "+" — single-sample timings are noisy and can legitimately go negative.
C2PA_DELTA_MS=$(awk -v a="$SEAL_FULL_MS" -v b="$SEAL_NOC2PA_MS" 'BEGIN{printf "%+.1f", a-b}')

# --- batch seal throughput: one process, N files (--recursive) --------------
BATCH="$WORK/batch"; mkdir -p "$BATCH"
for i in $(seq 1 "$N"); do head -c "$FILE_BYTES" /dev/urandom > "$BATCH/f$i.bin"; done
t0=$(now)
"$BIN" seal "$BATCH" --recursive --sealed-at "$SEALED_AT" --key "$KEY" --hmac-key "$HMAC_KEY" >/dev/null
t1=$(now)
SEAL_BATCH_T=$(elapsed "$t0" "$t1")
SEAL_PER_SEC=$(per_sec "$N" "$SEAL_BATCH_T")

# --- batch verify: per-file CLI invocation (includes process startup) -------
t0=$(now)
for i in $(seq 1 "$N"); do
  "$BIN" verify "$BATCH/f$i.bin" "$BATCH/f$i.bin.seal.json" --hmac-key "$HMAC_KEY" >/dev/null
done
t1=$(now)
VERIFY_BATCH_T=$(elapsed "$t0" "$t1")
VERIFY_PER_SEC=$(per_sec "$N" "$VERIFY_BATCH_T")

# --- emit the Markdown table -------------------------------------------------
cat <<EOF
| Operation | Profile | Result |
|---|---|---|
| Seal (single file) | offline: HMAC + Ed25519 + C2PA | ${SEAL_FULL_MS} ms |
| Seal (single file) | HMAC + Ed25519 (\`--no-c2pa\`) | ${SEAL_NOC2PA_MS} ms |
| C2PA cost (delta) | the JUMBF manifest layer | ${C2PA_DELTA_MS} ms |
| Verify (single file) | offline, all present layers | ${VERIFY_MS} ms |
| Seal throughput | batch \`seal <dir> -r\`, ${N}×${FILE_BYTES}B, one process | ${SEAL_PER_SEC} seals/s |
| Verify throughput | per-file CLI (incl. process startup), ${N}× | ${VERIFY_PER_SEC} verifies/s |
| Receipt size | offline seal of a ${FILE_BYTES}B file | ${RECEIPT_BYTES} bytes |
EOF
