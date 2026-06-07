#!/bin/bash -eu
# ClusterFuzzLite / OSS-Fuzz build script: compile the cargo-fuzz targets and
# copy each fuzzer binary into $OUT (the directory ClusterFuzzLite runs from).
cd "$SRC/apohara-sealchain"

cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
  name="$(basename "${f%.*}")"
  cp "$FUZZ_TARGET_OUTPUT_DIR/$name" "$OUT/"
done
