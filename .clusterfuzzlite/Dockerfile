# ClusterFuzzLite build environment for apohara-sealchain (Rust / cargo-fuzz).
# Uses the OSS-Fuzz Rust base image, which provides a nightly toolchain,
# cargo-fuzz, and the sanitizer wiring ClusterFuzzLite expects.
FROM gcr.io/oss-fuzz-base/base-builder-rust

COPY . $SRC/apohara-sealchain
WORKDIR $SRC/apohara-sealchain
COPY .clusterfuzzlite/build.sh $SRC/
