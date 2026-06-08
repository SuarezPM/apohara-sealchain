# ClusterFuzzLite build environment for apohara-sealchain (Rust / cargo-fuzz).
# Uses the OSS-Fuzz Rust base image, which provides a nightly toolchain,
# cargo-fuzz, and the sanitizer wiring ClusterFuzzLite expects.
# Pinned by digest (Scorecard Pinned-Dependencies); refresh the digest when the
# base image is rebuilt (the `:latest`-equivalent tag is base-builder-rust).
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:44c906bab39d3c75733008b0fe30356920b1bf165df0dbbf03f37d8136b0f696

COPY . $SRC/apohara-sealchain
WORKDIR $SRC/apohara-sealchain
COPY .clusterfuzzlite/build.sh $SRC/
