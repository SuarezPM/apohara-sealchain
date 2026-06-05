# Contributing to apohara-sealchain

Thanks for your interest in contributing. This document covers the basics for
building, testing, and submitting changes.

## Building and testing

This is a Cargo workspace. The native engine is the default build.

```sh
# Build everything
cargo build

# Build the release binary (stripped, LTO)
cargo build --release -p apohara-sealchain

# Run the full test suite
cargo test
```

The WASM verifier is a separate target:

```sh
cargo build -p sealchain-wasm --target wasm32-unknown-unknown
```

## Quality gate

Every commit MUST keep the following green. CI enforces all of them; please run
them locally before opening a PR:

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Pull requests that break `cargo test` or introduce clippy warnings will not be
merged.

## Pull requests

- Keep changes focused; one logical change per PR.
- Update `CHANGELOG.md` under `[Unreleased]` when your change is user-visible.
- Code and comments are written in English. Comment the *why*, not the *what*.

### Conventional Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, etc. This keeps the
history machine-readable and drives changelog generation.

### Developer Certificate of Origin (DCO)

By contributing, you certify the [DCO](https://developercertificate.org/): that
you wrote the patch or otherwise have the right to submit it under the project's
license. Sign off your commits with `git commit -s`, which appends a
`Signed-off-by:` trailer.

## License of contributions

This project is dual-licensed under **MIT OR Apache-2.0**. Per the Rust
ecosystem convention:

> Unless you explicitly state otherwise, any contribution intentionally
> submitted for inclusion in the work by you, as defined in the Apache-2.0
> license, shall be dual-licensed as above, without any additional terms or
> conditions.
