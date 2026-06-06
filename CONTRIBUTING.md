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

## Coding standards

The project's **required coding style is enforced automatically**, so there is no
style guide to memorize:

- **Formatting:** `rustfmt` with the repository defaults (`cargo fmt`). All code
  MUST be `rustfmt`-clean; CI runs `cargo fmt --all -- --check`.
- **Linting:** `clippy` with **warnings denied** (`cargo clippy --all-targets -- -D warnings`).
  Contributions MUST be clippy-clean; CI denies any warning.
- **Language:** code and comments are in **English**; comment the *why*, not the
  *what*.

Contributions are expected to generally comply with these standards. Because both
tools are run in CI and required to pass, compliance is checked on every change
rather than left to reviewer discretion.

## Testing policy

Tests are part of the change, not an afterthought:

- **Major new functionality MUST add tests** to the automated test suite in the
  same change. A feature without tests is not considered complete and will not be
  merged.
- **Bug fixes SHOULD add a regression test** that fails before the fix and passes
  after, so the bug cannot silently return.
- The automated suite runs **on every push and pull request** (CI, three OS
  targets) and reports success/failure; a red suite blocks the merge.
- New cryptographic behavior MUST be exercised by real tests (produce-and-verify
  round-trips, tamper-detection), never asserted — consistent with the project's
  *measure, don't assert* principle.

Statement coverage is measured with [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)
(`cargo llvm-cov --workspace --summary-only`); see
[`docs/best-practices-silver.md`](docs/best-practices-silver.md) for the current
figure.

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
