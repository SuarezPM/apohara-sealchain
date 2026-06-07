# OpenSSF Best Practices — Silver criteria evidence

Project: **apohara-sealchain** · badge entry [#13119](https://www.bestpractices.dev/projects/13119).

This maps every **Silver** criterion ([bestpractices.dev/en/criteria/1](https://www.bestpractices.dev/en/criteria/1))
to its status and the exact evidence, so the questionnaire can be answered
quickly. Status is honest: **Met**, **N/A** (with justification), or **Human
action** (something only the maintainer can do, e.g. completing the form or
holding recovery keys). Silver also requires the **Passing** badge first.

> Coverage figure referenced below: **statement coverage ≈ 84%** (83.90% lines /
> 84.43% regions), measured with `cargo llvm-cov --workspace --summary-only`
> (default suite; the `#[ignore]` live TSA/Rekor tests need network and are
> excluded). Re-run to refresh.

## Prerequisite
| Criterion | Status | Evidence |
|---|---|---|
| `achieve_passing` | **Human action** | Complete the Passing questionnaire on bestpractices.dev. The repo satisfies it (FLOSS MIT/Apache, public git, SemVer tags, build+test CI, SECURITY.md, signed releases, static analysis). |
| `license_location` (Passing) | Met | Top-level [`LICENSE`](../LICENSE) file (dual MIT OR Apache-2.0, SPDX id, pointing to `LICENSE-MIT` / `LICENSE-APACHE` / `NOTICE`). **Note:** bestpractices.dev's auto-scanner only recognizes a top-level `LICENSE`/`COPYING` (± `.txt`/`.md`); the hyphenated Rust-convention files `LICENSE-MIT`/`LICENSE-APACHE` are *not* matched by its regex, which is why a plain `LICENSE` file is required for the criterion to stay "Met". URL for the form: `https://github.com/SuarezPM/apohara-sealchain/blob/main/LICENSE`. |

## Basics
| Criterion | Status | Evidence |
|---|---|---|
| `contribution_requirements` | Met | `CONTRIBUTING.md` — quality gate + coding standards + acceptable-contribution requirements. |
| `bus_factor` (SHOULD) | Justified unmet | Single maintainer today; `GOVERNANCE.md` documents continuity and an open invitation to co-maintainers. SHOULD, not MUST. |
| `access_continuity` | Met (+ human follow-through) | `GOVERNANCE.md` § Access continuity: credential custody + break-glass recovery + keyless releases + fork-ability. Human half: keep off-site recovery copies with a trusted party. |
| `roles_responsibilities` | Met | `GOVERNANCE.md` § Roles and responsibilities (table). |
| `code_of_conduct` | Met | `CODE_OF_CONDUCT.md` (Contributor Covenant 3.0). |
| `governance` | Met | `GOVERNANCE.md` § Governance model. |
| `dco` (SHOULD) | Met | `CONTRIBUTING.md` § Developer Certificate of Origin (`git commit -s`). |
| `documentation_achievements` | Met | `README.md` badge block links the OpenSSF Best Practices badge (#13119). |
| `documentation_current` | Met | Docs are versioned with the code and updated in the same change; `CHANGELOG.md` per release; `cargo doc` is kept warning-free (verified during release prep). |
| `documentation_quick_start` | Met | `README.md` § Quick Start. |
| `documentation_security` | Met | `SECURITY.md` (threat model) + `docs/TRUST-PROFILE.md` + `docs/ASSURANCE.md`. |
| `documentation_architecture` | Met | `SPEC.md` (wire format + verify) + `README.md` § Repository layout. |
| `documentation_roadmap` | Met | `README.md` § Roadmap covers ≥ the next year (third-party C2PA anchor, eIDAS QTSP presets, HF Hub push). |
| `internationalization` (SHOULD) | N/A | The CLI does not generate localized end-user text or sort human-readable text. |
| `accessibility_best_practices` (SHOULD) | Met | Plain-Markdown docs + a no-JS, semantic-HTML WASM verifier page (keyboard-usable, no custom widgets); the CLI is plain text. |
| `sites_password_security` | N/A | The project stores no user passwords (no auth server). |

## Change Control
| Criterion | Status | Evidence |
|---|---|---|
| `maintenance_or_update` | Met | SemVer + `CHANGELOG.md`; old receipts keep verifying across versions (embedded key + listed shard keys); upgrade path documented. |

## Reporting
| Criterion | Status | Evidence |
|---|---|---|
| `report_tracker` | Met | GitHub Issues. |
| `vulnerability_response_process` | Met | `SECURITY.md` — private GitHub Security Advisories, 5-business-day ack, coordinated disclosure. |
| `vulnerability_report_credit` | N/A | No vulnerabilities resolved in the last 12 months. |

## Quality
| Criterion | Status | Evidence |
|---|---|---|
| `coding_standards_enforced` | Met | CI runs `cargo fmt --check` + `cargo clippy -D warnings` (`.github/workflows/ci.yml`). |
| `coding_standards` | Met | `CONTRIBUTING.md` § Coding standards (rustfmt + clippy). |
| `build_repeatable` | Met (justified) | `Cargo.lock` pins every dependency and `rust-toolchain.toml` pins the channel, so a build is deterministic **given an identical toolchain version**. Full bit-for-bit reproducibility across compiler versions is **not** guaranteed (standard for Rust release builds: embedded paths, codegen across patch releases); the channel is rolling `stable`, not a frozen version. OpenSSF permits this as a justified partial. |
| `build_non_recursive` | N/A | Cargo workspace; no recursive Make with cross-dependencies. |
| `build_preserve_debug` (SHOULD) | Met | Cargo honors profile debug settings; no stripping of requested debug info. |
| `build_standard_variables` | Met | Cargo honors `RUSTFLAGS`; native C deps (bundled SQLite) build via `cc`, which honors `CFLAGS`. |
| `installation_development_quick` | Met | `cargo build` / `cargo test` set up the full dev + test environment (`CONTRIBUTING.md`). |
| `installation_standard_variables` | N/A | Distributed via `cargo install` / prebuilt release binaries / `npx`; no POSIX `DESTDIR`-style installer. |
| `installation_common` | Met | `cargo install apohara-sealchain`, `npx -y @apohara/sealchain`, or the GitHub Release binaries. |
| `interfaces_current` | Met | Dependencies tracked by `cargo-deny`/`cargo-audit`; no deprecated/obsolete APIs where FLOSS alternatives exist. |
| `external_dependencies` | Met | External dependencies are listed in a computer-processable form: `Cargo.toml` + the fully-resolved `Cargo.lock`; `cargo metadata` emits the complete graph as JSON. |
| `dependency_monitoring` | Met | `cargo-audit` (RUSTSEC advisories) + `cargo-deny advisories` run in CI on every push (`.github/workflows/ci.yml`); reviewed exceptions are documented in `deny.toml` (RUSTSEC-2023-0071, RUSTSEC-2024-0370). |
| `updateable_reused_components` | Met | All reused components are standard crates.io crates pinned in `Cargo.lock`, updatable with `cargo update`; nothing is vendored or forked, so each is trivially identifiable and updatable. |
| `test_statement_coverage80` | **Met** | ≈84% statement coverage measured with `cargo llvm-cov --workspace --summary-only` (local measurement; the command is reproducible — not a CI gate, which the criterion does not require). |
| `regression_tests_added50` | Met | Bug fixes ship with regression tests (e.g. the SDK receipt-path fix, the policy future-date fix) added to the suite. |
| `automated_integration_testing` | Met | `cargo test` runs on every push/PR across 3 OS (`.github/workflows/ci.yml`) and reports pass/fail. |
| `tests_documented_added` | Met | `CONTRIBUTING.md` § Testing policy (new functionality must add tests). |
| `test_policy_mandated` | Met | `CONTRIBUTING.md` § Testing policy (written, mandatory). |
| `warnings_strict` | Met | `clippy -D warnings` (no warnings tolerated). |

## Security
| Criterion | Status | Evidence |
|---|---|---|
| `implement_secure_design` | Met | `docs/ASSURANCE.md` § 3 (secure-design principles applied). |
| `crypto_verification_private` | Met | TLS (seal-time TSA/Rekor) uses `reqwest`+`rustls`; certificate verification is on before any request. |
| `crypto_certificate_verification` | Met | `reqwest` default-features include rustls cert verification; not disabled anywhere. |
| `crypto_tls12` (SHOULD) | Met | `rustls` negotiates TLS 1.2+ (no SSL/TLS<1.2). |
| `crypto_used_network` (SHOULD) | Met | Only HTTPS is used (TSA/Rekor); no FTP/telnet/HTTP/SSLv3. |
| `crypto_credential_agility` | Met | Keystore is separate from receipts, rotatable (`key rotate`), updatable without recompilation. |
| `crypto_algorithm_agility` (SHOULD) | Justified | Algorithms (SHA-256, Ed25519, HMAC-SHA256) are fixed per the `apohara-seal-v1` wire format; agility is provided by **versioning the format** (`SchemaVersion`) rather than runtime negotiation. |
| `crypto_weaknesses` | Met | No SHA-1/MD5/CBC-SSH; SHA-256 + Ed25519 only. |
| `version_tags_signed` (SUGGESTED) | Partial | Git tags are not GPG-signed, but **release artifacts carry SLSA build provenance** (Sigstore keyless), verifiable with `gh attestation verify`. Signing tags is a possible future addition. |
| `signed_releases` | Met | Release binaries are signed via SLSA build provenance (Sigstore keyless — no on-site private key); verification documented in `SECURITY.md` + `README.md`. |
| `assurance_case` | Met | `docs/ASSURANCE.md` (threat model + trust boundaries + secure-design + countered weaknesses). |
| `hardening` (SHOULD) | Met | Memory-safe Rust; release profile; CI static analysis; no `unsafe` in shipped library paths. |
| `input_validation` | Met | **Allowlist** validation of untrusted input: the receipt is parsed against the `apohara-seal-v1` schema (`packaging/receipt.schema.json`) — only known schema versions and structural shapes are accepted, everything else is rejected as a structural error; malformed hex/base64/proof-indices are handled, never panic (`docs/ASSURANCE.md` § 4). |

## Analysis
| Criterion | Status | Evidence |
|---|---|---|
| `static_analysis_common_vulnerabilities` | Met | `clippy` + `cargo-audit` (RUSTSEC) + `cargo-deny` in CI. |
| `dynamic_analysis_unsafe` | N/A | The produced software is memory-safe Rust (no memory-unsafe language), so the memory-safety dynamic-analysis requirement does not apply. |

## Summary
After these docs, **every Silver criterion is Met or justifiably N/A** except the
items that require a human: (1) completing the **Passing** questionnaire, and
(2) the **off-site custody** half of the access-continuity plan. `bus_factor` is a
SHOULD and is honestly documented as a single-maintainer project open to
co-maintainers. No criterion is marked Met that is not genuinely satisfied.
