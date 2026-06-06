# Governance

This document describes how **apohara-sealchain** is governed: how decisions are
made, who holds which roles, and how the project continues if the maintainer
becomes unavailable. It is intentionally lightweight and honest about the
project's current size (a single maintainer with outside contributors welcome).

## Governance model

apohara-sealchain follows a **single-maintainer (BDFL-style) model** with
open, consensus-seeking discussion:

- **Proposals and decisions happen in the open.** Features, changes, and bug
  reports are discussed in GitHub [Issues](https://github.com/SuarezPM/apohara-sealchain/issues)
  and [Pull Requests](https://github.com/SuarezPM/apohara-sealchain/pulls). Anyone may
  open an issue or PR.
- **The maintainer is the final decision-maker** on what is merged and released,
  but seeks consensus with contributors and prefers the least-surprising,
  best-justified option. Disagreements are resolved by discussion in the
  relevant issue/PR; the maintainer's decision is final if consensus is not
  reached.
- **Non-negotiable design principles** (see [`docs/ASSURANCE.md`](docs/ASSURANCE.md)
  and [`README.md`](README.md#-how-it-works--honesty)) constrain every decision:
  *real-or-abort* sealing, no hardcoded `verified=true`, an always-offline
  `verify` path, and honesty about each layer's limits. Changes that weaken these
  are rejected on principle.

## Roles and responsibilities

| Role | Who | Responsibilities |
|------|-----|------------------|
| **Maintainer** | [@SuarezPM](https://github.com/SuarezPM) (Pablo Suarez) | Reviews and merges changes; cuts releases; triages issues and security reports; owns the crates.io / npm / GitHub credentials; final decision-maker. |
| **Security contact** | the maintainer, via [`SECURITY.md`](SECURITY.md) | Receives and responds to vulnerability reports (private GitHub Security Advisories). |
| **Code of Conduct moderator** | the maintainer, via [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Receives and acts on conduct reports. |
| **Contributors** | anyone | Open issues/PRs; contributions are accepted per [`CONTRIBUTING.md`](CONTRIBUTING.md) and dual-licensed MIT OR Apache-2.0. |

There is currently **one maintainer**; the project actively welcomes additional
maintainers. A contributor with a sustained track record of high-quality,
on-principle contributions may be invited by the maintainer to become a
co-maintainer (gaining merge/release rights and credential access under the
continuity plan below).

## Access continuity (bus factor)

The project must be able to continue — create and close issues, accept changes,
and publish releases — within about a week even if the maintainer becomes
unavailable. The continuity plan:

- **Credential custody.** The credentials required to operate the project — the
  GitHub account (and repository admin), the crates.io API token, the npm token
  for the `@apohara` scope, and the `apohara.dev` DNS credentials — are stored in
  the maintainer's password manager, **with recovery/break-glass copies kept
  off-site** so a designated trusted party can recover access if the maintainer
  is incapacitated.
- **No single on-disk secret is load-bearing for verification.** Published
  receipts verify **offline** from the receipt itself (embedded Ed25519 public
  key) plus the in-binary pinned Rekor shard keys — so a downstream user can keep
  verifying artifacts indefinitely regardless of the project's operational state.
  Releases are signed via **keyless** Sigstore attestation (no long-lived signing
  key to lose; see [`SECURITY.md`](SECURITY.md#build--supply-chain-integrity)).
- **Reproducible from source.** The repository is the single source of truth;
  anyone with the credentials can rebuild and re-publish from a clean checkout
  (`cargo build --release`, then the documented steps in
  [`docs/PUBLISHING.md`](docs/PUBLISHING.md)).
- **Fork-ability.** Under the permissive MIT OR Apache-2.0 license, the community
  can fork and continue the project without the maintainer's involvement if ever
  required.

> Maintainer action (kept current out-of-band): ensure the break-glass recovery
> copies are held by a trusted second party. This is the human half of the bus
> factor and is not something the repository can enforce on its own.

## Releases

Releases follow [Semantic Versioning](https://semver.org); each release is a git
tag (`vMAJOR.MINOR.PATCH`) that triggers the publish workflow (crates.io + npm + a
GitHub Release). The release **binaries** carry SLSA build provenance (Sigstore
keyless), verifiable with `gh attestation verify`; the git tags themselves are not
GPG-signed. The release procedure is documented in
[`docs/PUBLISHING.md`](docs/PUBLISHING.md) and the changes per release in
[`CHANGELOG.md`](CHANGELOG.md).

## Changing this document

Changes to governance are proposed via pull request and decided by the maintainer
in the open, like any other change.
