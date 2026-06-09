<div align="center">

# apohara-sealchain

**Prove your AI artifact wasn't tampered with — and prove _exactly_ how much that proof is worth.**

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-sealchain/ci.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-sealchain/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge)](#-license)
[![crates.io](https://img.shields.io/crates/v/apohara-sealchain?style=for-the-badge&logo=rust&label=crates.io)](https://crates.io/crates/apohara-sealchain)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20http-success?style=for-the-badge)](https://modelcontextprotocol.io)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/SuarezPM/apohara-sealchain?style=for-the-badge&label=OpenSSF%20Scorecard)](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-sealchain)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13119/badge)](https://www.bestpractices.dev/projects/13119)

**[Quick Start](#-quick-start)** · **[The five layers](#-the-five-layers)** · **[Trust profile](#-trust-profile)** · **[How it works / honesty](#-how-it-works--honesty)**

A single Rust binary — a **CLI** and an **MCP server** — that seals any file into a tamper-evident `<artifact>.seal.json` receipt anyone can verify **offline**. Five real cryptographic layers, no account, no SaaS, and **no `verified=true` hardcoded anywhere**: every layer re-checks its own crypto, or the seal aborts.

</div>

---

```console
$ apohara-sealchain seal model.bin
SEALED model.bin.seal.json
  sealedAt: 2026-01-01T00:00:00+00:00
  layers:   hmac, ed25519, c2pa

$ apohara-sealchain verify model.bin model.bin.seal.json
PASS
  content  [ok] artifact hash matches receipt
  hmac     [ok] hmac verified
  ed25519  [ok] ed25519 verified
  c2pa     [ok] c2pa manifest valid; payload hash bound

$ printf 'x' >> model.bin            # flip one byte

$ apohara-sealchain verify model.bin model.bin.seal.json
FAIL
  content  [FAIL] artifact hash mismatch: file does not match receipt
$ echo $?
1
```

> Real output from `scripts/demo.sh`, which doubles as a CI smoke test. A seal is **evidence, not a verdict** — `verify` reports each layer with a reason, and exits non-zero the instant a byte moves.

---

## 💡 Concept

> [!NOTE]
> **An AI artifact is only as trustworthy as the proof that travels with it.** A model on the Hub, a dataset in a bucket, a generated image in a PR — a downloader has no way to know it's byte-for-byte what you produced, that *you* produced it, when it existed, or whether anyone can audit that claim. apohara-sealchain answers those questions with math you can re-run yourself, offline, with nothing but the file and its receipt.

apohara-sealchain reads a file and emits an `<artifact>.seal.json` **receipt** — a self-contained JSON sidecar chaining up to five independent cryptographic layers, canonicalized with [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785). Publish the receipt next to your artifact and **anyone** can verify it offline: the CLI, the [in-browser WASM verifier](web/), or the thin [Python / Node SDKs](sdk/). The Ed25519 public key is embedded in the receipt, so verification needs no key server and no network.

The same binary speaks the [Model Context Protocol](https://modelcontextprotocol.io), so an AI agent (Claude Desktop, Claude Code, Cursor, or any MCP client) can seal and verify artifacts as native tools.

---

## ✨ Features

| | |
|---|---|
| 🧾 **Self-contained receipts** | One `<artifact>.seal.json` sidecar carries every layer + the embedded public key. Verify with just the file and the receipt — no account, no key server, no network. |
| 🔌 **CLI _and_ MCP server** | `apohara-sealchain` is a full CLI; `apohara-sealchain mcp` is an MCP server (stdio by default, or streamable-HTTP with `mcp --http <host:port>` for remote/CI) exposing `seal_artifact` / `verify_receipt` / `show_chain` to any agent. |
| 🧭 **Canonical trust profile** | [`packaging/trust-profile.json`](packaging/trust-profile.json) states, machine-readably, **what each layer combination proves and does not prove**. |
| 🎫 **Attestation policies** | `verify --policy file.toml` or `--profile {offline-basic\|transparency\|legal-grade\|full}` enforces a bar after verification — exit `5` if crypto is valid but the policy isn't met, `1` if the artifact was tampered. |
| 📊 **Offline transparency dashboard** | `apohara-sealchain dashboard` renders a self-contained HTML report of your receipts — layers, an honest verify status, policy compliance — with **zero network references**. |
| 🌐 **In-browser verifier (WASM)** | Drag a file + its receipt onto a static page and verify content + Ed25519 + C2PA fully offline in WebAssembly — no backend, no upload. |
| 📜 **SLSA-style provenance** | `apohara-sealchain provenance` maps a receipt onto an in-toto Statement v1 for supply-chain tooling — honestly typed, never claiming SLSA *build* semantics. `--format model-signing` emits the model-transparency / OpenSSF Model Signing shape for ML-ecosystem interop. |
| 🦀 **Honest by construction** | Pure Rust. `verify` is always offline. Every layer produces and re-checks real crypto, or the seal aborts — there is no faked pass anywhere in the tree. |
| 🔏 **Signed releases** | Every release binary carries a SLSA **build provenance (L2+)** attestation (Sigstore keyless) — verify it with `gh attestation verify` before you run it. |
| 🧪 **Continuously fuzzed** | [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) runs the `verify_receipt` harness on every push/PR and weekly; SAST via [CodeQL](https://codeql.github.com/); cargo deps + GitHub Actions auto-bumped by [Dependabot](https://github.com/SuarezPM/apohara-sealchain/pulls?q=is%3Apr+author%3Aapp%2Fdependabot). |
| 🌐 **Live in-browser verifier** | The same offline WASM verifier is auto-built and deployed to GitHub Pages: **[suarezpm.github.io/apohara-sealchain](https://suarezpm.github.io/apohara-sealchain/)** — drag a file + receipt, no backend, no upload. |

---

## 🔐 The five layers

All five are implemented and **live-exercised** — no placeholders, no unexercised crypto.

| Layer | What it proves | Notes |
|---|---|---|
| **HMAC-SHA256** | local integrity (symmetric) | always present; the secret is **never** in the receipt |
| **Ed25519** | authorship by the key holder | public key embedded → offline, self-contained verify |
| **C2PA** | a provenance manifest is bound to the payload | real JUMBF manifest; v0.1 is **self-signed** with the seal key (not third-party-trust-anchored); `--ai-generated` records the IPTC `trainedAlgorithmicMedia` source type |
| **RFC-3161 TSA** | existence-before-a-point-in-time, per the authority | real token; the default TSA is **not** eIDAS-qualified — point `--tsa` at a [QTSP](#-how-it-works--honesty) for legal-grade |
| **Sigstore Rekor v2** | public, append-only transparency-log inclusion | real DSSE entry; offline-verifiable inclusion proof + C2SP checkpoint against a pinned shard key |

The **default `seal` is fully offline** (HMAC + Ed25519 + C2PA). `--tsa` / `--rekor` add the network-backed transparency layers; `--all` seals every configured layer **real-or-abort** (if a requested layer can't be produced, the seal aborts and writes nothing). **`verify` is always offline** — signature, timestamp, C2PA, and the Rekor inclusion proof all check from the receipt alone.

---

## 🚀 Quick Start

```sh
# Install the CLI (builds from source — lowest-trust path)
cargo install apohara-sealchain

# Seal a file — offline default: HMAC + Ed25519 + C2PA
apohara-sealchain seal model.bin
#   -> writes model.bin.seal.json

# Verify offline — exits 0 on PASS, 1 on tamper
apohara-sealchain verify model.bin model.bin.seal.json
```

Run it as an **MCP server** — add this to your client config (matches [`packaging/mcp.json`](packaging/mcp.json)):

```json
{
  "mcpServers": {
    "apohara-sealchain": { "command": "npx", "args": ["-y", "@apohara/sealchain"] }
  }
}
```

<details>
<summary><b>Advanced usage</b> — transparency layers, policies, dashboard, SDKs</summary>

```sh
# Add the public transparency layers (RFC-3161 TSA + Sigstore Rekor v2; needs network at seal time)
apohara-sealchain seal model.bin --all

# Enforce a named profile after verification (exit 0 = pass, 5 = policy fail, 1 = tamper)
apohara-sealchain verify model.bin model.bin.seal.json --profile transparency

# ...or a custom declarative policy
apohara-sealchain verify model.bin model.bin.seal.json --policy examples/policies/legal-grade.toml

# Render a self-contained, offline HTML transparency report of your receipts
apohara-sealchain dashboard --from-dir . --profile offline-basic -o report.html

# Emit an in-toto / SLSA-style provenance Statement for supply-chain tooling
apohara-sealchain provenance model.bin.seal.json

# Batch-seal a directory and query the local index
apohara-sealchain seal ./out --recursive
apohara-sealchain ls
apohara-sealchain find model
```

**Other paths.** `npx -y @apohara/sealchain` downloads the prebuilt binary and runs the MCP server. Pre-built per-OS binaries are on [Releases](https://github.com/SuarezPM/apohara-sealchain/releases). Thin [Python / Node SDKs](sdk/) wrap the binary, and a reusable [GitHub Action](.github/actions/seal-artifact) seals build artifacts in CI.

> [!WARNING]
> Downloading a pre-built binary is itself a supply-chain surface — the very risk this tool exists to make auditable. Prefer `cargo install` and build from source, or verify the release provenance (below) before running.

**Verify the release provenance.** Every release binary ships with a SLSA **build provenance (L2+)** attestation, minted by the release workflow with Sigstore keyless signing (no long-lived key). Verify a downloaded asset against this repository before running it:

```sh
gh attestation verify apohara-sealchain-x86_64-unknown-linux-gnu \
  --repo SuarezPM/apohara-sealchain
```

The attestation is bound to the asset's digest, so it covers exactly the bytes you run. (We claim **L2+**, not L3, until the level is independently verified against a published release — measure, don't assert.)

</details>

---

## 🧭 Trust profile

A seal proves the properties of the layers it actually carries — nothing more. [`packaging/trust-profile.json`](packaging/trust-profile.json) is the machine-readable source of truth; [`docs/TRUST-PROFILE.md`](docs/TRUST-PROFILE.md) is its human-readable rendering. The named profiles below are enforceable with `verify --profile` and surfaced per-row in the dashboard.

| Profile | Requires (present **and** verified) | Use it for |
|---|---|---|
| `offline-basic` | HMAC + Ed25519 + C2PA | the fully-offline default: integrity + authorship + provenance |
| `transparency` | Ed25519 + Rekor v2 | publicly-recorded authorship (append-only log) |
| `legal-grade` | Ed25519 + a **qualified** eIDAS QTSP timestamp | an eIDAS-oriented timestamp (see honesty note) |
| `full` | all five layers | the maximal chain |

A layer counts toward a profile **only if it is present and its verification passed** — there is no asserted pass.

---

## 🔬 How it works / honesty

> [!WARNING]
> **A seal is evidence, not a verdict — and not legal advice.** It does not make an artifact "trusted"; it lets a human (or a policy) decide based on layers that each re-check their own crypto. Read these limits before you rely on it:
>
> - **The default timestamp is _not_ legally qualified.** A non-eIDAS TSA is fine for integrity/credibility but is not a court-admissible *qualified* timestamp under [eIDAS Art. 42](https://eur-lex.europa.eu/eli/reg/2014/910/oj). For legal weight, point `--tsa` at a Qualified Trust Service Provider on an [EU Trusted List](https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists) — that is your account to provide.
> - **The v0.1 C2PA manifest is self-signed** with the seal's Ed25519 key (trust check disabled — "Valid, not Trusted"). It binds the payload, but is not a third-party-trust-anchored C2PA credential. The CA-issued upgrade path (SSL.com / DigiCert) and its trade-offs are documented in [`docs/c2pa-trust.md`](docs/c2pa-trust.md).
> - **`require_qualified_tsa` is a host-allowlist match**, not cryptographic proof of eIDAS qualification — and the violation message says so.
> - **HMAC is symmetric.** Only the secret holder can re-check it; a third party verifies content + Ed25519 + C2PA instead, and the tools say so rather than fake a pass.

**Measure, don't assert.** No layer hardcodes a pass. Each re-derives and re-checks its binding at verify time, or reports `ok: false` with a reason. The Rekor inclusion proof and signed checkpoint verify **offline** against a shard key [pinned with provenance](packaging/rekor-shards.json) — never fetched from the thing being verified — and an unknown log key is a measured `ok: false`, never a silent pass.

**Wire format.** The receipt schema (`apohara-seal-v1`), every layer's binding, and verify semantics are specified in [`SPEC.md`](SPEC.md) — including a per-field [compatibility matrix](SPEC.md#51-field-compatibility-matrix) (since-version, required/optional, native vs WASM verifier coverage) backed by the machine-readable [`packaging/receipt.schema.json`](packaging/receipt.schema.json). The format is a clean-room Rust reimplementation of an Apache-2.0 reference; where the reference is internally inconsistent, this implementation defines the canonical behavior and documents the divergence (see [`NOTICE`](NOTICE)).

**Performance.** Honest, reproducible offline-profile numbers (seal/verify latency, batch throughput, the C2PA cost, receipt size) live in [`BENCHMARK.md`](BENCHMARK.md) — regenerate them yourself with [`scripts/bench.sh`](scripts/bench.sh).

---

## 🏗️ Repository layout

```text
apohara-sealchain/
├── crates/
│   ├── apohara-sealchain-core/      # the apohara-seal-v1 engine: layers, seal/verify, JCS
│   │   ├── src/layers/      # hmac · ed25519 · c2pa · tsa · rekor
│   │   ├── src/{policy,dashboard,trust_profile,provenance,keystore,index}.rs
│   │   └── trust-profile.json
│   ├── apohara-sealchain/           # the CLI + MCP stdio server
│   └── sealchain-wasm/      # the offline in-browser verifier (wasm-bindgen)
├── web/                     # static drag-and-drop WASM verifier page
├── sdk/{python,node}/       # thin SDKs over the binary
├── packaging/               # mcp.json · plugin.json · trust-profile.json · receipt schema
├── examples/                # HuggingFace seal-your-fine-tune · attestation policies
├── docs/                    # SPEC, trust profile, positioning, publishing, key management, assurance case
├── fuzz/                    # ClusterFuzzLite harness (verify_receipt target)
├── .clusterfuzzlite/        # Dockerfile + build script for OSS-Fuzz Lite
├── osv-scanner.toml         # OSV vulnerability scan policy
└── .github/                 # CI, release, scorecard, pages, codeql, cflite, seal-artifact + huggingface-seal Actions
```

---

## 🗺️ Roadmap

- [x] Five real, live-exercised layers (HMAC · Ed25519 · C2PA · RFC-3161 TSA · Rekor v2)
- [x] CLI + MCP server (stdio **and** streamable-HTTP) + offline in-browser WASM verifier
- [x] Canonical machine-readable trust profile + attestation policies + transparency dashboard
- [x] Thin Python / Node SDKs · in-toto/SLSA-style provenance (+ model-transparency interop) · encrypted keystore + rotation
- [x] Batch sealing + local receipt index · reusable GitHub Actions (`seal-artifact`, `huggingface-seal`)
- [x] Signed releases (SLSA build provenance) · OpenSSF Scorecard · `SECURITY.md` · honest [benchmarks](BENCHMARK.md)
- [x] Rekor seal-time stale-shard guard (TUF SigningConfig) · C2PA AI-generated disclosure (`--ai-generated`)
- [ ] Third-party-trust-anchored C2PA signer beyond v0.1 self-signed (workflow documented in [`docs/c2pa-trust.md`](docs/c2pa-trust.md))
- [ ] First-class eIDAS QTSP presets for legal-grade timestamps
- [ ] Direct HuggingFace Hub model-registry push (beyond the seal Action)

---

## 🛡️ Security

Found a vulnerability? Please report it **privately** via [GitHub Security Advisories](https://github.com/SuarezPM/apohara-sealchain/security/advisories/new) — see [`SECURITY.md`](SECURITY.md) for the disclosure process, supported versions, and the **threat model** (what each layer protects and what it deliberately does not). The full **assurance case** (security requirements, trust boundaries, secure-design argument, and how common weaknesses are countered) is in [`docs/ASSURANCE.md`](docs/ASSURANCE.md).

**Continuous supply-chain hardening, measured in the open.** The repository runs — and is graded by — the [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-sealchain) on every push to `main` and weekly (`.github/workflows/scorecard.yml`). Live subscores on the current `main`:

| | | | |
|---|---|---|---|
| Fuzzing **10** | Vulnerabilities **10** | Pinned-Dependencies **10** | Dangerous-Workflow **10** |
| CI-Tests **10** | Binary-Artifacts **10** | Token-Permissions **10** | Security-Policy **10** |
| Dependency-Update-Tool **10** | Packaging **10** | SAST **7** (CodeQL) | License **9** |
| CII-Best-Practices **7** | Branch-Protection **3** | Contributors **3** | Signed-Releases 0 · Maintained 0 · Code-Review 0 |

Honest gaps: release binaries carry SLSA **build provenance** (attestation verifiable with `gh attestation verify`) but are not `cosign sign-release`–style signed, so the Scorecard `Signed-Releases` check reads 0; `Maintained` and `Code-Review` reflect single-maintainer activity. Each is something to lift, not to paper over.

---

## 🤝 Contributing

Contributions are welcome.

1. **Fork** the repository.
2. Create a feature **branch** (`git checkout -b feature/my-change`).
3. Make your change and run the gate: `cargo test --workspace` (plus `cargo clippy --workspace --all-targets` and `cargo fmt --check`).
4. Open a **pull request**.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the build/test/quality gate, coding
standards, and the testing policy. By participating you agree to the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) (Contributor Covenant 3.0). How the
project is governed — roles, decision-making, and access continuity — is in
[`GOVERNANCE.md`](GOVERNANCE.md).

> Unless you state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual-licensed as below, without any additional terms or conditions.

---

## 📄 License

Licensed under either of **[MIT](LICENSE-MIT)** or **[Apache-2.0](LICENSE-APACHE)**, at your option. See [`NOTICE`](NOTICE) for attribution.

Maintained by **[SuarezPM](https://github.com/SuarezPM)**.
