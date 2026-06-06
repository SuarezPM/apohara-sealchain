# Publishing apohara-sealchain

This document describes the release process for **apohara-sealchain**. The build
artifacts (crate metadata, docs.rs config, CHANGELOG/CONTRIBUTING, npx wrapper)
are prepared in-repo. The steps below marked 🔒 **GATED** require the maintainer's
credentials and explicit authorization — they are *not* run by CI or by any
agent. They push to remotes and publish to public registries.

## Release artifacts

| Artifact | Where it goes |
|----------|---------------|
| `apohara-sealchain-core` crate | crates.io |
| `apohara-sealchain` crate (bin: CLI + MCP server) | crates.io |
| Prebuilt platform binaries | GitHub Release assets |
| `apohara-sealchain` npx wrapper | npm |
| Browser verifier (`sealchain-wasm`) | apohara.dev/sealchain |

## Measured release binary size

Built with `cargo build --release -p apohara-sealchain` on the release profile
(`strip = true`, `lto = true`, `codegen-units = 1`):

| Binary | Bytes | Human |
|--------|-------|-------|
| `target/release/apohara-sealchain` | **17,577,152** | **16.76 MiB** (~17.58 MB) |

Note: c2pa's `file_io` feature was already dropped (the engine uses only
in-memory streams), which keeps openssl/std-fs out of the binary and the
wasm verify path. The size above reflects that.

## Two-crate publish order

`apohara-sealchain` (the bin) depends on `apohara-sealchain-core` by path. For publishing, the
path dependency also carries an explicit `version`:

```toml
apohara-sealchain-core = { path = "../apohara-sealchain-core", version = "0.1.0" }
```

crates.io requires the dependency to already exist at that version, so the
order is fixed:

1. **`apohara-sealchain-core` FIRST** — `cargo publish -p apohara-sealchain-core`
2. **`apohara-sealchain` SECOND** — `cargo publish -p apohara-sealchain` (resolves
   `apohara-sealchain-core` from crates.io)

Verify packaging without publishing:

```sh
cargo publish --dry-run -p apohara-sealchain-core
# then, after core is live on crates.io:
cargo publish --dry-run -p apohara-sealchain
```

## Vendored Rekor shard keys

`apohara-sealchain-core` embeds the pinned Rekor shard keys at compile time via
`include_str!`. `cargo publish` only packages files inside the crate directory,
so the crate carries an in-crate copy at
`crates/apohara-sealchain-core/rekor-shards.json`. The source of truth remains the
workspace `packaging/rekor-shards.json`; the in-crate copy is a vendored
duplicate (a plain file, not a symlink, so the Windows release build needs no
symlink support). **When rotating a shard, update both files.**

## docs.rs

`apohara-sealchain-core` declares `[package.metadata.docs.rs]` with
`features = ["native"]`. docs.rs builds with **no network access**; the native
feature is offline-safe because c2pa uses `rust_native_crypto` (no
openssl/network) and the TSA/Rekor clients only *compile* — they make no calls
at build time. Confirm locally:

```sh
cargo doc -p apohara-sealchain-core --no-deps
```

---

## 🔒 GATED release steps (maintainer only)

These require the maintainer's credentials/authorization. Do not run them
automatically.

### 1. 🔒 Push to GitHub

```sh
git remote add origin https://github.com/SuarezPM/apohara-sealchain.git  # if not set
git push -u origin main
```

### 2. 🔒 Tag and cut the GitHub Release (cargo-dist)

```sh
git tag v0.1.0
git push origin v0.1.0
```

The `v*` tag triggers `.github/workflows/release.yml` (cargo-dist when
initialized; the no-dist fallback otherwise), which builds the per-target
binaries and uploads them as Release assets:

- `apohara-sealchain-x86_64-unknown-linux-gnu`
- `apohara-sealchain-aarch64-apple-darwin`
- `apohara-sealchain-x86_64-pc-windows-msvc.exe`

These asset names MUST match the `ASSETS` map in `npx/install.js`.

### 3. 🔒 Publish to crates.io (core then bin)

```sh
cargo login            # uses the maintainer's crates.io token
cargo publish -p apohara-sealchain-core
# wait for it to index, then:
cargo publish -p apohara-sealchain
```

### 4. 🔒 Publish the npx wrapper to npm

The wrapper's `postinstall` downloads the Release binary for the host platform,
so step 2 must be complete and the assets present first.

```sh
cd npx
npm login              # uses the maintainer's npm credentials
npm publish --access public
```

### 5. 🔒 MCP marketplace submission

Submit `apohara-sealchain` to the MCP server marketplace/registry per its current
submission process (requires the maintainer's account).

### 6. 🔒 apohara.dev/sealchain page

Publish the project page and the in-browser WASM verifier
(`sealchain-wasm`) at https://apohara.dev/sealchain.

### 7. 🔒 OpenSSF Best Practices registration

The OpenSSF Scorecard badge (in the README) populates automatically once
`scorecard.yml` runs on the default branch. The **OpenSSF Best Practices** badge,
in contrast, requires a one-time manual registration:

1. Sign in at <https://www.bestpractices.dev> with the maintainer's GitHub account.
2. Register `github.com/SuarezPM/apohara-sealchain` and complete the questionnaire.
3. Add the project-id badge to the README **only after** registration, so the badge
   reflects the project's real status (`in progress` / `passing`) — never paste a
   `passing` badge before the criteria are actually met.

---

**All steps in this GATED section require the maintainer's credentials and explicit
authorization.** None of them are performed by CI or by an agent.
