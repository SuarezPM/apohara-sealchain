# sealchain (Node SDK)

A **thin** Node wrapper over the `apohara-sealchain` command-line tool. It does not
reimplement any cryptography: every call shells out (via `child_process`) to the
real `apohara-sealchain` binary (the same one built from `crates/apohara-sealchain`) and parses
its JSON output. The binary is the source of truth; this package only marshals
arguments.

## Requirements

- Node 18+ (uses `node:test`, ESM)
- The `apohara-sealchain` binary, resolved (in order) via:
  1. the `SEALCHAIN_BIN` environment variable,
  2. `apohara-sealchain` on your `PATH`,
  3. the in-repo release build at `<repo>/target/release/apohara-sealchain`.

Build the binary from the repo root:

```sh
cargo build --release -p apohara-sealchain
```

## Install

```sh
npm install ./sdk/node
```

(No runtime dependencies; the wrapper uses only Node built-ins.)

## Usage

```js
import { seal, verify, show } from "sealchain";

// Default offline seal: HMAC + Ed25519 + C2PA sidecar, no network.
const receipt = seal("model.gguf");          // -> "model.gguf.seal.json"

const verdict = verify("model.gguf", receipt);
// verdict == { ok: true, layers: [{ name, ok, reason }, ...] }

console.log(show(receipt));                   // human-readable chain trail
```

Network-backed layers (require connectivity at seal time):

```js
// "" -> default endpoint; a URL -> override it.
seal("model.gguf", { tsa: "", rekor: "https://rekor.example/v2" });

// Seal everything real-or-abort:
seal("model.gguf", { all: true });
```

Other options mirror the CLI flags:

```js
seal("photo.png", {
  c2pa: true,          // false -> --no-c2pa
  embed: true,         // embed the C2PA manifest in-file (supported media)
  sealedAt: "2026-01-01T00:00:00+00:00",
  out: "photo.seal.json",
});
```

## API

| Function | CLI equivalent | Returns |
|----------|----------------|---------|
| `seal(path, opts?)` | `apohara-sealchain seal ... --json` | receipt path (`string`) |
| `verify(path, receipt)` | `apohara-sealchain verify ... --json` | `{ ok, layers }` |
| `show(receipt)` | `apohara-sealchain show` | chain trail (`string`) |

`opts` for `seal`: `{ c2pa = true, embed = false, tsa = null, rekor = null, all = false, sealedAt = null, out = null }`.

`seal` and `show` throw `SealchainError` (with `.exitCode` and `.stderr`) on a
non-zero exit. `verify` treats exit 1 (verification failed) as a normal verdict
with `ok: false`; only structural failures throw.

## Tests

```sh
cd sdk/node
SEALCHAIN_BIN=<repo>/target/release/apohara-sealchain node --test
```

Tests skip gracefully when no binary can be resolved.
