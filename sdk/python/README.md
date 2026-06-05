# sealchain (Python SDK)

A **thin** Python wrapper over the `apohara-sealchain` command-line tool. It does not
reimplement any cryptography: every call shells out to the real `apohara-sealchain`
binary (the same one built from `crates/apohara-sealchain`) and parses its JSON output.
The binary is the source of truth; this package only marshals arguments.

## Requirements

- Python 3.9+
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
pip install -e sdk/python
```

(No runtime dependencies; the wrapper uses only the standard library.)

## Usage

```python
import sealchain

# Default offline seal: HMAC + Ed25519 + C2PA sidecar, no network.
receipt = sealchain.seal("model.gguf")          # -> "model.gguf.seal.json"

verdict = sealchain.verify("model.gguf", receipt)
assert verdict["ok"] is True
# verdict == {"ok": True, "layers": [{"name", "ok", "reason"}, ...]}

print(sealchain.show(receipt))                   # human-readable chain trail
```

Network-backed layers (require connectivity at seal time):

```python
# Empty string -> default endpoint; a URL -> override it.
sealchain.seal("model.gguf", tsa="", rekor="https://rekor.example/v2")

# Seal everything real-or-abort:
sealchain.seal("model.gguf", all=True)
```

Other options mirror the CLI flags:

```python
sealchain.seal(
    "photo.png",
    c2pa=True,          # False -> --no-c2pa
    embed=True,         # embed the C2PA manifest in-file (supported media)
    sealed_at="2026-01-01T00:00:00+00:00",
    out="photo.seal.json",
)
```

## API

| Function | CLI equivalent | Returns |
|----------|----------------|---------|
| `seal(path, *, c2pa=True, embed=False, tsa=None, rekor=None, all=False, sealed_at=None, out=None)` | `apohara-sealchain seal ... --json` | receipt path (`str`) |
| `verify(path, receipt)` | `apohara-sealchain verify ... --json` | `{"ok": bool, "layers": [...]}` |
| `show(receipt)` | `apohara-sealchain show` | chain trail (`str`) |

`seal` and `show` raise `SealchainError` (with `.exit_code` and `.stderr`) on a
non-zero exit. `verify` treats exit 1 (verification failed) as a normal verdict
with `ok=False`; only structural failures raise.

## Tests

```sh
cd sdk/python
SEALCHAIN_BIN=<repo>/target/release/apohara-sealchain python3 -m pytest
```

Tests skip gracefully when no binary can be resolved.
