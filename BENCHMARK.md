# Benchmarks

Honest, reproducible micro-benchmarks for the **offline** profile of
apohara-sealchain. A seal is evidence, not a verdict — these numbers describe
*cost*, not trust. Re-run them yourself with [`scripts/bench.sh`](scripts/bench.sh);
the table below is its verbatim output.

## What is (and isn't) measured

- **Offline only.** Only the fully-offline seal (`HMAC + Ed25519 + C2PA`) and
  offline `verify` are measured. The network tiers (`--tsa`, `--rekor`) are
  **deliberately excluded**: their latency is dominated by the remote
  timestamp/transparency service, not by this tool, and is not reproducible.
- **`verify` throughput is per-file CLI invocation** — it includes process
  startup on every call, so it understates the in-process crypto cost. It reflects
  the realistic "shell loop over many receipts" pattern, not a library-level
  hot loop.
- **`seal` throughput is one process over a directory** (`seal <dir> -r`), so
  process startup is amortized across the batch — the realistic batch-sealing path.
- Each artifact is random bytes; the C2PA JUMBF manifest dominates the receipt size
  regardless of payload size, so the receipt is ~constant.
- The seal latencies **include the default local-index write** (to an isolated temp
  `XDG_DATA_HOME`, so no real index is touched) — i.e. these are realistic
  end-to-end numbers, not pure-crypto. Pass `--no-index` to seal without indexing.

## Environment

| | |
|---|---|
| CPU | AMD Ryzen 5 3600 (6c/12t, Zen 2) |
| RAM | 48 GB DDR4 @ 2933 MT/s |
| Storage | NVMe Gen4 SSD (Btrfs, zstd:1) |
| OS | CachyOS (Arch, rolling), Linux |
| Toolchain | `rustc 1.96.0`, release build (`cargo build --release`) |
| Binary | `apohara-sealchain 0.1.0` |
| Command | `scripts/bench.sh 1000 1024` (N = 1000 files, 1024 bytes each) |

Numbers vary by machine and load; treat them as order-of-magnitude, not a contract.

## Results

| Operation | Profile | Result |
|---|---|---|
| Seal (single file) | offline: HMAC + Ed25519 + C2PA | 6.0 ms |
| Seal (single file) | HMAC + Ed25519 (`--no-c2pa`) | 4.0 ms |
| C2PA cost (delta) | the JUMBF manifest layer | +2.0 ms |
| Verify (single file) | offline, all present layers | 4.0 ms |
| Seal throughput | batch `seal <dir> -r`, 1000×1024B, one process | 1124 seals/s |
| Verify throughput | per-file CLI (incl. process startup), 1000× | 324 verifies/s |
| Receipt size | offline seal of a 1024B file | 25302 bytes |

### Reading the numbers

- **C2PA is the dominant cost.** It adds ~2 ms per seal and ~25 KB to every
  receipt (the JUMBF manifest), regardless of payload size. Use `--no-c2pa` when
  you only need integrity + authorship and the ~25 KB / ~2 ms matters.
- **Batch sealing amortizes startup** (~1100 seals/s in one process) far better
  than a shell loop of single `seal` calls would.
- **Verify is cheap in-process** (~4 ms) but the per-file CLI throughput (~324/s)
  is gated by process startup — verify many receipts in one process (the WASM
  verifier or the SDKs) for higher throughput.

## Reproduce

```sh
# Full run (defaults: N=1000 files, 1024 bytes each)
scripts/bench.sh

# Quick run
N=50 scripts/bench.sh 50 256
```

The script is self-contained: it uses an isolated `XDG_CONFIG_HOME`/`XDG_DATA_HOME`,
generates its own keypair and inputs, cleans up on exit, and prints the Markdown
table above. CI runs it with a small `N` as a smoke test (asserting it exits 0 and
produces a table — never a throughput threshold, so it cannot flake).
