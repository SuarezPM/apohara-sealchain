"""Thin Python SDK over the ``apohara-sealchain`` CLI.

This package does not reimplement any cryptography. It shells out to the real
``apohara-sealchain`` binary (the same one built from ``crates/apohara-sealchain``) and parses
its output. The binary is the single source of truth; this module only marshals
arguments and JSON.

Binary resolution order:

1. ``SEALCHAIN_BIN`` environment variable, if set.
2. ``apohara-sealchain`` on ``PATH``.
3. The in-repo release build at ``<repo>/target/release/apohara-sealchain``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

__all__ = ["seal", "verify", "show", "resolve_bin", "SealchainError"]

__version__ = "0.1.0"


class SealchainError(RuntimeError):
    """Raised when the ``apohara-sealchain`` binary exits non-zero.

    Carries the process ``exit_code`` and captured ``stderr`` for diagnosis.
    """

    def __init__(self, message: str, *, exit_code: int, stderr: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


def resolve_bin() -> str:
    """Resolve the ``apohara-sealchain`` binary path.

    Honors ``SEALCHAIN_BIN``, then ``PATH``, then the in-repo release build.
    Returns the resolved path or command name; raises ``FileNotFoundError`` if
    none is usable.
    """
    env_bin = os.environ.get("SEALCHAIN_BIN")
    if env_bin:
        return env_bin

    on_path = shutil.which("apohara-sealchain")
    if on_path:
        return on_path

    # Repo fallback: this file lives at sdk/python/sealchain/__init__.py, so the
    # repo root is three parents up.
    repo_root = Path(__file__).resolve().parents[3]
    candidate = repo_root / "target" / "release" / "sealchain"
    if candidate.is_file():
        return str(candidate)

    raise FileNotFoundError(
        "apohara-sealchain binary not found. Set SEALCHAIN_BIN, put `apohara-sealchain` on PATH, "
        "or build it with `cargo build --release -p apohara-sealchain`."
    )


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the binary with ``args``, capturing text stdout/stderr."""
    return subprocess.run(
        [resolve_bin(), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def seal(
    path: str | os.PathLike[str],
    *,
    c2pa: bool = True,
    embed: bool = False,
    tsa: str | None = None,
    rekor: str | None = None,
    all: bool = False,
    sealed_at: str | None = None,
    out: str | os.PathLike[str] | None = None,
) -> str:
    """Seal ``path`` into a receipt and return the receipt path.

    Mirrors ``apohara-sealchain seal``. The default is fully offline (HMAC + Ed25519 +
    C2PA sidecar). ``tsa``/``rekor``/``all`` add network-backed layers that need
    connectivity at seal time.

    Args:
        path: Artifact to seal.
        c2pa: Emit the offline C2PA sidecar (on by default). ``False`` passes
            ``--no-c2pa``.
        embed: Embed the C2PA manifest in the artifact file (supported media
            only).
        tsa: Add an RFC 3161 TSA layer. Pass a URL to override the default
            authority, or an empty string to use the default.
        rekor: Add a Sigstore Rekor v2 layer. Pass a URL to override the default
            shard, or an empty string to use the default.
        all: Seal all layers real-or-abort.
        sealed_at: Fixed RFC 3339 timestamp (reproducible demos/interop).
        out: Receipt output path (default ``<path>.seal.json``).

    Returns:
        The receipt path reported by the binary.

    Raises:
        SealchainError: If the binary exits non-zero (stderr attached).
    """
    args: list[str] = ["seal", os.fspath(path)]
    if not c2pa:
        args.append("--no-c2pa")
    if embed:
        args.append("--embed")
    if tsa is not None:
        args.append("--tsa")
        if tsa:
            args.append(tsa)
    if rekor is not None:
        args.append("--rekor")
        if rekor:
            args.append(rekor)
    if all:
        args.append("--all")
    if sealed_at is not None:
        args.extend(["--sealed-at", sealed_at])
    if out is not None:
        args.extend(["--out", os.fspath(out)])
    args.append("--json")

    proc = _run(args)
    if proc.returncode != 0:
        raise SealchainError(
            f"apohara-sealchain seal failed (exit {proc.returncode})",
            exit_code=proc.returncode,
            stderr=proc.stderr.strip(),
        )

    payload = json.loads(proc.stdout)
    # `seal --json` emits a batch envelope: {"sealed","failed","files":[{...,"receipt_path"}]}.
    # (A single path is just a batch of one.) Fall back to a top-level field for
    # forward-compatibility if the CLI ever emits one.
    files = payload.get("files") or []
    if payload.get("failed"):
        raise SealchainError(
            f"apohara-sealchain seal reported {payload['failed']} failure(s)",
            exit_code=proc.returncode,
            stderr=proc.stderr.strip(),
        )
    if files:
        return files[0]["receipt_path"]
    if "receipt_path" in payload:
        return payload["receipt_path"]
    raise SealchainError(
        "apohara-sealchain seal produced no receipt path in --json output",
        exit_code=proc.returncode,
        stderr=proc.stderr.strip(),
    )


def verify(
    path: str | os.PathLike[str],
    receipt: str | os.PathLike[str],
) -> dict[str, Any]:
    """Verify ``path`` against ``receipt`` and return the verdict.

    Mirrors ``apohara-sealchain verify --json``. Returns the parsed verdict
    ``{"ok": bool, "layers": [{"name", "ok", "reason"}, ...]}``.

    A failed verification (tamper/mismatch, exit 1) is NOT an error: it returns
    the verdict with ``ok=False``. Only structural failures (bad receipt, exit
    3) raise.

    Raises:
        SealchainError: On structural failure (non 0/1 exit).
    """
    proc = _run(["verify", os.fspath(path), os.fspath(receipt), "--json"])
    # Exit 0 = pass, 1 = verification failed; both produce a JSON verdict.
    if proc.returncode not in (0, 1):
        raise SealchainError(
            f"apohara-sealchain verify failed (exit {proc.returncode})",
            exit_code=proc.returncode,
            stderr=proc.stderr.strip(),
        )
    return json.loads(proc.stdout)


def show(receipt: str | os.PathLike[str]) -> str:
    """Return the human-readable chain trail for ``receipt``.

    Mirrors ``apohara-sealchain show``.

    Raises:
        SealchainError: If the binary exits non-zero.
    """
    proc = _run(["show", os.fspath(receipt)])
    if proc.returncode != 0:
        raise SealchainError(
            f"apohara-sealchain show failed (exit {proc.returncode})",
            exit_code=proc.returncode,
            stderr=proc.stderr.strip(),
        )
    return proc.stdout
