"""SDK round-trip tests against the real apohara-sealchain binary.

These tests are build-binary-aware: if no binary can be resolved (no
SEALCHAIN_BIN, not on PATH, no in-repo release build), they skip rather than
fail. Run them with the built binary, e.g.:

    SEALCHAIN_BIN=<repo>/target/release/apohara-sealchain python3 -m pytest
"""

from __future__ import annotations

import pytest

import sealchain


def _binary_available() -> bool:
    try:
        sealchain.resolve_bin()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _binary_available(),
    reason="apohara-sealchain binary not found (set SEALCHAIN_BIN or build the release binary)",
)


def test_seal_verify_show_roundtrip(tmp_path):
    artifact = tmp_path / "doc.txt"
    artifact.write_text("sealchain python sdk roundtrip\n")

    # Default offline seal (HMAC + Ed25519 + C2PA sidecar), no network.
    receipt = sealchain.seal(artifact)
    assert receipt, "seal returns a receipt path"

    verdict = sealchain.verify(artifact, receipt)
    assert verdict["ok"] is True
    names = {layer["name"] for layer in verdict["layers"]}
    assert {"content", "hmac", "ed25519", "c2pa"}.issubset(names)

    trail = sealchain.show(receipt)
    assert isinstance(trail, str)
    assert "apohara-seal-v1" in trail


def test_verify_detects_tamper(tmp_path):
    artifact = tmp_path / "doc.txt"
    artifact.write_text("original content\n")
    receipt = sealchain.seal(artifact)

    # Mutate the artifact after sealing: verification must report ok=False
    # without raising (exit 1 is a verdict, not an error).
    artifact.write_text("tampered content\n")
    verdict = sealchain.verify(artifact, receipt)
    assert verdict["ok"] is False


def test_seal_honors_out_and_sealed_at(tmp_path):
    artifact = tmp_path / "doc.txt"
    artifact.write_text("pinned timestamp\n")
    out = tmp_path / "custom.seal.json"

    receipt = sealchain.seal(
        artifact, out=out, sealed_at="2026-01-01T00:00:00+00:00"
    )
    assert receipt == str(out)
    assert out.is_file()

    trail = sealchain.show(receipt)
    assert "2026-01-01T00:00:00+00:00" in trail


def test_seal_raises_on_missing_artifact(tmp_path):
    missing = tmp_path / "nope.txt"
    with pytest.raises(sealchain.SealchainError) as exc:
        sealchain.seal(missing)
    assert exc.value.exit_code != 0
