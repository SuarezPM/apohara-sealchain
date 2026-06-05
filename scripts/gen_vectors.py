#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Deterministic conformance-vector generator for apohara-sealchain.

Runs against the Python `core/seal` reference (apohara-probanza) to emit a
byte-reproducible corpus of `apohara-seal-v1` records that the Rust
reimplementation must verify (Tier-A conformance gate).

Determinism: pinned `sealed_at`, FIXED HMAC key + FIXED Ed25519 seed. The
keys are NON-SECRET, test-only material (allowlisted in .gitleaks.toml).

Usage (from the probanza repo root, with its venv):
    cd /home/thelinconx/apohara-probanza
    .venv/bin/python /home/thelinconx/apohara-sealchain/scripts/gen_vectors.py

Output: crates/apohara-sealchain-core/tests/vectors/ (keys.json + vec_*.json + INDEX.json)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# --- locate probanza (the reference) and import core.seal ---
PROBANZA = Path(os.environ.get("PROBANZA_DIR", "/home/thelinconx/apohara-probanza"))
if str(PROBANZA) not in sys.path:
    sys.path.insert(0, str(PROBANZA))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from core.seal import seal, verify  # noqa: E402
from core.seal.ed25519 import Ed25519KeyPair  # noqa: E402

# --- pinned, deterministic inputs ---
SEALED_AT = "2026-01-01T00:00:00+00:00"
HMAC_KEY = b"apohara-sealchain-test-hmac-key-fixed-01!"  # 32 bytes, NON-SECRET test key
ED25519_SEED = bytes(range(32))                  # fixed 32-byte seed, NON-SECRET

OUT_DIR = Path(__file__).resolve().parent.parent / "crates" / "apohara-sealchain-core" / "tests" / "vectors"


def fixed_keypair() -> Ed25519KeyPair:
    sk = Ed25519PrivateKey.from_private_bytes(ED25519_SEED)
    return Ed25519KeyPair(private_key=sk, public_key=sk.public_key(), key_id="default")


def pem_private(kp: Ed25519KeyPair) -> bytes:
    return kp.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def dump(path: Path, obj: object) -> None:
    # sort_keys + fixed separators => byte-reproducible files.
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    kp = fixed_keypair()
    pub_pem = kp.public_pem()

    # (name, payload, use_ed25519) — Tier-A: deterministic, no network.
    #
    # The corpus is MAXIMIZED to exercise the JCS + schema + HMAC + Ed25519 path
    # across as much payload-shape diversity as is byte-reproducible between the
    # Python `rfc8785` and Rust `serde_jcs` canonicalizers. C2PA/TSA/Rekor are
    # intentionally absent (non-deterministic; covered by their own tests).
    #
    # vec_01..vec_08 are the original corpus and are kept byte-stable. vec_09+
    # extend coverage. Every record self-verifies under core.seal.verify below.
    cases = [
        # --- original corpus (unchanged) ---
        ("vec_01_hmac_only", {"verdict": "blocked"}, False),
        ("vec_02_hmac_ed", {"verdict": "blocked"}, True),
        ("vec_03_simple_v1", {"v": 1}, True),
        ("vec_04_excluded_key", {"verdict": "ok", "truncated": True, "charsSeen": 123}, True),
        ("vec_05_astral_unicode", {"msg": "rocket \U0001F680", "lab": "\U0001F9EA", "cjk": "末"}, True),
        ("vec_06_numbers", {"int": 1, "float": 1.5, "neg": -3, "zero": 0, "big": 1000000, "frac": 0.001, "negzero": -0.0}, True),
        ("vec_07_nested", {"outer": {"b": 2, "a": 1}, "list": [3, 2, 1], "z": "末"}, True),
        ("vec_08_artifact_descriptor", {
            "artifactSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "path": "model.bin", "size": 0, "mime": "application/octet-stream",
        }, True),

        # --- maximized corpus (vec_09+) ---
        # Degenerate / empty shapes.
        ("vec_09_empty_object", {}, True),
        ("vec_10_empty_string_values", {"a": "", "b": "", "empty": ""}, True),
        # Deep nesting (5 levels) + objects sharing key names at each level.
        ("vec_11_deeply_nested", {
            "l1": {"l2": {"l3": {"l4": {"l5": "deep", "k": 1}, "k": 2}, "k": 3}, "k": 4}, "k": 5,
        }, True),
        # Arrays of mixed scalar types (string, int, float, bool, null).
        ("vec_12_array_mixed", {"items": ["s", 1, 2.5, True, False, None, ""]}, True),
        # Arrays of objects (order-significant within the array, JCS-sorted keys).
        ("vec_13_array_of_objects", {
            "rows": [{"b": 1, "a": 2}, {"z": "end", "a": "start"}, {}],
        }, True),
        # JCS-safe integer bounds: RFC 8785 numbers are IEEE-754 doubles, so the
        # exact-integer domain is ±(2^53 - 1). Exercise that ceiling/floor and
        # adjacent values (larger ints would be float-coerced and are rejected
        # by the rfc8785 reference — intentionally out of Tier-A scope).
        ("vec_14_int_bounds", {
            "max_safe": 9007199254740991, "min_safe": -9007199254740991,
            "near_max": 9007199254740990, "near_min": -9007199254740990,
            "million": 1000000, "billion": 1000000000,
        }, True),
        # Floats with ES6/RFC-8785 formatting edge cases that both
        # canonicalizers must render identically (incl. 1e21 -> exponential,
        # -0.0 -> 0, sub-normal-ish small magnitudes).
        ("vec_15_floats_edge", {
            "tiny": 1e-7, "smaller": 5e-324, "big_exp": 1e21,
            "onefive": 1.5, "milli": 0.001, "negzero": -0.0, "neg": -2.25,
        }, True),
        # Unicode: combining marks (NFC vs decomposed left as-authored), RTL,
        # astral, CJK — JCS does NOT normalize, only escapes minimally.
        ("vec_16_unicode_combining_rtl", {
            "combining": "é",            # e + COMBINING ACUTE ACCENT
            "rtl": "אבג",      # Hebrew alef-bet-gimel
            "arabic": "العربية",  # "العربية"
            "astral": "\U0001F4A9\U0001F600",  # pile-of-poo + grinning face
        }, True),
        # JCS sort stress: out-of-order keys, uppercase vs lowercase (uppercase
        # sorts before lowercase by UTF-16 code unit), digits, symbols.
        ("vec_17_jcs_sort", {
            "z": 1, "a": 2, "Z": 3, "A": 4, "m": 5, "M": 6,
            "0": 7, "9": 8, "_": 9, "-": 10, " ": 11,
        }, True),
        # Every excluded key present at top level + nested (verify strip): the
        # seal must be identical to the same payload with these keys removed.
        ("vec_18_all_excluded", {
            "kept": "content",
            "kg_status": "killed", "kg_latency_ms": 42, "surface_status": "ok",
            "truncated": True, "charsSeen": 9999, "lowConfidenceTier": True,
            "nested": {
                "alsoKept": 1,
                "kg_status": "x", "kg_latency_ms": 0, "surface_status": "y",
                "truncated": False, "charsSeen": 0, "lowConfidenceTier": False,
            },
        }, True),
        # Boolean / null scalar values at top level.
        ("vec_19_bool_null", {"yes": True, "no": False, "nothing": None}, True),
        # Same key spelling at different depths (no key collision; JCS treats
        # each object independently).
        ("vec_20_repeated_nested_keys", {
            "id": "root", "child": {"id": "c1", "child": {"id": "c2"}},
        }, True),
        # Large payload: many top-level keys to stress JCS sort + size.
        ("vec_21_large_payload", {f"k{i:03d}": i for i in range(64)}, True),
        # HMAC-only variants covering shape diversity without Ed25519.
        ("vec_22_hmac_only_nested", {"a": {"b": {"c": [1, 2, 3]}}, "flag": True}, False),
        ("vec_23_hmac_only_unicode", {"msg": "\U0001F680 末 א"}, False),
        # Artifact-descriptor with optional/extra metadata fields populated.
        ("vec_24_artifact_full", {
            "artifactSha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "path": "weights/model.safetensors", "size": 1073741824,
            "mime": "application/octet-stream", "producer": "apohara",
            "tags": ["fp16", "quantized"], "version": 3,
        }, True),
        # Escaping stress: control chars, quotes, backslashes, slash (JCS does
        # NOT escape forward slash), tab/newline.
        ("vec_25_escapes", {
            "quote": "he said \"hi\"", "backslash": "a\\b",
            "slash": "a/b", "tab": "x\ty", "newline": "x\ny",
            "backspace": "x\by", "formfeed": "x\fy",
            "carriage": "x\ry", "unit_sep": "a\u001fb",
        }, True),
        # Empty array + array of empty objects/arrays + nested empties.
        ("vec_26_empty_containers", {
            "arr": [], "obj": {}, "arr_of_empty": [{}, [], {}],
            "nested_empty": {"a": {}, "b": []},
        }, True),
    ]

    index = []
    for name, payload, use_ed in cases:
        record = seal(
            payload,
            key_hmac=HMAC_KEY,
            key_ed25519=(kp if use_ed else None),
            sealed_at=SEALED_AT,
        ).to_dict()

        # self-check against the reference verifier
        if use_ed:
            ok = verify(record, key_hmac=HMAC_KEY, public_key_ed25519_pem=pub_pem)
        else:
            ok = verify(record, key_hmac=HMAC_KEY)
        if not ok:
            print(f"FAIL: reference verify() rejected {name}", file=sys.stderr)
            return 1

        dump(OUT_DIR / f"{name}.json", record)
        index.append({"name": name, "uses_ed25519": use_ed,
                      "layers": ["hmac"] + (["ed25519"] if use_ed else [])})
        print(f"ok  {name}  (ed25519={use_ed})")

    dump(OUT_DIR / "keys.json", {
        "note": "FIXED NON-SECRET test keys for conformance vectors only.",
        "sealed_at": SEALED_AT,
        "hmac_key_hex": HMAC_KEY.hex(),
        "hmac_key_id": "hmac-default",
        "ed25519_key_id": "default",
        "ed25519_private_pem": pem_private(kp).decode("ascii"),
        "ed25519_public_pem": pub_pem.decode("ascii"),
    })
    dump(OUT_DIR / "INDEX.json", {"tier": "A", "count": len(index), "vectors": index})
    print(f"\nWrote {len(index)} Tier-A vectors + keys.json + INDEX.json to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
