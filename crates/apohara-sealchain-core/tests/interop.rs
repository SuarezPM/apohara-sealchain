//! Cross-implementation interop: Rust seals, Python verifies.
//!
//! Produces a record with [`seal_deterministic`] using the FIXED conformance
//! keys and `sealed_at = 2026-01-01T00:00:00+00:00`, then shells the probanza
//! reference interpreter to verify it through `core.seal.verify`. A green run
//! proves both engines agree on the JCS preimage and the HMAC + Ed25519 layers.
//!
//! `#[ignore]` by design — it depends on the probanza checkout and its venv.
//! Run it on demand:
//!
//! ```text
//! PROBANZA_DIR=/home/thelinconx/apohara-probanza \
//!   cargo test -p apohara-sealchain-core --test interop -- --ignored
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use apohara_sealchain_core::layers::ed25519 as ed_layer;
use apohara_sealchain_core::seal_deterministic;
use serde_json::Value;

const KEYS: &str = include_str!("vectors/keys.json");
const SEALED_AT: &str = "2026-01-01T00:00:00+00:00";

/// Default probanza checkout when `PROBANZA_DIR` is unset.
const DEFAULT_PROBANZA: &str = "/home/thelinconx/apohara-probanza";

/// Python verifier driver: loads the record + keys from argv paths and asserts
/// `core.seal.verify(...) is True`, exiting non-zero on any failure.
const PY_DRIVER: &str = r#"
import json, sys
from pathlib import Path
from core.seal import verify

record = json.loads(Path(sys.argv[1]).read_text())
key_hmac = bytes.fromhex(sys.argv[2])
public_pem = Path(sys.argv[3]).read_bytes()

ok = verify(record, key_hmac=key_hmac, public_key_ed25519_pem=public_pem)
if ok is not True:
    print(f"verify returned {ok!r}", file=sys.stderr)
    sys.exit(1)
print("OK")
"#;

#[test]
#[ignore = "requires probanza checkout + venv; run with --ignored and PROBANZA_DIR"]
fn rust_seal_verifies_in_python() {
    let probanza = std::env::var("PROBANZA_DIR").unwrap_or_else(|_| DEFAULT_PROBANZA.to_string());
    let probanza = PathBuf::from(probanza);
    let python = probanza.join(".venv/bin/python");
    assert!(
        python.is_file(),
        "probanza python not found at {} (set PROBANZA_DIR)",
        python.display()
    );

    // Parse fixed keys.
    let keys: Value = serde_json::from_str(KEYS).expect("keys.json parses");
    let hmac_hex = keys["hmac_key_hex"].as_str().expect("hmac_key_hex");
    let hmac_key = hex::decode(hmac_hex).expect("hmac hex decodes");
    let private_pem = keys["ed25519_private_pem"].as_str().expect("private pem");
    let public_pem = keys["ed25519_public_pem"].as_str().expect("public pem");
    let signing = ed_layer::signing_key_from_pem(private_pem).expect("signing key parses");

    // Seal a representative payload with the fixed timestamp.
    let payload = serde_json::json!({ "verdict": "blocked", "n": 42 });
    let record = seal_deterministic(&payload, &hmac_key, Some(&signing), SEALED_AT)
        .expect("seal_deterministic");
    let record_json = serde_json::to_string(&record).expect("serialize record");

    // Materialize record, driver script, and public key for the subprocess.
    let tmp = tempfile::tempdir().expect("tempdir");
    let record_path = tmp.path().join("record.json");
    std::fs::write(&record_path, record_json).expect("write record");

    let pub_path = tmp.path().join("public.pem");
    std::fs::write(&pub_path, public_pem).expect("write public pem");

    let driver_path = tmp.path().join("driver.py");
    let mut f = std::fs::File::create(&driver_path).expect("create driver");
    f.write_all(PY_DRIVER.as_bytes()).expect("write driver");

    // Running a script file does not put the cwd on sys.path; point PYTHONPATH
    // at the probanza root so `core.seal` imports resolve.
    let output = Command::new(&python)
        .arg(&driver_path)
        .arg(&record_path)
        .arg(hmac_hex)
        .arg(&pub_path)
        .current_dir(&probanza)
        .env("PYTHONPATH", &probanza)
        .output()
        .expect("spawn python verifier");

    assert!(
        output.status.success(),
        "python verify failed (exit {:?})\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
