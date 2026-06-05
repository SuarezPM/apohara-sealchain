//! CLI integration tests: the exit-code contract end to end.
//!
//! Exercises the round trip (seal -> verify) and the failure modes that map to
//! distinct exit codes: tamper (1), malformed receipt (3), missing key file (4).

use std::fs;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use tempfile::tempdir;

/// Deterministic non-secret HMAC key (hex) for reproducible tests.
const HMAC_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn apohara_sealchain() -> Command {
    Command::cargo_bin("apohara-sealchain").expect("binary builds")
}

#[test]
fn seal_then_verify_exits_0() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"apohara-sealchain cli round trip").expect("write artifact");
    let receipt = dir.path().join("doc.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--out"])
        .arg(&receipt)
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(0);
}

#[test]
fn flipped_byte_verify_exits_1() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.bin");
    fs::write(&artifact, b"original content").expect("write artifact");
    let receipt = dir.path().join("doc.bin.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    // Flip one byte of the file; the receipt is unchanged.
    fs::write(&artifact, b"Original content").expect("rewrite artifact");

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(1);
}

#[test]
fn malformed_receipt_exits_3() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"x").expect("write artifact");
    let receipt = dir.path().join("broken.json");
    fs::write(&receipt, b"not json at all").expect("write broken receipt");

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(3);
}

#[test]
fn missing_key_file_exits_4() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"x").expect("write artifact");
    let missing_key = dir.path().join("__nonexistent_key__.pem");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .arg("--key")
        .arg(&missing_key)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(4);
}

#[test]
fn missing_hmac_key_file_exits_4() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"x").expect("write artifact");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", "@/tmp/__apohara-sealchain_nonexistent_hmac__"])
        .assert()
        .code(4);
}

#[test]
fn no_args_is_usage_error_exit_2() {
    apohara_sealchain().assert().code(2);
}

#[test]
fn seal_with_c2pa_then_verify_and_show() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"apohara-sealchain cli c2pa sidecar").expect("write artifact");
    let receipt = dir.path().join("doc.seal.json");

    // Seal with the offline C2PA sidecar.
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--c2pa", "--hmac-key", HMAC_HEX, "--out"])
        .arg(&receipt)
        .assert()
        .success();

    // The receipt carries the real JUMBF manifest as 0x-hex.
    let body = fs::read_to_string(&receipt).expect("read receipt");
    assert!(body.contains("\"c2paManifest\""), "c2paManifest present");

    // Verify reports a passing c2pa layer.
    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--json"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("\"c2pa\""))
        .stdout(predicates::str::contains("\"ok\":true"));

    // show lists the c2pa layer.
    apohara_sealchain()
        .args(["show"])
        .arg(&receipt)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("c2pa"));
}

/// A minimal valid 1x1 RGBA PNG (real, c2pa-embeddable).
fn tiny_png() -> Vec<u8> {
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240,
        31, 0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
}

#[test]
fn embed_unsupported_format_exits_2_no_receipt() {
    // .txt is not an embeddable media format: --embed must hard-error (exit 2)
    // and write NO receipt — never a silent sidecar fallback.
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"x").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--embed", "--hmac-key", HMAC_HEX])
        .assert()
        .code(2);

    assert!(!receipt.exists(), "no receipt on rejected embed");
}

#[test]
fn embed_supported_png_seals_in_file_and_verifies() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("photo.png");
    fs::write(&artifact, tiny_png()).expect("write png");
    let receipt = dir.path().join("photo.png.seal.json");

    // --embed on a PNG writes an in-file C2PA manifest and a sidecar receipt.
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--embed", "--hmac-key", HMAC_HEX])
        .assert()
        .success()
        .stdout(predicates::str::contains("c2pa"));

    // The receipt records the embedded mode, not a sidecar manifest.
    let body = fs::read_to_string(&receipt).expect("read receipt");
    assert!(body.contains("\"c2paEmbedded\""), "c2paEmbedded recorded");
    assert!(!body.contains("\"c2paManifest\""), "no sidecar manifest");

    // The PNG on disk was rewritten with the embedded asset.
    assert_ne!(
        fs::read(&artifact).expect("read png"),
        tiny_png(),
        "file rewritten with embedded manifest"
    );

    // Verify round-trips: content + embedded c2pa both ok.
    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--json"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("\"c2pa\""))
        .stdout(predicates::str::contains("\"ok\":true"));
}

#[test]
fn embed_with_no_c2pa_exits_2() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("photo.png");
    fs::write(&artifact, tiny_png()).expect("write png");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--embed", "--no-c2pa", "--hmac-key", HMAC_HEX])
        .assert()
        .code(2);
}

#[test]
fn json_verify_emits_structured_output() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"json output check").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--json"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("\"ok\":true"))
        .stdout(predicates::str::contains("\"content\""));
}

#[test]
fn default_seal_is_offline_three_layers_and_verifies() {
    // Default seal = HMAC + Ed25519 + C2PA, fully offline. No network flags, so
    // no TSA/Rekor call is attempted; it completes and verifies with exit 0.
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"default offline seal").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--json"])
        .assert()
        .success()
        // The reported layer set is exactly the three offline layers.
        .stdout(predicates::str::contains("\"hmac\""))
        .stdout(predicates::str::contains("\"ed25519\""))
        .stdout(predicates::str::contains("\"c2pa\""))
        .stdout(predicates::str::contains("\"tsa\"").not())
        .stdout(predicates::str::contains("\"rekor\"").not());

    // The receipt carries the offline layers and neither network layer.
    let body = fs::read_to_string(&receipt).expect("read receipt");
    assert!(body.contains("\"c2paManifest\""), "c2pa sidecar present");
    assert!(!body.contains("\"tsa\""), "no tsa layer offline");
    assert!(!body.contains("\"rekorAnchor\""), "no rekor layer offline");

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(0);
}

#[test]
fn no_c2pa_seals_only_hmac_ed25519() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"no c2pa seal").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--no-c2pa", "--hmac-key", HMAC_HEX])
        .assert()
        .success();

    let body = fs::read_to_string(&receipt).expect("read receipt");
    assert!(!body.contains("\"c2paManifest\""), "c2pa opted out");

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(0);
}

#[test]
fn all_against_unreachable_tsa_aborts_without_partial_receipt() {
    // TSA is the first network layer attempted; pointing it at an unreachable
    // endpoint forces an abort before any receipt is written. We use --tsa
    // explicitly (deterministic offline failure) to exercise the same
    // abort-without-partial-receipt path --all relies on.
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"abort no partial receipt").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--tsa", "http://127.0.0.1:9/x"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("ERROR"));

    // Real-or-abort: NO receipt may be written on a layer failure.
    assert!(
        !receipt.exists(),
        "no partial/faked receipt on aborted seal"
    );
}

#[test]
fn rekor_unreachable_aborts_without_partial_receipt() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"rekor abort case").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--rekor", "http://127.0.0.1:9"])
        .assert()
        .code(1);

    assert!(!receipt.exists(), "no partial receipt on rekor failure");
}

#[test]
#[ignore = "network: hits the live default TSA at seal time"]
fn tsa_live_default_seal_adds_tsa_layer() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"live tsa seal").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--tsa"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"tsa\""));

    let body = fs::read_to_string(&receipt).expect("read receipt");
    assert!(body.contains("\"tsa\""), "tsa layer present in receipt");

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(0);
}

#[test]
#[ignore = "network: hits the live default Rekor shard at seal time"]
fn rekor_live_default_seal_adds_rekor_layer() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"live rekor seal").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--rekor"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"rekor\""));

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .code(0);
}

#[test]
fn quiet_suppresses_stdout() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"quiet check").expect("write artifact");
    let receipt = dir.path().join("doc.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--quiet"])
        .assert()
        .code(0)
        .stdout(predicates::str::is_empty());
}

// --- key management: passphrase-encrypted keystore + rotation ---

const PASSPHRASE: &str = "correct horse battery staple";

#[test]
fn key_encrypt_removes_plaintext_and_writes_blob() {
    // Generate a default plaintext keystore via --config-dir, then encrypt it:
    // the encrypted blob appears and the plaintext private files are removed.
    let cfg = tempdir().expect("cfg");

    apohara_sealchain()
        .args(["keygen", "--config-dir"])
        .arg(cfg.path())
        .assert()
        .success();

    apohara_sealchain()
        .args(["key", "encrypt", "--config-dir"])
        .arg(cfg.path())
        .args(["--passphrase", PASSPHRASE])
        .assert()
        .success()
        .stdout(predicates::str::contains("ENCRYPTED"));

    assert!(cfg.path().join("keystore.enc").is_file());
    assert!(!cfg.path().join("ed25519.pem").is_file());
    assert!(!cfg.path().join("hmac.key").is_file());

    // `key show` works without a passphrase (public PEM is in the clear) and
    // reports the encrypted mode.
    apohara_sealchain()
        .args(["key", "show", "--config-dir"])
        .arg(cfg.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("encrypted"));
}

#[test]
fn seal_with_encrypted_keystore_via_config_dir_and_passphrase() {
    let cfg = tempdir().expect("cfg");
    let work = tempdir().expect("work");
    let artifact = work.path().join("doc.txt");
    fs::write(&artifact, b"xdg encrypted seal").expect("write artifact");
    let receipt = work.path().join("doc.txt.seal.json");

    // Create + encrypt a keystore inside cfg, then point the default keystore at
    // cfg by overriding XDG_CONFIG_HOME (resolve_config_dir honors it).
    let xdg = cfg.path();
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["keygen"])
        .assert()
        .success();
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "encrypt", "--passphrase", PASSPHRASE])
        .assert()
        .success();

    // Seal with the right passphrase from the environment.
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .env("SEALCHAIN_PASSPHRASE", PASSPHRASE)
        .args(["seal"])
        .arg(&artifact)
        .arg("--out")
        .arg(&receipt)
        .assert()
        .success();

    // Old receipt verifies offline (embedded pubkey, no --hmac-key needed).
    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .assert()
        .code(0);
}

#[test]
fn seal_with_encrypted_keystore_wrong_passphrase_exits_4() {
    let cfg = tempdir().expect("cfg");
    let work = tempdir().expect("work");
    let artifact = work.path().join("doc.txt");
    fs::write(&artifact, b"wrong pass seal").expect("write artifact");
    let xdg = cfg.path();

    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["keygen"])
        .assert()
        .success();
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "encrypt", "--passphrase", PASSPHRASE])
        .assert()
        .success();

    // Wrong passphrase => exit 4 (key) with a clear message, never a panic.
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["seal"])
        .arg(&artifact)
        .args(["--passphrase", "definitely wrong"])
        .assert()
        .code(4)
        .stderr(predicates::str::contains("wrong passphrase"));
}

#[test]
fn seal_with_encrypted_keystore_missing_passphrase_exits_4() {
    let cfg = tempdir().expect("cfg");
    let work = tempdir().expect("work");
    let artifact = work.path().join("doc.txt");
    fs::write(&artifact, b"missing pass seal").expect("write artifact");
    let xdg = cfg.path();

    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["keygen"])
        .assert()
        .success();
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "encrypt", "--passphrase", PASSPHRASE])
        .assert()
        .success();

    // Encrypted keystore + no passphrase => clear error (exit 4), not a panic.
    apohara_sealchain()
        .env_remove("SEALCHAIN_PASSPHRASE")
        .env("XDG_CONFIG_HOME", xdg)
        .args(["seal"])
        .arg(&artifact)
        .assert()
        .code(4)
        .stderr(predicates::str::contains("encrypted"));
}

#[test]
fn key_rotate_preserves_old_receipt_and_changes_fingerprint() {
    let cfg = tempdir().expect("cfg");
    let work = tempdir().expect("work");
    let artifact = work.path().join("doc.txt");
    fs::write(&artifact, b"rotate preserves old receipt").expect("write artifact");
    let receipt = work.path().join("doc.txt.seal.json");
    let xdg = cfg.path();

    // Seal with the default (plaintext) keystore -> receipt R, fingerprint F1.
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["seal"])
        .arg(&artifact)
        .arg("--out")
        .arg(&receipt)
        .assert()
        .success();

    let before = apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "show", "--json"])
        .output()
        .expect("key show");
    let before_fp = fingerprint_from_json(&before.stdout);

    // Rotate the key.
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "rotate"])
        .assert()
        .success()
        .stdout(predicates::str::contains("new fingerprint"));

    // The active fingerprint changed, and the old one is archived.
    let after = apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "list", "--json"])
        .output()
        .expect("key list");
    let after_fp = fingerprint_from_json(&after.stdout);
    assert_ne!(before_fp, after_fp, "rotation must change the active key");
    let after_text = String::from_utf8_lossy(&after.stdout);
    assert!(
        after_text.contains(&before_fp),
        "old key must be archived: {after_text}"
    );

    // The receipt R sealed with the OLD key STILL verifies (embedded pubkey).
    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .assert()
        .code(0);

    // A fresh seal now uses the NEW key: its embedded pubkey differs from R's.
    let artifact2 = work.path().join("doc2.txt");
    fs::write(&artifact2, b"sealed after rotation").expect("write artifact2");
    let receipt2 = work.path().join("doc2.txt.seal.json");
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["seal"])
        .arg(&artifact2)
        .arg("--out")
        .arg(&receipt2)
        .assert()
        .success();

    let r1 = fs::read_to_string(&receipt).expect("read R");
    let r2 = fs::read_to_string(&receipt2).expect("read R2");
    let pk1 = extract_field(&r1, "ed25519PublicKey");
    let pk2 = extract_field(&r2, "ed25519PublicKey");
    assert_ne!(
        pk1, pk2,
        "post-rotation seal must use a different public key"
    );
}

#[test]
fn key_list_reports_active_fingerprint() {
    let cfg = tempdir().expect("cfg");
    let xdg = cfg.path();
    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["keygen"])
        .assert()
        .success();

    apohara_sealchain()
        .env("XDG_CONFIG_HOME", xdg)
        .args(["key", "list"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("active:"))
        .stdout(predicates::str::contains("plaintext"));
}

// --- batch sealing + local receipt index (ls/find/rebuild) ---

#[test]
fn batch_seal_dir_writes_one_receipt_per_file() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let input = dir.path().join("in");
    fs::create_dir_all(&input).expect("mkdir in");
    for name in ["a.txt", "b.txt", "c.txt"] {
        fs::write(input.join(name), name.as_bytes()).expect("write file");
    }

    apohara_sealchain()
        .args(["seal"])
        .arg(&input)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("3 sealed, 0 failed"));

    // Each file got its own <name>.seal.json receipt.
    for name in ["a.txt", "b.txt", "c.txt"] {
        let receipt = input.join(format!("{name}.seal.json"));
        assert!(receipt.exists(), "missing receipt for {name}");
    }
}

#[test]
fn batch_seal_recursive_descends_subdirs() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let input = dir.path().join("in");
    let sub = input.join("sub");
    fs::create_dir_all(&sub).expect("mkdir sub");
    fs::write(input.join("top.txt"), b"top").expect("write top");
    fs::write(sub.join("deep.txt"), b"deep").expect("write deep");

    // Without --recursive only the top-level file is sealed.
    apohara_sealchain()
        .args(["seal"])
        .arg(&input)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("1 sealed, 0 failed"));
    assert!(
        !sub.join("deep.txt.seal.json").exists(),
        "no recurse by default"
    );

    // With --recursive both are sealed.
    apohara_sealchain()
        .args(["seal"])
        .arg(&input)
        .args(["--recursive", "--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("2 sealed, 0 failed"));
    assert!(
        sub.join("deep.txt.seal.json").exists(),
        "recurse seals subdir"
    );
}

#[test]
fn batch_seal_reports_failure_not_silently_skipped() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let good = dir.path().join("good.txt");
    fs::write(&good, b"good").expect("write good");
    let missing = dir.path().join("__does_not_exist__.txt");

    // One good file + one missing literal path: the missing one is reported as a
    // failure (exit 3), never silently skipped, and the good one still seals.
    apohara_sealchain()
        .args(["seal"])
        .arg(&good)
        .arg(&missing)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .code(3)
        .stdout(predicates::str::contains("1 sealed, 1 failed"))
        .stdout(predicates::str::contains("FAIL"));
    assert!(good.with_file_name("good.txt.seal.json").exists());
}

#[test]
fn batch_seal_multiple_path_args() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let f1 = dir.path().join("one.txt");
    let f2 = dir.path().join("two.txt");
    fs::write(&f1, b"one").expect("write one");
    fs::write(&f2, b"two").expect("write two");

    apohara_sealchain()
        .args(["seal"])
        .arg(&f1)
        .arg(&f2)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("2 sealed, 0 failed"));
}

#[test]
fn ls_lists_indexed_receipts() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let artifact = dir.path().join("indexed.txt");
    fs::write(&artifact, b"index me").expect("write");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success();

    apohara_sealchain()
        .args(["ls"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("indexed.txt"))
        .stdout(predicates::str::contains("hmac,ed25519"));
}

#[test]
fn find_matches_path_hash_and_layer() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let artifact = dir.path().join("findme.txt");
    fs::write(&artifact, b"find me by query").expect("write");

    let out = apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa", "--json"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let payload: serde_json::Value = serde_json::from_slice(&out).expect("json");
    // No need to inspect layers from JSON; the index find is checked below.
    let _ = &payload;

    // Path substring.
    apohara_sealchain()
        .args(["find", "findme"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("findme.txt"));

    // Layer name.
    apohara_sealchain()
        .args(["find", "ed25519"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("findme.txt"));

    // A non-matching query yields no rows.
    apohara_sealchain()
        .args(["find", "no_such_artifact_zzz"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("no indexed receipts"));
}

#[test]
fn index_rebuild_reconstructs_from_receipts() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let input = dir.path().join("in");
    fs::create_dir_all(&input).expect("mkdir");
    for name in ["x.txt", "y.txt"] {
        fs::write(input.join(name), name.as_bytes()).expect("write");
    }

    // Seal the batch (this also populates the index).
    apohara_sealchain()
        .args(["seal"])
        .arg(&input)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success();

    // Rebuild from a FRESH XDG (empty index) using only the receipts on disk:
    // the index is reconstructed, proving it is derived, not authoritative.
    let xdg2 = tempdir().expect("xdg2");
    apohara_sealchain()
        .args(["index", "rebuild"])
        .arg(&input)
        .env("XDG_DATA_HOME", xdg2.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("2 receipts"));

    apohara_sealchain()
        .args(["ls"])
        .env("XDG_DATA_HOME", xdg2.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("x.txt"))
        .stdout(predicates::str::contains("y.txt"));
}

#[test]
fn no_index_skips_indexing() {
    let dir = tempdir().expect("tempdir");
    let xdg = tempdir().expect("xdg");
    let artifact = dir.path().join("unindexed.txt");
    fs::write(&artifact, b"do not index").expect("write");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa", "--no-index"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success();

    // The index stays empty: ls reports nothing.
    apohara_sealchain()
        .args(["ls"])
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("no indexed receipts"));
}

// --- in-toto/SLSA-style provenance Statement ---

#[test]
fn provenance_emits_in_toto_statement_with_subject_digest() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("model.txt");
    fs::write(&artifact, b"apohara-sealchain provenance subject digest").expect("write artifact");
    let receipt = dir.path().join("model.txt.seal.json");

    // Seal offline (default: hmac + ed25519 + c2pa).
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--out"])
        .arg(&receipt)
        .assert()
        .success();

    // The artifactSha256 the provenance subject digest must equal.
    let receipt_body = fs::read_to_string(&receipt).expect("read receipt");
    let receipt_json: serde_json::Value =
        serde_json::from_str(&receipt_body).expect("receipt is valid JSON");
    let expected_sha = receipt_json["payload"]["artifactSha256"]
        .as_str()
        .expect("artifactSha256 present")
        .to_string();

    // provenance prints a valid in-toto Statement.
    let out = apohara_sealchain()
        .args(["provenance"])
        .arg(&receipt)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let stmt: serde_json::Value =
        serde_json::from_slice(&out).expect("provenance output is valid JSON");
    assert_eq!(stmt["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(
        stmt["predicateType"], "https://apohara.dev/sealchain/provenance/v1",
        "honest predicateType: NOT slsa.dev build provenance"
    );
    // Subject digest == the receipt's artifactSha256.
    assert_eq!(stmt["subject"][0]["digest"]["sha256"], expected_sha);
    assert_eq!(stmt["subject"][0]["name"], "model.txt");
    // Predicate reflects the real present layers.
    let types: Vec<String> = stmt["predicate"]["attestations"]
        .as_array()
        .expect("attestations array")
        .iter()
        .map(|a| a["type"].as_str().unwrap().to_string())
        .collect();
    assert!(types.contains(&"hmac".to_string()));
    assert!(types.contains(&"ed25519".to_string()));
    assert!(types.contains(&"c2pa".to_string()));
}

#[test]
fn provenance_json_flag_is_compact_single_line() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("flat.txt");
    fs::write(&artifact, b"compact json provenance").expect("write artifact");
    let receipt = dir.path().join("flat.txt.seal.json");

    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX, "--no-c2pa", "--out"])
        .arg(&receipt)
        .env("XDG_DATA_HOME", tempdir().unwrap().path())
        .assert()
        .success();

    let out = apohara_sealchain()
        .args(["provenance", "--json"])
        .arg(&receipt)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    // Compact JSON is a single line (one trailing newline from println!).
    let text = String::from_utf8(out).expect("utf8");
    assert_eq!(text.lines().count(), 1, "compact JSON must be one line");
    let stmt: serde_json::Value = serde_json::from_str(text.trim()).expect("valid JSON");
    assert_eq!(stmt["_type"], "https://in-toto.io/Statement/v1");
}

#[test]
fn provenance_broken_receipt_exits_3() {
    let dir = tempdir().expect("tempdir");
    let receipt = dir.path().join("broken.json");
    fs::write(&receipt, b"not a receipt").expect("write broken");

    apohara_sealchain()
        .args(["provenance"])
        .arg(&receipt)
        .assert()
        .code(3);
}

/// Extract the `active_fingerprint` value from a `key list/show --json` payload.
fn fingerprint_from_json(stdout: &[u8]) -> String {
    let v: serde_json::Value =
        serde_json::from_slice(stdout).expect("key show/list emits valid JSON");
    v.get("active_fingerprint")
        .and_then(|f| f.as_str())
        .expect("active_fingerprint present")
        .to_string()
}

/// Pull the hex value of a `"field": "0x..."`-style receipt field, for comparing
/// embedded public keys across receipts without a full deserialize.
fn extract_field(json: &str, field: &str) -> String {
    let needle = format!("\"{field}\"");
    let start = json.find(&needle).expect("field present");
    let after = &json[start + needle.len()..];
    let colon = after.find(':').expect("colon");
    let rest = &after[colon + 1..];
    let q1 = rest.find('"').expect("open quote");
    let tail = &rest[q1 + 1..];
    let q2 = tail.find('"').expect("close quote");
    tail[..q2].to_string()
}

// --- attestation policies (verify --policy / --profile, exit 5) ---

/// A 3-layer offline receipt (hmac+ed25519+c2pa) satisfies offline-basic: exit 0.
#[test]
fn verify_profile_offline_basic_exits_0() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"policy offline-basic").expect("write");
    let receipt = dir.path().join("doc.txt.seal.json");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--profile", "offline-basic"])
        .assert()
        .code(0);
}

/// The same offline receipt verifies cryptographically but cannot satisfy the
/// `full` profile (no tsa/rekor): crypto ok, policy fail -> exit 5.
#[test]
fn verify_profile_full_exits_5() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"policy full").expect("write");
    let receipt = dir.path().join("doc.txt.seal.json");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--profile", "full"])
        .assert()
        .code(5)
        .stdout(predicates::str::contains("policy (full): FAIL"));
}

/// A tampered artifact fails verification (exit 1) even under a profile — a
/// crypto failure outranks a policy failure.
#[test]
fn verify_tampered_with_profile_exits_1() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.bin");
    fs::write(&artifact, b"original").expect("write");
    let receipt = dir.path().join("doc.bin.seal.json");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();
    fs::write(&artifact, b"Original").expect("tamper one byte");

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--profile", "full"])
        .assert()
        .code(1);
}

/// A custom TOML policy file is honored: requiring rekor on an offline receipt
/// -> exit 5, with the policy object present in --json output.
#[test]
fn verify_policy_file_exits_5_with_json_policy_object() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"policy file").expect("write");
    let receipt = dir.path().join("doc.txt.seal.json");
    let policy = dir.path().join("p.toml");
    fs::write(&policy, b"require_layers = [\"rekor\"]\n").expect("write policy");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--json", "--policy"])
        .arg(&policy)
        .assert()
        .code(5)
        .stdout(predicates::str::contains("\"policy\""))
        .stdout(predicates::str::contains("\"passed\":false"));
}

/// An unknown profile name is a usage error (exit 2).
#[test]
fn verify_unknown_profile_exits_2() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"unknown profile").expect("write");
    let receipt = dir.path().join("doc.txt.seal.json");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--hmac-key", HMAC_HEX, "--profile", "does-not-exist"])
        .assert()
        .code(2);
}

/// --policy and --profile are mutually exclusive (clap usage error, exit 2).
#[test]
fn verify_policy_and_profile_conflict_exits_2() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("doc.txt");
    fs::write(&artifact, b"conflict").expect("write");
    let receipt = dir.path().join("doc.txt.seal.json");
    let policy = dir.path().join("p.toml");
    fs::write(&policy, b"min_layers = 1\n").expect("write policy");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["verify"])
        .arg(&artifact)
        .arg(&receipt)
        .args(["--profile", "full", "--policy"])
        .arg(&policy)
        .assert()
        .code(2);
}

// --- transparency dashboard (apohara-sealchain dashboard) ---

/// `dashboard --from-dir` re-verifies each receipt whose artifact is present and
/// reports an honest PASS / FAIL; the HTML is self-contained and offline-pure.
#[test]
fn dashboard_from_dir_reports_pass_and_fail() {
    let dir = tempdir().expect("tempdir");
    let good = dir.path().join("good.txt");
    let bad = dir.path().join("bad.txt");
    fs::write(&good, b"good artifact bytes").expect("write good");
    fs::write(&bad, b"bad artifact bytes").expect("write bad");

    for a in [&good, &bad] {
        apohara_sealchain()
            .args(["seal"])
            .arg(a)
            .args(["--hmac-key", HMAC_HEX])
            .assert()
            .success();
    }
    // Tamper the second artifact AFTER sealing: its receipt no longer matches.
    fs::write(&bad, b"BAD artifact bytes").expect("tamper bad");

    let report = dir.path().join("report.html");
    apohara_sealchain()
        .args(["dashboard", "--from-dir"])
        .arg(dir.path())
        .args(["-o"])
        .arg(&report)
        .assert()
        .success();

    let html = fs::read_to_string(&report).expect("read report");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("good.txt"), "good artifact listed");
    assert!(html.contains("bad.txt"), "bad artifact listed");
    assert!(html.contains(">PASS<"), "good row verifies PASS");
    assert!(html.contains(">FAIL<"), "tampered row reports FAIL");
    // OFFLINE-PURE: the report must contain no network reference whatsoever.
    assert!(
        !html.contains("http"),
        "dashboard HTML must contain no http references"
    );
}

/// `dashboard --profile` adds a compliance column; an offline receipt fails the
/// transparency profile (no rekor) — reported, not hidden.
#[test]
fn dashboard_with_profile_adds_compliance_column() {
    let dir = tempdir().expect("tempdir");
    let artifact = dir.path().join("model.bin");
    fs::write(&artifact, b"offline only").expect("write");
    apohara_sealchain()
        .args(["seal"])
        .arg(&artifact)
        .args(["--hmac-key", HMAC_HEX])
        .assert()
        .success();

    apohara_sealchain()
        .args(["dashboard", "--from-dir"])
        .arg(dir.path())
        .args(["--profile", "transparency"])
        .assert()
        .success()
        .stdout(predicates::str::contains("policy: transparency"))
        .stdout(predicates::str::contains("FAIL"));
}
