//! Sigstore Rekor v2 transparency layer tests (story R-003).
//!
//! Three honest tiers:
//!
//! * **Tier-C LIVE** (`live_submit_and_verify_anchor`, `#[ignore]`): submits a
//!   *real* DSSE v0.0.2 entry to the public v2 shard `log2025-1`, signed by a
//!   fixed test seal Ed25519 key over a fixed preimage, then verifies the
//!   returned anchor OFFLINE (RFC 6962 Merkle recompute + Ed25519 checkpoint
//!   signature against the pinned shard key). Marked `#[ignore]` so CI without
//!   network stays green; run with
//!   `cargo test -p apohara-sealchain-core --test rekor -- --ignored`. Setting
//!   `SEALCHAIN_REKOR_CAPTURE=1` freezes the captured anchor into the offline
//!   vector (used once to mint `tests/vectors/rekor/log2025-1_anchor.json`).
//!
//! * **Offline** (`frozen_*`, NOT ignored): replays the committed real anchor.
//!   It verifies against the pinned shard key (`ok:true`); a corrupted root hash,
//!   a corrupted checkpoint signature, and an unknown `logId` each fail
//!   (`ok:false`) with the right reason. This is the deterministic CI gate.
//!
//! * **Structural** (`malformed_*`): a malformed anchor is handled (`Err` /
//!   `ok:false`), never a panic.

use apohara_sealchain_core::{
    classify_shard, load_or_generate, load_rekor_shards, resolve_rekor_shard, seal_deterministic,
    submit_rekor_anchor, verify_artifact, verify_rekor_anchor, RekorAnchor, SealedRecord,
    ShardActiveness, DEFAULT_REKOR_V2_URL,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

/// The pinned 2025-1 shard log ID (base64), matching `packaging/rekor-shards.json`
/// and the Sigstore TrustedRoot entry for `log2025-1.rekor.sigstore.dev`.
const LOG2025_1_LOG_ID: &str = "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=";

const SHARDS_JSON: &str = include_str!("../../../packaging/rekor-shards.json");

const FROZEN_VECTOR: &str = include_str!("vectors/rekor/log2025-1_anchor.json");

/// A fixed 32-byte test seal signing key seed (deterministic, test-only).
const TEST_SEAL_SEED: [u8; 32] = [
    0x42, 0x6f, 0x75, 0x6c, 0x64, 0x65, 0x72, 0x21, 0x07, 0x21, 0x07, 0x21, 0x07, 0x21, 0x07, 0x21,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

/// The fixed preimage anchored by the live + frozen tests (stand-in for a real
/// seal's canonical preimage). The in-toto subject digest is `sha256(preimage)`.
const TEST_PREIMAGE: &[u8] = b"apohara-sealchain-rekor-R003-anchor: canonical preimage bytes";

fn test_seal_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_SEAL_SEED)
}

/// Resolve the pinned shard public key PEM bytes for a log ID, via the loader.
fn shard_pem_for(log_id: &str) -> Option<Vec<u8>> {
    let shards = load_rekor_shards(SHARDS_JSON).expect("parse shards");
    resolve_rekor_shard(&shards, log_id).map(|s| s.public_key_pem.clone().into_bytes())
}

fn vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/rekor/log2025-1_anchor.json")
}

fn frozen_anchor_json() -> Value {
    let v: Value = serde_json::from_str(FROZEN_VECTOR).expect("frozen vector parses");
    v["rekorAnchor"].clone()
}

fn frozen_anchor() -> RekorAnchor {
    RekorAnchor::from_json(&frozen_anchor_json()).expect("frozen anchor maps")
}

/// Tier-C LIVE: submit a real entry to log2025-1 and verify the anchor offline.
#[test]
#[ignore = "live network: submits a real DSSE v2 entry to the public Rekor shard"]
fn live_submit_and_verify_anchor() {
    let key = test_seal_key();
    let anchor = submit_rekor_anchor(TEST_PREIMAGE, &key, DEFAULT_REKOR_V2_URL)
        .expect("live Rekor v2 submit");

    // An inclusion proof must come back with a checkpoint.
    assert!(anchor.log_index >= 0, "log index present");
    assert!(
        !anchor.inclusion_proof.checkpoint.is_empty(),
        "inclusion proof must carry a checkpoint"
    );
    assert_eq!(
        anchor.log_id, LOG2025_1_LOG_ID,
        "shard returned the pinned 2025-1 log id"
    );

    // Verify offline against the pinned shard key: Merkle recompute + checkpoint.
    let pem = shard_pem_for(&anchor.log_id).expect("2025-1 key pinned");
    let result = verify_rekor_anchor(&anchor, Some(&pem));
    assert!(
        result.ok,
        "live anchor must verify offline against the pinned key: {}",
        result.reason
    );

    // Optional: freeze the captured anchor as the offline vector.
    if std::env::var("SEALCHAIN_REKOR_CAPTURE").is_ok() {
        let vector = serde_json::json!({
            "preimageHex": format!("0x{}", hex::encode(TEST_PREIMAGE)),
            "sealSeedHex": format!("0x{}", hex::encode(TEST_SEAL_SEED)),
            "rekorAnchor": anchor.to_json(),
        });
        let path = vector_path();
        std::fs::create_dir_all(path.parent().unwrap()).expect("create vectors/rekor dir");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&vector).expect("serialize vector"),
        )
        .expect("write frozen vector");
        eprintln!("captured frozen Rekor anchor -> {}", path.display());
    }
}

/// Offline gate: the frozen real anchor verifies against the pinned shard key
/// (RFC 6962 Merkle recompute + checkpoint signature) — `ok:true`.
#[test]
fn frozen_anchor_verifies_against_pinned_key() {
    let anchor = frozen_anchor();
    let pem = shard_pem_for(&anchor.log_id).expect("pinned key resolves by logId");
    let result = verify_rekor_anchor(&anchor, Some(&pem));
    assert_eq!(result.name, "rekor");
    assert!(
        result.ok,
        "frozen anchor must verify offline against the pinned key: {}",
        result.reason
    );
    assert!(
        result.reason.contains("checkpoint signature verified"),
        "reason should note the checkpoint sig verified: {}",
        result.reason
    );
}

/// Offline gate: a corrupted root hash fails the Merkle inclusion — `ok:false`.
#[test]
fn frozen_anchor_corrupted_root_hash_fails() {
    let mut anchor = frozen_anchor();
    // Flip the first byte of the root hash hex (still valid hex, wrong value).
    let mut root = hex::decode(&anchor.inclusion_proof.root_hash).expect("root hex");
    root[0] ^= 0xff;
    anchor.inclusion_proof.root_hash = hex::encode(root);

    let pem = shard_pem_for(&anchor.log_id).expect("pinned key");
    let result = verify_rekor_anchor(&anchor, Some(&pem));
    assert!(!result.ok, "corrupted root hash must not verify");
    // The corrupted root no longer matches the checkpoint's committed root.
    assert!(
        result.reason.contains("root hash") || result.reason.contains("merkle inclusion"),
        "reason should point at the root/merkle failure: {}",
        result.reason
    );
}

/// Offline gate: a corrupted checkpoint signature fails the C2SP check —
/// `ok:false`. The Merkle structure is left intact, isolating the signature.
#[test]
fn frozen_anchor_corrupted_checkpoint_sig_fails() {
    let mut anchor = frozen_anchor();
    let cp = &anchor.inclusion_proof.checkpoint;
    // Split the note body from the signature lines and corrupt the last base64
    // char of the signature blob (still parses; signature no longer verifies).
    let (body, sigs) = cp.split_once("\n\n").expect("checkpoint has separator");
    let mut lines: Vec<String> = sigs.lines().map(str::to_string).collect();
    let last = lines.last_mut().expect("a signature line");
    // Mutate one character inside the trailing base64 token.
    let bytes = unsafe { last.as_bytes_mut() };
    let i = bytes.len() - 2;
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    anchor.inclusion_proof.checkpoint = format!("{body}\n\n{}\n", lines.join("\n"));

    let pem = shard_pem_for(&anchor.log_id).expect("pinned key");
    let result = verify_rekor_anchor(&anchor, Some(&pem));
    assert!(!result.ok, "corrupted checkpoint signature must not verify");
    // The Merkle structure and the checkpoint-committed root are intact, so the
    // failure must be the signature gate specifically — proving the checkpoint
    // signature is a real pass-bar, not Merkle-structure-only.
    assert_eq!(
        result.reason, "checkpoint signature invalid for configured shard key",
        "must fail on the checkpoint signature, not earlier"
    );
}

/// Offline gate: an anchor whose `logId` is not pinned in config is a measured
/// `ok:false` with the documented reason — never an `Err`, never a silent pass.
#[test]
fn unknown_log_id_is_measured_false() {
    let mut anchor = frozen_anchor();
    anchor.log_id = "not-a-pinned-log-id".to_string();

    // The orchestrator resolves None for an unknown logId; mirror that here.
    let pem = shard_pem_for(&anchor.log_id);
    assert!(pem.is_none(), "unknown logId must not resolve a key");

    let result = verify_rekor_anchor(&anchor, pem.as_deref());
    assert!(!result.ok, "unknown key must be a measured failure");
    assert_eq!(
        result.reason,
        "log key unknown for logId not-a-pinned-log-id"
    );
}

/// Structural: a malformed anchor JSON is a structural error, never a panic.
#[test]
fn malformed_anchor_is_structural_error() {
    let bad = serde_json::json!({ "logId": "x", "logIndex": 1 });
    let err = RekorAnchor::from_json(&bad).expect_err("malformed anchor");
    assert!(matches!(
        err,
        apohara_sealchain_core::SealError::Malformed(_)
    ));
}

/// Orchestrator wiring (offline): a receipt carrying `seal.rekorAnchor` makes
/// `verify_artifact` append a `rekor` LayerResult that resolves the pinned shard
/// key by `logId` and verifies (Merkle + checkpoint) — `ok:true`. The frozen real
/// anchor is grafted onto a minimal real receipt; the rekor layer is independent
/// of the seal's other fields, so this isolates the orchestrator wiring with no
/// network. A tampered anchor `logId` then trips the layer (unknown key).
#[test]
fn verify_artifact_appends_rekor_layer_from_seal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = load_or_generate(Some(dir.path())).expect("keys");
    let artifact = dir.path().join("data.txt");
    std::fs::write(&artifact, b"rekor wiring artifact").expect("write artifact");

    // A minimal real receipt; the payload hash is irrelevant to the rekor layer.
    let record_value = serde_json::to_value(
        seal_deterministic(
            &json!({ "artifactSha256": "00", "path": "data.txt", "size": 0u64, "mime": "x" }),
            &keys.hmac,
            Some(&keys.ed25519),
            "2026-01-01T00:00:00+00:00",
        )
        .expect("seal_deterministic"),
    )
    .expect("to_value");
    let mut record: SealedRecord = serde_json::from_value(record_value).expect("from_value");
    record.seal.ed25519_public_key = Some(keys.ed25519_public_pem.clone());
    record.seal.rekor_anchor = Some(frozen_anchor_json());

    let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
    let rekor = results
        .iter()
        .find(|r| r.name == "rekor")
        .expect("rekor layer present");
    assert!(
        rekor.ok,
        "rekor layer must verify via the orchestrator: {}",
        rekor.reason
    );

    // Tamper the anchor's logId: the orchestrator can no longer resolve a pinned
    // key, so the layer is a measured ok:false (unknown key).
    let mut tampered = record.clone();
    let mut anchor_json = frozen_anchor_json();
    anchor_json["logId"] = Value::String("tampered-log-id".to_string());
    tampered.seal.rekor_anchor = Some(anchor_json);
    let results = verify_artifact(&artifact, &tampered, Some(&keys.hmac)).expect("verify");
    let rekor = results
        .iter()
        .find(|r| r.name == "rekor")
        .expect("rekor layer");
    assert!(!rekor.ok, "unknown logId must trip the rekor layer");
    assert_eq!(rekor.reason, "log key unknown for logId tampered-log-id");
}

/// The pinned config carries the 2025-1 key with a documented sha256 fingerprint.
#[test]
fn pinned_shard_has_fingerprint_and_provenance() {
    let shards = load_rekor_shards(SHARDS_JSON).expect("parse shards");
    let shard = resolve_rekor_shard(&shards, LOG2025_1_LOG_ID).expect("2025-1 shard");
    assert_eq!(shard.origin, "log2025-1.rekor.sigstore.dev");
    assert_eq!(shard.key_sha256.len(), 64, "sha256 hex fingerprint");
    assert!(shard.public_key_pem.contains("BEGIN PUBLIC KEY"));
}

// --- B-1a: seal-time stale-shard classification (pure, no network) ----------

#[test]
fn classify_shard_stale_aborts() {
    // The active set lists a NEW shard; our default rotated out -> must abort
    // (real-or-abort) rather than silently anchor to a deprecated shard.
    let active = vec!["https://log2026-1.rekor.sigstore.dev".to_string()];
    let err = classify_shard(DEFAULT_REKOR_V2_URL, &active)
        .expect_err("a stale default shard must abort the seal");
    let msg = err.to_string();
    assert!(
        msg.contains("stale Rekor shard"),
        "explains the abort: {msg}"
    );
    assert!(
        msg.contains(DEFAULT_REKOR_V2_URL),
        "names the stale URL: {msg}"
    );
}

#[test]
fn classify_shard_active_is_active() {
    let active = vec![
        DEFAULT_REKOR_V2_URL.to_string(),
        "https://log2026-1.rekor.sigstore.dev".to_string(),
    ];
    assert_eq!(
        classify_shard(DEFAULT_REKOR_V2_URL, &active).expect("active"),
        ShardActiveness::Active
    );
    // A single trailing slash must not cause a false stale-abort.
    let slashed = vec![format!("{DEFAULT_REKOR_V2_URL}/")];
    assert_eq!(
        classify_shard(DEFAULT_REKOR_V2_URL, &slashed).expect("active, slash-normalized"),
        ShardActiveness::Active
    );
}

#[test]
fn classify_shard_empty_set_is_undeterminable() {
    // No v2 endpoint distributed in the SigningConfig (the rollout window) -> we
    // cannot conclude staleness, so proceed without a false abort.
    assert_eq!(
        classify_shard(DEFAULT_REKOR_V2_URL, &[]).expect("undeterminable"),
        ShardActiveness::Undeterminable
    );
}
