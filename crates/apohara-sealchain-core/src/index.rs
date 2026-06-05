//! Local receipt index, native only.
//!
//! A small SQLite database that records *where* receipts live and a few
//! discovery-friendly fields (artifact path, content hash, sealed-at time, the
//! layer set, the receipt path). It is a **convenience/discovery layer, never a
//! source of truth**: every fact it holds is also embedded in the receipt on
//! disk, so the whole index is rebuildable from receipts via `rebuild`. An
//! index failure therefore never invalidates a receipt.
//!
//! The DB lives at `$XDG_DATA_HOME/apohara-sealchain/index.db` (or
//! `$HOME/.local/share/apohara-sealchain/index.db` when `XDG_DATA_HOME` is unset). Tests
//! point `XDG_DATA_HOME` at a temp dir so the real index is never touched.
//!
//! `rusqlite` is pulled in with the `bundled` feature: SQLite is compiled from
//! source, so no system `libsqlite3` is required. This module is gated behind the
//! crate's `native` feature and is absent from the wasm `verify-only` build.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::error::SealError;
use crate::schema::SealedRecord;

/// One indexed receipt row. A flattened, query-friendly projection of a
/// [`SealedRecord`] plus the on-disk location of its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRecord {
    /// Artifact path as recorded in the receipt payload (`payload.path`).
    pub artifact_path: String,
    /// Lowercase hex SHA-256 of the artifact (`payload.artifactSha256`).
    pub artifact_sha256: String,
    /// RFC 3339 seal timestamp (`seal.sealedAt`).
    pub sealed_at: String,
    /// Comma-separated layer names present in the receipt, in chain order.
    pub layers: String,
    /// Path to the `<artifact>.seal.json` receipt on disk.
    pub receipt_path: String,
    /// RFC 3339 time the row was inserted/updated in the index.
    pub indexed_at: String,
}

/// The layer names present in a sealed record, in chain order: the always-present
/// `hmac`, then the present-only siblings. Mirrors the CLI's `produced_layers`
/// so the index and the seal output agree on layer naming.
pub fn present_layers(record: &SealedRecord) -> Vec<String> {
    let seal = &record.seal;
    let mut layers = vec!["hmac".to_string()];
    if seal.ed25519.is_some() {
        layers.push("ed25519".to_string());
    }
    if seal.c2pa_manifest.is_some() || seal.c2pa_embedded == Some(true) {
        layers.push("c2pa".to_string());
    }
    if seal.tsa.is_some() {
        layers.push("tsa".to_string());
    }
    if seal.rekor_anchor.is_some() {
        layers.push("rekor".to_string());
    }
    layers
}

/// Build an [`IndexRecord`] from a sealed record and the path its receipt was
/// written to. Pulls `path`/`artifactSha256` from the payload and `sealedAt`
/// from the seal; `indexed_at` is stamped at call time.
fn index_record_from(record: &SealedRecord, receipt_path: &Path) -> IndexRecord {
    let payload = &record.payload;
    let artifact_path = payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let artifact_sha256 = payload
        .get("artifactSha256")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    IndexRecord {
        artifact_path,
        artifact_sha256,
        sealed_at: record.seal.sealed_at.clone(),
        layers: present_layers(record).join(","),
        receipt_path: receipt_path.to_string_lossy().into_owned(),
        indexed_at: now_rfc3339(),
    }
}

/// Resolve the index DB path: `$XDG_DATA_HOME/apohara-sealchain/index.db`, else
/// `$HOME/.local/share/apohara-sealchain/index.db`.
fn resolve_db_path() -> Result<PathBuf, SealError> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg)
                .join("apohara-sealchain")
                .join("index.db"));
        }
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| SealError::Index("cannot resolve data dir: $HOME unset".into()))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("apohara-sealchain")
        .join("index.db"))
}

/// Open the index DB at the resolved path (creating its parent dir + schema as
/// needed) and run `f` against the connection.
fn with_db<T>(f: impl FnOnce(&Connection) -> Result<T, SealError>) -> Result<T, SealError> {
    let path = resolve_db_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SealError::Index(format!("create data dir {}: {e}", parent.display())))?;
    }
    let conn = Connection::open(&path)
        .map_err(|e| SealError::Index(format!("open index {}: {e}", path.display())))?;
    init_schema(&conn)?;
    f(&conn)
}

/// Create the `receipts` table if absent. The receipt path is the primary key:
/// re-sealing the same artifact updates the existing row (upsert) rather than
/// accumulating duplicates.
fn init_schema(conn: &Connection) -> Result<(), SealError> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS receipts (
            receipt_path    TEXT PRIMARY KEY,
            artifact_path   TEXT NOT NULL,
            artifact_sha256 TEXT NOT NULL,
            sealed_at       TEXT NOT NULL,
            layers          TEXT NOT NULL,
            indexed_at      TEXT NOT NULL
        )",
        [],
    )
    .map_err(|e| SealError::Index(format!("init schema: {e}")))?;
    Ok(())
}

/// Insert or update the index row for `record`, whose receipt was written to
/// `receipt_path`. Keyed by the receipt path, so re-sealing the same artifact
/// refreshes the row in place.
pub fn index_insert(record: &SealedRecord, receipt_path: &Path) -> Result<(), SealError> {
    let row = index_record_from(record, receipt_path);
    with_db(|conn| upsert(conn, &row))
}

/// Upsert a single [`IndexRecord`] into an open connection.
fn upsert(conn: &Connection, row: &IndexRecord) -> Result<(), SealError> {
    conn.execute(
        "INSERT INTO receipts
            (receipt_path, artifact_path, artifact_sha256, sealed_at, layers, indexed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(receipt_path) DO UPDATE SET
            artifact_path   = excluded.artifact_path,
            artifact_sha256 = excluded.artifact_sha256,
            sealed_at       = excluded.sealed_at,
            layers          = excluded.layers,
            indexed_at      = excluded.indexed_at",
        params![
            row.receipt_path,
            row.artifact_path,
            row.artifact_sha256,
            row.sealed_at,
            row.layers,
            row.indexed_at,
        ],
    )
    .map_err(|e| SealError::Index(format!("insert row: {e}")))?;
    Ok(())
}

/// List every indexed receipt, most-recently-sealed first.
pub fn index_list() -> Result<Vec<IndexRecord>, SealError> {
    with_db(|conn| {
        query_rows(
            conn,
            "SELECT artifact_path, artifact_sha256, sealed_at, layers, receipt_path, indexed_at
             FROM receipts
             ORDER BY sealed_at DESC, receipt_path ASC",
            params![],
        )
    })
}

/// Find indexed receipts matching `query` by artifact-path substring, OR
/// content-hash prefix, OR exact layer name. Case-insensitive for path and hash;
/// layer match is exact on a comma-split element. Results are de-duplicated and
/// ordered like [`index_list`].
pub fn index_find(query: &str) -> Result<Vec<IndexRecord>, SealError> {
    let needle = query.to_lowercase();
    let all = index_list()?;
    Ok(all
        .into_iter()
        .filter(|r| {
            r.artifact_path.to_lowercase().contains(&needle)
                || r.artifact_sha256.to_lowercase().starts_with(&needle)
                || r.layers.split(',').any(|l| l == needle)
        })
        .collect())
}

/// Run a SELECT and map each row into an [`IndexRecord`].
fn query_rows(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<IndexRecord>, SealError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| SealError::Index(format!("prepare query: {e}")))?;
    let rows = stmt
        .query_map(params, |r| {
            Ok(IndexRecord {
                artifact_path: r.get(0)?,
                artifact_sha256: r.get(1)?,
                sealed_at: r.get(2)?,
                layers: r.get(3)?,
                receipt_path: r.get(4)?,
                indexed_at: r.get(5)?,
            })
        })
        .map_err(|e| SealError::Index(format!("run query: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| SealError::Index(format!("read row: {e}")))?);
    }
    Ok(out)
}

/// Rebuild the index by rescanning `dir` (recursively) for `*.seal.json` files,
/// parsing each into a [`SealedRecord`], and replacing the index contents with
/// the reconstructed rows. This proves the index is *derived* from the receipts,
/// not authoritative: dropping the DB and rebuilding yields the same rows.
///
/// A receipt file that fails to parse is skipped (it is not a valid receipt);
/// the count returned is the number of rows actually indexed.
pub fn rebuild(dir: &Path) -> Result<usize, SealError> {
    let receipts = scan_receipts(dir)?;
    with_db(|conn| {
        conn.execute("DELETE FROM receipts", [])
            .map_err(|e| SealError::Index(format!("clear index: {e}")))?;
        let mut count = 0usize;
        for (path, record) in &receipts {
            let row = index_record_from(record, path);
            upsert(conn, &row)?;
            count += 1;
        }
        Ok(count)
    })
}

/// Recursively collect `(receipt_path, record)` pairs for every `*.seal.json`
/// under `dir` that parses as a [`SealedRecord`]. Unparseable `*.seal.json`
/// files are skipped (they are not valid receipts).
///
/// Public so the transparency dashboard ([`crate::dashboard`]) can build a report
/// straight from a directory of receipts without touching the global index.
pub fn scan_receipts(dir: &Path) -> Result<Vec<(PathBuf, SealedRecord)>, SealError> {
    let mut found = Vec::new();
    scan_into(dir, &mut found)?;
    Ok(found)
}

/// Depth-first walk appending parseable receipts into `out`.
fn scan_into(dir: &Path, out: &mut Vec<(PathBuf, SealedRecord)>) -> Result<(), SealError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| SealError::Index(format!("scan {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| SealError::Index(format!("scan entry: {e}")))?;
        let path = entry.path();
        if path.is_dir() {
            scan_into(&path, out)?;
        } else if is_receipt_file(&path) {
            if let Some(record) = parse_receipt(&path) {
                out.push((path, record));
            }
        }
    }
    Ok(())
}

/// Whether `path` is a `*.seal.json` receipt file (by name suffix).
fn is_receipt_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".seal.json"))
        .unwrap_or(false)
}

/// Parse a receipt file into a [`SealedRecord`], returning `None` if it is not a
/// valid receipt (unreadable or malformed JSON).
fn parse_receipt(path: &Path) -> Option<SealedRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<SealedRecord>(&text).ok()
}

/// Current UTC time as an RFC 3339 string (seconds precision, `+00:00` offset),
/// matching the seal-time format.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::load_or_generate;
    use crate::seal::seal_deterministic;
    use serde_json::json;
    use std::sync::{Mutex, MutexGuard};

    /// `XDG_DATA_HOME` is process-global; serialize the index tests so they don't
    /// race on it (and so each gets its own clean temp DB).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Point `XDG_DATA_HOME` at a fresh temp dir for the duration of a test. The
    /// returned guard holds the lock; the `TempDir` keeps the dir alive.
    fn with_temp_xdg() -> (MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_DATA_HOME", dir.path());
        (guard, dir)
    }

    /// A self-contained sealed record over a tiny synthetic payload, plus the
    /// receipt path it would be written to, for index round-trip tests.
    fn make_record(name: &str, body: &[u8]) -> (SealedRecord, PathBuf) {
        let keydir = tempfile::tempdir().expect("keydir");
        let keys = load_or_generate(Some(keydir.path())).expect("keys");
        let sha = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(body))
        };
        let payload = json!({
            "artifactSha256": sha,
            "path": name,
            "size": body.len() as u64,
            "mime": "application/octet-stream",
        });
        let mut record = seal_deterministic(
            &payload,
            &keys.hmac,
            Some(&keys.ed25519),
            "2026-01-01T00:00:00+00:00",
        )
        .expect("seal");
        record.seal.ed25519_public_key = Some(keys.ed25519_public_pem.clone());
        // A synthetic receipt path; these tests never read it back from disk
        // (the rebuild test writes its own receipt files into a scan dir).
        let receipt = PathBuf::from(format!(
            "/tmp/apohara-sealchain-index-test/{name}.seal.json"
        ));
        (record, receipt)
    }

    #[test]
    fn insert_then_list_returns_row() {
        let (_g, _xdg) = with_temp_xdg();
        let (record, receipt) = make_record("a.txt", b"alpha");
        index_insert(&record, &receipt).expect("insert");

        let rows = index_list().expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].artifact_path, "a.txt");
        assert_eq!(rows[0].receipt_path, receipt.to_string_lossy());
        assert!(rows[0].layers.contains("hmac"));
        assert!(rows[0].layers.contains("ed25519"));
    }

    #[test]
    fn reseal_same_receipt_upserts_not_duplicates() {
        let (_g, _xdg) = with_temp_xdg();
        let (record, receipt) = make_record("b.txt", b"bravo");
        index_insert(&record, &receipt).expect("insert 1");
        index_insert(&record, &receipt).expect("insert 2");

        let rows = index_list().expect("list");
        assert_eq!(rows.len(), 1, "same receipt path upserts, no duplicate");
    }

    #[test]
    fn find_matches_path_hash_and_layer() {
        let (_g, _xdg) = with_temp_xdg();
        let (r1, p1) = make_record("report.pdf", b"one");
        let (r2, p2) = make_record("photo.png", b"two");
        index_insert(&r1, &p1).expect("insert 1");
        index_insert(&r2, &p2).expect("insert 2");

        // Path substring.
        let by_path = index_find("report").expect("find path");
        assert_eq!(by_path.len(), 1);
        assert_eq!(by_path[0].artifact_path, "report.pdf");

        // Hash prefix (first 8 hex of r2's content hash).
        let prefix = &r2.payload["artifactSha256"].as_str().unwrap()[..8];
        let by_hash = index_find(prefix).expect("find hash");
        assert_eq!(by_hash.len(), 1);
        assert_eq!(by_hash[0].artifact_path, "photo.png");

        // Layer name (both have ed25519).
        let by_layer = index_find("ed25519").expect("find layer");
        assert_eq!(by_layer.len(), 2);
    }

    #[test]
    fn rebuild_reconstructs_same_rows_from_receipts() {
        let (_g, _xdg) = with_temp_xdg();
        let scan = tempfile::tempdir().expect("scan dir");
        let nested = scan.path().join("nested");
        std::fs::create_dir_all(&nested).expect("mkdir nested");

        // Write two receipts on disk (one nested) — these are the source of truth.
        let (r1, _) = make_record("doc.txt", b"first");
        let (r2, _) = make_record("img.png", b"second");
        let p1 = scan.path().join("doc.txt.seal.json");
        let p2 = nested.join("img.png.seal.json");
        std::fs::write(&p1, serde_json::to_string(&r1).unwrap()).expect("write r1");
        std::fs::write(&p2, serde_json::to_string(&r2).unwrap()).expect("write r2");
        // A non-receipt file must be ignored by the scan.
        std::fs::write(scan.path().join("notes.txt"), b"ignore me").expect("write noise");

        let count = rebuild(scan.path()).expect("rebuild");
        assert_eq!(count, 2, "two receipts reconstructed");

        let rows = index_list().expect("list");
        assert_eq!(rows.len(), 2);
        let paths: Vec<&str> = rows.iter().map(|r| r.artifact_path.as_str()).collect();
        assert!(paths.contains(&"doc.txt"));
        assert!(paths.contains(&"img.png"));
    }

    #[test]
    fn rebuild_replaces_stale_index_contents() {
        let (_g, _xdg) = with_temp_xdg();
        // Seed a row that does NOT exist as a receipt on disk.
        let (ghost, ghost_path) = make_record("ghost.txt", b"boo");
        index_insert(&ghost, &ghost_path).expect("seed ghost");
        assert_eq!(index_list().expect("list").len(), 1);

        // Rebuild from an empty scan dir: the index must drop the ghost row.
        let scan = tempfile::tempdir().expect("scan dir");
        let count = rebuild(scan.path()).expect("rebuild");
        assert_eq!(count, 0);
        assert!(
            index_list().expect("list").is_empty(),
            "rebuild is derived: stale rows are dropped"
        );
    }
}
