//! apohara-sealchain CLI.
//!
//! Subcommands: `seal`, `verify`, `show`, `keygen`, and the `key` group
//! (`rotate`/`list`/`show`/`encrypt`/`decrypt`). Output is human-readable by
//! default, structured with `--json`, suppressed with `--quiet`.
//!
//! A passphrase for the encrypted-at-rest keystore is read from `--passphrase`
//! or, when absent, the `SEALCHAIN_PASSPHRASE` environment variable. With no
//! passphrase the keystore stays plaintext (the backward-compatible default);
//! when the on-disk keystore is encrypted, the passphrase is required and a
//! wrong one fails cleanly (exit 4) rather than panicking.
//!
//! Exit-code contract (mirrors the Python `tools/verify.py` matrix):
//! * `0` — pass / verify ok
//! * `1` — verify failed (tamper, mismatch)
//! * `2` — usage error (clap-handled)
//! * `3` — schema error (structural [`SealError`], bad record)
//! * `4` — key file missing
//! * `5` — policy not satisfied: the receipt verified cryptographically, but a
//!   `--policy`/`--profile` requirement was not met. Crypto failure (1) always
//!   outranks a policy failure (a tampered receipt is exit 1, never 5).

use std::path::{Path, PathBuf};

use apohara_sealchain_core::{
    decrypt_keystore, default_receipt_path, encrypt_keystore, evaluate_policy_now, from_overrides,
    generated_at_now, index_find, index_insert, index_list, index_rebuild, keystore_info,
    load_or_generate_with_passphrase, present_layers, profile_names, provenance_statement,
    render_chain, render_dashboard, rotate_keystore, scan_receipts, seal_artifact, verify_artifact,
    DashboardEntry, IndexRecord, Keys, KeystoreInfo, LayerResult, Policy, PolicyReport, SealError,
    SealedRecord, VerifyStatus, DEFAULT_REKOR_V2_URL, DEFAULT_TSA_URL,
};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};

/// Process exit codes.
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAIL: i32 = 1;
pub const EXIT_SCHEMA: i32 = 3;
pub const EXIT_KEY: i32 = 4;
/// Crypto verified ok, but a `--policy`/`--profile` requirement was not met.
pub const EXIT_POLICY: i32 = 5;

/// Verifiable, tamper-evident receipts for AI artifacts.
#[derive(Parser)]
#[command(name = "apohara-sealchain", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Seal a file into a `<artifact>.seal.json` receipt.
    ///
    /// Default is fully offline: HMAC + Ed25519 + C2PA, no network. The
    /// `--tsa`/`--rekor`/`--all` flags add network-backed layers that require
    /// connectivity at seal time; with `--all` any layer that cannot be produced
    /// aborts the seal (no partial receipt is written).
    Seal(SealArgs),
    /// Verify a file against its receipt.
    Verify(VerifyArgs),
    /// Print a human-readable chain trail for a receipt.
    Show(ShowArgs),
    /// Emit an in-toto/SLSA-style provenance Statement for a receipt.
    ///
    /// Maps the receipt onto an in-toto Statement v1 (subject = the artifact's
    /// sha256, predicate = the receipt's real attestations). The predicateType is
    /// an apohara-sealchain predicate — SLSA-style envelope, NOT slsa.dev build
    /// provenance: apohara-sealchain seals artifacts, it does not run builds.
    Provenance(ProvenanceArgs),
    /// Generate a key pair and report where it is stored.
    Keygen(KeygenArgs),
    /// Manage the keystore: rotate, list, show, encrypt, or decrypt keys.
    Key(KeyArgs),
    /// List indexed receipts (path, short hash, sealedAt, layers).
    Ls(LsArgs),
    /// Find indexed receipts by path substring, hash prefix, or layer name.
    Find(FindArgs),
    /// Manage the local receipt index (rebuild it from receipts on disk).
    Index(IndexArgs),
    /// Render a self-contained, offline HTML transparency report from receipts.
    ///
    /// One row per receipt with its layers, an honest verification status, and an
    /// optional `--policy`/`--profile` compliance column. The report has no
    /// network references and re-verifies each receipt whose artifact is present.
    Dashboard(DashboardArgs),
    /// Run the MCP server over stdio (seal_artifact/verify_receipt/show_chain).
    Mcp,
}

#[derive(Args)]
struct KeyArgs {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Archive the active key and generate a fresh one (mode-preserving).
    ///
    /// Old receipts still verify: each embeds its own Ed25519 public key, so no
    /// keyring lookup is needed after rotation.
    Rotate(KeyRotateArgs),
    /// List the active key fingerprint and all archived (rotated-out) keys.
    List(KeyListArgs),
    /// Show the active key fingerprint and storage mode (alias of `list`).
    Show(KeyListArgs),
    /// Convert a plaintext keystore into a passphrase-encrypted one.
    Encrypt(KeyConvertArgs),
    /// Convert a passphrase-encrypted keystore back into plaintext.
    Decrypt(KeyConvertArgs),
}

#[derive(Args)]
struct KeyRotateArgs {
    /// Config directory holding the keystore.
    #[arg(long = "config-dir")]
    config_dir: Option<PathBuf>,
    /// Passphrase for an encrypted keystore (else `SEALCHAIN_PASSPHRASE`).
    #[arg(long)]
    passphrase: Option<String>,
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct KeyListArgs {
    /// Config directory holding the keystore.
    #[arg(long = "config-dir")]
    config_dir: Option<PathBuf>,
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct KeyConvertArgs {
    /// Config directory holding the keystore.
    #[arg(long = "config-dir")]
    config_dir: Option<PathBuf>,
    /// Passphrase to encrypt with / decrypt with (else `SEALCHAIN_PASSPHRASE`).
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args)]
struct SealArgs {
    /// One or more inputs to seal: a file, a directory (seal each file inside),
    /// or a glob pattern (e.g. `out/*.png`). Repeat the argument for several
    /// inputs. Each artifact gets its own `<artifact>.seal.json` receipt.
    #[arg(required = true, num_args = 1..)]
    paths: Vec<PathBuf>,
    /// Recurse into subdirectories when an input is a directory (default: only
    /// the directory's immediate files are sealed).
    #[arg(long, short)]
    recursive: bool,
    /// Stop at the first artifact that fails to seal instead of continuing and
    /// reporting it in the summary (default: continue, report all results).
    #[arg(long = "fail-fast")]
    fail_fast: bool,
    /// Do not record sealed receipts in the local index (default: index on).
    #[arg(long = "no-index")]
    no_index: bool,
    /// Receipt output path (default `<artifact>.seal.json`). Only valid for a
    /// single resolved artifact; rejected for batch input.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Fixed RFC 3339 timestamp (for reproducible demos/interop).
    #[arg(long = "sealed-at")]
    sealed_at: Option<String>,
    /// Ed25519 private key PEM (PKCS#8) to sign with.
    #[arg(long)]
    key: Option<PathBuf>,
    /// HMAC key as hex, or `@file` to read raw bytes from a file.
    #[arg(long = "hmac-key")]
    hmac_key: Option<String>,
    /// Passphrase for an encrypted default keystore (else `SEALCHAIN_PASSPHRASE`).
    /// Ignored when `--key`/`--hmac-key` overrides are supplied.
    #[arg(long)]
    passphrase: Option<String>,
    /// Emit a real C2PA sidecar manifest (JUMBF) bound to the payload hash,
    /// stored in `seal.c2paManifest`. Offline, self-signed (test) Ed25519. On by
    /// default (part of the offline seal); pass `--no-c2pa` to opt out.
    #[arg(long)]
    c2pa: bool,
    /// Opt out of the default offline C2PA sidecar layer.
    #[arg(long = "no-c2pa", conflicts_with = "c2pa")]
    no_c2pa: bool,
    /// Add a real RFC 3161 TSA timestamp layer (network at seal time). Without a
    /// value uses the default authority; pass a URL to override.
    #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_TSA_URL)]
    tsa: Option<String>,
    /// Add a real Sigstore Rekor v2 transparency layer (network at seal time).
    /// Without a value uses the default shard; pass a shard URL to override.
    #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_REKOR_V2_URL)]
    rekor: Option<String>,
    /// Seal all configured layers (HMAC+Ed25519+C2PA+TSA+Rekor) real-or-abort:
    /// if any requested layer cannot be produced (e.g. network down), the seal
    /// aborts and no receipt is written. Implies `--tsa` and `--rekor` at their
    /// default endpoints.
    #[arg(long)]
    all: bool,
    /// Embed the C2PA manifest IN the artifact file (native in-file hard binding)
    /// for supported media (JPEG, PNG, TIFF/DNG, WEBP, AVIF/HEIF, MP4/MOV, GIF,
    /// SVG, WAV, MP3, FLAC, JXL). The file is rewritten with the embedded asset
    /// and the receipt records `c2paEmbedded` instead of the sidecar manifest. An
    /// unsupported format is a hard error (exit 2) — it never silently falls back
    /// to the sidecar. Cannot be combined with `--no-c2pa`.
    #[arg(long)]
    embed: bool,
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
    /// Suppress non-essential stdout.
    #[arg(long)]
    quiet: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to the artifact.
    path: PathBuf,
    /// Path to the receipt JSON.
    receipt: PathBuf,
    /// HMAC key as hex, or `@file`. Without it, only offline layers are checked.
    #[arg(long = "hmac-key")]
    hmac_key: Option<String>,
    /// Enforce a declarative attestation policy (TOML file) after verification.
    /// A crypto-valid receipt that fails the policy exits 5 (a tampered receipt
    /// still exits 1). Mutually exclusive with `--profile`.
    #[arg(long, conflicts_with = "profile")]
    policy: Option<PathBuf>,
    /// Enforce a named built-in profile (e.g. `offline-basic`, `transparency`,
    /// `legal-grade`, `full`) from the canonical trust profile. Mutually
    /// exclusive with `--policy`.
    #[arg(long)]
    profile: Option<String>,
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
    /// Suppress non-essential stdout.
    #[arg(long)]
    quiet: bool,
}

#[derive(Args)]
struct ShowArgs {
    /// Path to the receipt JSON.
    receipt: PathBuf,
}

#[derive(Args)]
struct ProvenanceArgs {
    /// Path to the receipt JSON.
    receipt: PathBuf,
    /// Emit compact single-line JSON (default: pretty, multi-line).
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct KeygenArgs {
    /// Config directory to write keys into.
    #[arg(long = "config-dir")]
    config_dir: Option<PathBuf>,
    /// Passphrase: when given (or `SEALCHAIN_PASSPHRASE` is set), a fresh
    /// keystore is created encrypted at rest. Without it the keystore is
    /// plaintext (the backward-compatible default).
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args)]
struct LsArgs {
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct FindArgs {
    /// Match by artifact-path substring, content-hash prefix, or layer name.
    query: String,
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct IndexArgs {
    #[command(subcommand)]
    command: IndexCommand,
}

#[derive(Subcommand)]
enum IndexCommand {
    /// Rescan a directory for `*.seal.json` receipts and rebuild the index from
    /// them (proves the index is derived from receipts, not authoritative).
    Rebuild(IndexRebuildArgs),
}

#[derive(Args)]
struct IndexRebuildArgs {
    /// Directory to rescan recursively for receipts (default: current dir).
    dir: Option<PathBuf>,
    /// Emit structured JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DashboardArgs {
    /// Build the report from this directory of receipts (recursive) instead of
    /// the local index. Each receipt's artifact is looked up next to it
    /// (`<artifact>.seal.json` -> `<artifact>`).
    #[arg(long = "from-dir")]
    from_dir: Option<PathBuf>,
    /// Write the HTML report to this file (default: stdout).
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Per-row attestation policy (TOML file) for a compliance column. Mutually
    /// exclusive with `--profile`.
    #[arg(long, conflicts_with = "profile")]
    policy: Option<PathBuf>,
    /// Per-row named profile (e.g. `transparency`) for a compliance column.
    /// Mutually exclusive with `--policy`.
    #[arg(long)]
    profile: Option<String>,
}

/// Parse args and run, returning the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Command::Seal(args) => run_seal(args),
        Command::Verify(args) => run_verify(args),
        Command::Show(args) => run_show(args),
        Command::Provenance(args) => run_provenance(args),
        Command::Keygen(args) => run_keygen(args),
        Command::Key(args) => run_key(args),
        Command::Ls(args) => run_ls(args),
        Command::Find(args) => run_find(args),
        Command::Index(args) => run_index(args),
        Command::Dashboard(args) => run_dashboard(args),
        Command::Mcp => run_mcp(),
    }
}

/// Resolve a passphrase: explicit `--passphrase`, else `SEALCHAIN_PASSPHRASE`,
/// else `None`. An empty env var counts as unset.
fn resolve_passphrase(explicit: Option<&str>) -> Option<String> {
    if let Some(p) = explicit {
        return Some(p.to_string());
    }
    match std::env::var("SEALCHAIN_PASSPHRASE") {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Run the MCP stdio server until the client disconnects.
///
/// Builds a multi-threaded tokio runtime, serves [`crate::mcp::SealchainServer`]
/// over stdio, and blocks until the peer closes the connection. The sync core is
/// driven from blocking threads inside each tool, so the runtime stays free.
fn run_mcp() -> i32 {
    use rmcp::transport::stdio;
    use rmcp::ServiceExt;

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ERROR: build async runtime: {e}");
            return EXIT_SCHEMA;
        }
    };

    runtime.block_on(async {
        let service = match crate::mcp::SealchainServer::new().serve(stdio()).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ERROR: start MCP server: {e}");
                return EXIT_SCHEMA;
            }
        };
        if let Err(e) = service.waiting().await {
            eprintln!("ERROR: MCP server: {e}");
            return EXIT_FAIL;
        }
        EXIT_OK
    })
}

/// Resolve an `--hmac-key` value: `@file` reads raw bytes (missing file ->
/// `EXIT_KEY`), otherwise the value is decoded as hex.
fn resolve_hmac_key(spec: &str) -> Result<Vec<u8>, i32> {
    if let Some(path) = spec.strip_prefix('@') {
        return std::fs::read(path).map_err(|_| EXIT_KEY);
    }
    let body = spec.strip_prefix("0x").unwrap_or(spec);
    hex::decode(body).map_err(|_| EXIT_KEY)
}

/// Map a structural [`SealError`] to its exit code. A missing key file is
/// surfaced as [`EXIT_KEY`]; everything else structural is [`EXIT_SCHEMA`].
fn schema_exit(err: &SealError) -> i32 {
    match err {
        // A key file problem and a decrypt failure (wrong/missing passphrase)
        // both surface as the "key" exit code: the operator must fix the key
        // material or the passphrase, not the record schema.
        SealError::KeyError(_) | SealError::Decrypt(_) => EXIT_KEY,
        _ => EXIT_SCHEMA,
    }
}

/// CLI usage-error exit code (clap also uses this for arg parse errors).
const EXIT_USAGE: i32 = 2;

/// Why a single seal failed, used to pick the run's exit code. The CLI's
/// exit-code contract is preserved per file: an embed/usage problem is a usage
/// error (2), a requested network layer that could not be produced is an abort
/// (1), and everything else structural is a schema error (3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    /// `--embed` on an unsupported media format (or a key override problem).
    Usage,
    /// A requested network-backed layer (TSA/Rekor) could not be produced.
    Network,
    /// Any other structural failure (read error, malformed input, etc.).
    Schema,
}

/// A per-file seal failure: the message to report and its exit-code category.
struct SealFailure {
    message: String,
    kind: FailureKind,
}

/// Outcome of sealing one artifact in a batch run.
struct SealOutcome {
    /// The artifact that was processed.
    artifact: PathBuf,
    /// `Ok((receipt_path, layers))` on success, `Err(failure)` on failure.
    result: Result<(PathBuf, Vec<String>), SealFailure>,
}

fn run_seal(args: SealArgs) -> i32 {
    // --embed and --no-c2pa are mutually exclusive (the in-file manifest IS the
    // C2PA layer); reject the combination as a usage error before touching keys.
    if args.embed && args.no_c2pa {
        if !args.quiet {
            eprintln!("ERROR: --embed cannot be combined with --no-c2pa (the embedded manifest is the C2PA layer)");
        }
        return EXIT_USAGE;
    }

    // Expand the inputs (files, directories, globs) into a flat artifact list.
    // `missing` holds literal inputs that resolved to nothing (a typo'd or
    // removed path): these are reported as failures, never silently skipped.
    let (artifacts, missing) = match expand_inputs(&args.paths, args.recursive) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    if artifacts.is_empty() && missing.is_empty() {
        if !args.quiet {
            eprintln!("ERROR: no artifacts matched the given inputs");
        }
        return EXIT_USAGE;
    }
    // --out names a single receipt; it is ambiguous for a batch.
    if args.out.is_some() && (artifacts.len() > 1 || !missing.is_empty()) {
        if !args.quiet {
            eprintln!("ERROR: --out is only valid for a single artifact");
        }
        return EXIT_USAGE;
    }

    // Resolve keys: explicit overrides if given, else load-or-generate default.
    let keys = match resolve_keys_for_seal(&args) {
        Ok(k) => k,
        Err(code) => return code,
    };

    // Resolve the requested seal mode into the concrete layer set.
    // C2PA is on by default (offline); `--no-c2pa` opts out. `--all` and the
    // explicit `--tsa`/`--rekor` flags select the network-backed layers.
    let c2pa = !args.no_c2pa;
    let tsa: Option<&str> = if args.all {
        Some(DEFAULT_TSA_URL)
    } else {
        args.tsa.as_deref()
    };
    let rekor: Option<&str> = if args.all {
        Some(DEFAULT_REKOR_V2_URL)
    } else {
        args.rekor.as_deref()
    };
    // Whether any network-backed layer was requested. When it was, a layer
    // failure on any file fails the whole run (exit 1).
    let network_requested = tsa.is_some() || rekor.is_some();

    let cfg = SealConfig {
        keys: &keys,
        sealed_at: args.sealed_at.as_deref(),
        c2pa,
        embed: args.embed,
        tsa,
        rekor,
        network_requested,
        no_index: args.no_index,
        quiet: args.quiet,
    };

    // Seal each artifact, collecting honest per-file outcomes. A failure on one
    // file is reported (never silently skipped); with --fail-fast we stop early.
    let mut outcomes: Vec<SealOutcome> = Vec::new();

    // Inputs that matched nothing are reported up front as failures.
    for m in &missing {
        if !args.quiet {
            eprintln!(
                "ERROR: {}: no such file, directory, or glob match",
                m.display()
            );
        }
        outcomes.push(SealOutcome {
            artifact: m.clone(),
            result: Err(SealFailure {
                message: "no such file, directory, or glob match".to_string(),
                kind: FailureKind::Schema,
            }),
        });
        if args.fail_fast {
            report_batch(&outcomes, args.json, args.quiet);
            return exit_code_for(&outcomes);
        }
    }

    for artifact in &artifacts {
        let out = args
            .out
            .clone()
            .unwrap_or_else(|| default_receipt_path(artifact));
        let result = seal_one(artifact, &out, &cfg);
        let failed = result.is_err();
        outcomes.push(SealOutcome {
            artifact: artifact.clone(),
            result,
        });
        if failed && args.fail_fast {
            break;
        }
    }

    report_batch(&outcomes, args.json, args.quiet);
    exit_code_for(&outcomes)
}

/// The process exit code for a batch run: `0` when every artifact sealed, else
/// the most severe failure category — a usage error (2) outranks a network abort
/// (1), which outranks a schema error (3). (Lower number = harder/earlier stop.)
fn exit_code_for(outcomes: &[SealOutcome]) -> i32 {
    let mut code = EXIT_OK;
    for o in outcomes {
        if let Err(f) = &o.result {
            let c = match f.kind {
                FailureKind::Usage => EXIT_USAGE,
                FailureKind::Network => EXIT_FAIL,
                FailureKind::Schema => EXIT_SCHEMA,
            };
            // Prefer the more severe (numerically smaller, non-zero) code.
            if code == EXIT_OK || c < code {
                code = c;
            }
        }
    }
    code
}

/// Per-artifact knobs shared across a batch run (resolved once in `run_seal`).
struct SealConfig<'a> {
    keys: &'a Keys,
    sealed_at: Option<&'a str>,
    c2pa: bool,
    embed: bool,
    tsa: Option<&'a str>,
    rekor: Option<&'a str>,
    network_requested: bool,
    no_index: bool,
    quiet: bool,
}

/// Seal a single artifact to `out` and (unless `no_index`) record it in the
/// local index. Returns the receipt path and produced layer names on success, or
/// a categorized [`SealFailure`]. A failure message is also echoed to stderr
/// (prefixed `ERROR:`) so the legacy single-file stderr contract still holds. An
/// index write failure is **not** fatal (the receipt is the source of truth): it
/// is warned about but the seal still counts as a success.
fn seal_one(
    artifact: &Path,
    out: &Path,
    cfg: &SealConfig,
) -> Result<(PathBuf, Vec<String>), SealFailure> {
    let record = match seal_artifact(
        artifact,
        cfg.keys,
        cfg.sealed_at,
        cfg.c2pa,
        cfg.embed,
        cfg.tsa,
        cfg.rekor,
    ) {
        Ok(r) => r,
        Err(e) => {
            if !cfg.quiet {
                eprintln!("ERROR: {e}");
            }
            // Classify for the run's exit code, mirroring the legacy contract:
            // an unsupported-format embed is a usage error (2); a requested
            // network layer that could not be produced is an abort (1); anything
            // else structural keeps the schema/key exit code (3/4).
            let kind = if cfg.embed && matches!(e, SealError::C2pa(_)) {
                FailureKind::Usage
            } else if cfg.network_requested {
                FailureKind::Network
            } else {
                FailureKind::Schema
            };
            return Err(SealFailure {
                message: e.to_string(),
                kind,
            });
        }
    };

    let serialized = match serde_json::to_string_pretty(&record) {
        Ok(s) => s,
        Err(e) => return Err(schema_failure(cfg.quiet, format!("serialize receipt: {e}"))),
    };
    if let Err(e) = std::fs::write(out, serialized) {
        return Err(schema_failure(
            cfg.quiet,
            format!("write receipt {}: {e}", out.display()),
        ));
    }

    if !cfg.no_index {
        if let Err(e) = index_insert(&record, out) {
            // The index is a convenience layer, never a source of truth, so an
            // index failure does not fail the seal — surface it and move on.
            eprintln!("WARN: index insert failed for {}: {e}", out.display());
        }
    }

    Ok((out.to_path_buf(), present_layers(&record)))
}

/// Build a [`FailureKind::Schema`] failure, echoing the message to stderr unless
/// `quiet`.
fn schema_failure(quiet: bool, message: String) -> SealFailure {
    if !quiet {
        eprintln!("ERROR: {message}");
    }
    SealFailure {
        message,
        kind: FailureKind::Schema,
    }
}

/// Print per-file results and a final summary for a batch seal run.
fn report_batch(outcomes: &[SealOutcome], json: bool, quiet: bool) {
    if quiet {
        return;
    }
    let sealed = outcomes.iter().filter(|o| o.result.is_ok()).count();
    let failed = outcomes.len() - sealed;

    if json {
        let files: Vec<Value> = outcomes
            .iter()
            .map(|o| match &o.result {
                Ok((receipt, layers)) => json!({
                    "artifact": o.artifact.to_string_lossy(),
                    "ok": true,
                    "receipt_path": receipt.to_string_lossy(),
                    "layers": layers,
                }),
                Err(f) => json!({
                    "artifact": o.artifact.to_string_lossy(),
                    "ok": false,
                    "error": f.message,
                }),
            })
            .collect();
        let payload = json!({
            "sealed": sealed,
            "failed": failed,
            "files": files,
        });
        println!("{payload}");
        return;
    }

    for o in outcomes {
        match &o.result {
            Ok((receipt, layers)) => {
                println!("OK   {} -> {}", o.artifact.display(), receipt.display());
                println!("       layers: {}", layers.join(", "));
            }
            Err(f) => {
                println!("FAIL {}: {}", o.artifact.display(), f.message);
            }
        }
    }
    println!("summary: {sealed} sealed, {failed} failed");
}

/// Expand the user's inputs into `(artifacts, missing)`. Each input is resolved
/// in turn:
/// * an existing **file** is taken as-is;
/// * an existing **directory** contributes its files (recursing when `recursive`);
/// * a **glob** pattern (contains `*`/`?`/`[`) is expanded — matching nothing is
///   benign (e.g. `out/*.png` with no PNGs), so it is silently dropped;
/// * a **literal path** that exists as neither a file nor a directory is a
///   *missing* input (a typo'd or removed path): it is collected into `missing`
///   so the caller reports it as a failure, never silently skipped.
///
/// Existing `*.seal.json` receipts are never sealed (we do not seal receipts of
/// receipts). The `artifacts` list is de-duplicated and sorted for determinism.
fn expand_inputs(inputs: &[PathBuf], recursive: bool) -> Result<(Vec<PathBuf>, Vec<PathBuf>), i32> {
    let mut artifacts: Vec<PathBuf> = Vec::new();
    let mut missing: Vec<PathBuf> = Vec::new();
    for input in inputs {
        if input.is_file() {
            artifacts.push(input.clone());
        } else if input.is_dir() {
            collect_dir(input, recursive, &mut artifacts)?;
        } else if is_glob_pattern(input) {
            let pattern = input.to_string_lossy();
            let paths = glob::glob(&pattern).map_err(|e| {
                eprintln!("ERROR: invalid glob {pattern}: {e}");
                EXIT_USAGE
            })?;
            for entry in paths {
                match entry {
                    Ok(p) if p.is_file() => artifacts.push(p),
                    Ok(_) => {} // skip directories matched by the glob
                    Err(e) => eprintln!("WARN: glob entry error: {e}"),
                }
            }
        } else {
            // A literal path that does not exist: report it, do not skip it.
            missing.push(input.clone());
        }
    }
    // Drop receipts, de-duplicate, and order deterministically.
    artifacts.retain(|p| !is_receipt_path(p));
    artifacts.sort();
    artifacts.dedup();
    Ok((artifacts, missing))
}

/// Whether `path` looks like a glob pattern (contains `*`, `?`, or `[`).
fn is_glob_pattern(path: &Path) -> bool {
    path.to_string_lossy()
        .chars()
        .any(|c| matches!(c, '*' | '?' | '['))
}

/// Collect the files under `dir` into `out`, recursing when `recursive`.
fn collect_dir(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<(), i32> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        eprintln!("ERROR: read dir {}: {e}", dir.display());
        EXIT_SCHEMA
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            eprintln!("ERROR: read dir entry: {e}");
            EXIT_SCHEMA
        })?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_dir(&path, recursive, out)?;
            }
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Whether `path` is itself a `*.seal.json` receipt (never sealed as an input).
fn is_receipt_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".seal.json"))
        .unwrap_or(false)
}

/// For sealing we always need a usable key bundle. With overrides, honor them;
/// without, fall back to the default config dir (load-or-generate).
fn resolve_keys_for_seal(args: &SealArgs) -> Result<Keys, i32> {
    let hmac_bytes = match args.hmac_key.as_deref() {
        Some(spec) => Some(resolve_hmac_key(spec)?),
        None => None,
    };

    if hmac_bytes.is_some() || args.key.is_some() {
        return from_overrides(hmac_bytes.as_deref(), args.key.as_deref()).map_err(|e| {
            if !args.quiet {
                eprintln!("ERROR: {e}");
            }
            schema_exit(&e)
        });
    }

    // Default keystore: honor the passphrase so an encrypted keystore can be read
    // (and a fresh one created encrypted). With no passphrase this stays the
    // plaintext load-or-generate path.
    let passphrase = resolve_passphrase(args.passphrase.as_deref());
    load_or_generate_with_passphrase(None, passphrase.as_deref()).map_err(|e| {
        if !args.quiet {
            eprintln!("ERROR: {e}");
        }
        schema_exit(&e)
    })
}

fn run_verify(args: VerifyArgs) -> i32 {
    let hmac_bytes = match args.hmac_key.as_deref() {
        Some(spec) => match resolve_hmac_key(spec) {
            Ok(b) => Some(b),
            Err(code) => {
                if !args.quiet {
                    eprintln!("ERROR: cannot read HMAC key");
                }
                return code;
            }
        },
        None => None,
    };

    let record = match read_receipt(&args.receipt) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let results = match verify_artifact(&args.path, &record, hmac_bytes.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            if !args.quiet {
                eprintln!("ERROR: {e}");
            }
            return schema_exit(&e);
        }
    };

    let crypto_ok = results.iter().all(|r| r.ok);

    // Resolve the optional policy (TOML file or named profile) and evaluate it
    // against the freshly-computed layer results.
    let policy_report = match resolve_policy(&args) {
        Ok(Some((policy, profile))) => {
            let mut report = evaluate_policy_now(&policy, &record, &results);
            report.profile = profile;
            Some(report)
        }
        Ok(None) => None,
        Err(code) => return code,
    };

    if !args.quiet {
        if args.json {
            println!(
                "{}",
                verdict_json(crypto_ok, &results, policy_report.as_ref())
            );
        } else {
            print_human_verdict(crypto_ok, &results, policy_report.as_ref());
        }
    }

    // Exit precedence: a crypto failure (tamper/mismatch) always outranks a
    // policy failure — a tampered receipt is exit 1, never 5.
    if !crypto_ok {
        return EXIT_FAIL;
    }
    match &policy_report {
        Some(report) if !report.passed => EXIT_POLICY,
        _ => EXIT_OK,
    }
}

/// Resolve `--policy <file>` (declarative TOML) or `--profile <name>` (a named
/// trust-profile profile) into a [`Policy`] plus the profile name for reporting.
/// Returns `Ok(None)` when neither flag is set. clap already enforces that the
/// two are mutually exclusive.
fn resolve_policy(args: &VerifyArgs) -> Result<Option<(Policy, Option<String>)>, i32> {
    if let Some(path) = &args.policy {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if !args.quiet {
                eprintln!("ERROR: read policy {}: {e}", path.display());
            }
            EXIT_SCHEMA
        })?;
        let policy = Policy::from_toml_str(&text).map_err(|e| {
            if !args.quiet {
                eprintln!("ERROR: {e}");
            }
            EXIT_SCHEMA
        })?;
        Ok(Some((policy, None)))
    } else if let Some(name) = &args.profile {
        match Policy::from_profile(name) {
            Some(policy) => Ok(Some((policy, Some(name.clone())))),
            None => {
                if !args.quiet {
                    eprintln!(
                        "ERROR: unknown profile '{name}' (available: {})",
                        profile_names().join(", ")
                    );
                }
                Err(EXIT_USAGE)
            }
        }
    } else {
        Ok(None)
    }
}

fn run_show(args: ShowArgs) -> i32 {
    let record = match read_receipt(&args.receipt) {
        Ok(r) => r,
        Err(code) => return code,
    };

    // render_chain emits each line with a trailing newline, matching the
    // previous per-line println! output.
    print!("{}", render_chain(&record));
    EXIT_OK
}

/// `apohara-sealchain provenance <receipt>`: print the in-toto Statement for a receipt.
///
/// The Statement's subject digest is the receipt's `artifactSha256` and its
/// predicate reflects the receipt's real present layers. Pretty JSON by default;
/// `--json` emits compact single-line JSON. A broken/unreadable receipt is a
/// schema error (exit 3), matching `show`/`verify`.
fn run_provenance(args: ProvenanceArgs) -> i32 {
    let record = match read_receipt(&args.receipt) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let statement = provenance_statement(&record);
    let rendered = if args.json {
        statement.to_string()
    } else {
        // to_string_pretty on a serde_json::Value cannot fail; fall back defensively.
        serde_json::to_string_pretty(&statement).unwrap_or_else(|_| statement.to_string())
    };
    println!("{rendered}");
    EXIT_OK
}

fn run_keygen(args: KeygenArgs) -> i32 {
    let passphrase = resolve_passphrase(args.passphrase.as_deref());
    let keys =
        match load_or_generate_with_passphrase(args.config_dir.as_deref(), passphrase.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("ERROR: {e}");
                return schema_exit(&e);
            }
        };
    // The keystore loader always resolves and returns the directory it used, so
    // the CLI can report the actual path (XDG/HOME-derived) even for the default.
    let dir = keys
        .config_dir()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(unknown config dir)".to_string());
    println!("Keys ready in {dir}");
    print!("{}", keys.ed25519_public_pem);
    EXIT_OK
}

/// Dispatch the `key` subcommand group.
fn run_key(args: KeyArgs) -> i32 {
    match args.command {
        KeyCommand::Rotate(a) => run_key_rotate(a),
        KeyCommand::List(a) | KeyCommand::Show(a) => run_key_list(a),
        KeyCommand::Encrypt(a) => run_key_convert(a, true),
        KeyCommand::Decrypt(a) => run_key_convert(a, false),
    }
}

/// `apohara-sealchain ls`: list every indexed receipt.
fn run_ls(args: LsArgs) -> i32 {
    let rows = match index_list() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_SCHEMA;
        }
    };
    print_index_rows(&rows, args.json);
    EXIT_OK
}

/// `apohara-sealchain find <query>`: list indexed receipts matching by path substring,
/// hash prefix, or layer name.
fn run_find(args: FindArgs) -> i32 {
    let rows = match index_find(&args.query) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_SCHEMA;
        }
    };
    print_index_rows(&rows, args.json);
    EXIT_OK
}

/// Dispatch the `index` subcommand group.
fn run_index(args: IndexArgs) -> i32 {
    match args.command {
        IndexCommand::Rebuild(a) => run_index_rebuild(a),
    }
}

/// `apohara-sealchain index rebuild [dir]`: rescan a directory for `*.seal.json`
/// receipts and rebuild the index from them.
fn run_index_rebuild(args: IndexRebuildArgs) -> i32 {
    let dir = args.dir.unwrap_or_else(|| PathBuf::from("."));
    let count = match index_rebuild(&dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return EXIT_SCHEMA;
        }
    };
    if args.json {
        println!(
            "{}",
            json!({ "ok": true, "dir": dir.to_string_lossy(), "indexed": count })
        );
    } else {
        println!("REBUILT index from {} ({count} receipts)", dir.display());
    }
    EXIT_OK
}

/// Print index rows as a human table or a JSON array. The hash is shortened to
/// its first 12 hex chars in the human view; JSON keeps the full value.
fn print_index_rows(rows: &[IndexRecord], json: bool) {
    if json {
        let arr: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "artifact_path": r.artifact_path,
                    "artifact_sha256": r.artifact_sha256,
                    "sealed_at": r.sealed_at,
                    "layers": r.layers,
                    "receipt_path": r.receipt_path,
                    "indexed_at": r.indexed_at,
                })
            })
            .collect();
        println!("{}", json!(arr));
        return;
    }
    if rows.is_empty() {
        println!("(no indexed receipts)");
        return;
    }
    for r in rows {
        let short = if r.artifact_sha256.len() >= 12 {
            &r.artifact_sha256[..12]
        } else {
            r.artifact_sha256.as_str()
        };
        println!(
            "{}  {}  {}  [{}]",
            r.sealed_at, short, r.artifact_path, r.layers
        );
    }
}

/// `apohara-sealchain dashboard`: render a self-contained, offline HTML transparency
/// report from the local index (default) or a scanned `--from-dir`.
fn run_dashboard(args: DashboardArgs) -> i32 {
    // Resolve the optional per-row policy/profile once (clap enforces exclusivity).
    let policy = match resolve_dashboard_policy(&args) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let policy_label = policy.as_ref().map(|(_, label)| label.clone());

    // Gather (receipt_path, record, artifact_path) from the chosen source.
    let sources = match gather_dashboard_sources(&args) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let entries: Vec<DashboardEntry> = sources
        .into_iter()
        .map(|(receipt_path, record, artifact)| {
            build_dashboard_entry(
                receipt_path,
                record,
                artifact,
                policy.as_ref().map(|(p, _)| p),
            )
        })
        .collect();

    let html = render_dashboard(&entries, &generated_at_now(), policy_label.as_deref());

    match &args.out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &html) {
                eprintln!("ERROR: write {}: {e}", path.display());
                return EXIT_SCHEMA;
            }
            println!("WROTE {} ({} receipts)", path.display(), entries.len());
        }
        None => print!("{html}"),
    }
    EXIT_OK
}

/// Resolve `--policy <file>` or `--profile <name>` into `(Policy, column-label)`.
fn resolve_dashboard_policy(args: &DashboardArgs) -> Result<Option<(Policy, String)>, i32> {
    if let Some(path) = &args.policy {
        let text = std::fs::read_to_string(path).map_err(|e| {
            eprintln!("ERROR: read policy {}: {e}", path.display());
            EXIT_SCHEMA
        })?;
        let policy = Policy::from_toml_str(&text).map_err(|e| {
            eprintln!("ERROR: {e}");
            EXIT_SCHEMA
        })?;
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "policy".to_string());
        Ok(Some((policy, label)))
    } else if let Some(name) = &args.profile {
        match Policy::from_profile(name) {
            Some(policy) => Ok(Some((policy, name.clone()))),
            None => {
                eprintln!(
                    "ERROR: unknown profile '{name}' (available: {})",
                    profile_names().join(", ")
                );
                Err(EXIT_USAGE)
            }
        }
    } else {
        Ok(None)
    }
}

/// Collect the `(receipt_path, record, artifact_path)` rows for the dashboard.
/// `--from-dir` scans a directory of receipts (artifact looked up next to each);
/// the default uses the local index (artifact path as recorded at seal time).
fn gather_dashboard_sources(
    args: &DashboardArgs,
) -> Result<Vec<(PathBuf, SealedRecord, PathBuf)>, i32> {
    if let Some(dir) = &args.from_dir {
        let scanned = scan_receipts(dir).map_err(|e| {
            eprintln!("ERROR: {e}");
            EXIT_SCHEMA
        })?;
        Ok(scanned
            .into_iter()
            .map(|(receipt_path, record)| {
                let artifact = artifact_path_for_receipt(&receipt_path);
                (receipt_path, record, artifact)
            })
            .collect())
    } else {
        let rows = index_list().map_err(|e| {
            eprintln!("ERROR: {e}");
            EXIT_SCHEMA
        })?;
        let mut out = Vec::new();
        for row in rows {
            let receipt_path = PathBuf::from(&row.receipt_path);
            // Skip an indexed receipt whose file is unreadable/stale: the index is
            // a convenience layer, never a source of truth.
            if let Ok(record) = read_receipt(&receipt_path) {
                out.push((receipt_path, record, PathBuf::from(&row.artifact_path)));
            }
        }
        Ok(out)
    }
}

/// The artifact path for a receipt path: strip the `.seal.json` suffix.
fn artifact_path_for_receipt(receipt: &Path) -> PathBuf {
    let s = receipt.to_string_lossy();
    match s.strip_suffix(".seal.json") {
        Some(base) => PathBuf::from(base),
        None => receipt.to_path_buf(),
    }
}

/// Build one dashboard row, re-verifying the receipt when its artifact is present
/// (honest status: PASS/FAIL when verified, receipt-only when the file is gone).
fn build_dashboard_entry(
    receipt_path: PathBuf,
    record: SealedRecord,
    artifact: PathBuf,
    policy: Option<&Policy>,
) -> DashboardEntry {
    let layers = present_layers(&record);
    let artifact_sha256 = record
        .payload
        .get("artifactSha256")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let sealed_at = record.seal.sealed_at.clone();

    // Re-verify only when the artifact file is present. A missing file is
    // receipt-only — we never claim a pass we did not earn. Policy is a secondary
    // gate, meaningful only once the receipt verifies: a FAIL row shows no policy
    // (the verify failure is the headline, mirroring the CLI's crypto-dominates
    // precedence).
    let (status, layer_results, policy_report) = match artifact
        .exists()
        .then(|| verify_artifact(&artifact, &record, None))
    {
        Some(Ok(results)) => {
            let all_ok = results.iter().all(|r| r.ok);
            let status = if all_ok {
                VerifyStatus::Pass
            } else {
                VerifyStatus::Fail
            };
            let report = all_ok
                .then(|| policy.map(|p| evaluate_policy_now(p, &record, &results)))
                .flatten();
            (status, results, report)
        }
        // Missing artifact, or a structural verify error: receipt-only.
        _ => (VerifyStatus::ReceiptOnly, Vec::new(), None),
    };

    DashboardEntry {
        artifact_path: artifact.to_string_lossy().into_owned(),
        artifact_sha256,
        sealed_at,
        layers,
        receipt_path: receipt_path.to_string_lossy().into_owned(),
        status,
        layer_results,
        policy: policy_report,
    }
}

fn run_key_rotate(args: KeyRotateArgs) -> i32 {
    let passphrase = resolve_passphrase(args.passphrase.as_deref());
    let keys = match rotate_keystore(args.config_dir.as_deref(), passphrase.as_deref()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return schema_exit(&e);
        }
    };
    let fingerprint = match keys.fingerprint() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return schema_exit(&e);
        }
    };
    let dir = keys
        .config_dir()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(unknown config dir)".to_string());
    if args.json {
        println!(
            "{}",
            json!({ "ok": true, "config_dir": dir, "active_fingerprint": fingerprint })
        );
    } else {
        println!("ROTATED keystore in {dir}");
        println!("  new fingerprint: {fingerprint}");
    }
    EXIT_OK
}

fn run_key_list(args: KeyListArgs) -> i32 {
    let info = match keystore_info(args.config_dir.as_deref()) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return schema_exit(&e);
        }
    };
    if args.json {
        match serde_json::to_string(&info) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("ERROR: serialize keystore info: {e}");
                return EXIT_SCHEMA;
            }
        }
    } else {
        print_keystore_info(&info);
    }
    EXIT_OK
}

fn print_keystore_info(info: &KeystoreInfo) {
    println!("config dir: {}", info.config_dir);
    println!(
        "mode:       {}",
        if info.encrypted {
            "encrypted"
        } else {
            "plaintext"
        }
    );
    match &info.active_fingerprint {
        Some(fp) => println!("active:     {fp}"),
        None => println!("active:     (none)"),
    }
    if info.archived.is_empty() {
        println!("archived:   (none)");
    } else {
        println!("archived:");
        for a in &info.archived {
            let fp = a.fingerprint.as_deref().unwrap_or("(unknown)");
            println!("  {} {}", a.archived_at, fp);
        }
    }
}

fn run_key_convert(args: KeyConvertArgs, encrypt: bool) -> i32 {
    let passphrase = match resolve_passphrase(args.passphrase.as_deref()) {
        Some(p) => p,
        None => {
            eprintln!(
                "ERROR: a passphrase is required (pass --passphrase or set SEALCHAIN_PASSPHRASE)"
            );
            return EXIT_KEY;
        }
    };
    let result = if encrypt {
        encrypt_keystore(args.config_dir.as_deref(), &passphrase)
    } else {
        decrypt_keystore(args.config_dir.as_deref(), &passphrase)
    };
    match result {
        Ok(_) => {
            println!("{}", if encrypt { "ENCRYPTED" } else { "DECRYPTED" });
            EXIT_OK
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            schema_exit(&e)
        }
    }
}

/// Read and parse a receipt file, mapping failures to exit codes.
///
/// A missing/unreadable file or malformed JSON is a schema error ([`EXIT_SCHEMA`]),
/// matching the Python contract where a broken record yields exit 3.
fn read_receipt(path: &Path) -> Result<SealedRecord, i32> {
    let text = std::fs::read_to_string(path).map_err(|_| EXIT_SCHEMA)?;
    serde_json::from_str::<SealedRecord>(&text).map_err(|_| EXIT_SCHEMA)
}

fn print_human_verdict(ok: bool, results: &[LayerResult], policy: Option<&PolicyReport>) {
    println!("{}", if ok { "PASS" } else { "FAIL" });
    for r in results {
        let mark = if r.ok { "ok" } else { "FAIL" };
        println!("  {:<8} [{mark}] {}", r.name, r.reason);
    }
    if let Some(report) = policy {
        let label = report.profile.as_deref().unwrap_or("policy");
        println!(
            "policy ({label}): {}",
            if report.passed { "PASS" } else { "FAIL" }
        );
        for v in &report.violations {
            println!("  - {v}");
        }
    }
}

fn verdict_json(ok: bool, results: &[LayerResult], policy: Option<&PolicyReport>) -> String {
    let layers: Vec<Value> = results
        .iter()
        .map(|r| json!({"name": r.name, "ok": r.ok, "reason": r.reason}))
        .collect();
    let mut obj = json!({ "ok": ok, "layers": layers });
    if let Some(report) = policy {
        obj["policy"] = json!({
            "passed": report.passed,
            "profile": report.profile,
            "violations": report.violations,
        });
    }
    obj.to_string()
}
