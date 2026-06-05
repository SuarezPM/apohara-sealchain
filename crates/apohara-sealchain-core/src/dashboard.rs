//! Transparency dashboard.
//!
//! Renders a **self-contained, offline** HTML report from a set of receipts: one
//! row per artifact with its layers, an honest verification status, and optional
//! attestation-policy compliance. The report embeds its own CSS, uses no
//! JavaScript, and contains **no network references at all** (no external fonts,
//! scripts, styles, or links) — it is a static file you can open locally or hand
//! to someone else. Native-only.
//!
//! ## Honesty (rule #1)
//!
//! The dashboard reports only what it actually checked. A row is [`VerifyStatus::Pass`]
//! only when the artifact file was present at its recorded path and every present
//! layer verified; if the file is missing it is [`VerifyStatus::ReceiptOnly`]
//! (the receipt is shown, but no pass is claimed), and a failed re-verification is
//! [`VerifyStatus::Fail`]. The HTML-escapes every dynamic string.

use crate::artifact::LayerResult;
use crate::policy::PolicyReport;

/// One row of the dashboard: a receipt and its honest verification outcome.
#[derive(Debug, Clone)]
pub struct DashboardEntry {
    /// Artifact path as recorded (the index's `artifact_path`).
    pub artifact_path: String,
    /// Lowercase hex SHA-256 of the artifact.
    pub artifact_sha256: String,
    /// RFC 3339 seal time.
    pub sealed_at: String,
    /// Present layer names, in chain order.
    pub layers: Vec<String>,
    /// Path to the receipt on disk.
    pub receipt_path: String,
    /// The verification status, honest about what could be checked.
    pub status: VerifyStatus,
    /// Per-layer results when the artifact was re-verified (empty for receipt-only).
    pub layer_results: Vec<LayerResult>,
    /// Policy/profile compliance, when one was supplied and the row was verifiable.
    pub policy: Option<PolicyReport>,
}

/// The honest verification status of a dashboard row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    /// The artifact was present and every present layer verified.
    Pass,
    /// The artifact was present but at least one layer failed (tamper/mismatch).
    Fail,
    /// The artifact file was not found at its recorded path, so it could not be
    /// re-verified — the receipt is shown, but no pass is claimed.
    ReceiptOnly,
}

impl VerifyStatus {
    /// Short label for the status cell.
    fn label(self) -> &'static str {
        match self {
            VerifyStatus::Pass => "PASS",
            VerifyStatus::Fail => "FAIL",
            VerifyStatus::ReceiptOnly => "receipt-only",
        }
    }

    /// CSS class for the status cell.
    fn css(self) -> &'static str {
        match self {
            VerifyStatus::Pass => "ok",
            VerifyStatus::Fail => "bad",
            VerifyStatus::ReceiptOnly => "warn",
        }
    }
}

/// Escape the five characters that are unsafe in HTML text/attribute context.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// First 12 hex chars of a content hash (or the whole thing when shorter).
fn short_hash(hash: &str) -> &str {
    if hash.len() >= 12 {
        &hash[..12]
    } else {
        hash
    }
}

/// The current UTC time as an RFC 3339 string, for the report's "generated"
/// label. Lives here so the CLI need not depend on `chrono` directly.
pub fn generated_at_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

/// Render the dashboard entries into a single self-contained HTML document.
///
/// `generated_at` is a free-form label shown in the header (e.g. an RFC-3339
/// time, or `"—"`). When `policy_label` is `Some`, a compliance column is shown
/// titled with that label (the policy file name or profile name).
pub fn render_html(
    entries: &[DashboardEntry],
    generated_at: &str,
    policy_label: Option<&str>,
) -> String {
    let total = entries.len();
    let pass = entries
        .iter()
        .filter(|e| e.status == VerifyStatus::Pass)
        .count();
    let fail = entries
        .iter()
        .filter(|e| e.status == VerifyStatus::Fail)
        .count();
    let receipt_only = entries
        .iter()
        .filter(|e| e.status == VerifyStatus::ReceiptOnly)
        .count();

    let mut h = String::new();
    h.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str("<title>apohara-sealchain transparency dashboard</title>\n");
    h.push_str(STYLE);
    h.push_str("</head>\n<body>\n");

    // Header + summary.
    h.push_str("<header>\n<h1>apohara-sealchain transparency</h1>\n");
    h.push_str(&format!(
        "<p class=\"meta\">generated {} &middot; offline report, no network</p>\n",
        esc(generated_at)
    ));
    h.push_str("<ul class=\"summary\">\n");
    h.push_str(&format!("<li><b>{total}</b> receipts</li>\n"));
    h.push_str(&format!("<li class=\"ok\"><b>{pass}</b> verified</li>\n"));
    h.push_str(&format!("<li class=\"bad\"><b>{fail}</b> failed</li>\n"));
    h.push_str(&format!(
        "<li class=\"warn\"><b>{receipt_only}</b> receipt-only</li>\n"
    ));
    h.push_str("</ul>\n</header>\n");

    // Table.
    h.push_str("<table>\n<thead>\n<tr>");
    h.push_str("<th>artifact</th><th>hash</th><th>sealed</th><th>layers</th><th>verify</th>");
    if let Some(label) = policy_label {
        h.push_str(&format!("<th>policy: {}</th>", esc(label)));
    }
    h.push_str("</tr>\n</thead>\n<tbody>\n");

    if entries.is_empty() {
        let cols = if policy_label.is_some() { 6 } else { 5 };
        h.push_str(&format!(
            "<tr><td colspan=\"{cols}\" class=\"empty\">no receipts indexed</td></tr>\n"
        ));
    }

    for e in entries {
        h.push_str("<tr>\n");
        h.push_str(&format!(
            "<td class=\"path\">{}</td>",
            esc(&e.artifact_path)
        ));
        h.push_str(&format!(
            "<td class=\"hash\" title=\"{}\">{}</td>",
            esc(&e.artifact_sha256),
            esc(short_hash(&e.artifact_sha256))
        ));
        h.push_str(&format!("<td class=\"sealed\">{}</td>", esc(&e.sealed_at)));

        // Layer badges, with per-layer verify state in the title when known.
        h.push_str("<td class=\"layers\">");
        for layer in &e.layers {
            let state = e.layer_results.iter().find(|r| &r.name == layer);
            let (cls, title) = match state {
                Some(r) if r.ok => ("badge ok", r.reason.clone()),
                Some(r) => ("badge bad", r.reason.clone()),
                None => ("badge", "present (not re-verified)".to_string()),
            };
            h.push_str(&format!(
                "<span class=\"{cls}\" title=\"{}\">{}</span>",
                esc(&title),
                esc(layer)
            ));
        }
        h.push_str("</td>");

        // Verify status.
        h.push_str(&format!(
            "<td class=\"status {}\">{}</td>",
            e.status.css(),
            e.status.label()
        ));

        // Optional policy compliance.
        if policy_label.is_some() {
            match &e.policy {
                Some(report) if report.passed => {
                    h.push_str("<td class=\"status ok\">PASS</td>");
                }
                Some(report) => {
                    let why = report.violations.join("; ");
                    h.push_str(&format!(
                        "<td class=\"status bad\" title=\"{}\">FAIL ({})</td>",
                        esc(&why),
                        report.violations.len()
                    ));
                }
                None => h.push_str("<td class=\"status warn\" title=\"artifact missing; not evaluated\">&mdash;</td>"),
            }
        }
        h.push_str("\n</tr>\n");
    }

    h.push_str("</tbody>\n</table>\n");
    h.push_str(FOOTER);
    h.push_str("</body>\n</html>\n");
    h
}

/// Inline stylesheet (no external fonts/resources — fully offline).
const STYLE: &str = "<style>\n\
:root{color-scheme:light dark}\n\
*{box-sizing:border-box}\n\
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:2rem auto;max-width:60rem;padding:0 1rem;line-height:1.5}\n\
h1{font-size:1.4rem;margin:0}\n\
.meta{color:#888;margin:.2rem 0 1rem}\n\
.summary{list-style:none;display:flex;gap:1rem;flex-wrap:wrap;padding:0;margin:0 0 1.5rem}\n\
.summary li{border:1px solid #8884;border-radius:.4rem;padding:.3rem .7rem}\n\
table{border-collapse:collapse;width:100%;font-size:.85rem}\n\
th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid #8883;vertical-align:top}\n\
th{font-weight:700;border-bottom:2px solid #8886}\n\
.path{word-break:break-all}\n\
.hash{color:#888;font-size:.8rem}\n\
.badge{display:inline-block;border:1px solid #8886;border-radius:.3rem;padding:.05rem .35rem;margin:0 .2rem .2rem 0;font-size:.75rem}\n\
.status{font-weight:700}\n\
.ok{color:#1a7f37}\n\
.bad{color:#c1121f}\n\
.warn{color:#9a6700}\n\
.badge.ok{border-color:#1a7f3777}\n\
.badge.bad{border-color:#c1121f77}\n\
.empty{color:#888;text-align:center;padding:1.5rem}\n\
footer{color:#888;font-size:.75rem;margin-top:1.5rem;border-top:1px solid #8883;padding-top:.8rem}\n\
</style>\n";

/// Footer with the honesty note (no links — kept network-reference-free).
const FOOTER: &str = "<footer>\n\
A seal is evidence, not a verdict. Each row reports only what was re-checked: a \
PASS means the artifact was present and every present layer verified; receipt-only \
means the artifact file was not found, so no pass is claimed. See SPEC.md and \
docs/TRUST-PROFILE.md for what each layer proves.\n\
</footer>\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, status: VerifyStatus, layers: &[&str]) -> DashboardEntry {
        DashboardEntry {
            artifact_path: path.to_string(),
            artifact_sha256: "abcdef0123456789abcdef".to_string(),
            sealed_at: "2026-01-01T00:00:00+00:00".to_string(),
            layers: layers.iter().map(|s| s.to_string()).collect(),
            receipt_path: format!("{path}.seal.json"),
            status,
            layer_results: Vec::new(),
            policy: None,
        }
    }

    #[test]
    fn renders_self_contained_offline_html() {
        let entries = vec![
            entry(
                "model.bin",
                VerifyStatus::Pass,
                &["hmac", "ed25519", "c2pa"],
            ),
            entry("data.csv", VerifyStatus::Fail, &["hmac", "ed25519"]),
            entry("old.bin", VerifyStatus::ReceiptOnly, &["hmac"]),
        ];
        let html = render_html(&entries, "2026-06-05T00:00:00+00:00", None);

        // Structurally an HTML document.
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("</html>"));
        // Each artifact name appears.
        assert!(html.contains("model.bin"));
        assert!(html.contains("data.csv"));
        assert!(html.contains("old.bin"));
        // Honest statuses present.
        assert!(html.contains(">PASS<"));
        assert!(html.contains(">FAIL<"));
        assert!(html.contains("receipt-only"));
        // OFFLINE-PURE: not a single network reference anywhere.
        assert!(
            !html.contains("http"),
            "dashboard HTML must contain no http references"
        );
    }

    #[test]
    fn escapes_dynamic_strings() {
        let entries = vec![entry(
            "<script>evil()</script>.bin",
            VerifyStatus::Pass,
            &["hmac"],
        )];
        let html = render_html(&entries, "—", None);
        assert!(
            !html.contains("<script>evil()"),
            "artifact name must be escaped"
        );
        assert!(html.contains("&lt;script&gt;evil()"));
    }

    #[test]
    fn policy_column_present_only_with_label() {
        let entries = vec![entry("a.bin", VerifyStatus::Pass, &["hmac"])];
        assert!(!render_html(&entries, "—", None).contains("policy:"));
        assert!(render_html(&entries, "—", Some("transparency")).contains("policy: transparency"));
    }

    #[test]
    fn empty_renders_placeholder_row() {
        let html = render_html(&[], "—", None);
        assert!(html.contains("no receipts indexed"));
        assert!(!html.contains("http"));
    }
}
