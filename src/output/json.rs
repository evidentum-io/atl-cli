//! JSON output formatting
//!
//! Every `status` and `reason_code` printed here comes from
//! [`crate::verify::verdict`] via `verdict()`; nothing in this module
//! decides an outcome of its own. The human renderer reads the same verdict,
//! so the two cannot disagree, and the process exit code is derived from it
//! as well.

use serde::Serialize;

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::anchor::{AnchorDetails, AnchorVerificationResult};
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::single::SingleVerificationResult;
use crate::verify::verdict::{ReasonCode, ReceiptVerdict};

#[derive(Serialize)]
struct SingleResultJson {
    /// `"valid"` / `"untrusted"` / `"invalid"` / `"pending"`.
    ///
    /// `"untrusted"` means nothing about the evidence was refuted: this
    /// verifier was not given the trust material to finish the check. It is
    /// never a success — see `reason_code` for what to supply.
    status: &'static str,
    /// Stable machine-readable reason; absent when `status` is `"valid"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    anchor_status: &'static str,
    mode: &'static str,
    source_file: String,
    receipt_file: String,
    file_hash: FileHashJson,
    verification: Option<VerificationJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_verification: Option<AnchorVerificationJson>,
    errors: Vec<ErrorJson>,
}

#[derive(Serialize)]
struct FileHashJson {
    computed: String,
    expected: String,
    #[serde(rename = "match")]
    is_match: bool,
}

#[derive(Serialize)]
struct VerificationJson {
    entry_id: String,
    inclusion_valid: bool,
    super_inclusion_valid: Option<bool>,
    super_consistency_valid: Option<bool>,
    /// Honest single-number aggregate over what was actually checked:
    /// `inclusion_valid` AND (super proofs, if the receipt has a
    /// `super_proof`). This is a statement about **proofs**, not about
    /// **trust** — it can be `true` for an unanchored receipt, an
    /// unverified checkpoint signature, or a timestamp no external anchor
    /// corroborates. Consumers must look at `status` and
    /// `anchor_verification` to judge trust; do not read `proofs_valid:
    /// true` as "this receipt is verified". See `ProofVerdict::proofs_valid`.
    proofs_valid: bool,
}

impl VerificationJson {
    fn from_verdict(entry_id: String, verdict: crate::verify::ProofVerdict) -> Self {
        Self {
            entry_id,
            inclusion_valid: verdict.inclusion_valid,
            super_inclusion_valid: verdict.super_proof.map(|s| s.inclusion_valid),
            super_consistency_valid: verdict.super_proof.map(|s| s.consistency_valid),
            proofs_valid: verdict.proofs_valid(),
        }
    }
}

#[derive(Serialize)]
struct ErrorJson {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

/// Build the JSON representation of a single-file verification result.
///
/// One shape for both modes: RFC 3161 anchors are verified identically
/// offline and online, so there is no reason for the two to report
/// differently-shaped documents. `mode` says whether any network-backed
/// check ran.
///
/// Split out from [`print_single_result`] so tests can inspect the resulting
/// fields directly instead of parsing captured stdout.
fn build_single_result_json(
    result: &SingleVerificationResult,
    mode: VerificationMode,
) -> SingleResultJson {
    let verdict = result.verdict();

    SingleResultJson {
        status: verdict.status.as_str(),
        reason_code: verdict.reason_code.map(ReasonCode::as_str),
        anchor_status: if result.receipt.anchors.is_empty() {
            "unanchored"
        } else {
            "anchored"
        },
        mode: match mode {
            VerificationMode::Online => "online",
            VerificationMode::Offline => "offline",
        },
        source_file: result.source_path.display().to_string(),
        receipt_file: result.receipt_path.display().to_string(),
        file_hash: FileHashJson {
            computed: format!("sha256:{}", hex::encode(result.file_hash)),
            expected: result.receipt.entry.payload_hash.clone(),
            is_match: result.file_hash_valid,
        },
        verification: if result.file_hash_valid {
            Some(VerificationJson::from_verdict(
                result.receipt.entry.id.to_string(),
                result.proof_verdict(),
            ))
        } else {
            None
        },
        anchor_verification: build_anchor_verification(&result.anchor_results),
        errors: build_errors(verdict, result),
    }
}

/// The `errors` array, derived from the verdict rather than from a second
/// pass over `atl-core`'s error list, so it can never name a problem the
/// status does not reflect (or stay silent about one it does).
fn build_errors(verdict: ReceiptVerdict, result: &SingleVerificationResult) -> Vec<ErrorJson> {
    let Some(reason) = verdict.reason_code else {
        return Vec::new();
    };
    if verdict.is_valid() || reason == ReasonCode::ReceiptUnanchored {
        return Vec::new();
    }

    let mut errors = vec![ErrorJson {
        error_type: reason.as_str().to_string(),
        message: describe(reason),
    }];

    for anchor in &result.anchor_results {
        if let (Some(code), Some(message)) = (anchor.verdict.reason_code(), anchor.error.as_ref()) {
            if code != reason {
                continue;
            }
            errors.push(ErrorJson {
                error_type: format!("{}_detail", code.as_str()),
                message: message.clone(),
            });
        }
    }

    errors
}

/// One-line prose for a reason code. The code is the contract; this text is
/// not, and may be reworded freely.
fn describe(reason: ReasonCode) -> String {
    match reason {
        ReasonCode::FileHashMismatch => "File hash does not match receipt",
        ReasonCode::TsaRootNotTrusted => {
            "TSA certificate chain terminates in a root no trust store names"
        }
        ReasonCode::TsaChainIncomplete => "TSA certificate chain is missing an issuer certificate",
        ReasonCode::BitcoinBlockNotChecked => "Bitcoin block was not fetched",
        ReasonCode::BitcoinBlockUnavailable => "Bitcoin block lookup failed",
        ReasonCode::BatchItemsInvalid => "One or more items failed verification",
        ReasonCode::BatchItemsUntrusted => "One or more items reached no configured trust root",
        ReasonCode::LogConsistencyFailed => "Cross-receipt log consistency verification failed",
        other => return other.as_str().replace('_', " "),
    }
    .to_string()
}

pub fn print_single_result(
    result: &SingleVerificationResult,
    mode: VerificationMode,
) -> CliResult<()> {
    let output = build_single_result_json(result, mode);
    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

#[derive(Serialize)]
struct BatchResultJson {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    mode: &'static str,
    source_dir: String,
    receipt_dir: String,
    summary: SummaryJson,
    consistency: Option<ConsistencyJson>,
    items: Vec<BatchItemJson>,
    errors: Vec<ErrorJson>,
}

#[derive(Serialize)]
struct SummaryJson {
    total: usize,
    valid: usize,
    /// Items that were not refuted but reached no configured trust root.
    untrusted: usize,
    invalid: usize,
    errors: usize,
    unmatched: usize,
}

#[derive(Serialize)]
struct ConsistencyJson {
    status: &'static str,
    genesis_super_root: Option<String>,
    receipt_count: usize,
    cross_checks_passed: usize,
    cross_checks: Vec<CrossCheckJson>,
}

#[derive(Serialize)]
struct CrossCheckJson {
    from_index: usize,
    to_index: usize,
    from_file: String,
    to_file: String,
    included: bool,
}

#[derive(Serialize)]
struct BatchItemJson {
    file: String,
    receipt: Option<String>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    super_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_tree_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Render one verified batch item, whatever bucket it landed in. The status
/// string comes from the item's own verdict, so a `Valid` bucket can never
/// print anything but `"valid"`/`"pending"`.
fn batch_item_json(result: &SingleVerificationResult) -> BatchItemJson {
    let verdict = result.verdict();
    let (super_root, data_tree_index) = result
        .receipt
        .super_proof
        .as_ref()
        .map_or((None, None), |sp| {
            (Some(sp.super_root.clone()), Some(sp.data_tree_index))
        });

    BatchItemJson {
        file: file_name(&result.source_path),
        receipt: Some(file_name(&result.receipt_path)),
        status: verdict.status.as_str(),
        reason_code: verdict.reason_code.map(ReasonCode::as_str),
        file_hash_match: Some(result.file_hash_valid),
        super_root,
        data_tree_index,
        error: verdict
            .reason_code
            .filter(|_| !verdict.is_valid())
            .map(describe),
    }
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

pub fn print_batch_result(
    result: &BatchVerificationResult,
    mode: VerificationMode,
    source_dir: &std::path::Path,
    receipt_dir: &std::path::Path,
) -> CliResult<()> {
    let total = result.valid_count
        + result.untrusted_count
        + result.invalid_count
        + result.error_count
        + result.unmatched_count;

    // Build sorted list of items for cross-check file name lookup. Untrusted
    // items take part in consistency checking too (their proofs are sound),
    // so they belong in this list alongside valid ones.
    let mut checked_items_sorted: Vec<_> = result
        .items
        .iter()
        .filter_map(|item| match item {
            BatchItemResult::Valid(r) | BatchItemResult::Untrusted(r) => {
                let data_tree_index = r
                    .receipt
                    .super_proof
                    .as_ref()
                    .map_or(0, |sp| sp.data_tree_index);
                Some((data_tree_index, file_name(&r.source_path)))
            }
            _ => None,
        })
        .collect();
    checked_items_sorted.sort_by_key(|(idx, _)| *idx);

    let consistency = result.consistency.as_ref().map(|c| {
        let cross_checks_passed = c
            .cross_results
            .iter()
            .filter(|cr| cr.history_consistent)
            .count();

        let cross_checks: Vec<CrossCheckJson> = c
            .cross_results
            .iter()
            .enumerate()
            .map(|(idx, cr)| CrossCheckJson {
                from_index: idx + 1,
                to_index: idx + 2,
                from_file: checked_items_sorted
                    .get(idx)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_default(),
                to_file: checked_items_sorted
                    .get(idx + 1)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_default(),
                included: cr.history_consistent,
            })
            .collect();

        ConsistencyJson {
            status: if c.is_valid() { "verified" } else { "failed" },
            genesis_super_root: c
                .genesis_super_root
                .map(|h| format!("sha256:{}", hex::encode(h))),
            receipt_count: c.receipt_count,
            cross_checks_passed,
            cross_checks,
        }
    });

    let items: Vec<BatchItemJson> = result
        .items
        .iter()
        .map(|item| match item {
            BatchItemResult::Valid(r)
            | BatchItemResult::Untrusted(r)
            | BatchItemResult::Invalid(r) => batch_item_json(r),
            BatchItemResult::Error { source, error, .. } => BatchItemJson {
                file: file_name(source),
                receipt: None,
                status: "error",
                reason_code: None,
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: Some(error.to_string()),
            },
            BatchItemResult::NoReceipt(path) => BatchItemJson {
                file: file_name(path),
                receipt: None,
                status: "no_receipt",
                reason_code: None,
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: None,
            },
            BatchItemResult::NoSource(path) => BatchItemJson {
                file: file_name(path),
                receipt: None,
                status: "no_source",
                reason_code: None,
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: None,
            },
        })
        .collect();

    let verdict = result.verdict();
    let output = BatchResultJson {
        status: verdict.status.as_str(),
        reason_code: verdict.reason_code.map(ReasonCode::as_str),
        mode: match mode {
            VerificationMode::Online => "online",
            VerificationMode::Offline => "offline",
        },
        source_dir: source_dir.display().to_string(),
        receipt_dir: receipt_dir.display().to_string(),
        summary: SummaryJson {
            total,
            valid: result.valid_count,
            untrusted: result.untrusted_count,
            invalid: result.invalid_count,
            errors: result.error_count,
            unmatched: result.unmatched_count,
        },
        consistency,
        items,
        errors: match verdict.reason_code {
            Some(reason) if !verdict.is_valid() => vec![ErrorJson {
                error_type: reason.as_str().to_string(),
                message: describe(reason),
            }],
            _ => Vec::new(),
        },
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

#[derive(Serialize)]
struct AnchorResultJson {
    #[serde(rename = "type")]
    anchor_type: String,
    /// `true` only when the anchor is fully accepted. An anchor whose root
    /// is merely `assumed` is `false` here, however sound its cryptography.
    verified: bool,
    /// Stable machine-readable reason; absent when `verified` is `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_nanos: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    // Bitcoin OTS verification chain (only for bitcoin_ots type)
    #[serde(skip_serializing_if = "Option::is_none")]
    target_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    computed_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_merkle_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_match: Option<bool>,
    // RFC 3161 facts (only for rfc3161 type) -- see `Rfc3161AnchorFacts` in
    // atl-core. Reported as *facts*, not a collapsed verdict.
    // `trust_state` is the one summary label
    // (`"trusted"`/`"assumed"`/`"incomplete"`/`"failed"`) the human renderer
    // uses too, derived from the same classification as `verified` and
    // `reason_code`, so the three can never disagree.
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    imprint_matches_root: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cms_signature_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_valid_at_gen_time: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamping_eku_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_anchor: Option<TerminalAnchorJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation: Option<&'static str>,
}

#[derive(Serialize)]
struct TerminalAnchorJson {
    /// `"trusted"` if the fingerprint was matched against the caller's
    /// `--tsa-trust-store`, `"assumed"` if the chain merely terminates in
    /// an unverified self-signed certificate.
    kind: &'static str,
    /// SHA-256 fingerprint of the terminal certificate, with `sha256:`
    /// prefix, regardless of `kind`.
    sha256_fingerprint: String,
}

#[derive(Serialize)]
struct AnchorVerificationJson {
    all_verified: bool,
    results: Vec<AnchorResultJson>,
}

/// `atl_core::PathStatus` -> a stable lowercase JSON string.
fn path_status_str(status: atl_core::PathStatus) -> &'static str {
    match status {
        atl_core::PathStatus::Complete => "complete",
        atl_core::PathStatus::Incomplete => "incomplete",
        atl_core::PathStatus::Invalid => "invalid",
    }
}

/// `atl_core::Revocation` -> a stable lowercase JSON string. Only
/// `NotChecked` exists today (see the type's own docs), but this is written
/// as a `match` so a future variant fails to compile here instead of
/// silently falling through.
fn revocation_str(revocation: atl_core::Revocation) -> &'static str {
    match revocation {
        atl_core::Revocation::NotChecked => "not_checked",
    }
}

/// `atl_core::TerminalAnchor` -> its JSON representation.
fn terminal_anchor_json(anchor: atl_core::TerminalAnchor) -> TerminalAnchorJson {
    let (kind, fingerprint) = match anchor {
        atl_core::TerminalAnchor::Trusted { sha256_fingerprint } => ("trusted", sha256_fingerprint),
        atl_core::TerminalAnchor::Assumed { sha256_fingerprint } => ("assumed", sha256_fingerprint),
    };
    TerminalAnchorJson {
        kind,
        sha256_fingerprint: format!("sha256:{}", hex::encode(fingerprint)),
    }
}

/// Format nanoseconds timestamp to ISO 8601 string
fn format_timestamp_iso(nanos: u64) -> Option<String> {
    use chrono::{TimeZone, Utc};
    let secs = i64::try_from(nanos / 1_000_000_000).ok()?;
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Format seconds timestamp to ISO 8601 string
fn format_timestamp_secs_iso(secs: u64) -> Option<String> {
    use chrono::{TimeZone, Utc};
    let secs_i64 = i64::try_from(secs).ok()?;
    Utc.timestamp_opt(secs_i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Render one anchor's fact set.
fn anchor_result_json(anchor: &AnchorVerificationResult) -> AnchorResultJson {
    let (
        block_height,
        block_timestamp,
        target_hash,
        operation_count,
        computed_root,
        block_merkle_root,
        merkle_match,
    ) = match &anchor.details {
        AnchorDetails::Bitcoin {
            block_height,
            block_timestamp_secs,
            target_hash,
            operation_count,
            computed_root,
            block_merkle_root,
            merkle_match,
        } => (
            Some(*block_height),
            format_timestamp_secs_iso(*block_timestamp_secs),
            Some(target_hash.clone()),
            Some(*operation_count),
            Some(computed_root.clone()),
            block_merkle_root.clone(),
            *merkle_match,
        ),
        _ => (None, None, None, None, None, None, None),
    };

    let (
        imprint_matches_root,
        cms_signature_valid,
        chain_valid_at_gen_time,
        timestamping_eku_ok,
        path_status,
        terminal_anchor,
        revocation,
    ) = match &anchor.details {
        AnchorDetails::Rfc3161 {
            imprint_matches_root,
            cms_signature_valid,
            chain_valid_at_gen_time,
            timestamping_eku_ok,
            path_status,
            terminal_anchor,
            revocation,
        } => (
            Some(*imprint_matches_root),
            Some(*cms_signature_valid),
            Some(*chain_valid_at_gen_time),
            Some(*timestamping_eku_ok),
            Some(path_status_str(*path_status)),
            terminal_anchor.map(terminal_anchor_json),
            Some(revocation_str(*revocation)),
        ),
        _ => (None, None, None, None, None, None, None),
    };

    AnchorResultJson {
        anchor_type: anchor.anchor_type.clone(),
        verified: anchor.verified(),
        reason_code: anchor.verdict.reason_code().map(ReasonCode::as_str),
        timestamp_nanos: anchor.timestamp_nanos,
        timestamp: anchor.timestamp_nanos.and_then(format_timestamp_iso),
        block_height,
        block_timestamp,
        error: anchor.error.clone(),
        target_hash,
        operation_count,
        computed_root,
        block_merkle_root,
        merkle_match,
        trust_state: anchor.details.rfc3161_trust_state(),
        imprint_matches_root,
        cms_signature_valid,
        chain_valid_at_gen_time,
        timestamping_eku_ok,
        path_status,
        terminal_anchor,
        revocation,
    }
}

fn build_anchor_verification(
    anchors: &[AnchorVerificationResult],
) -> Option<AnchorVerificationJson> {
    if anchors.is_empty() {
        return None;
    }
    Some(AnchorVerificationJson {
        all_verified: anchors.iter().all(AnchorVerificationResult::verified),
        results: anchors.iter().map(anchor_result_json).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::anchor::AnchorVerdict;
    use atl_core::{PathStatus, Revocation, TerminalAnchor};
    use std::path::{Path, PathBuf};

    fn create_test_receipt() -> atl_core::Receipt {
        serde_json::from_str(include_str!(
            "../../test_data/receipts/valid/document.pdf.atl"
        ))
        .expect("Failed to parse test receipt")
    }

    fn create_test_verification_result(is_valid: bool) -> atl_core::VerificationResult {
        let receipt = create_test_receipt();
        let mut result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        result.is_valid = is_valid;
        if !is_valid {
            result
                .errors
                .push(atl_core::VerificationError::MetadataHashMismatch {
                    actual: "sha256:test".to_string(),
                    expected: "sha256:expected".to_string(),
                });
        }
        result
    }

    fn single_result(file_hash_valid: bool, core_valid: bool) -> SingleVerificationResult {
        SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(core_valid),
            anchor_results: vec![],
        }
    }

    fn rfc3161_anchor(
        verdict: AnchorVerdict,
        terminal: Option<TerminalAnchor>,
    ) -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verdict,
            timestamp_nanos: Some(1_768_797_900_000_000_000),
            error: match verdict {
                AnchorVerdict::Valid => None,
                _ => Some("detail".to_string()),
            },
            details: AnchorDetails::Rfc3161 {
                imprint_matches_root: true,
                cms_signature_valid: true,
                chain_valid_at_gen_time: terminal.is_some(),
                timestamping_eku_ok: true,
                // A terminal certificate exists only for a complete path;
                // keep the fixture internally consistent with what atl-core
                // would actually report.
                path_status: if terminal.is_some() {
                    PathStatus::Complete
                } else {
                    PathStatus::Incomplete
                },
                terminal_anchor: terminal,
                revocation: Revocation::NotChecked,
            },
        }
    }

    #[test]
    fn unanchored_receipt_reports_pending() {
        let result = single_result(true, true);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "pending");
        assert_eq!(json.reason_code, Some("receipt_unanchored"));
        assert_eq!(json.anchor_status, "unanchored");
        assert!(json.errors.is_empty(), "pending is not an error state");
        assert!(json.anchor_verification.is_none());
    }

    #[test]
    fn file_hash_mismatch_reports_invalid_with_reason() {
        let result = single_result(false, false);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "invalid");
        assert_eq!(json.reason_code, Some("file_hash_mismatch"));
        assert!(json.verification.is_none());
        assert_eq!(json.errors[0].error_type, "file_hash_mismatch");
    }

    #[test]
    fn assumed_root_reports_untrusted_never_valid() {
        // THE contract this whole change exists for: sound cryptography plus
        // an unvouched-for root is `untrusted`, not `invalid` and never
        // `valid`.
        let mut result = single_result(true, true);
        result
            .receipt
            .anchors
            .push(atl_core::ReceiptAnchor::Rfc3161 {
                target: "data_tree_root".to_string(),
                target_hash: result.receipt.proof.root_hash.clone(),
                tsa_url: "https://example.invalid/tsa".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                token_der: "base64:token".to_string(),
            });
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [0x11; 32],
            }),
        ));

        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "untrusted");
        assert_eq!(json.reason_code, Some("tsa_root_not_trusted"));
        assert_eq!(json.anchor_status, "anchored");

        let anchors = json.anchor_verification.expect("anchors must be reported");
        assert!(!anchors.all_verified);
        assert!(!anchors.results[0].verified);
        assert_eq!(anchors.results[0].trust_state, Some("assumed"));
        assert_eq!(anchors.results[0].reason_code, Some("tsa_root_not_trusted"));
    }

    #[test]
    fn incomplete_chain_reports_untrusted_not_invalid() {
        let mut result = single_result(true, true);
        result
            .receipt
            .anchors
            .push(atl_core::ReceiptAnchor::Rfc3161 {
                target: "data_tree_root".to_string(),
                target_hash: result.receipt.proof.root_hash.clone(),
                tsa_url: "https://example.invalid/tsa".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                token_der: "base64:token".to_string(),
            });
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
            None,
        ));

        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "untrusted");
        assert_eq!(json.reason_code, Some("tsa_chain_incomplete"));
        let anchors = json.anchor_verification.expect("anchors must be reported");
        assert_eq!(anchors.results[0].trust_state, Some("incomplete"));
    }

    #[test]
    fn refuted_anchor_outranks_untrusted_anchor() {
        let mut result = single_result(true, true);
        for _ in 0..2 {
            result
                .receipt
                .anchors
                .push(atl_core::ReceiptAnchor::Rfc3161 {
                    target: "data_tree_root".to_string(),
                    target_hash: result.receipt.proof.root_hash.clone(),
                    tsa_url: "https://example.invalid/tsa".to_string(),
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                    token_der: "base64:token".to_string(),
                });
        }
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [0x11; 32],
            }),
        ));
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid),
            None,
        ));

        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "invalid");
        assert_eq!(json.reason_code, Some("cms_signature_invalid"));
    }

    #[test]
    fn mode_is_reported_verbatim() {
        let result = single_result(true, true);
        assert_eq!(
            build_single_result_json(&result, VerificationMode::Online).mode,
            "online"
        );
        assert_eq!(
            build_single_result_json(&result, VerificationMode::Offline).mode,
            "offline"
        );
    }

    #[test]
    fn print_single_result_succeeds_for_every_mode() {
        let result = single_result(true, true);
        assert!(print_single_result(&result, VerificationMode::Offline).is_ok());
        assert!(print_single_result(&result, VerificationMode::Online).is_ok());
    }

    #[test]
    fn batch_summary_counts_untrusted_separately() {
        let result = BatchVerificationResult {
            valid_count: 1,
            untrusted_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };
        assert_eq!(result.verdict().status.as_str(), "untrusted");
        assert!(print_batch_result(
            &result,
            VerificationMode::Offline,
            Path::new("/src"),
            Path::new("/rcpt")
        )
        .is_ok());
    }

    #[test]
    fn batch_with_failures_is_invalid() {
        let result = BatchVerificationResult {
            valid_count: 1,
            untrusted_count: 1,
            invalid_count: 1,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };
        assert_eq!(result.verdict().status.as_str(), "invalid");
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::BatchItemsInvalid)
        );
    }

    #[test]
    fn batch_items_render_every_bucket() {
        let result = BatchVerificationResult {
            valid_count: 1,
            untrusted_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 2,
            consistency: None,
            items: vec![
                BatchItemResult::Valid(single_result(true, true)),
                BatchItemResult::Untrusted(single_result(true, true)),
                BatchItemResult::Invalid(single_result(false, false)),
                BatchItemResult::Error {
                    source: PathBuf::from("broken.pdf"),
                    receipt: None,
                    error: crate::error::CliError::VerificationFailed("boom".into()),
                },
                BatchItemResult::NoReceipt(PathBuf::from("lonely.pdf")),
                BatchItemResult::NoSource(PathBuf::from("lonely.pdf.atl")),
            ],
        };
        assert!(print_batch_result(
            &result,
            VerificationMode::Offline,
            Path::new("/src"),
            Path::new("/rcpt")
        )
        .is_ok());
    }

    #[test]
    fn batch_item_status_comes_from_the_item_verdict() {
        // Even sitting in the `Untrusted` bucket, the printed status is the
        // item's own verdict -- the bucket cannot lie about it.
        let item = batch_item_json(&single_result(false, false));
        assert_eq!(item.status, "invalid");
        assert_eq!(item.reason_code, Some("file_hash_mismatch"));
        assert_eq!(item.file_hash_match, Some(false));
    }

    #[test]
    fn bitcoin_anchor_reports_its_chain() {
        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Valid,
            timestamp_nanos: Some(1_768_806_080_000_000_000),
            error: None,
            details: AnchorDetails::Bitcoin {
                block_height: 932_897,
                block_timestamp_secs: 1_768_806_080,
                target_hash: "sha256:abc123".to_string(),
                operation_count: 39,
                computed_root: "sha256:def456".to_string(),
                block_merkle_root: Some("sha256:def456".to_string()),
                merkle_match: Some(true),
            },
        };
        let json = serde_json::to_value(anchor_result_json(&anchor)).unwrap();
        assert_eq!(json["type"], "bitcoin_ots");
        assert_eq!(json["verified"], true);
        assert_eq!(json["block_height"], 932_897);
        assert_eq!(json["merkle_match"], true);
        assert_eq!(json["timestamp"], "2026-01-19T07:01:20Z");
        // RFC 3161 fields must not appear for a Bitcoin anchor.
        assert!(json.get("trust_state").is_none());
        assert!(json.get("path_status").is_none());
        // A valid anchor carries no reason code.
        assert!(json.get("reason_code").is_none());
    }

    #[test]
    fn rfc3161_anchor_omits_bitcoin_fields() {
        let anchor = rfc3161_anchor(
            AnchorVerdict::Valid,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
        );
        let json_str = serde_json::to_string(&anchor_result_json(&anchor)).unwrap();
        assert!(!json_str.contains("target_hash"));
        assert!(!json_str.contains("operation_count"));
        assert!(!json_str.contains("block_merkle_root"));
        assert!(json_str.contains("\"trust_state\":\"trusted\""));
        assert!(json_str.contains("\"kind\":\"trusted\""));
    }

    #[test]
    fn timestamp_helpers_render_iso8601() {
        assert_eq!(
            format_timestamp_iso(1_768_797_900_000_000_000),
            Some("2026-01-19T04:45:00Z".to_string())
        );
        assert_eq!(
            format_timestamp_secs_iso(1_768_797_900),
            Some("2026-01-19T04:45:00Z".to_string())
        );
        assert_eq!(
            format_timestamp_iso(0),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn stable_string_maps_cover_every_variant() {
        assert_eq!(path_status_str(PathStatus::Complete), "complete");
        assert_eq!(path_status_str(PathStatus::Incomplete), "incomplete");
        assert_eq!(path_status_str(PathStatus::Invalid), "invalid");
        assert_eq!(revocation_str(Revocation::NotChecked), "not_checked");
        assert_eq!(
            terminal_anchor_json(TerminalAnchor::Assumed {
                sha256_fingerprint: [0u8; 32]
            })
            .kind,
            "assumed"
        );
    }

    #[test]
    fn verification_block_mirrors_the_proof_verdict() {
        let result = single_result(true, true);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        let verification = json.verification.expect("hash matched, so proofs reported");
        assert_eq!(verification.entry_id, result.receipt.entry.id.to_string());
        assert_eq!(
            verification.proofs_valid,
            result.proof_verdict().proofs_valid()
        );
    }
}
