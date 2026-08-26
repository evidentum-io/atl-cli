//! JSON output formatting

use serde::Serialize;

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::online::{AnchorDetails, OnlineVerificationResult, Rfc3161Trust};
use crate::verify::single::SingleVerificationResult;

#[derive(Serialize)]
struct SingleResultJson {
    status: &'static str,
    anchor_status: &'static str,
    mode: &'static str,
    source_file: String,
    receipt_file: String,
    file_hash: FileHashJson,
    verification: Option<VerificationJson>,
    anchors: Vec<AnchorJson>,
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
    /// corroborates. Consumers must look at `status` (and, in online mode,
    /// `anchor_verification`) to judge trust; do not read `proofs_valid:
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
#[allow(dead_code)]
struct AnchorJson {
    #[serde(rename = "type")]
    anchor_type: String,
    target: String,
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
}

#[derive(Serialize)]
struct ErrorJson {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

/// Build the JSON representation of a single-file (offline) verification result.
///
/// Split out from [`print_single_result`] so tests can inspect the resulting
/// fields directly instead of parsing captured stdout.
fn build_single_result_json(
    result: &SingleVerificationResult,
    mode: VerificationMode,
) -> SingleResultJson {
    let (status, anchor_status) = if result.is_lite_valid() {
        ("pending", "unanchored")
    } else if result.is_valid() {
        ("valid", "anchored")
    } else {
        ("invalid", "n/a")
    };

    let output = SingleResultJson {
        status,
        anchor_status,
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
        anchors: vec![], // Anchors not verified in offline mode
        errors: if !result.is_valid() && !result.is_lite_valid() {
            if !result.file_hash_valid {
                vec![ErrorJson {
                    error_type: "file_hash_mismatch".to_string(),
                    message: "File hash does not match receipt".to_string(),
                }]
            } else {
                result
                    .core_result
                    .errors
                    .iter()
                    .map(|e| ErrorJson {
                        error_type: "verification_failed".to_string(),
                        message: format!("{e:?}"),
                    })
                    .collect()
            }
        } else {
            vec![]
        },
    };

    output
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
    file_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    super_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_tree_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn print_batch_result(
    result: &BatchVerificationResult,
    mode: VerificationMode,
    source_dir: &std::path::Path,
    receipt_dir: &std::path::Path,
) -> CliResult<()> {
    let total =
        result.valid_count + result.invalid_count + result.error_count + result.unmatched_count;

    // Build sorted list of valid items for cross-check file name lookup
    let mut valid_items_sorted: Vec<_> = result
        .items
        .iter()
        .filter_map(|item| match item {
            BatchItemResult::Valid(r) => {
                let data_tree_index = r
                    .receipt
                    .super_proof
                    .as_ref()
                    .map(|sp| sp.data_tree_index)
                    .unwrap_or(0);
                let filename = r
                    .source_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                Some((data_tree_index, filename))
            }
            _ => None,
        })
        .collect();
    valid_items_sorted.sort_by_key(|(idx, _)| *idx);

    let consistency = result.consistency.as_ref().map(|c| {
        let cross_checks_passed = c
            .cross_results
            .iter()
            .filter(|cr| cr.history_consistent)
            .count();

        // Build cross_checks array with file names
        let cross_checks: Vec<CrossCheckJson> = c
            .cross_results
            .iter()
            .enumerate()
            .map(|(idx, cr)| {
                let from_file = valid_items_sorted
                    .get(idx)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_default();
                let to_file = valid_items_sorted
                    .get(idx + 1)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_default();

                CrossCheckJson {
                    from_index: idx + 1,
                    to_index: idx + 2,
                    from_file,
                    to_file,
                    included: cr.history_consistent,
                }
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
            BatchItemResult::Valid(r) => {
                let (super_root, data_tree_index) = r
                    .receipt
                    .super_proof
                    .as_ref()
                    .map(|sp| (Some(sp.super_root.clone()), Some(sp.data_tree_index)))
                    .unwrap_or((None, None));

                BatchItemJson {
                    file: r
                        .source_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    receipt: Some(
                        r.receipt_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                    ),
                    status: "valid",
                    file_hash_match: Some(true),
                    super_root,
                    data_tree_index,
                    error: None,
                }
            }
            BatchItemResult::Invalid(r) => {
                let (super_root, data_tree_index) = r
                    .receipt
                    .super_proof
                    .as_ref()
                    .map(|sp| (Some(sp.super_root.clone()), Some(sp.data_tree_index)))
                    .unwrap_or((None, None));

                BatchItemJson {
                    file: r
                        .source_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    receipt: Some(
                        r.receipt_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                    ),
                    status: "invalid",
                    file_hash_match: Some(r.file_hash_valid),
                    super_root,
                    data_tree_index,
                    error: if !r.file_hash_valid {
                        Some("File hash mismatch".to_string())
                    } else {
                        None
                    },
                }
            }
            BatchItemResult::Error { source, error, .. } => BatchItemJson {
                file: source
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                receipt: None,
                status: "error",
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: Some(error.to_string()),
            },
            BatchItemResult::NoReceipt(path) => BatchItemJson {
                file: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                receipt: None,
                status: "no_receipt",
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: None,
            },
            BatchItemResult::NoSource(path) => BatchItemJson {
                file: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                receipt: None,
                status: "no_source",
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: None,
            },
        })
        .collect();

    let output = BatchResultJson {
        status: if result.is_valid() {
            "valid"
        } else {
            "invalid"
        },
        mode: match mode {
            VerificationMode::Online => "online",
            VerificationMode::Offline => "offline",
        },
        source_dir: source_dir.display().to_string(),
        receipt_dir: receipt_dir.display().to_string(),
        summary: SummaryJson {
            total,
            valid: result.valid_count,
            invalid: result.invalid_count,
            errors: result.error_count,
            unmatched: result.unmatched_count,
        },
        consistency,
        items,
        errors: if !result.is_valid() {
            vec![ErrorJson {
                error_type: "batch_verification_failed".to_string(),
                message: format!(
                    "{} files failed verification",
                    result.invalid_count + result.error_count
                ),
            }]
        } else {
            vec![]
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
    verified: bool,
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
    // atl-core. Reported as *facts*, not a collapsed verdict, matching the
    // core API this is built from; `trust_state` is the single tri-state
    // summary (`"trusted"` / `"assumed"` / `"failed"`) that the human
    // renderer's status line is built from too, so the two can never
    // disagree about which of the three states an anchor is in.
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

#[derive(Serialize)]
struct SingleOnlineResultJson {
    status: &'static str,
    mode: &'static str,
    file: String,
    receipt: String,
    file_hash_valid: bool,
    computed_hash: String,
    expected_hash: String,
    // Same shape as the offline `verification` block (`VerificationJson`) —
    // online mode used to be a strictly poorer subset of offline; this keeps
    // the two structurally identical so consumers get the same diagnostics
    // regardless of mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<VerificationJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_verification: Option<AnchorVerificationJson>,
}

/// `Rfc3161Trust` -> the JSON string used for `trust_state`, identical in
/// spirit to the human renderer's status line ("TRUSTED" / "ASSUMED..." /
/// "FAILED").
fn trust_state_str(trust: Rfc3161Trust) -> &'static str {
    match trust {
        Rfc3161Trust::Trusted => "trusted",
        Rfc3161Trust::Assumed => "assumed",
        Rfc3161Trust::Failed => "failed",
    }
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

/// Build the JSON representation of a single-file online verification result.
///
/// Split out from [`print_single_online_result`] so tests can inspect the
/// resulting fields directly instead of parsing captured stdout.
fn build_single_online_result_json(result: &OnlineVerificationResult) -> SingleOnlineResultJson {
    let status = if result.is_valid() {
        "valid"
    } else if result.offline.is_lite_valid() {
        "pending"
    } else {
        "invalid"
    };

    // Verification details — same canonical `ProofVerdict` the offline
    // renderer uses, so online and offline JSON can never disagree.
    let verification = if result.offline.file_hash_valid {
        Some(VerificationJson::from_verdict(
            result.offline.receipt.entry.id.to_string(),
            result.offline.proof_verdict(),
        ))
    } else {
        None
    };

    let anchor_verification = if !result.anchor_results.is_empty() {
        Some(AnchorVerificationJson {
            all_verified: result.all_anchors_verified,
            results: result
                .anchor_results
                .iter()
                .map(|a| {
                    // Extract Bitcoin-specific fields
                    let (
                        block_height,
                        block_timestamp,
                        target_hash,
                        operation_count,
                        computed_root,
                        block_merkle_root,
                        merkle_match,
                    ) = match &a.details {
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

                    // Extract RFC 3161 facts. `trust_state` is derived from
                    // the very same `AnchorDetails::rfc3161_trust()` the
                    // human renderer's status line uses (via `a.verified`,
                    // which is `true` iff that method returns `Trusted`), so
                    // JSON and human output are structurally unable to
                    // disagree about which of the three states an anchor is
                    // in.
                    let (
                        imprint_matches_root,
                        cms_signature_valid,
                        chain_valid_at_gen_time,
                        timestamping_eku_ok,
                        path_status,
                        terminal_anchor,
                        revocation,
                    ) = match &a.details {
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
                    let trust_state = a.details.rfc3161_trust().map(trust_state_str);

                    AnchorResultJson {
                        anchor_type: a.anchor_type.clone(),
                        verified: a.verified,
                        timestamp_nanos: a.timestamp_nanos,
                        timestamp: a.timestamp_nanos.and_then(format_timestamp_iso),
                        block_height,
                        block_timestamp,
                        error: a.error.clone(),
                        target_hash,
                        operation_count,
                        computed_root,
                        block_merkle_root,
                        merkle_match,
                        trust_state,
                        imprint_matches_root,
                        cms_signature_valid,
                        chain_valid_at_gen_time,
                        timestamping_eku_ok,
                        path_status,
                        terminal_anchor,
                        revocation,
                    }
                })
                .collect(),
        })
    } else {
        None
    };

    let output = SingleOnlineResultJson {
        status,
        mode: "online",
        file: result.offline.source_path.display().to_string(),
        receipt: result.offline.receipt_path.display().to_string(),
        file_hash_valid: result.offline.file_hash_valid,
        computed_hash: format!("sha256:{}", hex::encode(result.offline.file_hash)),
        expected_hash: result.offline.receipt.entry.payload_hash.clone(),
        verification,
        anchor_verification,
    };

    output
}

pub fn print_single_online_result(result: &OnlineVerificationResult) -> CliResult<()> {
    let output = build_single_online_result_json(result);
    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_test_receipt() -> atl_core::Receipt {
        // Load a minimal valid receipt from test data
        serde_json::from_str(include_str!(
            "../../test_data/receipts/valid/document.pdf.atl"
        ))
        .expect("Failed to parse test receipt")
    }

    fn create_test_verification_result(is_valid: bool) -> atl_core::VerificationResult {
        // Create a real verification result using the test receipt
        let receipt = create_test_receipt();
        let mut result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Override is_valid for testing purposes
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

    #[test]
    fn test_print_single_result_valid() {
        use crate::cli::VerificationMode;

        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_single_result_invalid() {
        use crate::cli::VerificationMode;

        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(false),
        };

        assert!(print_single_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_single_result_hash_mismatch() {
        use crate::cli::VerificationMode;

        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_single_result_with_super_proof() {
        use crate::cli::VerificationMode;

        let receipt = create_test_receipt();
        // The test receipt already has super_proof

        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_all_valid() {
        use crate::cli::VerificationMode;
        use std::path::Path;

        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_print_batch_result_with_failures() {
        use crate::cli::VerificationMode;
        use std::path::Path;

        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 1,
            consistency: None,
            items: vec![],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_print_batch_result_with_consistency() {
        use crate::cli::VerificationMode;
        use crate::verify::consistency::ConsistencyResult;
        use std::path::Path;

        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: Some(ConsistencyResult {
                genesis_super_root: Some([0x12; 32]),
                receipt_count: 2,
                same_log: true,
                history_consistent: true,
                cross_results: vec![],
                errors: vec![],
            }),
            items: vec![],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_print_batch_result_consistency_failed() {
        use crate::cli::VerificationMode;
        use crate::verify::consistency::ConsistencyResult;
        use std::path::Path;

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: Some(ConsistencyResult {
                genesis_super_root: None,
                receipt_count: 2,
                same_log: false,
                history_consistent: false,
                cross_results: vec![],
                errors: vec!["Inconsistent logs".to_string()],
            }),
            items: vec![],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_batch_item_valid() {
        use crate::cli::VerificationMode;
        use std::path::Path;

        let item = BatchItemResult::Valid(SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        });

        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![item],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_batch_item_invalid() {
        use crate::cli::VerificationMode;
        use std::path::Path;

        let item = BatchItemResult::Invalid(SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(false),
        });

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 1,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![item],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_batch_item_error() {
        use crate::cli::VerificationMode;
        use crate::error::CliError;
        use std::path::Path;

        let item = BatchItemResult::Error {
            source: PathBuf::from("test.pdf"),
            receipt: Some(PathBuf::from("test.pdf.atl")),
            error: CliError::SourceNotFound(PathBuf::from("test.pdf")),
        };

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 0,
            error_count: 1,
            unmatched_count: 0,
            consistency: None,
            items: vec![item],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_batch_item_no_receipt() {
        use crate::cli::VerificationMode;
        use std::path::Path;

        let item = BatchItemResult::NoReceipt(PathBuf::from("test.pdf"));

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 1,
            consistency: None,
            items: vec![item],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_batch_item_no_source() {
        use crate::cli::VerificationMode;
        use std::path::Path;

        let item = BatchItemResult::NoSource(PathBuf::from("test.pdf.atl"));

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 1,
            consistency: None,
            items: vec![item],
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_batch_mixed_items() {
        use crate::cli::VerificationMode;
        use crate::error::CliError;
        use std::path::Path;

        let items = vec![
            BatchItemResult::Valid(SingleVerificationResult {
                source_path: PathBuf::from("test1.pdf"),
                receipt_path: PathBuf::from("test1.pdf.atl"),
                file_hash: [0xab; 32],
                file_hash_valid: true,
                receipt: create_test_receipt(),
                core_result: create_test_verification_result(true),
            }),
            BatchItemResult::Invalid(SingleVerificationResult {
                source_path: PathBuf::from("test2.pdf"),
                receipt_path: PathBuf::from("test2.pdf.atl"),
                file_hash: [0xcd; 32],
                file_hash_valid: false,
                receipt: create_test_receipt(),
                core_result: create_test_verification_result(false),
            }),
            BatchItemResult::Error {
                source: PathBuf::from("test3.pdf"),
                receipt: Some(PathBuf::from("test3.pdf.atl")),
                error: CliError::SourceNotFound(PathBuf::from("test3.pdf")),
            },
            BatchItemResult::NoReceipt(PathBuf::from("test4.pdf")),
            BatchItemResult::NoSource(PathBuf::from("test5.pdf.atl")),
        ];

        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 2,
            consistency: None,
            items,
        };

        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(
            print_batch_result(&result, VerificationMode::Offline, source_dir, receipt_dir).is_ok()
        );
    }

    #[test]
    fn test_serialization_structures() {
        // Test that all JSON structures can be serialized
        let file_hash = FileHashJson {
            computed: "sha256:abcd".to_string(),
            expected: "sha256:abcd".to_string(),
            is_match: true,
        };
        assert!(serde_json::to_string(&file_hash).is_ok());

        let verification = VerificationJson {
            entry_id: "1".to_string(),
            inclusion_valid: true,
            super_inclusion_valid: Some(true),
            super_consistency_valid: Some(true),
            proofs_valid: true,
        };
        assert!(serde_json::to_string(&verification).is_ok());

        let anchor = AnchorJson {
            anchor_type: "bitcoin".to_string(),
            target: "000000000000000000012345".to_string(),
            verified: Some(true),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            block_height: Some(800000),
        };
        assert!(serde_json::to_string(&anchor).is_ok());

        let error = ErrorJson {
            error_type: "verification_failed".to_string(),
            message: "Test error".to_string(),
        };
        assert!(serde_json::to_string(&error).is_ok());

        let summary = SummaryJson {
            total: 10,
            valid: 8,
            invalid: 1,
            errors: 1,
            unmatched: 0,
        };
        assert!(serde_json::to_string(&summary).is_ok());

        let cross_check = CrossCheckJson {
            from_index: 1,
            to_index: 2,
            from_file: "test1.pdf".to_string(),
            to_file: "test2.pdf".to_string(),
            included: true,
        };
        assert!(serde_json::to_string(&cross_check).is_ok());

        let consistency = ConsistencyJson {
            status: "verified",
            genesis_super_root: Some("sha256:abcd".to_string()),
            receipt_count: 10,
            cross_checks_passed: 9,
            cross_checks: vec![cross_check],
        };
        assert!(serde_json::to_string(&consistency).is_ok());

        let batch_item = BatchItemJson {
            file: "test.pdf".to_string(),
            receipt: Some("test.pdf.atl".to_string()),
            status: "valid",
            file_hash_match: Some(true),
            super_root: Some("sha256:abc123".to_string()),
            data_tree_index: Some(5),
            error: None,
        };
        assert!(serde_json::to_string(&batch_item).is_ok());
    }

    #[test]
    fn should_format_timestamp_as_iso8601() {
        // Arrange
        let nanos: u64 = 1_768_797_900_000_000_000;

        // Act
        let result = format_timestamp_iso(nanos);

        // Assert
        assert_eq!(result, Some("2026-01-19T04:45:00Z".to_string()));
    }

    #[test]
    fn should_format_timestamp_secs_as_iso8601() {
        // Arrange
        let secs: u64 = 1_768_797_900;

        // Act
        let result = format_timestamp_secs_iso(secs);

        // Assert
        assert_eq!(result, Some("2026-01-19T04:45:00Z".to_string()));
    }

    #[test]
    fn should_handle_zero_timestamp() {
        // Arrange
        let nanos: u64 = 0;

        // Act
        let result = format_timestamp_iso(nanos);

        // Assert
        assert_eq!(result, Some("1970-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn should_serialize_verification_details_json() {
        // Arrange
        let details = VerificationJson {
            entry_id: "896d398f-f983-467b-a376-60e795e66d3b".to_string(),
            inclusion_valid: true,
            super_inclusion_valid: Some(true),
            super_consistency_valid: Some(true),
            proofs_valid: true,
        };

        // Act
        let json = serde_json::to_value(&details).unwrap();

        // Assert
        assert_eq!(json["entry_id"], "896d398f-f983-467b-a376-60e795e66d3b");
        assert_eq!(json["inclusion_valid"], true);
    }

    #[test]
    fn should_serialize_anchor_result_with_bitcoin_fields() {
        // Arrange
        let anchor = AnchorResultJson {
            anchor_type: "bitcoin_ots".to_string(),
            verified: true,
            timestamp_nanos: Some(1_768_806_080_000_000_000),
            timestamp: Some("2026-01-19T07:01:20Z".to_string()),
            block_height: Some(932897),
            block_timestamp: Some("2026-01-19T07:01:20Z".to_string()),
            error: None,
            target_hash: Some("sha256:abc123".to_string()),
            operation_count: Some(39),
            computed_root: Some("sha256:def456".to_string()),
            block_merkle_root: Some("sha256:def456".to_string()),
            merkle_match: Some(true),
            trust_state: None,
            imprint_matches_root: None,
            cms_signature_valid: None,
            chain_valid_at_gen_time: None,
            timestamping_eku_ok: None,
            path_status: None,
            terminal_anchor: None,
            revocation: None,
        };

        // Act
        let json = serde_json::to_value(&anchor).unwrap();

        // Assert
        assert_eq!(json["type"], "bitcoin_ots");
        assert_eq!(json["verified"], true);
        assert_eq!(json["timestamp"], "2026-01-19T07:01:20Z");
        assert_eq!(json["target_hash"], "sha256:abc123");
        assert_eq!(json["operation_count"], 39);
        assert_eq!(json["merkle_match"], true);
    }

    #[test]
    fn should_skip_bitcoin_fields_for_rfc3161() {
        // Arrange
        let anchor = AnchorResultJson {
            anchor_type: "rfc3161".to_string(),
            verified: true,
            timestamp_nanos: Some(1_768_797_900_000_000_000),
            timestamp: Some("2026-01-19T04:45:00Z".to_string()),
            block_height: None,
            block_timestamp: None,
            error: None,
            target_hash: None,
            operation_count: None,
            computed_root: None,
            block_merkle_root: None,
            merkle_match: None,
            trust_state: Some("trusted"),
            imprint_matches_root: Some(true),
            cms_signature_valid: Some(true),
            chain_valid_at_gen_time: Some(true),
            timestamping_eku_ok: Some(true),
            path_status: Some("complete"),
            terminal_anchor: Some(TerminalAnchorJson {
                kind: "trusted",
                sha256_fingerprint: "sha256:00".to_string(),
            }),
            revocation: Some("not_checked"),
        };

        // Act
        let json_str = serde_json::to_string(&anchor).unwrap();

        // Assert
        assert!(!json_str.contains("target_hash"));
        assert!(!json_str.contains("operation_count"));
        assert!(!json_str.contains("merkle_match"));
        assert!(json_str.contains("timestamp"));
        assert!(json_str.contains("\"trust_state\":\"trusted\""));
    }

    #[test]
    fn assumed_rfc3161_anchor_never_reports_verified_or_trusted() {
        // Direct regression test for the trust-model requirement: an anchor
        // whose terminal certificate is `Assumed` must have `verified:
        // false` and `trust_state: "assumed"` in the JSON, never
        // `"trusted"` and never `verified: true`.
        let online = online_result_with_rfc3161_anchor(
            false,
            crate::verify::online::AnchorDetails::Rfc3161 {
                imprint_matches_root: true,
                cms_signature_valid: true,
                chain_valid_at_gen_time: true,
                timestamping_eku_ok: true,
                path_status: atl_core::PathStatus::Complete,
                terminal_anchor: Some(atl_core::TerminalAnchor::Assumed {
                    sha256_fingerprint: [0x33; 32],
                }),
                revocation: atl_core::Revocation::NotChecked,
            },
        );

        let json = build_single_online_result_json(&online);
        let value = serde_json::to_value(&json).unwrap();

        assert_eq!(value["status"], "invalid");
        let anchor = &value["anchor_verification"]["results"][0];
        assert_eq!(anchor["verified"], false);
        assert_eq!(anchor["trust_state"], "assumed");
        assert_eq!(anchor["terminal_anchor"]["kind"], "assumed");
        assert_eq!(value["anchor_verification"]["all_verified"], false);
    }

    #[test]
    fn trusted_rfc3161_anchor_reports_verified_and_trusted_consistently() {
        let online = online_result_with_rfc3161_anchor(
            true,
            crate::verify::online::AnchorDetails::Rfc3161 {
                imprint_matches_root: true,
                cms_signature_valid: true,
                chain_valid_at_gen_time: true,
                timestamping_eku_ok: true,
                path_status: atl_core::PathStatus::Complete,
                terminal_anchor: Some(atl_core::TerminalAnchor::Trusted {
                    sha256_fingerprint: [0x44; 32],
                }),
                revocation: atl_core::Revocation::NotChecked,
            },
        );

        let json = build_single_online_result_json(&online);
        let value = serde_json::to_value(&json).unwrap();

        assert_eq!(value["status"], "valid");
        let anchor = &value["anchor_verification"]["results"][0];
        assert_eq!(anchor["verified"], true);
        assert_eq!(anchor["trust_state"], "trusted");
        assert_eq!(anchor["terminal_anchor"]["kind"], "trusted");
        assert_eq!(value["anchor_verification"]["all_verified"], true);
    }

    fn online_result_with_rfc3161_anchor(
        verified: bool,
        details: crate::verify::online::AnchorDetails,
    ) -> OnlineVerificationResult {
        use crate::verify::online::AnchorVerificationResult;

        // `receipt.anchors` must be non-empty here -- as it always is in
        // production, where `anchor_results` is derived directly from the
        // receipt's own anchors (see `verify_single_online`) -- so
        // `is_lite_valid()`'s "genuinely unanchored" guard does not
        // mistake "has an anchor that isn't Trusted" for "has no anchor at
        // all" and report `status: "pending"` instead of `"invalid"`.
        let mut receipt = create_test_receipt();
        receipt.anchors.push(atl_core::ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: receipt.proof.root_hash.clone(),
            tsa_url: "https://example.com/tsa".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            token_der: "base64:dGVzdA==".to_string(),
        });
        // `core_result` here only needs to agree with `verified` on
        // `is_valid` -- its `errors`/`anchor_results` internals are not
        // what these tests are exercising (that's covered by
        // `verify::online::tests::rfc3161_trust_*`); what matters is that
        // `OnlineVerificationResult::is_valid()` (offline AND all anchors)
        // lands where the scenario says it should.
        let mut core_result = real_unanchored_core_result();
        core_result.is_valid = verified;
        if verified {
            core_result.errors.clear();
        }
        let offline = single_result_with(core_result, receipt);
        let anchor = AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified,
            timestamp_nanos: Some(1_700_000_000_000_000_000),
            error: if verified {
                None
            } else {
                Some("trust anchor not established".to_string())
            },
            details,
        };

        OnlineVerificationResult {
            offline,
            anchor_results: vec![anchor],
            all_anchors_verified: verified,
            mode: crate::cli::VerificationMode::Online,
        }
    }

    // ========================================================================
    // Canonical verdict regression tests
    //
    // Covers the two symmetric bugs the `ProofVerdict` refactor fixes:
    // - offline JSON used to fold `inclusion_valid` / super fields into the
    //   aggregate `core_result.is_valid`, which is `false` for any valid but
    //   unanchored receipt (too strict);
    // - online JSON only ever exposed base `inclusion_valid` and never
    //   exposed the super-tree fields at all, so a broken super-tree proof
    //   was invisible in online mode (too lenient — the online *human*
    //   renderer had the matching bug, fixed by the same shared method).
    // ========================================================================

    /// Real (unmodified) anchor-only verification of the bundled valid
    /// receipt: unanchored (`NoTrustAnchor`), but every cryptographic proof
    /// — base inclusion, super inclusion, super consistency — genuinely
    /// passes.
    fn real_unanchored_core_result() -> atl_core::VerificationResult {
        let receipt = create_test_receipt();
        atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt")
    }

    fn single_result_with(
        core_result: atl_core::VerificationResult,
        receipt: atl_core::Receipt,
    ) -> SingleVerificationResult {
        SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
        }
    }

    #[test]
    fn unanchored_valid_receipt_reports_true_inclusion_and_super_flags_offline() {
        use crate::cli::VerificationMode;

        // core_result.is_valid is false here (NoTrustAnchor) — the whole
        // point of the test is that this must NOT leak into the proof flags.
        let core_result = real_unanchored_core_result();
        assert!(!core_result.is_valid, "fixture must be unanchored");
        assert!(core_result.inclusion_valid);
        assert!(core_result.super_inclusion_valid);
        assert!(core_result.super_consistency_valid);

        let result = single_result_with(core_result, create_test_receipt());
        let json = build_single_result_json(&result, VerificationMode::Offline);
        let value = serde_json::to_value(&json).unwrap();

        assert_eq!(value["status"], "pending");
        assert_eq!(value["verification"]["inclusion_valid"], true);
        assert_eq!(value["verification"]["super_inclusion_valid"], true);
        assert_eq!(value["verification"]["super_consistency_valid"], true);
        assert_eq!(value["verification"]["proofs_valid"], true);
    }

    #[test]
    fn broken_super_proof_reports_invalid_in_offline_json() {
        use crate::cli::VerificationMode;

        let mut core_result = real_unanchored_core_result();
        core_result.super_inclusion_valid = false;
        core_result.is_valid = false;
        core_result
            .errors
            .push(atl_core::VerificationError::SuperInclusionFailed {
                reason: "data tree root not included in super root".to_string(),
            });

        let result = single_result_with(core_result, create_test_receipt());
        // Base inclusion is untouched and genuinely valid; only the super
        // proof is broken.
        assert!(result.core_result.inclusion_valid);

        let json = build_single_result_json(&result, VerificationMode::Offline);
        let value = serde_json::to_value(&json).unwrap();

        assert_eq!(value["status"], "invalid");
        assert_eq!(value["verification"]["inclusion_valid"], true);
        assert_eq!(value["verification"]["super_inclusion_valid"], false);
        assert_eq!(
            value["verification"]["proofs_valid"], false,
            "a broken super-tree proof must never be reported as proofs_valid: true"
        );
    }

    #[test]
    fn broken_super_consistency_only_reports_invalid_via_real_crypto() {
        // Review finding: `broken_super_proof.atl` corrupts `super_root`,
        // which breaks BOTH `super_inclusion_valid` and
        // `super_consistency_valid` at once (for a size-1 Super-Tree,
        // inclusion requires `super_root == data_tree_root` and consistency
        // requires `genesis_super_root == super_root`). That fixture alone
        // cannot prove the renderer catches a consistency-only failure. This
        // test uses a second fixture,
        // `broken_super_consistency_only.atl`, that keeps `super_root`
        // correct (so super-tree inclusion genuinely passes) and corrupts
        // only `genesis_super_root` (so consistency-to-origin genuinely
        // fails) — verified through the real `atl_core` crypto path, not by
        // hand-flipping `VerificationResult` fields.
        use crate::cli::VerificationMode;

        let receipt: atl_core::Receipt = serde_json::from_str(include_str!(
            "../../test_data/receipts/invalid/broken_super_consistency_only.atl"
        ))
        .expect("Failed to parse fixture receipt");
        assert!(receipt.super_proof.is_some());

        let core_result = atl_core::verify_receipt_anchor_only(&receipt)
            .expect("Failed to verify fixture receipt");
        assert!(
            core_result.inclusion_valid,
            "base inclusion must be untouched by this fixture"
        );
        assert!(
            core_result.super_inclusion_valid,
            "super-tree inclusion must genuinely pass: super_root was not touched"
        );
        assert!(
            !core_result.super_consistency_valid,
            "consistency-to-origin must genuinely fail: genesis_super_root was corrupted"
        );

        let result = single_result_with(core_result, receipt);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        let value = serde_json::to_value(&json).unwrap();

        assert_eq!(value["status"], "invalid");
        assert_eq!(value["verification"]["inclusion_valid"], true);
        assert_eq!(value["verification"]["super_inclusion_valid"], true);
        assert_eq!(
            value["verification"]["super_consistency_valid"], false,
            "consistency-only breakage must surface distinctly from inclusion breakage"
        );
        assert_eq!(value["verification"]["proofs_valid"], false);
    }

    #[test]
    fn broken_super_proof_reports_invalid_in_online_json() {
        // Regression for the online-mode "mildness" bug: online JSON used to
        // report only `core_result.is_valid` under `inclusion_valid` and had
        // no super fields at all, so a broken super-tree proof was
        // completely invisible. It must now match the offline shape and
        // verdict exactly.
        let mut core_result = real_unanchored_core_result();
        core_result.super_inclusion_valid = false;
        core_result.is_valid = false;
        core_result
            .errors
            .push(atl_core::VerificationError::SuperInclusionFailed {
                reason: "data tree root not included in super root".to_string(),
            });

        let offline = single_result_with(core_result, create_test_receipt());
        let online = OnlineVerificationResult {
            offline,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: crate::cli::VerificationMode::Online,
        };

        let json = build_single_online_result_json(&online);
        let value = serde_json::to_value(&json).unwrap();

        assert_eq!(value["status"], "invalid");
        assert_eq!(value["verification"]["inclusion_valid"], true);
        assert_eq!(value["verification"]["super_inclusion_valid"], false);
        assert_eq!(value["verification"]["proofs_valid"], false);
    }

    #[test]
    fn offline_and_online_json_agree_on_verdict_matrix() {
        // Structural equality check: build both offline and online JSON from
        // the same underlying (core_result, receipt) pair across a matrix of
        // scenarios, and assert the `verification` blocks are byte-for-byte
        // identical. This is what makes divergence between the two renderers
        // structurally impossible rather than "currently consistent".
        use crate::cli::VerificationMode;

        // Test-only fixture; a state machine / enum would obscure the
        // matrix more than the four independent flags it's spelling out.
        #[allow(clippy::struct_excessive_bools)]
        struct Case {
            name: &'static str,
            has_super_proof: bool,
            inclusion_valid: bool,
            super_inclusion_valid: bool,
            super_consistency_valid: bool,
        }

        let cases = [
            Case {
                name: "no super_proof, base valid",
                has_super_proof: false,
                inclusion_valid: true,
                super_inclusion_valid: true,
                super_consistency_valid: true,
            },
            Case {
                name: "no super_proof, base broken",
                has_super_proof: false,
                inclusion_valid: false,
                super_inclusion_valid: true,
                super_consistency_valid: true,
            },
            Case {
                name: "super_proof present, all valid",
                has_super_proof: true,
                inclusion_valid: true,
                super_inclusion_valid: true,
                super_consistency_valid: true,
            },
            Case {
                name: "super_proof present, super_inclusion broken",
                has_super_proof: true,
                inclusion_valid: true,
                super_inclusion_valid: false,
                super_consistency_valid: true,
            },
            Case {
                name: "super_proof present, super_consistency broken",
                has_super_proof: true,
                inclusion_valid: true,
                super_inclusion_valid: true,
                super_consistency_valid: false,
            },
            Case {
                name: "super_proof present, base inclusion broken",
                has_super_proof: true,
                inclusion_valid: false,
                super_inclusion_valid: true,
                super_consistency_valid: true,
            },
        ];

        for case in cases {
            let mut core_result = real_unanchored_core_result();
            core_result.inclusion_valid = case.inclusion_valid;
            core_result.super_inclusion_valid = case.super_inclusion_valid;
            core_result.super_consistency_valid = case.super_consistency_valid;

            let mut receipt = create_test_receipt();
            if !case.has_super_proof {
                receipt.super_proof = None;
            }

            let offline_result = single_result_with(core_result, receipt);
            let offline_json = build_single_result_json(&offline_result, VerificationMode::Offline);
            let offline_value = serde_json::to_value(&offline_json).unwrap();

            let online_result = OnlineVerificationResult {
                offline: offline_result,
                anchor_results: vec![],
                all_anchors_verified: true,
                mode: VerificationMode::Online,
            };
            let online_json = build_single_online_result_json(&online_result);
            let online_value = serde_json::to_value(&online_json).unwrap();

            assert_eq!(
                offline_value["verification"], online_value["verification"],
                "offline/online verification blocks diverged for case: {}",
                case.name
            );
            // Note: `status` is deliberately NOT compared here. Its
            // offline/online precedence (`is_lite_valid()` vs `is_valid()`
            // checked first) is pre-existing, untouched by this fix (see
            // task scope: "не меняй семантику status"), and unreachable in
            // practice — the real CLI only ever routes to the online
            // renderer when `receipt.anchors` is non-empty, at which point
            // `is_lite_valid()` is false for both. This test wraps a
            // zero-anchor core_result in `OnlineVerificationResult` purely
            // to reuse the same fixture across the matrix; it does not
            // claim that combination is production-reachable.
        }
    }

    #[test]
    fn no_inclusion_field_is_derived_from_aggregate_is_valid() {
        // Direct regression test for the root cause: build two otherwise
        // identical results that differ ONLY in `core_result.is_valid`, and
        // assert every `*inclusion*` field in the JSON output is unchanged.
        // If any of them were still wired to the aggregate, this would fail.
        use crate::cli::VerificationMode;

        let mut valid_core = real_unanchored_core_result();
        valid_core.is_valid = true;

        let mut invalid_core = real_unanchored_core_result();
        invalid_core.is_valid = false;

        let valid_result = single_result_with(valid_core, create_test_receipt());
        let invalid_result = single_result_with(invalid_core, create_test_receipt());

        let valid_json = serde_json::to_value(build_single_result_json(
            &valid_result,
            VerificationMode::Offline,
        ))
        .unwrap();
        let invalid_json = serde_json::to_value(build_single_result_json(
            &invalid_result,
            VerificationMode::Offline,
        ))
        .unwrap();

        assert_eq!(
            valid_json["verification"]["inclusion_valid"],
            invalid_json["verification"]["inclusion_valid"]
        );
        assert_eq!(
            valid_json["verification"]["super_inclusion_valid"],
            invalid_json["verification"]["super_inclusion_valid"]
        );
        assert_eq!(
            valid_json["verification"]["super_consistency_valid"],
            invalid_json["verification"]["super_consistency_valid"]
        );
    }
}
