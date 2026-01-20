//! Human-readable output formatting

use colored::Colorize;

use crate::error::CliResult;
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::consistency::ConsistencyResult;
use crate::verify::online::{AnchorDetails, OnlineVerificationResult};
use crate::verify::single::SingleVerificationResult;

/// Print single file result
pub fn print_single_result(result: &SingleVerificationResult, use_color: bool) -> CliResult<()> {
    println!("Verification Result");
    println!("===================");
    println!();

    // File info
    println!("File: {}", result.source_path.display());
    println!("Receipt: {}", result.receipt_path.display());

    // Status - handle lite receipt case (check lite first!)
    print!("Status: ");
    if result.is_lite_valid() {
        print_status_pending("PENDING (unanchored)", use_color);
    } else if result.is_valid() {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    // File hash comparison
    println!("File Hash:");
    println!("  Computed: {}", format_hash(&result.file_hash));
    println!("  Expected: {}", &result.receipt.entry.payload_hash);
    print!("  Match: ");
    if result.file_hash_valid {
        print_status("YES", true, use_color);
    } else {
        print_status("NO", false, use_color);
    }
    println!();

    // If hash doesn't match, show explanation and stop
    if !result.file_hash_valid {
        println!();
        println!("The file content does not match the receipt.");
        println!("The file may have been modified since the receipt was issued.");
        return Ok(());
    }

    // Receipt verification details
    println!("Receipt Verification:");
    println!("  Entry ID: {}", result.receipt.entry.id);

    // Inclusion proof - account for super_proof being None
    print!("  Inclusion Proof: ");
    let proofs_valid = if result.receipt.super_proof.is_some() {
        result.core_result.inclusion_valid
            && result.core_result.super_inclusion_valid
            && result.core_result.super_consistency_valid
    } else {
        // No super_proof = only check basic inclusion
        result.core_result.inclusion_valid
    };
    if proofs_valid {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    // Anchor status for lite receipts
    if result.is_lite_valid() {
        print!("  Anchor Status: ");
        print_status_pending("UNANCHORED", use_color);
        println!();
        println!(
            "Note: This receipt is cryptographically valid but lacks external timestamp anchors."
        );
        println!("      Request an upgraded receipt with TSA or Bitcoin anchoring for independent verification.");
    }

    // Errors (excluding NoTrustAnchor for lite receipts)
    let errors: Vec<_> = result
        .core_result
        .errors
        .iter()
        .filter(|e| {
            !matches!(e, atl_core::VerificationError::NoTrustAnchor) || !result.is_lite_valid()
        })
        .collect();

    if !errors.is_empty() {
        println!();
        println!("Errors:");
        for err in errors {
            println!("  - {err:?}");
        }
    }

    Ok(())
}

/// Print batch result
pub fn print_batch_result(result: &BatchVerificationResult, use_color: bool) -> CliResult<()> {
    println!("Batch Verification Summary");
    println!("==========================");
    println!();

    // Summary
    let total =
        result.valid_count + result.invalid_count + result.error_count + result.unmatched_count;
    println!("Files: {total} total");
    println!();

    println!("Results:");
    print!("  Valid:     ");
    print_count(result.valid_count, result.valid_count > 0, use_color);
    print!("  Invalid:   ");
    print_count(result.invalid_count, result.invalid_count == 0, use_color);
    print!("  Errors:    ");
    print_count(result.error_count, result.error_count == 0, use_color);
    print!("  Unmatched: ");
    println!("{}", result.unmatched_count);
    println!();

    // Consistency
    if let Some(consistency) = &result.consistency {
        print_consistency(consistency, use_color);
    }

    // Individual results
    println!("Individual Results:");
    println!("------------------");
    println!();

    for (i, item) in result.items.iter().enumerate() {
        print_batch_item(i + 1, item, use_color);
    }

    // Overall status
    print!("Overall: ");
    if result.is_valid() {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    Ok(())
}

fn print_consistency(consistency: &ConsistencyResult, use_color: bool) {
    print!("Log Consistency: ");
    if consistency.is_valid() {
        print_status(
            &format!("VERIFIED ({} receipts)", consistency.receipt_count),
            true,
            use_color,
        );
        if let Some(genesis) = &consistency.genesis_super_root {
            println!("  Genesis: {}", format_hash(genesis));
        }
        println!("  All receipts from same log instance");
    } else {
        print_status("FAILED", false, use_color);
        for err in &consistency.errors {
            println!("  Error: {err}");
        }
    }
    println!();
}

fn print_batch_item(index: usize, item: &BatchItemResult, use_color: bool) {
    match item {
        BatchItemResult::Valid(result) => {
            println!(
                "[{index}] {}",
                result
                    .source_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            print!("    Status: ");
            print_status("VALID", true, use_color);
        }
        BatchItemResult::Invalid(result) => {
            println!(
                "[{index}] {}",
                result
                    .source_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            print!("    Status: ");
            print_status("INVALID", false, use_color);
            if !result.file_hash_valid {
                println!("    Error: File hash mismatch");
            }
        }
        BatchItemResult::Error { source, error, .. } => {
            println!(
                "[{index}] {}",
                source.file_name().unwrap_or_default().to_string_lossy()
            );
            print!("    Status: ");
            print_status("ERROR", false, use_color);
            println!("    Error: {error}");
        }
        BatchItemResult::NoReceipt(path) => {
            println!(
                "[{index}] {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            print!("    Status: ");
            if use_color {
                println!("{}", "NO RECEIPT".yellow());
            } else {
                println!("NO RECEIPT");
            }
        }
        BatchItemResult::NoSource(path) => {
            println!(
                "[{index}] {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            print!("    Status: ");
            if use_color {
                println!("{}", "NO SOURCE FILE".yellow());
            } else {
                println!("NO SOURCE FILE");
            }
        }
    }
    println!();
}

fn print_status(text: &str, is_success: bool, use_color: bool) {
    if use_color {
        if is_success {
            println!("{}", text.green().bold());
        } else {
            println!("{}", text.red().bold());
        }
    } else {
        println!("{text}");
    }
}

fn print_status_pending(text: &str, use_color: bool) {
    if use_color {
        println!("{}", text.yellow().bold());
    } else {
        println!("{text}");
    }
}

fn print_count(count: usize, is_good: bool, use_color: bool) {
    if use_color {
        if is_good {
            println!("{}", count.to_string().green());
        } else {
            println!("{}", count.to_string().red());
        }
    } else {
        println!("{count}");
    }
}

fn format_hash(hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash))
}

/// Print single file result with online anchor verification
pub fn print_single_online_result(
    result: &OnlineVerificationResult,
    use_color: bool,
) -> CliResult<()> {
    println!("Verification Result");
    println!("===================");
    println!();

    // File info
    println!("File: {}", result.offline.source_path.display());
    println!("Receipt: {}", result.offline.receipt_path.display());

    // Status
    print!("Status: ");
    if result.is_valid() {
        print_status("VALID", true, use_color);
    } else if result.offline.is_lite_valid() {
        print_status_pending("PENDING (unanchored)", use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    // File hash comparison
    println!("File Hash:");
    println!("  Computed: {}", format_hash(&result.offline.file_hash));
    println!("  Expected: {}", &result.offline.receipt.entry.payload_hash);
    print!("  Match: ");
    if result.offline.file_hash_valid {
        print_status("YES", true, use_color);
    } else {
        print_status("NO", false, use_color);
    }
    println!();

    // If hash doesn't match, show explanation and stop
    if !result.offline.file_hash_valid {
        println!();
        println!("The file content does not match the receipt.");
        println!("The file may have been modified since the receipt was issued.");
        return Ok(());
    }

    // Receipt verification details
    println!("Receipt Verification:");
    println!("  Entry ID: {}", result.offline.receipt.entry.id);

    // Inclusion proof
    print!("  Inclusion Proof: ");
    let proofs_valid = result.offline.core_result.inclusion_valid;
    if proofs_valid {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    // Anchor verification results
    if !result.anchor_results.is_empty() {
        println!("Anchor Verification:");
        for (i, anchor) in result.anchor_results.iter().enumerate() {
            println!("  [{}] {}", i + 1, format_anchor_type(&anchor.anchor_type));
            print!("      Status: ");
            if anchor.verified {
                print_status("VALID", true, use_color);
            } else {
                print_status("FAILED", false, use_color);
            }

            if let Some(error) = &anchor.error {
                println!("      Error: {error}");
            }

            match &anchor.details {
                AnchorDetails::Rfc3161 { .. } => {
                    if let Some(ts) = anchor.timestamp_nanos {
                        println!("      Timestamp: {}", format_timestamp_nanos(ts));
                    }
                }
                AnchorDetails::Bitcoin {
                    block_height,
                    block_timestamp_secs,
                    target_hash,
                    operation_count,
                    computed_root,
                    block_merkle_root,
                    merkle_match,
                } => {
                    println!();
                    println!("      Verification Chain:");
                    println!("        Target Hash:       {}", target_hash);
                    println!("              ↓ OTS proof ({} operations)", operation_count);
                    println!("        Computed Root:     {}", computed_root);

                    match (block_merkle_root, merkle_match) {
                        (Some(block_root), Some(true)) => {
                            // Online mode, match
                            if use_color {
                                println!("              {} (verified)", "✓".green());
                            } else {
                                println!("              ✓ (verified)");
                            }
                            println!("        Block Merkle Root: {}", block_root);
                        }
                        (Some(block_root), Some(false)) => {
                            // Online mode, mismatch
                            if use_color {
                                println!("              {} (mismatch)", "✗".red().bold());
                            } else {
                                println!("              ✗ (mismatch)");
                            }
                            println!("        Block Merkle Root: {}", block_root);
                        }
                        (None, None) => {
                            // Offline mode or API error
                            if use_color {
                                println!("              {} (not verified)", "?".yellow());
                            } else {
                                println!("              ? (not verified)");
                            }
                        }
                        _ => {}
                    }

                    println!("              ↓");
                    if *block_timestamp_secs > 0 {
                        println!(
                            "        Block #{} @ {}",
                            block_height,
                            format_timestamp_secs(*block_timestamp_secs)
                        );
                    } else {
                        println!("        Block #{}", block_height);
                    }
                }
                AnchorDetails::Unknown => {}
            }
        }
    }

    Ok(())
}

fn format_anchor_type(anchor_type: &str) -> &str {
    match anchor_type {
        "rfc3161" => "RFC 3161 (TSA)",
        "bitcoin_ots" => "Bitcoin OTS",
        _ => anchor_type,
    }
}

fn format_timestamp_nanos(nanos: u64) -> String {
    use chrono::{TimeZone, Utc};
    let secs = i64::try_from(nanos / 1_000_000_000).unwrap_or(i64::MAX);
    Utc.timestamp_opt(secs, 0).single().map_or_else(
        || format!("{nanos} ns"),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

fn format_timestamp_secs(secs: u64) -> String {
    use chrono::{TimeZone, Utc};
    let secs_i64 = i64::try_from(secs).unwrap_or(i64::MAX);
    Utc.timestamp_opt(secs_i64, 0).single().map_or_else(
        || format!("{secs} s"),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
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
    fn test_print_single_result_valid_with_color() {
        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_single_result_valid_no_color() {
        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_single_result_invalid() {
        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(false),
        };

        assert!(print_single_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_single_result_hash_mismatch() {
        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_color() {
        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_batch_result_no_color() {
        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_failures() {
        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 1,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_consistency_valid() {
        use crate::verify::consistency::ConsistencyResult;

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

        assert!(print_batch_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_consistency_failed() {
        use crate::verify::consistency::ConsistencyResult;

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

        assert!(print_batch_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_batch_all_item_types() {
        use crate::error::CliError;

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

        assert!(print_batch_result(&result, true).is_ok());
        assert!(print_batch_result(&result, false).is_ok());
    }

    #[test]
    fn test_format_hash() {
        let hash = [0xab; 32];
        let formatted = format_hash(&hash);
        assert!(formatted.starts_with("sha256:"));
        assert!(!formatted.ends_with("...")); // No truncation
        assert_eq!(formatted.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_print_status_success_with_color() {
        print_status("VALID", true, true);
    }

    #[test]
    fn test_print_status_failure_with_color() {
        print_status("INVALID", false, true);
    }

    #[test]
    fn test_print_status_no_color() {
        print_status("VALID", true, false);
        print_status("INVALID", false, false);
    }

    #[test]
    fn test_print_count_with_color() {
        print_count(5, true, true);
        print_count(0, false, true);
    }

    #[test]
    fn test_print_count_no_color() {
        print_count(5, true, false);
        print_count(0, false, false);
    }

    #[test]
    fn test_print_consistency_verified() {
        use crate::verify::consistency::ConsistencyResult;

        let consistency = ConsistencyResult {
            genesis_super_root: Some([0xaa; 32]),
            receipt_count: 5,
            same_log: true,
            history_consistent: true,
            cross_results: vec![],
            errors: vec![],
        };

        print_consistency(&consistency, true);
        print_consistency(&consistency, false);
    }

    #[test]
    fn test_print_consistency_failed() {
        use crate::verify::consistency::ConsistencyResult;

        let consistency = ConsistencyResult {
            genesis_super_root: None,
            receipt_count: 5,
            same_log: false,
            history_consistent: false,
            cross_results: vec![],
            errors: vec!["Error 1".to_string(), "Error 2".to_string()],
        };

        print_consistency(&consistency, true);
        print_consistency(&consistency, false);
    }

    #[test]
    fn test_print_batch_item_valid() {
        let item = BatchItemResult::Valid(SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        });

        print_batch_item(1, &item, true);
        print_batch_item(1, &item, false);
    }

    #[test]
    fn test_print_batch_item_invalid() {
        let item = BatchItemResult::Invalid(SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(false),
        });

        print_batch_item(1, &item, true);
        print_batch_item(1, &item, false);
    }

    #[test]
    fn test_print_batch_item_error() {
        use crate::error::CliError;

        let item = BatchItemResult::Error {
            source: PathBuf::from("test.pdf"),
            receipt: Some(PathBuf::from("test.pdf.atl")),
            error: CliError::SourceNotFound(PathBuf::from("test.pdf")),
        };

        print_batch_item(1, &item, true);
        print_batch_item(1, &item, false);
    }

    #[test]
    fn test_print_batch_item_no_receipt() {
        let item = BatchItemResult::NoReceipt(PathBuf::from("test.pdf"));

        print_batch_item(1, &item, true);
        print_batch_item(1, &item, false);
    }

    #[test]
    fn test_print_batch_item_no_source() {
        let item = BatchItemResult::NoSource(PathBuf::from("test.pdf.atl"));

        print_batch_item(1, &item, true);
        print_batch_item(1, &item, false);
    }

    #[test]
    fn test_print_single_online_result_valid_with_color() {
        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_single_online_result_with_rfc3161_anchor() {
        use crate::verify::online::{AnchorDetails, AnchorVerificationResult};

        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let anchor = AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: true,
            timestamp_nanos: Some(1700000000000000000),
            error: None,
            details: AnchorDetails::Rfc3161 {
                algorithm_oid: "2.16.840.1.101.3.4.2.1".to_string(),
            },
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![anchor],
            all_anchors_verified: true,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
        assert!(print_single_online_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_single_online_result_with_bitcoin_anchor_verified() {
        use crate::verify::online::{AnchorDetails, AnchorVerificationResult};

        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: true,
            timestamp_nanos: Some(1700000000000000000),
            error: None,
            details: AnchorDetails::Bitcoin {
                block_height: 800000,
                block_timestamp_secs: 1700000000,
                target_hash: "sha256:abc123".to_string(),
                operation_count: 39,
                computed_root: "sha256:def456".to_string(),
                block_merkle_root: Some("sha256:def456".to_string()),
                merkle_match: Some(true),
            },
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![anchor],
            all_anchors_verified: true,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
        assert!(print_single_online_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_single_online_result_with_bitcoin_anchor_mismatch() {
        use crate::verify::online::{AnchorDetails, AnchorVerificationResult};

        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("Merkle root mismatch".to_string()),
            details: AnchorDetails::Bitcoin {
                block_height: 800000,
                block_timestamp_secs: 1700000000,
                target_hash: "sha256:abc123".to_string(),
                operation_count: 39,
                computed_root: "sha256:def456".to_string(),
                block_merkle_root: Some("sha256:wrong789".to_string()),
                merkle_match: Some(false),
            },
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![anchor],
            all_anchors_verified: false,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
        assert!(print_single_online_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_single_online_result_with_bitcoin_anchor_offline() {
        use crate::verify::online::{AnchorDetails, AnchorVerificationResult};

        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("API error".to_string()),
            details: AnchorDetails::Bitcoin {
                block_height: 800000,
                block_timestamp_secs: 0,
                target_hash: "sha256:abc123".to_string(),
                operation_count: 39,
                computed_root: "sha256:def456".to_string(),
                block_merkle_root: None,
                merkle_match: None,
            },
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![anchor],
            all_anchors_verified: false,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
        assert!(print_single_online_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_single_online_result_with_unknown_anchor() {
        use crate::verify::online::{AnchorDetails, AnchorVerificationResult};

        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let anchor = AnchorVerificationResult {
            anchor_type: "unknown".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("Unknown anchor type".to_string()),
            details: AnchorDetails::Unknown,
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![anchor],
            all_anchors_verified: false,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
    }

    #[test]
    fn test_print_single_online_result_hash_mismatch() {
        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, false).is_ok());
    }

    #[test]
    fn test_print_single_online_result_lite_pending() {
        let mut offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };
        // Empty anchors for lite receipt
        offline.receipt.anchors = vec![];

        let result = OnlineVerificationResult {
            offline,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: crate::cli::VerificationMode::Online,
        };

        assert!(print_single_online_result(&result, true).is_ok());
    }

    #[test]
    fn test_format_anchor_type() {
        assert_eq!(format_anchor_type("rfc3161"), "RFC 3161 (TSA)");
        assert_eq!(format_anchor_type("bitcoin_ots"), "Bitcoin OTS");
        assert_eq!(format_anchor_type("other"), "other");
    }

    #[test]
    fn test_format_timestamp_nanos() {
        // Valid timestamp
        let ts = format_timestamp_nanos(1700000000000000000);
        assert!(ts.contains("2023"));

        // Zero timestamp
        let ts_zero = format_timestamp_nanos(0);
        assert_eq!(ts_zero, "1970-01-01T00:00:00Z");

        // Very large timestamp - when divided by 1B becomes i64::MAX
        // chrono::Utc.timestamp_opt() returns None for out-of-range values
        let ts_large = format_timestamp_nanos(u64::MAX);
        // Should contain either valid date or fallback format with "ns"
        assert!(ts_large.contains("ns") || ts_large.contains("Z"));
    }

    #[test]
    fn test_format_timestamp_secs() {
        // Valid timestamp
        let ts = format_timestamp_secs(1700000000);
        assert!(ts.contains("2023"));

        // Zero timestamp
        let ts_zero = format_timestamp_secs(0);
        assert_eq!(ts_zero, "1970-01-01T00:00:00Z");

        // Very large invalid timestamp
        let ts_large = format_timestamp_secs(u64::MAX);
        assert!(ts_large.contains(" s"));
    }

    #[test]
    fn test_print_status_pending_with_color() {
        print_status_pending("PENDING", true);
    }

    #[test]
    fn test_print_status_pending_no_color() {
        print_status_pending("PENDING", false);
    }
}
