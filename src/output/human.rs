//! Human-readable output formatting

use colored::Colorize;

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::consistency::ConsistencyResult;
use crate::verify::single::SingleVerificationResult;

/// Print single file result
pub fn print_single_result(
    result: &SingleVerificationResult,
    use_color: bool,
    mode: VerificationMode,
) -> CliResult<()> {
    println!("Verification Result");
    println!("===================");
    println!();

    // Mode indicator
    println!(
        "Mode: {}",
        match mode {
            VerificationMode::Online => "ONLINE",
            VerificationMode::Offline => "OFFLINE",
        }
    );

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
    println!();

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
    println!();
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
        println!();
        println!("Note: This receipt is cryptographically valid but lacks external timestamp anchors.");
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
pub fn print_batch_result(
    result: &BatchVerificationResult,
    use_color: bool,
    mode: VerificationMode,
) -> CliResult<()> {
    println!("Batch Verification Summary");
    println!("==========================");
    println!();

    println!(
        "Mode: {}",
        match mode {
            VerificationMode::Online => "ONLINE",
            VerificationMode::Offline => "OFFLINE",
        }
    );

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
    println!();
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
        use crate::cli::VerificationMode;

        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, true, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_single_result_valid_no_color() {
        use crate::cli::VerificationMode;

        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(true),
        };

        assert!(print_single_result(&result, false, VerificationMode::Offline).is_ok());
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

        assert!(print_single_result(&result, true, VerificationMode::Offline).is_ok());
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

        assert!(print_single_result(&result, false, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_color() {
        use crate::cli::VerificationMode;

        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, true, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_no_color() {
        use crate::cli::VerificationMode;

        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, false, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_failures() {
        use crate::cli::VerificationMode;

        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 1,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, true, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_consistency_valid() {
        use crate::cli::VerificationMode;
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

        assert!(print_batch_result(&result, true, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_consistency_failed() {
        use crate::cli::VerificationMode;
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

        assert!(print_batch_result(&result, false, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_all_item_types() {
        use crate::cli::VerificationMode;
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

        assert!(print_batch_result(&result, true, VerificationMode::Offline).is_ok());
        assert!(print_batch_result(&result, false, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_format_hash() {
        let hash = [0xab; 32];
        let formatted = format_hash(&hash);
        assert!(formatted.starts_with("sha256:"));
        assert!(!formatted.ends_with("...")); // No truncation
        assert_eq!(formatted.len(), 7 + 64);  // "sha256:" + 64 hex chars
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
}
