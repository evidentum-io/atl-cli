//! JSON output formatting

use serde::Serialize;

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::single::SingleVerificationResult;

#[derive(Serialize)]
struct SingleResultJson {
    status: &'static str,
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

pub fn print_single_result(
    result: &SingleVerificationResult,
    mode: VerificationMode,
) -> CliResult<()> {
    let output = SingleResultJson {
        status: if result.is_valid() {
            "valid"
        } else {
            "invalid"
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
            Some(VerificationJson {
                entry_id: result.receipt.entry.id.to_string(),
                inclusion_valid: result.core_result.is_valid,
                super_inclusion_valid: result
                    .receipt
                    .super_proof
                    .as_ref()
                    .map(|_| result.core_result.is_valid),
                super_consistency_valid: result
                    .receipt
                    .super_proof
                    .as_ref()
                    .map(|_| result.core_result.is_valid),
            })
        } else {
            None
        },
        anchors: vec![], // Anchors not verified in offline mode
        errors: if !result.is_valid() {
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
}

#[derive(Serialize)]
struct BatchItemJson {
    file: String,
    receipt: Option<String>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn print_batch_result(
    result: &BatchVerificationResult,
    mode: VerificationMode,
) -> CliResult<()> {
    let total =
        result.valid_count + result.invalid_count + result.error_count + result.unmatched_count;

    let consistency = result.consistency.as_ref().map(|c| ConsistencyJson {
        status: if c.is_valid() { "verified" } else { "failed" },
        genesis_super_root: c
            .genesis_super_root
            .map(|h| format!("sha256:{}", hex::encode(h))),
        receipt_count: c.receipt_count,
    });

    let items: Vec<BatchItemJson> = result
        .items
        .iter()
        .map(|item| match item {
            BatchItemResult::Valid(r) => BatchItemJson {
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
                error: None,
            },
            BatchItemResult::Invalid(r) => BatchItemJson {
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
                error: if !r.file_hash_valid {
                    Some("File hash mismatch".to_string())
                } else {
                    None
                },
            },
            BatchItemResult::Error { source, error, .. } => BatchItemJson {
                file: source
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                receipt: None,
                status: "error",
                file_hash_match: None,
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
        source_dir: String::new(), // Would need to be passed in
        receipt_dir: String::new(),
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

        let result = BatchVerificationResult {
            valid_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_with_consistency() {
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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_batch_result_consistency_failed() {
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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_batch_item_valid() {
        use crate::cli::VerificationMode;

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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_batch_item_invalid() {
        use crate::cli::VerificationMode;

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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_batch_item_error() {
        use crate::cli::VerificationMode;
        use crate::error::CliError;

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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_batch_item_no_receipt() {
        use crate::cli::VerificationMode;

        let item = BatchItemResult::NoReceipt(PathBuf::from("test.pdf"));

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 1,
            consistency: None,
            items: vec![item],
        };

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_batch_item_no_source() {
        use crate::cli::VerificationMode;

        let item = BatchItemResult::NoSource(PathBuf::from("test.pdf.atl"));

        let result = BatchVerificationResult {
            valid_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 1,
            consistency: None,
            items: vec![item],
        };

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_batch_mixed_items() {
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

        assert!(print_batch_result(&result, VerificationMode::Offline).is_ok());
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

        let consistency = ConsistencyJson {
            status: "verified",
            genesis_super_root: Some("sha256:abcd".to_string()),
            receipt_count: 10,
        };
        assert!(serde_json::to_string(&consistency).is_ok());

        let batch_item = BatchItemJson {
            file: "test.pdf".to_string(),
            receipt: Some("test.pdf.atl".to_string()),
            status: "valid",
            file_hash_match: Some(true),
            error: None,
        };
        assert!(serde_json::to_string(&batch_item).is_ok());
    }
}
