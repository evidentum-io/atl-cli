//! JSON output formatting

use serde::Serialize;

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

pub fn print_single_result(result: &SingleVerificationResult) -> CliResult<()> {
    let output = SingleResultJson {
        status: if result.is_valid() { "valid" } else { "invalid" },
        mode: "offline",
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

pub fn print_batch_result(result: &BatchVerificationResult) -> CliResult<()> {
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
        status: if result.is_valid() { "valid" } else { "invalid" },
        mode: "offline",
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
