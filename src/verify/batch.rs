//! Batch/directory verification logic

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use atl_core::TrustStore;

use crate::error::{CliError, CliResult};
use crate::verify::consistency::{verify_consistency, ConsistencyResult};
use crate::verify::single::{verify_single, SingleVerificationResult};
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Result of a single file in batch mode
#[derive(Debug)]
pub enum BatchItemResult {
    /// Verification succeeded (including unanchored Receipt-Lite items,
    /// which carry [`Status::Pending`])
    Valid(SingleVerificationResult),
    /// Nothing refuted, but the item's anchors did not reach a configured
    /// trust root
    Untrusted(SingleVerificationResult),
    /// Verification failed (cryptographic or hash)
    Invalid(SingleVerificationResult),
    /// Error during verification
    Error {
        source: PathBuf,
        #[allow(dead_code)]
        receipt: Option<PathBuf>,
        error: CliError,
    },
    /// No receipt found for file
    NoReceipt(PathBuf),
    /// No source file found for receipt
    NoSource(PathBuf),
}

/// Result of batch verification
#[derive(Debug)]
pub struct BatchVerificationResult {
    /// Individual results for each file
    pub items: Vec<BatchItemResult>,
    /// Log consistency result (if enough valid receipts)
    pub consistency: Option<ConsistencyResult>,
    /// Count of valid files
    pub valid_count: usize,
    /// Count of files whose anchors reached no configured trust root
    pub untrusted_count: usize,
    /// Count of invalid files
    pub invalid_count: usize,
    /// Count of errors
    pub error_count: usize,
    /// Count of unmatched items
    pub unmatched_count: usize,
}

impl BatchVerificationResult {
    /// The batch's aggregate verdict, derived from the same per-receipt
    /// classification every item used — never re-derived here.
    ///
    /// A single refuted item makes the whole batch refuted. Failing that, a
    /// single item lacking trust material makes the batch untrusted: a batch
    /// is only accepted when every item was accepted.
    #[must_use]
    pub fn verdict(&self) -> ReceiptVerdict {
        if self.invalid_count > 0 || self.error_count > 0 {
            return ReceiptVerdict::invalid(ReasonCode::BatchItemsInvalid);
        }
        if self.consistency.as_ref().is_some_and(|c| !c.is_valid()) {
            return ReceiptVerdict::invalid(ReasonCode::LogConsistencyFailed);
        }
        if self.untrusted_count > 0 {
            return ReceiptVerdict::untrusted(ReasonCode::BatchItemsUntrusted);
        }
        ReceiptVerdict::VALID
    }

    /// Check if overall batch is valid (all files valid + consistent)
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; kept as the readable predicate
    pub fn is_valid(&self) -> bool {
        matches!(self.verdict().status, Status::Valid | Status::Pending)
    }

    /// Re-bucket every verified item and recompute the counts from each
    /// item's current [`SingleVerificationResult::verdict`].
    ///
    /// Called after the online pass has upgraded `bitcoin_ots` anchors in
    /// place: an item that was `Untrusted` only because no block had been
    /// fetched becomes `Valid` (or `Invalid`) once it has been. `error_count`
    /// and the unmatched items are untouched -- going online cannot change
    /// whether a file could be read or matched.
    pub fn reclassify(&mut self) {
        let mut valid_count = 0;
        let mut untrusted_count = 0;
        let mut invalid_count = 0;

        let items = std::mem::take(&mut self.items);
        self.items = items
            .into_iter()
            .map(|item| match item {
                BatchItemResult::Valid(result)
                | BatchItemResult::Untrusted(result)
                | BatchItemResult::Invalid(result) => match result.verdict().status {
                    Status::Valid | Status::Pending => {
                        valid_count += 1;
                        BatchItemResult::Valid(result)
                    }
                    Status::Untrusted => {
                        untrusted_count += 1;
                        BatchItemResult::Untrusted(result)
                    }
                    Status::Invalid => {
                        invalid_count += 1;
                        BatchItemResult::Invalid(result)
                    }
                },
                other => other,
            })
            .collect();

        self.valid_count = valid_count;
        self.untrusted_count = untrusted_count;
        self.invalid_count = invalid_count;
    }
}

/// Match files to receipts by name pattern
///
/// # Matching Rules
///
/// 1. `document.pdf` matches `document.pdf.atl`
/// 2. Exact basename match in different directories
///
/// # Arguments
///
/// * `source_dir` - Directory containing source files
/// * `receipt_dir` - Directory containing .atl receipt files
///
/// # Returns
///
/// Tuple of:
/// - Vector of matched (source, receipt) pairs
/// - Vector of unmatched source files
/// - Vector of unmatched receipt files
///
/// # Errors
///
/// Returns error if:
/// - Directories cannot be read
/// - No files found in source directory
/// - No receipts found in receipt directory
#[allow(clippy::type_complexity)]
pub fn match_files_to_receipts(
    source_dir: &Path,
    receipt_dir: &Path,
) -> CliResult<(Vec<(PathBuf, PathBuf)>, Vec<PathBuf>, Vec<PathBuf>)> {
    // Scan source directory for files
    let source_files: Vec<PathBuf> = std::fs::read_dir(source_dir)
        .map_err(|e| CliError::file_read_error(source_dir, e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| e.path().extension() != Some(std::ffi::OsStr::new("atl")))
        .map(|e| e.path())
        .collect();

    if source_files.is_empty() {
        return Err(CliError::EmptySourceDirectory(source_dir.to_path_buf()));
    }

    // Scan receipt directory for .atl files
    let receipt_files: Vec<PathBuf> = std::fs::read_dir(receipt_dir)
        .map_err(|e| CliError::file_read_error(receipt_dir, e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("atl")))
        .map(|e| e.path())
        .collect();

    if receipt_files.is_empty() {
        return Err(CliError::EmptyReceiptDirectory(receipt_dir.to_path_buf()));
    }

    // Build receipt lookup by expected source name
    let mut receipt_map: HashMap<String, PathBuf> = HashMap::new();
    for receipt_path in &receipt_files {
        if let Some(name) = receipt_path.file_name() {
            let name_str = name.to_string_lossy();
            if let Some(source_name) = name_str.strip_suffix(".atl") {
                receipt_map.insert(source_name.to_string(), receipt_path.clone());
            }
        }
    }

    // Match files
    let mut matched = Vec::new();
    let mut unmatched_sources = Vec::new();
    let mut used_receipts = HashSet::new();

    for source_path in &source_files {
        if let Some(name) = source_path.file_name() {
            let name_str = name.to_string_lossy().to_string();
            if let Some(receipt_path) = receipt_map.get(&name_str) {
                matched.push((source_path.clone(), receipt_path.clone()));
                used_receipts.insert(receipt_path.clone());
            } else {
                unmatched_sources.push(source_path.clone());
            }
        }
    }

    // Find unmatched receipts
    let unmatched_receipts: Vec<PathBuf> = receipt_files
        .into_iter()
        .filter(|r| !used_receipts.contains(r))
        .collect();

    Ok((matched, unmatched_sources, unmatched_receipts))
}

/// Verify a batch of files
///
/// # Process
///
/// 1. Match files to receipts by name
/// 2. Verify each matched pair individually
/// 3. Collect unmatched files/receipts
/// 4. Verify log consistency across valid receipts (if 2+)
///
/// # Arguments
///
/// * `source_dir` - Directory containing source files
/// * `receipt_dir` - Directory containing .atl receipt files
///
/// # Returns
///
/// Batch verification result with individual and consistency results
///
/// # Errors
///
/// Returns error if:
/// - Directories cannot be read
/// - No files or receipts found
///
/// `trust_store` is forwarded unchanged to every [`verify_single`] call --
/// see its docs for why RFC 3161 trust verification runs even in this
/// (offline) batch path.
pub fn verify_batch(
    source_dir: &Path,
    receipt_dir: &Path,
    trust_store: Option<&TrustStore>,
) -> CliResult<BatchVerificationResult> {
    // Match files to receipts
    let (matched, unmatched_sources, unmatched_receipts) =
        match_files_to_receipts(source_dir, receipt_dir)?;

    let mut items = Vec::new();
    let mut valid_results = Vec::new();
    let mut valid_count = 0;
    let mut untrusted_count = 0;
    let mut invalid_count = 0;
    let mut error_count = 0;

    // Verify each matched pair
    for (source_path, receipt_path) in matched {
        match verify_single(&source_path, &receipt_path, trust_store) {
            Ok(result) => match result.verdict().status {
                Status::Valid | Status::Pending => {
                    valid_count += 1;
                    valid_results.push(result.clone());
                    items.push(BatchItemResult::Valid(result));
                }
                Status::Untrusted => {
                    untrusted_count += 1;
                    // Still a structurally sound receipt from this log, so
                    // it takes part in cross-receipt consistency checking.
                    valid_results.push(result.clone());
                    items.push(BatchItemResult::Untrusted(result));
                }
                Status::Invalid => {
                    invalid_count += 1;
                    items.push(BatchItemResult::Invalid(result));
                }
            },
            Err(e) => {
                error_count += 1;
                items.push(BatchItemResult::Error {
                    source: source_path,
                    receipt: Some(receipt_path),
                    error: e,
                });
            }
        }
    }

    // Add unmatched items
    for source in unmatched_sources {
        items.push(BatchItemResult::NoReceipt(source));
    }
    for receipt in unmatched_receipts {
        items.push(BatchItemResult::NoSource(receipt));
    }

    let unmatched_count = items
        .iter()
        .filter(|i| {
            matches!(
                i,
                BatchItemResult::NoReceipt(_) | BatchItemResult::NoSource(_)
            )
        })
        .count();

    // Verify log consistency if we have 2+ valid receipts
    let consistency = if valid_results.len() >= 2 {
        Some(verify_consistency(&valid_results)?)
    } else {
        None
    };

    Ok(BatchVerificationResult {
        items,
        consistency,
        valid_count,
        untrusted_count,
        invalid_count,
        error_count,
        unmatched_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_match_files_to_receipts() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        // Create test files
        std::fs::write(source_dir.path().join("doc1.pdf"), b"content1").unwrap();
        std::fs::write(source_dir.path().join("doc2.pdf"), b"content2").unwrap();
        std::fs::write(receipt_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();
        // doc2.pdf has no receipt

        let (matched, unmatched_src, unmatched_rcpt) =
            match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(matched.len(), 1);
        assert_eq!(unmatched_src.len(), 1);
        assert_eq!(unmatched_rcpt.len(), 0);
    }

    #[test]
    fn test_match_empty_source_directory() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();
        std::fs::write(receipt_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();

        let result = match_files_to_receipts(source_dir.path(), receipt_dir.path());
        assert!(matches!(result, Err(CliError::EmptySourceDirectory(_))));
    }

    #[test]
    fn test_match_empty_receipt_directory() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("doc1.pdf"), b"content1").unwrap();

        let result = match_files_to_receipts(source_dir.path(), receipt_dir.path());
        assert!(matches!(result, Err(CliError::EmptyReceiptDirectory(_))));
    }

    #[test]
    fn test_match_ignores_atl_files_in_source() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        std::fs::write(source_dir.path().join("doc1.pdf"), b"content1").unwrap();
        std::fs::write(source_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();
        std::fs::write(receipt_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();

        let (matched, _, _) =
            match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn test_batch_verification_result_is_valid() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 5,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
        };
        assert!(result.is_valid());
    }

    #[test]
    fn test_batch_verification_result_invalid_count() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 3,
            untrusted_count: 0,
            invalid_count: 2,
            error_count: 0,
            unmatched_count: 0,
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_batch_verification_result_error_count() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 3,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 1,
            unmatched_count: 0,
        };
        assert!(!result.is_valid());
    }
}
