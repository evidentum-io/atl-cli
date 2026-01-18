//! Single file verification logic

use std::path::Path;

use atl_core::{verify_receipt_anchor_only, Receipt, VerificationResult};

use crate::error::{CliError, CliResult};
use crate::verify::file::{compare_hash, format_hash, hash_file, MAX_RECEIPT_SIZE};

/// Result of single file verification
#[derive(Debug, Clone)]
pub struct SingleVerificationResult {
    /// Path to source file
    pub source_path: std::path::PathBuf,
    /// Path to receipt file
    pub receipt_path: std::path::PathBuf,
    /// Computed file hash
    pub file_hash: [u8; 32],
    /// The parsed receipt
    pub receipt: Receipt,
    /// File hash matches payload_hash
    pub file_hash_valid: bool,
    /// Core verification result from atl-core
    pub core_result: VerificationResult,
}

impl SingleVerificationResult {
    /// Check if all verifications passed
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.file_hash_valid && self.core_result.is_valid
    }
}

/// Load a receipt from file
///
/// # Arguments
///
/// * `path` - Path to the .atl receipt file
///
/// # Errors
///
/// Returns error if:
/// - File does not exist
/// - File exceeds size limit (10 MB)
/// - File cannot be parsed as JSON
/// - Receipt version is not 2.x.x
pub fn load_receipt(path: &Path) -> CliResult<Receipt> {
    // Check file exists
    if !path.exists() {
        return Err(CliError::ReceiptNotFound(path.to_path_buf()));
    }

    // Check file size
    let metadata =
        std::fs::metadata(path).map_err(|e| CliError::file_read_error(path, e))?;

    if metadata.len() > MAX_RECEIPT_SIZE {
        return Err(CliError::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
            max_bytes: MAX_RECEIPT_SIZE,
        });
    }

    // Read and parse
    let contents = std::fs::read_to_string(path)
        .map_err(|e| CliError::file_read_error(path, e))?;

    let receipt: Receipt = serde_json::from_str(&contents)
        .map_err(|e| CliError::ReceiptParseError(e.to_string()))?;

    // Validate version
    if !receipt.spec_version.starts_with("2.") {
        return Err(CliError::UnsupportedReceiptVersion {
            version: receipt.spec_version.clone(),
            expected: "2.x.x".to_string(),
        });
    }

    Ok(receipt)
}

/// Verify a single file against its receipt
///
/// Uses ATL Protocol v2.0 anchor-only verification - NO PUBLIC KEY REQUIRED.
/// Trust is established through external anchors (RFC 3161, Bitcoin OTS).
///
/// # Verification Steps
///
/// 1. Load receipt from file
/// 2. Hash the source file (streaming SHA-256)
/// 3. Compare file hash with receipt's payload_hash
/// 4. Verify cryptographic proofs (metadata_hash, Merkle inclusion, Super-Tree)
///
/// # Arguments
///
/// * `source_path` - Path to the source file
/// * `receipt_path` - Path to the .atl receipt file
///
/// # Errors
///
/// Returns error if:
/// - Files cannot be read
/// - Receipt cannot be parsed
/// - File exceeds size limits
pub fn verify_single(
    source_path: &Path,
    receipt_path: &Path,
) -> CliResult<SingleVerificationResult> {
    // Load receipt first (fast fail if invalid)
    let receipt = load_receipt(receipt_path)?;

    // Hash the source file
    let file_hash = hash_file(source_path)?;

    // Compare hash with receipt
    let file_hash_valid = compare_hash(&file_hash, &receipt.entry.payload_hash);

    // Verify cryptographic proofs using anchor-only verification
    // ATL Protocol v2.0: NO PUBLIC KEY REQUIRED - trust from anchors
    let core_result = verify_receipt_anchor_only(&receipt)
        .map_err(|e| CliError::VerificationFailed(e.to_string()))?;

    Ok(SingleVerificationResult {
        source_path: source_path.to_path_buf(),
        receipt_path: receipt_path.to_path_buf(),
        file_hash,
        receipt,
        file_hash_valid,
        core_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_receipt_not_found() {
        let result = load_receipt(Path::new("/nonexistent/receipt.atl"));
        assert!(matches!(result, Err(CliError::ReceiptNotFound(_))));
    }

    // Note: Comprehensive tests with valid receipts are in integration tests
    // Unit tests here focus on error paths only
}
