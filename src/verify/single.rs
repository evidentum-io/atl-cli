//! Single file verification logic

use std::path::Path;

use atl_core::{verify_receipt_anchor_only, Receipt, VerificationResult};

use crate::error::{CliError, CliResult};
use crate::verify::file::{compare_hash, hash_file, MAX_RECEIPT_SIZE};

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
    ///
    /// Verification is valid if:
    /// - File hash matches payload_hash
    /// - Core cryptographic proofs are valid (inclusion, super_proof if present)
    ///
    /// Note: `NoTrustAnchor` error is NOT considered a failure for Receipt-Lite.
    /// This allows verification of receipts without external anchors (offline mode).
    ///
    /// When `super_proof` is None, super proof checks are skipped (nothing to verify).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        use atl_core::VerificationError;

        if !self.file_hash_valid {
            return false;
        }

        // Check if core verification passed
        if self.core_result.is_valid {
            return true;
        }

        // If not valid, check if the only error is NoTrustAnchor
        // In that case, consider it valid for Receipt-Lite (offline) verification
        if self.core_result.errors.len() == 1
            && matches!(
                self.core_result.errors.first(),
                Some(VerificationError::NoTrustAnchor)
            )
        {
            // NoTrustAnchor alone is OK - Receipt-Lite verification passed
            // Check basic inclusion proof
            if !self.core_result.inclusion_valid {
                return false;
            }

            // Super proof checks depend on whether super_proof exists
            // When super_proof is None, atl-core returns super_inclusion_valid=false
            // and super_consistency_valid=false - this is expected, not a failure
            if self.receipt.super_proof.is_some() {
                return self.core_result.super_inclusion_valid
                    && self.core_result.super_consistency_valid;
            }

            // No super_proof = skip super checks
            return true;
        }

        false
    }

    /// Check if this is a valid "lite" receipt (no anchors)
    ///
    /// Returns true if:
    /// - File hash matches
    /// - Basic inclusion proof is valid
    /// - If super_proof exists: super proofs are valid
    /// - If super_proof is None: super proof checks are skipped
    /// - The only "error" is NoTrustAnchor (no external anchors)
    #[must_use]
    pub fn is_lite_valid(&self) -> bool {
        use atl_core::VerificationError;

        if !self.file_hash_valid {
            return false;
        }

        // Basic inclusion proof MUST be valid
        if !self.core_result.inclusion_valid {
            return false;
        }

        // Super proof checks depend on whether super_proof exists
        // When super_proof is None, atl-core returns super_inclusion_valid=false
        // and super_consistency_valid=false - this is expected, not a failure
        if self.receipt.super_proof.is_some() {
            // If super_proof exists, it must be valid
            if !self.core_result.super_inclusion_valid || !self.core_result.super_consistency_valid {
                return false;
            }
        }
        // If super_proof is None, we skip these checks entirely

        // Check if the only "error" is NoTrustAnchor
        self.core_result.errors.len() == 1
            && matches!(
                self.core_result.errors.first(),
                Some(VerificationError::NoTrustAnchor)
            )
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
    let metadata = std::fs::metadata(path).map_err(|e| CliError::file_read_error(path, e))?;

    if metadata.len() > MAX_RECEIPT_SIZE {
        return Err(CliError::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
            max_bytes: MAX_RECEIPT_SIZE,
        });
    }

    // Read and parse
    let contents = std::fs::read_to_string(path).map_err(|e| CliError::file_read_error(path, e))?;

    let receipt: Receipt =
        serde_json::from_str(&contents).map_err(|e| CliError::ReceiptParseError(e.to_string()))?;

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
    fn test_load_receipt_not_found() {
        let result = load_receipt(Path::new("/nonexistent/receipt.atl"));
        assert!(matches!(result, Err(CliError::ReceiptNotFound(_))));
    }

    #[test]
    fn test_single_verification_result_is_valid_true() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: true,
            core_result: create_test_verification_result(true),
        };

        assert!(result.is_valid());
    }

    #[test]
    fn test_single_verification_result_is_valid_false_hash_mismatch() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: false,
            core_result: create_test_verification_result(true),
        };

        assert!(!result.is_valid());
    }

    #[test]
    fn test_single_verification_result_is_valid_false_core_invalid() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: true,
            core_result: create_test_verification_result(false),
        };

        assert!(!result.is_valid());
    }

    #[test]
    fn test_single_verification_result_valid_with_no_trust_anchor() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate NoTrustAnchor scenario
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt,
            file_hash_valid: true,
            core_result,
        };

        // NoTrustAnchor alone should be treated as valid for offline mode
        // when all cryptographic proofs are valid
        assert!(result.is_valid());
    }

    #[test]
    fn test_verify_single_result_clone() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: true,
            core_result: create_test_verification_result(true),
        };

        let cloned = result.clone();
        assert_eq!(result.source_path, cloned.source_path);
        assert_eq!(result.receipt_path, cloned.receipt_path);
        assert_eq!(result.file_hash, cloned.file_hash);
        assert_eq!(result.file_hash_valid, cloned.file_hash_valid);
    }

    #[test]
    fn test_is_lite_valid_true() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate lite receipt condition
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
        };

        assert!(result.is_lite_valid());
        assert!(result.is_valid()); // is_valid() should also return true
    }

    #[test]
    fn test_is_lite_valid_false_hash_mismatch() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate lite receipt with hash mismatch
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false, // Hash mismatch
            receipt,
            core_result,
        };

        assert!(!result.is_lite_valid());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_is_lite_valid_false_proof_failed() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate failed proofs
        core_result.is_valid = false;
        core_result.inclusion_valid = false; // Proof failed
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
        };

        assert!(!result.is_lite_valid());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_is_lite_valid_false_other_errors() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate other errors besides NoTrustAnchor
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::MetadataHashMismatch {
            actual: "sha256:test".to_string(),
            expected: "sha256:expected".to_string(),
        }];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
        };

        assert!(!result.is_lite_valid());
        assert!(!result.is_valid());
    }

    // Note: Comprehensive tests with valid receipts are in integration tests
    // Unit tests here focus on error paths and logic branches
}
