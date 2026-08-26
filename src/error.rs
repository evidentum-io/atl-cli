//! Error types and exit codes for atl-cli
//!
//! Exit codes:
//! - 0 = VALID (verification passed)
//! - 1 = INVALID (verification failed cryptographically)
//! - 2 = ERROR (runtime error)

use std::path::PathBuf;
use thiserror::Error;

/// Exit codes for the CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// All verifications passed
    Valid = 0,
    /// One or more verifications failed (cryptographic/hash failure)
    Invalid = 1,
    /// Runtime error (file not found, parse error, network, etc.)
    Error = 2,
}

impl ExitCode {
    /// Convert to process exit code
    #[must_use]
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Result type alias for CLI operations
#[allow(dead_code)]
pub type CliResult<T> = Result<T, CliError>;

/// CLI error type
#[derive(Debug, Error)]
pub enum CliError {
    // ========================================================================
    // Input Errors (Exit Code 2: ERROR)
    // ========================================================================
    /// Source file not found
    #[error("Source file not found: {0}")]
    SourceNotFound(PathBuf),

    /// Receipt file not found
    #[error("Receipt file not found: {0}")]
    ReceiptNotFound(PathBuf),

    /// Mismatched input types (e.g., file + directory)
    #[error("Mismatched input types: source is {}, receipt is {}",
        if *.source_is_dir { "directory" } else { "file" },
        if *.receipt_is_dir { "directory" } else { "file" }
    )]
    MismatchedInputTypes {
        source_is_dir: bool,
        receipt_is_dir: bool,
    },

    /// Failed to read file
    #[error("Failed to read file '{path}': {message}")]
    FileReadError { path: PathBuf, message: String },

    /// File too large to process
    #[error("File too large: {path} ({size_bytes} bytes, max {max_bytes} bytes)")]
    #[allow(dead_code)]
    FileTooLarge {
        path: PathBuf,
        size_bytes: u64,
        max_bytes: u64,
    },

    // ========================================================================
    // Receipt Parse Errors (Exit Code 2: ERROR)
    // ========================================================================
    /// Receipt JSON parse error
    #[error("Failed to parse receipt: {0}")]
    #[allow(dead_code)]
    ReceiptParseError(String),

    /// Invalid receipt format/structure
    #[error("Invalid receipt format: {0}")]
    InvalidReceiptFormat(String),

    /// Unsupported receipt version
    #[error("Unsupported receipt version: {version} (expected {expected})")]
    UnsupportedReceiptVersion { version: String, expected: String },

    // ========================================================================
    // Verification Failures (Exit Code 1: INVALID)
    // ========================================================================
    /// File hash does not match receipt's payload_hash
    #[error("File hash mismatch: file has changed since receipt was issued")]
    #[allow(dead_code)]
    FileHashMismatch {
        /// Path to the source file
        file_path: PathBuf,
        /// Hash computed from the current file
        computed_hash: String,
        /// Hash stored in the receipt
        expected_hash: String,
    },

    /// Metadata hash mismatch
    #[error("Metadata hash mismatch in receipt")]
    #[allow(dead_code)]
    MetadataHashMismatch { expected: String, actual: String },

    /// Merkle inclusion proof failed
    #[error("Merkle inclusion proof failed: {reason}")]
    #[allow(dead_code)]
    InclusionProofFailed { reason: String },

    /// Checkpoint signature verification failed
    #[error("Checkpoint signature verification failed")]
    #[allow(dead_code)]
    SignatureVerificationFailed,

    /// Super-Tree inclusion proof failed
    #[error("Super-Tree inclusion proof failed: {reason}")]
    #[allow(dead_code)]
    SuperInclusionFailed { reason: String },

    /// Super-Tree consistency proof failed
    #[error("Super-Tree consistency to origin failed: {reason}")]
    #[allow(dead_code)]
    SuperConsistencyFailed { reason: String },

    /// Generic verification failure (wraps atl-core errors)
    #[error("Verification failed: {0}")]
    #[allow(dead_code)]
    VerificationFailed(String),

    // ========================================================================
    // Batch Mode Errors (Exit Codes vary)
    // ========================================================================
    /// No matching receipt found for file (Exit Code 2 if critical, or just warning)
    #[error("No receipt found for file: {0}")]
    #[allow(dead_code)]
    NoReceiptForFile(PathBuf),

    /// No matching source file found for receipt
    #[error("No source file found for receipt: {0}")]
    #[allow(dead_code)]
    NoFileForReceipt(PathBuf),

    /// No files found in source directory
    #[error("No files found in directory: {0}")]
    #[allow(dead_code)]
    EmptySourceDirectory(PathBuf),

    /// No receipts found in receipt directory
    #[error("No receipts found in directory: {0}")]
    #[allow(dead_code)]
    EmptyReceiptDirectory(PathBuf),

    /// Batch verification had failures (Exit Code 1)
    #[error("Batch verification failed: {valid_count} valid, {invalid_count} invalid, {error_count} errors")]
    #[allow(dead_code)]
    BatchVerificationFailed {
        valid_count: usize,
        invalid_count: usize,
        error_count: usize,
    },

    // ========================================================================
    // Consistency Errors (Exit Code 1: INVALID)
    // ========================================================================
    /// Receipts have different genesis (from different logs)
    #[error(
        "Log consistency failed: receipts are from different logs (different genesis_super_root)"
    )]
    #[allow(dead_code)]
    DifferentLogOrigins {
        /// First receipt's genesis
        genesis_a: String,
        /// Second receipt's genesis (different)
        genesis_b: String,
    },

    /// Tree size anomaly detected
    #[error("Log consistency failed: tree size anomaly detected (potential log tampering)")]
    #[allow(dead_code)]
    TreeSizeAnomaly {
        /// Description of the anomaly
        description: String,
    },

    /// Cross-receipt consistency proof failed
    #[error("Log consistency failed: consistency proof verification failed")]
    #[allow(dead_code)]
    ConsistencyProofFailed { reason: String },

    // ========================================================================
    // Network Errors (Exit Code 2: ERROR)
    // ========================================================================
    /// No internet connection (when --online flag used)
    #[error("No internet connection (--online mode requires network access)")]
    #[allow(dead_code)]
    NoInternetConnection,

    /// Network request failed
    #[error("Network request failed: {0}")]
    #[allow(dead_code)]
    NetworkError(String),

    /// TSA verification failed (online)
    #[error("TSA verification failed: {0}")]
    #[allow(dead_code)]
    TsaVerificationFailed(String),

    /// Bitcoin/OTS verification failed (online)
    #[error("Bitcoin/OTS verification failed: {0}")]
    #[allow(dead_code)]
    OtsVerificationFailed(String),

    /// Failed to load `--tsa-trust-store` material (bad path or unparsable
    /// certificate)
    #[error("Failed to load TSA trust store: {0}")]
    TrustStoreError(String),

    /// No trust anchor available (ATL Protocol v2.0)
    ///
    /// Per ATL Protocol v2.0, trust is established through external anchors
    /// (RFC 3161 TSA or Bitcoin OTS). This error indicates that:
    /// - No valid external anchors were found/verified
    /// - Signature was not verified (no key provided or signature invalid)
    ///
    /// In offline mode, this is expected if anchors require online verification.
    /// Use online mode to verify anchors.
    #[error("No trust anchor available (no verified signature or valid external anchors)")]
    #[allow(dead_code)]
    NoTrustAnchor,

    // ========================================================================
    // Internal Errors (Exit Code 2: ERROR)
    // ========================================================================
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

impl CliError {
    /// Get the appropriate exit code for this error
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            // Verification failures -> INVALID (exit 1)
            Self::FileHashMismatch { .. }
            | Self::MetadataHashMismatch { .. }
            | Self::InclusionProofFailed { .. }
            | Self::SignatureVerificationFailed
            | Self::SuperInclusionFailed { .. }
            | Self::SuperConsistencyFailed { .. }
            | Self::VerificationFailed(_)
            | Self::BatchVerificationFailed { .. }
            | Self::DifferentLogOrigins { .. }
            | Self::TreeSizeAnomaly { .. }
            | Self::ConsistencyProofFailed { .. }
            | Self::TsaVerificationFailed(_)
            | Self::OtsVerificationFailed(_)
            | Self::NoTrustAnchor => ExitCode::Invalid,

            // Runtime errors -> ERROR (exit 2)
            Self::SourceNotFound(_)
            | Self::ReceiptNotFound(_)
            | Self::MismatchedInputTypes { .. }
            | Self::FileReadError { .. }
            | Self::FileTooLarge { .. }
            | Self::ReceiptParseError(_)
            | Self::InvalidReceiptFormat(_)
            | Self::UnsupportedReceiptVersion { .. }
            | Self::NoReceiptForFile(_)
            | Self::NoFileForReceipt(_)
            | Self::EmptySourceDirectory(_)
            | Self::EmptyReceiptDirectory(_)
            | Self::NoInternetConnection
            | Self::NetworkError(_)
            | Self::TrustStoreError(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::HexDecode(_) => ExitCode::Error,
        }
    }

    /// Check if this is a verification failure (vs runtime error)
    #[must_use]
    #[allow(dead_code)]
    pub fn is_verification_failure(&self) -> bool {
        self.exit_code() == ExitCode::Invalid
    }

    /// Check if this is a runtime error
    #[must_use]
    #[allow(dead_code)]
    pub fn is_runtime_error(&self) -> bool {
        self.exit_code() == ExitCode::Error
    }
}

// ========================================================================
// Conversions from atl-core
// ========================================================================

use atl_core::VerificationError as CoreVerificationError;

impl From<CoreVerificationError> for CliError {
    fn from(err: CoreVerificationError) -> Self {
        match err {
            CoreVerificationError::InvalidReceipt(msg) => Self::InvalidReceiptFormat(msg),
            CoreVerificationError::InvalidHash { field, message } => {
                Self::InvalidReceiptFormat(format!("Invalid hash in {field}: {message}"))
            }
            CoreVerificationError::SignatureFailed => Self::SignatureVerificationFailed,
            CoreVerificationError::InclusionProofFailed { reason } => {
                Self::InclusionProofFailed { reason }
            }
            CoreVerificationError::ConsistencyProofFailed { reason } => {
                Self::ConsistencyProofFailed { reason }
            }
            CoreVerificationError::RootHashMismatch => {
                Self::VerificationFailed("Root hash mismatch".to_string())
            }
            CoreVerificationError::TreeSizeMismatch => {
                Self::VerificationFailed("Tree size mismatch".to_string())
            }
            CoreVerificationError::AnchorFailed {
                anchor_type,
                reason,
            } => match anchor_type.as_str() {
                "rfc3161" => Self::TsaVerificationFailed(reason),
                "bitcoin_ots" => Self::OtsVerificationFailed(reason),
                _ => Self::VerificationFailed(format!("Anchor {anchor_type} failed: {reason}")),
            },
            CoreVerificationError::SuperInclusionFailed { reason } => {
                Self::SuperInclusionFailed { reason }
            }
            CoreVerificationError::SuperConsistencyFailed { reason } => {
                Self::SuperConsistencyFailed { reason }
            }
            CoreVerificationError::SuperDataMismatch {
                field,
                expected,
                actual,
            } => Self::VerificationFailed(format!(
                "Super-Tree data mismatch in {field}: expected {expected}, got {actual}"
            )),
            CoreVerificationError::MissingSuperProof => {
                Self::InvalidReceiptFormat("Missing super_proof (required in v2.0)".to_string())
            }
            CoreVerificationError::UnsupportedVersion(version) => Self::UnsupportedReceiptVersion {
                version,
                expected: "2.0.0".to_string(),
            },
            CoreVerificationError::MetadataHashMismatch { expected, actual } => {
                Self::MetadataHashMismatch { expected, actual }
            }
            CoreVerificationError::NoTrustAnchor => Self::NoTrustAnchor,
        }
    }
}

impl From<atl_core::AtlError> for CliError {
    fn from(err: atl_core::AtlError) -> Self {
        Self::VerificationFailed(err.to_string())
    }
}

// ========================================================================
// Helper Functions
// ========================================================================

impl CliError {
    /// Create a file read error
    #[allow(dead_code)]
    pub fn file_read_error(path: impl Into<PathBuf>, err: std::io::Error) -> Self {
        Self::FileReadError {
            path: path.into(),
            message: err.to_string(),
        }
    }

    /// Create a file hash mismatch error
    #[allow(dead_code)]
    pub fn file_hash_mismatch(
        file_path: impl Into<PathBuf>,
        computed: &[u8; 32],
        expected: &str,
    ) -> Self {
        Self::FileHashMismatch {
            file_path: file_path.into(),
            computed_hash: format!("sha256:{}", hex::encode(computed)),
            expected_hash: expected.to_string(),
        }
    }

    /// Create a different log origins error
    #[allow(dead_code)]
    pub fn different_logs(genesis_a: &[u8; 32], genesis_b: &[u8; 32]) -> Self {
        Self::DifferentLogOrigins {
            genesis_a: format!("sha256:{}", hex::encode(genesis_a)),
            genesis_b: format!("sha256:{}", hex::encode(genesis_b)),
        }
    }

    /// Create a batch verification failed error
    #[allow(dead_code)]
    pub fn batch_failed(valid: usize, invalid: usize, errors: usize) -> Self {
        Self::BatchVerificationFailed {
            valid_count: valid,
            invalid_count: invalid,
            error_count: errors,
        }
    }
}

// ========================================================================
// Error Context
// ========================================================================

/// Extension trait for adding context to errors
#[allow(dead_code)]
pub trait CliErrorContext<T> {
    /// Add context about what file was being processed
    fn with_file_context(self, path: &std::path::Path) -> Result<T, CliError>;
}

#[allow(dead_code)]
impl<T, E: Into<CliError>> CliErrorContext<T> for Result<T, E> {
    fn with_file_context(self, path: &std::path::Path) -> Result<T, CliError> {
        self.map_err(|e| {
            let cli_err = e.into();
            // Preserve the error but could add context in the future
            let _ = path;
            cli_err
        })
    }
}

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_valid() {
        assert_eq!(ExitCode::Valid.code(), 0);
    }

    #[test]
    fn test_exit_code_invalid() {
        assert_eq!(ExitCode::Invalid.code(), 1);
    }

    #[test]
    fn test_exit_code_error() {
        assert_eq!(ExitCode::Error.code(), 2);
    }

    #[test]
    fn test_file_not_found_is_error() {
        let err = CliError::SourceNotFound(PathBuf::from("missing.pdf"));
        assert_eq!(err.exit_code(), ExitCode::Error);
    }

    #[test]
    fn test_hash_mismatch_is_invalid() {
        let err = CliError::FileHashMismatch {
            file_path: PathBuf::from("test.pdf"),
            computed_hash: "sha256:abc".to_string(),
            expected_hash: "sha256:def".to_string(),
        };
        assert_eq!(err.exit_code(), ExitCode::Invalid);
    }

    #[test]
    fn test_signature_failed_is_invalid() {
        let err = CliError::SignatureVerificationFailed;
        assert_eq!(err.exit_code(), ExitCode::Invalid);
    }

    #[test]
    fn test_no_internet_is_error() {
        let err = CliError::NoInternetConnection;
        assert_eq!(err.exit_code(), ExitCode::Error);
    }

    #[test]
    fn test_different_logs_is_invalid() {
        let err = CliError::DifferentLogOrigins {
            genesis_a: "sha256:aaa".to_string(),
            genesis_b: "sha256:bbb".to_string(),
        };
        assert_eq!(err.exit_code(), ExitCode::Invalid);
    }

    #[test]
    fn test_batch_failed_is_invalid() {
        let err = CliError::batch_failed(5, 2, 1);
        assert_eq!(err.exit_code(), ExitCode::Invalid);
    }

    #[test]
    fn test_tsa_verification_failed_is_invalid() {
        let err = CliError::TsaVerificationFailed("certificate expired".to_string());
        assert_eq!(err.exit_code(), ExitCode::Invalid);
    }

    #[test]
    fn test_is_verification_failure() {
        let err = CliError::SignatureVerificationFailed;
        assert!(err.is_verification_failure());
        assert!(!err.is_runtime_error());
    }

    #[test]
    fn test_is_runtime_error() {
        let err = CliError::SourceNotFound(PathBuf::from("test.pdf"));
        assert!(err.is_runtime_error());
        assert!(!err.is_verification_failure());
    }

    #[test]
    fn test_from_core_signature_failed() {
        let core_err = CoreVerificationError::SignatureFailed;
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::SignatureVerificationFailed));
    }

    #[test]
    fn test_from_core_inclusion_failed() {
        let core_err = CoreVerificationError::InclusionProofFailed {
            reason: "test".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::InclusionProofFailed { .. }));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cli_err: CliError = io_err.into();
        assert!(matches!(cli_err, CliError::Io(_)));
    }

    #[test]
    fn test_from_core_anchor_failed_rfc3161() {
        let core_err = CoreVerificationError::AnchorFailed {
            anchor_type: "rfc3161".to_string(),
            reason: "TSA cert expired".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::TsaVerificationFailed(_)));
    }

    #[test]
    fn test_from_core_anchor_failed_bitcoin_ots() {
        let core_err = CoreVerificationError::AnchorFailed {
            anchor_type: "bitcoin_ots".to_string(),
            reason: "OTS not confirmed".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::OtsVerificationFailed(_)));
    }

    #[test]
    fn test_from_core_anchor_failed_unknown() {
        let core_err = CoreVerificationError::AnchorFailed {
            anchor_type: "unknown".to_string(),
            reason: "test".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::VerificationFailed(_)));
    }

    #[test]
    fn test_from_core_super_inclusion_failed() {
        let core_err = CoreVerificationError::SuperInclusionFailed {
            reason: "test reason".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::SuperInclusionFailed { .. }));
    }

    #[test]
    fn test_from_core_super_consistency_failed() {
        let core_err = CoreVerificationError::SuperConsistencyFailed {
            reason: "test reason".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::SuperConsistencyFailed { .. }));
    }

    #[test]
    fn test_from_core_super_data_mismatch() {
        let core_err = CoreVerificationError::SuperDataMismatch {
            field: "test_field".to_string(),
            expected: "expected_value".to_string(),
            actual: "actual_value".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::VerificationFailed(_)));
    }

    #[test]
    fn test_from_core_missing_super_proof() {
        let core_err = CoreVerificationError::MissingSuperProof;
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::InvalidReceiptFormat(_)));
    }

    #[test]
    fn test_from_core_unsupported_version() {
        let core_err = CoreVerificationError::UnsupportedVersion("3.0.0".to_string());
        let cli_err: CliError = core_err.into();
        assert!(matches!(
            cli_err,
            CliError::UnsupportedReceiptVersion { .. }
        ));
    }

    #[test]
    fn test_from_core_metadata_hash_mismatch() {
        let core_err = CoreVerificationError::MetadataHashMismatch {
            expected: "expected".to_string(),
            actual: "actual".to_string(),
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::MetadataHashMismatch { .. }));
    }

    #[test]
    fn test_from_core_no_trust_anchor() {
        let core_err = CoreVerificationError::NoTrustAnchor;
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::NoTrustAnchor));
    }

    #[test]
    fn test_network_error() {
        let err = CliError::NetworkError("connection failed".to_string());
        assert_eq!(err.exit_code(), ExitCode::Error);
    }

    #[test]
    fn test_ots_verification_failed() {
        let err = CliError::OtsVerificationFailed("test".to_string());
        assert_eq!(err.exit_code(), ExitCode::Invalid);
    }

    #[test]
    fn test_file_read_error_helper() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err = CliError::file_read_error(PathBuf::from("/test/file"), io_err);
        assert!(matches!(err, CliError::FileReadError { .. }));
    }

    #[test]
    fn test_file_hash_mismatch_helper() {
        let computed = [0u8; 32];
        let expected = "sha256:abcd";
        let err = CliError::file_hash_mismatch(PathBuf::from("/test/file"), &computed, expected);
        assert!(matches!(err, CliError::FileHashMismatch { .. }));
    }

    #[test]
    fn test_different_logs_helper() {
        let genesis_a = [0xAAu8; 32];
        let genesis_b = [0xBBu8; 32];
        let err = CliError::different_logs(&genesis_a, &genesis_b);
        assert!(matches!(err, CliError::DifferentLogOrigins { .. }));
    }

    #[test]
    fn test_receipt_parse_error() {
        let err = CliError::ReceiptParseError("invalid JSON".to_string());
        assert_eq!(err.exit_code(), ExitCode::Error);
    }

    #[test]
    fn test_unsupported_receipt_version() {
        let err = CliError::UnsupportedReceiptVersion {
            version: "3.0.0".to_string(),
            expected: "2.0.0".to_string(),
        };
        assert_eq!(err.exit_code(), ExitCode::Error);
    }

    #[test]
    fn test_file_too_large() {
        let err = CliError::FileTooLarge {
            path: PathBuf::from("/test/file"),
            size_bytes: 100_000_000,
            max_bytes: 10_000_000,
        };
        assert_eq!(err.exit_code(), ExitCode::Error);
    }
}
