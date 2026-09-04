//! Error types and exit codes for atl-cli
//!
//! Exit codes:
//! - 0 = VALID (accepted under the anchor policy in force -- the only
//!   status that exits 0)
//! - 1 = INVALID (the receipt itself was refuted)
//! - 2 = ERROR (runtime error)
//! - 3 = UNTRUSTED (the receipt was not refuted, and trust in it was not
//!   established -- which includes a receipt one of whose anchors was
//!   checked and found false)
//!
//! Codes 1 and 3 are deliberately distinct so a script can tell "this
//! receipt is disproved" from "I could not establish trust in it" without
//! parsing JSON. Code 2 is equally distinct: it means the tool failed to process an
//! input and says nothing about the evidence.
//!
//! The same input must produce the same code whether it was passed as a file
//! or as a directory. Batch mode aggregates per-item outcomes; it never
//! reclassifies them into a different kind of answer.

use std::path::PathBuf;
use thiserror::Error;

/// Exit codes for the CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// All verifications passed
    Valid = 0,
    /// One or more receipts was refuted (cryptographic/hash failure).
    ///
    /// About the receipt, never about one of its anchors: a receipt's
    /// `anchors` array is signed and hashed by nothing, so an anchor that
    /// fails verification is one anybody who relayed the receipt could have
    /// attached, and it exits 3.
    Invalid = 1,
    /// Runtime error (file not found, parse error, network, etc.)
    Error = 2,
    /// The receipt was not refuted, and trust in it was not established.
    /// Four shapes reach this code: an anchor that did not reach a trust
    /// root this verifier was configured with; a fact that could not be
    /// evaluated at all (cryptography this build does not implement); an
    /// anchor that **was** checked and found false, which refutes that
    /// anchor and not the receipt; and — in batch mode — a file the caller
    /// named that never paired up with its counterpart and was therefore
    /// never checked.
    ///
    /// The receipt stands in every case. Read the reason code before telling
    /// anyone what to supply: only the first shape is fixed by supplying
    /// trust material, and the third is a sign that somebody interfered with
    /// the receipt on its way here.
    Untrusted = 3,
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
    // Trust Material Missing (Exit Code 3: UNTRUSTED)
    // ========================================================================
    /// Trust in the receipt was not established, and the receipt was not
    /// refuted. Four shapes reach this variant: no anchor reached a trust
    /// root this verifier was configured with; the certificate path could
    /// not be evaluated at all; an anchor was checked and found false, which
    /// refutes that anchor and not the receipt; or, in a batch, a file the
    /// caller named had no counterpart to check it against.
    ///
    /// This is NOT a refutation of the receipt: nothing about the *receipt*
    /// was disproved. It gets its own exit code so callers never have to
    /// guess which of the two happened — and, in the third shape, so the
    /// failed anchor is reported without an accusation being manufactured
    /// out of it.
    #[error("{headline} ({reason_code}) -- {detail}")]
    TrustNotEstablished {
        /// Leading phrase. Two are possible, because "trust root
        /// unavailable" is a lie for
        /// [`crate::verify::verdict::ReasonCode::TsaChainIndeterminate`]:
        /// there nothing is unavailable, the check could not be performed.
        /// See [`Self::untrusted_headline`].
        headline: &'static str,
        /// Stable machine-readable reason (see
        /// [`crate::verify::verdict::ReasonCode`]).
        reason_code: &'static str,
        /// What the caller needs to supply, or what stopped the check.
        detail: String,
    },

    // ========================================================================
    // Batch Mode Errors (Exit Codes vary)
    // ========================================================================
    /// One or more batch items could not be processed at all — a file that
    /// would not open, or a receipt that would not parse.
    ///
    /// Exit code 2, matching what single-file mode returns for the very same
    /// input. This is an operational failure, not a statement about the
    /// evidence: the tool never got far enough to make one.
    #[error("ERROR: {errors} of {total} items could not be processed (no item was refuted)")]
    BatchItemsUnprocessable {
        /// Items that failed to be read or parsed.
        errors: usize,
        /// Total paths named by the caller.
        total: usize,
    },

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
    // Two variants used to live here and were removed rather than left
    // lying about: `DifferentLogOrigins` ("receipts are from different
    // logs") and `TreeSizeAnomaly` ("potential log tampering"). Both mapped
    // to exit 1 -- *the evidence was refuted* -- and neither was constructed
    // anywhere. ATL v2.0 defines no such refutations: §3.3.2 makes
    // `genesis_super_root` the identifier of a log instance rather than a
    // rule to break, §5.4.3 defines what to conclude when two identifiers
    // agree and no error when they differ, and the only tree-size check in
    // the spec is `checkpoint.tree_size == proof.tree_size` (§5.2), which is
    // already `ReasonCode::CheckpointTreeSizeMismatch`. A ready-made
    // refutation for a case the protocol does not call a fault is a loaded
    // gun for whoever wires it up next.
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
    ///
    /// # Do not wire this up as a refutation
    ///
    /// Nothing in this crate constructs it: the only route is the
    /// `From<CoreVerificationError>` impl below, which no production path
    /// uses ([`crate::verify::single::verify_single`] maps core errors
    /// through `VerificationFailed` instead). That is the only reason its
    /// `ExitCode::Invalid` mapping does no harm today.
    ///
    /// `atl-core` raises `NoTrustAnchor` when *fewer anchors verified than
    /// the threshold requires*, which is exactly the state
    /// [`crate::verify::single::classify_core_error`] answers `Deferred` to:
    /// an RFC 3161 anchor whose cryptography is sound but whose root nobody
    /// vouched for lands there, and that is `untrusted` (exit 3), not
    /// `invalid` (exit 1). If this variant is ever put on a live path, its
    /// exit code must be settled against [`crate::verify::verdict`] first —
    /// not left at `Invalid`.
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
            | Self::ConsistencyProofFailed { .. }
            | Self::TsaVerificationFailed(_)
            | Self::OtsVerificationFailed(_)
            | Self::NoTrustAnchor => ExitCode::Invalid,

            // Nothing refuted, trust material missing -> UNTRUSTED (exit 3).
            // Read straight off `Status` so the exit code for this state has
            // exactly one definition.
            Self::TrustNotEstablished { .. } => {
                crate::verify::verdict::Status::Untrusted.exit_code()
            }

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
            | Self::BatchItemsUnprocessable { .. }
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
            CoreVerificationError::NoTrustAnchor { .. } => Self::NoTrustAnchor,

            // Nothing was disproved and a check did not finish. There is no
            // `CliError` for that state and there must not be one: every
            // variant of this type carries an exit code, and the only honest
            // one here is 3 (untrusted), which the verdict machinery in
            // `crate::verify::verdict` already produces from the reason
            // codes. Routing it through `VerificationFailed` (exit 1) would
            // publish "this evidence is disproved" for a check that never
            // ran, so it is reported as the runtime condition it is.
            CoreVerificationError::MetadataNotCanonicalizable { path, reason } => {
                Self::VerificationFailed(format!(
                    "metadata at {path} has no RFC 8785 canonical form, so metadata_hash was \
                     never computed and never compared: {reason}"
                ))
            }
            CoreVerificationError::SourceTextNotChecked => Self::VerificationFailed(
                "the receipt's bytes were never checked for duplicate property names".to_string(),
            ),

            // Findings about an anchor, not about the receipt. This
            // conversion produces a `CliError`, which is a whole-run
            // failure, and an anchor finding is never that: it is reported
            // per anchor by `crate::verify::anchor`, and it does not decide
            // the receipt's status. Nothing on a live path constructs one
            // here -- see the note on `Self::NoTrustAnchor`.
            CoreVerificationError::AnchorFinding {
                index,
                anchor_type,
                finding,
            } => Self::VerificationFailed(format!("anchor {index} ({anchor_type}): {finding:?}")),
            CoreVerificationError::AnchorTargetInvalid { .. }
            | CoreVerificationError::AnchorTargetHashMismatch { .. }
            | CoreVerificationError::AnchorPayloadUndecodable { .. }
            | CoreVerificationError::AnchorTypeUnsupported { .. }
            | CoreVerificationError::BitcoinHeightContradictsProof { .. }
            | CoreVerificationError::BitcoinBlockNotObtained
            | CoreVerificationError::Rfc3161MessageImprint(_)
            | CoreVerificationError::Rfc3161CmsSignature(_)
            | CoreVerificationError::Rfc3161TimestampingEku(_)
            | CoreVerificationError::Rfc3161CertificatePath { .. }
            | CoreVerificationError::Rfc3161TerminalNotTrusted { .. } => {
                Self::VerificationFailed(format!("anchor finding: {err:?}"))
            }
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

    /// **An anchor finding may not become a whole-run failure.**
    ///
    /// `atl-core` 0.28 reported a failed anchor as an `AnchorFailed`
    /// aggregate, which this conversion turned into `TsaVerificationFailed`
    /// / `OtsVerificationFailed` — both exit 1, both saying the evidence was
    /// disproved. 0.29 removed that variant: a receipt's `anchors` array is
    /// authenticated by nothing, so a finding against one is a statement
    /// about that anchor and never about the receipt.
    ///
    /// The per-anchor findings that replaced it must therefore not be
    /// convertible into anything that claims a refuted receipt. They arrive
    /// as `VerificationFailed`, which no live path constructs from them —
    /// `crate::verify::anchor` reports every one of them per anchor instead.
    #[test]
    fn an_anchor_finding_is_never_a_receipt_level_failure() {
        for core_err in [
            CoreVerificationError::AnchorPayloadUndecodable {
                anchor_type: "rfc3161".to_string(),
                reason: "not CMS SignedData".to_string(),
            },
            CoreVerificationError::AnchorPayloadUndecodable {
                anchor_type: "bitcoin_ots".to_string(),
                reason: "not an OTS proof".to_string(),
            },
            CoreVerificationError::BitcoinBlockNotObtained,
            CoreVerificationError::AnchorFinding {
                index: 0,
                anchor_type: "rfc3161".to_string(),
                finding: Box::new(CoreVerificationError::AnchorTargetInvalid {
                    anchor_type: "rfc3161".to_string(),
                    expected: "data_tree_root".to_string(),
                    actual: "super_root".to_string(),
                }),
            },
        ] {
            let cli_err: CliError = core_err.into();
            assert!(
                matches!(cli_err, CliError::VerificationFailed(_)),
                "an anchor finding must not be reported as a specific receipt failure: {cli_err:?}"
            );
        }
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
        let core_err = CoreVerificationError::NoTrustAnchor {
            required: 1,
            verified: 0,
        };
        let cli_err: CliError = core_err.into();
        assert!(matches!(cli_err, CliError::NoTrustAnchor));
    }

    /// The inability half of `atl-core`'s receipt-level errors reaches this
    /// conversion as a message, never as a `CliError` that claims a specific
    /// refuted check. Nothing live constructs one — `verify_single` routes
    /// receipt-level errors through
    /// `crate::verify::single::classify_core_error` instead, which reports
    /// them as `receipt_check_incomplete` (untrusted, exit 3).
    #[test]
    fn receipt_level_inabilities_are_not_reported_as_refuted_checks() {
        for core_err in [
            CoreVerificationError::SourceTextNotChecked,
            CoreVerificationError::MetadataNotCanonicalizable {
                path: "/entry/metadata/x".to_string(),
                reason: "non-finite number".to_string(),
            },
        ] {
            let cli_err: CliError = core_err.into();
            assert!(
                matches!(cli_err, CliError::VerificationFailed(_)),
                "{cli_err:?}"
            );
        }
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
