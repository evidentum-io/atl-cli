//! CLI argument definitions

use crate::error::CliError;
use clap::{Parser, Subcommand, ValueHint};
use std::path::PathBuf;

/// ATL Protocol receipt verification tool
///
/// Verify cryptographic evidence receipts from Anchored Transparency Logs.
/// Trust is established through external anchors (TSA, Bitcoin), NOT operator keys.
///
/// The CLI auto-detects internet connectivity at startup:
/// - If online: performs full verification including anchor checks
/// - If offline: performs cryptographic proof verification only
///
/// Use --offline to skip online checks even when internet is available.
/// Use --online to require online verification (fails if no internet).
#[derive(Parser, Debug)]
#[command(name = "atl-cli")]
#[command(author = "Evidentum <info@evidentum.io>")]
#[command(version)]
#[command(about = "ATL Protocol receipt verification tool")]
#[command(long_about = None)]
#[command(propagate_version = true)]
pub struct Args {
    /// Command to execute
    #[command(subcommand)]
    pub command: Command,

    /// Suppress output (only exit code)
    ///
    /// When enabled, no output is printed to stdout/stderr.
    /// Use the exit code to determine verification result:
    /// - 0: VALID
    /// - 1: INVALID (verification failed)
    /// - 2: ERROR (runtime error)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    ///
    /// Outputs structured JSON instead of human-readable text.
    /// Useful for scripting and integration.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable colored output
    ///
    /// Forces plain text output without ANSI color codes.
    /// Automatically disabled when stdout is not a terminal.
    #[arg(long, global = true)]
    pub no_color: bool,
}

/// Available commands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Verify file(s) against receipt(s)
    ///
    /// Performs cryptographic verification of file(s) against ATL Protocol v2.0 receipt(s):
    ///
    /// **Single file mode:**
    ///   atl verify document.pdf document.pdf.atl
    ///
    /// **Batch mode:**
    ///   atl verify ./files/ ./receipts/
    ///
    /// **Verification steps (offline):**
    /// 1. Hash source file (SHA-256)
    /// 2. Compare hash with payload_hash in receipt
    /// 3. Verify metadata_hash (if present)
    /// 4. Verify Merkle inclusion proof
    /// 5. Verify Super-Tree proofs
    ///
    /// **Additional steps (online):**
    /// 6. Verify RFC 3161 TSA anchor (certificate chain)
    /// 7. Verify Bitcoin OTS anchor (blockchain confirmation)
    ///
    /// **Batch mode also verifies:**
    /// - Log consistency (all receipts from same append-only log)
    Verify(VerifyArgs),

    /// Display receipt contents
    ///
    /// Parses and displays the contents of a receipt file
    /// without performing verification against source file.
    Inspect(InspectArgs),
}

/// Arguments for the verify command
#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// Path to source file or directory
    ///
    /// If a file: verifies against the receipt
    /// If a directory: batch mode, verifies all files against matching receipts
    #[arg(value_hint = ValueHint::AnyPath)]
    pub source: PathBuf,

    /// Path to receipt file (.atl) or directory
    ///
    /// If a file: must be .atl receipt file
    /// If a directory: contains .atl files matched to source files
    #[arg(value_hint = ValueHint::AnyPath)]
    pub receipt: PathBuf,

    /// Force offline mode (skip online verification)
    ///
    /// Even if internet is available, only perform cryptographic
    /// proof verification without checking external anchors.
    ///
    /// Useful for:
    /// - Faster verification
    /// - Air-gapped systems
    /// - Avoiding external dependencies
    #[arg(long)]
    pub offline: bool,

    /// Force online mode (fail if no internet)
    ///
    /// Requires internet connectivity. If no internet is available,
    /// verification fails with an error instead of falling back to
    /// offline mode.
    ///
    /// Useful when you require anchor verification for trust.
    #[arg(long, conflicts_with = "offline")]
    pub online: bool,

    /// Show detailed verification steps
    ///
    /// Displays each verification step as it completes.
    /// Useful for debugging verification failures.
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the inspect command
#[derive(clap::Args, Debug)]
pub struct InspectArgs {
    /// Path to the .atl receipt file
    #[arg(value_hint = ValueHint::FilePath)]
    pub receipt: PathBuf,
}

/// Verification mode determined from args and environment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum VerificationMode {
    /// Offline verification only (no internet or --offline flag)
    Offline,
    /// Online verification (internet available, not forced offline)
    Online,
}

impl Args {
    /// Check if colored output should be used
    #[allow(dead_code)]
    pub fn use_color(&self) -> bool {
        !self.no_color && atty::is(atty::Stream::Stdout)
    }

    /// Check if output should be JSON
    #[allow(dead_code)]
    pub fn use_json(&self) -> bool {
        self.json
    }

    /// Check if output should be suppressed
    #[allow(dead_code)]
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }
}

impl VerifyArgs {
    /// Check if source is a directory (batch mode)
    #[allow(dead_code)]
    pub fn is_batch_mode(&self) -> bool {
        self.source.is_dir()
    }

    /// Determine verification mode from args and connectivity
    ///
    /// Priority:
    /// 1. --offline flag -> Offline
    /// 2. --online flag -> Online (or error if no internet)
    /// 3. No flag -> auto-detect (Online if internet available)
    #[allow(dead_code)]
    pub fn determine_mode(&self) -> crate::error::CliResult<VerificationMode> {
        if self.offline {
            return Ok(VerificationMode::Offline);
        }

        if self.online {
            #[cfg(feature = "online")]
            {
                if crate::net::detect::has_internet_blocking() {
                    return Ok(VerificationMode::Online);
                } else {
                    return Err(crate::error::CliError::NoInternetConnection);
                }
            }
            #[cfg(not(feature = "online"))]
            {
                return Err(crate::error::CliError::NetworkError(
                    "online feature not enabled".to_string(),
                ));
            }
        }

        // Auto-detect mode
        #[cfg(feature = "online")]
        {
            if crate::net::detect::has_internet_blocking() {
                Ok(VerificationMode::Online)
            } else {
                Ok(VerificationMode::Offline)
            }
        }

        #[cfg(not(feature = "online"))]
        {
            Ok(VerificationMode::Offline)
        }
    }

    /// Check if verbose output is requested
    #[allow(dead_code)]
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Validate source and receipt paths
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), CliError> {
        // Check source exists
        if !self.source.exists() {
            return Err(CliError::SourceNotFound(self.source.clone()));
        }

        // Check receipt exists
        if !self.receipt.exists() {
            return Err(CliError::ReceiptNotFound(self.receipt.clone()));
        }

        // Both must be same type (both files or both directories)
        let source_is_dir = self.source.is_dir();
        let receipt_is_dir = self.receipt.is_dir();

        if source_is_dir != receipt_is_dir {
            return Err(CliError::MismatchedInputTypes {
                source_is_dir,
                receipt_is_dir,
            });
        }

        // If source is a file, receipt must have .atl extension
        if !source_is_dir && self.receipt.extension() != Some(std::ffi::OsStr::new("atl")) {
            eprintln!("Warning: Receipt file does not have .atl extension");
        }

        // --offline and --online are mutually exclusive (handled by clap conflicts_with)

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_verification_mode_eq() {
        assert_eq!(VerificationMode::Offline, VerificationMode::Offline);
        assert_eq!(VerificationMode::Online, VerificationMode::Online);
        assert_ne!(VerificationMode::Offline, VerificationMode::Online);
    }

    #[test]
    fn test_verification_mode_clone() {
        let mode = VerificationMode::Offline;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_args_use_color_enabled() {
        let args = Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: false,
            json: false,
            no_color: false,
        };
        // use_color depends on atty::is_stdout which may vary
        let _ = args.use_color();
    }

    #[test]
    fn test_args_use_color_disabled() {
        let args = Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: false,
            json: false,
            no_color: true,
        };
        assert!(!args.use_color());
    }

    #[test]
    fn test_args_use_json() {
        let args = Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: false,
            json: true,
            no_color: false,
        };
        assert!(args.use_json());

        let args2 = Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: false,
            json: false,
            no_color: false,
        };
        assert!(!args2.use_json());
    }

    #[test]
    fn test_args_is_quiet() {
        let args = Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: true,
            json: false,
            no_color: false,
        };
        assert!(args.is_quiet());

        let args2 = Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: false,
            json: false,
            no_color: false,
        };
        assert!(!args2.is_quiet());
    }

    #[test]
    fn test_verify_args_is_batch_mode() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_path_buf();

        let args = VerifyArgs {
            source: dir_path.clone(),
            receipt: dir_path,
            offline: false,
            online: false,
            verbose: false,
        };
        assert!(args.is_batch_mode());

        let args2 = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
        };
        assert!(!args2.is_batch_mode());
    }

    #[test]
    fn test_verify_args_is_verbose() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: true,
        };
        assert!(args.is_verbose());

        let args2 = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
        };
        assert!(!args2.is_verbose());
    }

    #[test]
    fn test_determine_mode_offline_flag() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: true,
            online: false,
            verbose: false,
        };
        let mode = args.determine_mode().unwrap();
        assert_eq!(mode, VerificationMode::Offline);
    }

    #[test]
    #[cfg(not(feature = "online"))]
    fn test_determine_mode_auto_without_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
        };
        let mode = args.determine_mode().unwrap();
        assert_eq!(mode, VerificationMode::Offline);
    }

    #[test]
    #[cfg(not(feature = "online"))]
    fn test_determine_mode_online_without_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: true,
            verbose: false,
        };
        let result = args.determine_mode();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_source_not_found() {
        let args = VerifyArgs {
            source: PathBuf::from("/nonexistent/test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
        };
        let result = args.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::SourceNotFound(_)));
    }

    #[test]
    fn test_validate_receipt_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let source_path = temp_dir.path().join("test.pdf");
        fs::write(&source_path, b"test").unwrap();

        let args = VerifyArgs {
            source: source_path,
            receipt: PathBuf::from("/nonexistent/test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
        };
        let result = args.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::ReceiptNotFound(_)));
    }

    #[test]
    fn test_validate_mismatched_types() {
        let temp_dir = TempDir::new().unwrap();
        let source_file = temp_dir.path().join("test.pdf");
        let receipt_dir = temp_dir.path().join("receipts");

        fs::write(&source_file, b"test").unwrap();
        fs::create_dir(&receipt_dir).unwrap();

        let args = VerifyArgs {
            source: source_file,
            receipt: receipt_dir,
            offline: false,
            online: false,
            verbose: false,
        };
        let result = args.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CliError::MismatchedInputTypes { .. }
        ));
    }

    #[test]
    fn test_validate_valid_files() {
        let temp_dir = TempDir::new().unwrap();
        let source_path = temp_dir.path().join("test.pdf");
        let receipt_path = temp_dir.path().join("test.pdf.atl");

        fs::write(&source_path, b"test").unwrap();
        fs::write(&receipt_path, b"receipt").unwrap();

        let args = VerifyArgs {
            source: source_path,
            receipt: receipt_path,
            offline: false,
            online: false,
            verbose: false,
        };
        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_valid_directories() {
        let temp_dir = TempDir::new().unwrap();
        let source_dir = temp_dir.path().join("files");
        let receipt_dir = temp_dir.path().join("receipts");

        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&receipt_dir).unwrap();

        let args = VerifyArgs {
            source: source_dir,
            receipt: receipt_dir,
            offline: false,
            online: false,
            verbose: false,
        };
        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_non_atl_extension_warning() {
        let temp_dir = TempDir::new().unwrap();
        let source_path = temp_dir.path().join("test.pdf");
        let receipt_path = temp_dir.path().join("test.txt");

        fs::write(&source_path, b"test").unwrap();
        fs::write(&receipt_path, b"receipt").unwrap();

        let args = VerifyArgs {
            source: source_path,
            receipt: receipt_path,
            offline: false,
            online: false,
            verbose: false,
        };
        // Should still succeed, just prints warning
        let result = args.validate();
        assert!(result.is_ok());
    }
}
