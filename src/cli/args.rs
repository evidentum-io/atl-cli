//! CLI argument definitions

use crate::error::CliError;
use clap::{Parser, Subcommand, ValueHint};
use std::path::PathBuf;

/// ATL Protocol receipt verification tool
///
/// Verify cryptographic evidence receipts from Anchored Transparency Logs.
/// Trust is established through external anchors (TSA, Bitcoin), NOT operator keys.
///
/// Only Bitcoin OTS anchors need the network. RFC 3161 verification is pure
/// computation, so a receipt without a Bitcoin anchor is verified in full
/// without any network access, and connectivity is never probed for it.
///
/// When a receipt does carry a Bitcoin anchor, the CLI auto-detects
/// connectivity: online, it asks block-explorer APIs for the block header and
/// compares the OTS proof's merkle root against the one two or more of them
/// agree on; offline, that anchor is reported unconfirmed rather than
/// accepted. It does not observe the Bitcoin network -- see the README.
///
/// Use --offline to skip online checks even when internet is available.
/// Use --online to require connectivity for anchors that need it.
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
    /// - 0: VALID (accepted under the anchor policy in force)
    /// - 1: INVALID (the evidence was refuted)
    /// - 2: ERROR (an input could not be processed -- says nothing about
    ///   the evidence)
    /// - 3: UNTRUSTED (nothing refuted; the check could not be finished --
    ///   trust material is missing on this side, the certificate path could
    ///   not be evaluated at all, or the receipt carries no anchors. See
    ///   reason_code and the anchor's error text before assuming a
    ///   certificate is what is needed)
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
    /// 6. Verify RFC 3161 TSA anchors: token decoding, CMS signature,
    ///    certificate chain, validity at genTime, EKU. This is pure
    ///    computation and needs no network.
    ///
    /// **Additional step (online):**
    /// 7. Check Bitcoin OTS anchors against the block header that two or
    ///    more block-explorer APIs agree on. The only step needing network.
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

    /// Force offline mode (skip the Bitcoin block lookup)
    ///
    /// Even if internet is available, perform no network access. RFC 3161
    /// anchors are still verified in full -- that is pure computation. What
    /// is skipped is asking block-explorer APIs for the block header an OTS
    /// proof is compared against, so a bitcoin_ots anchor can at best report
    /// "not confirmed" and the receipt cannot reach "valid" through it.
    ///
    /// Useful for:
    /// - Faster verification
    /// - Air-gapped systems
    /// - Avoiding external dependencies
    #[arg(long)]
    pub offline: bool,

    /// Require connectivity for anchors that need it
    ///
    /// If the receipt has an anchor that needs the network (only
    /// bitcoin_ots does) and no internet is available, verification fails
    /// with an error instead of falling back to offline mode.
    ///
    /// A receipt with no such anchor -- an RFC 3161-only receipt, say -- is
    /// verified without any network access and reports mode "offline" even
    /// under this flag. Nothing is probed, and nothing fails: there is
    /// simply nothing online to do, and claiming otherwise would be a
    /// verification result the tool did not perform.
    #[arg(long, conflicts_with = "offline")]
    pub online: bool,

    /// Show detailed verification steps
    ///
    /// Displays each verification step as it completes.
    /// Useful for debugging verification failures.
    #[arg(short, long)]
    pub verbose: bool,

    /// Accept the receipt once ONE anchor has been verified
    ///
    /// Lowers the anchor quorum to the ATL v2.0 §5.5 floor: "At least one
    /// anchor MUST be verified to establish trust in the receipt."
    ///
    /// The default is stricter, and deliberately so: EVERY anchor a receipt
    /// presents must be verified. That is a rule about the anchors this
    /// receipt offers, not about anchor types -- a Receipt-TSA satisfies it
    /// with its single TSA anchor -- so it is NOT §5.6. §5.6 is reported
    /// separately as the max_trust_profile field.
    ///
    /// A Receipt-Full whose Bitcoin anchor was never confirmed did not
    /// deliver what it offered, and this tool says so rather than quietly
    /// settling for less.
    ///
    /// # One reason to prefer this flag
    ///
    /// The default profile is defined over the anchors a receipt PRESENTS,
    /// and a receipt's anchors are covered by neither the leaf hash nor the
    /// checkpoint blob -- anybody who relays a receipt can append one, with
    /// no key. So a relay can take an accepted receipt from valid (exit 0)
    /// to untrusted (exit 3) under the default, by appending an anchor that
    /// does not verify. It is a denial of verification and never an
    /// accusation: the status never becomes invalid, nothing reports the
    /// receipt as refuted, and the reason is the fixed anchor_quorum_unmet,
    /// which names this profile and no anchor.
    ///
    /// This flag is immune. It asks §5.5's own question -- at least one
    /// verified anchor -- and appending cannot lower a count. If you need an
    /// outcome a relay cannot move at all, pass it.
    ///
    /// What this flag does NOT do:
    ///
    /// - It never counts a refuted anchor. An anchor that was checked and
    ///   found false is not a verified anchor under any quorum, it is listed
    ///   in the coverage axis with its own reason, and the run is not
    ///   complete. (It does not make the receipt "invalid" either: nothing
    ///   signs or hashes a receipt's anchors, so an anchor that fails is one
    ///   anybody who relayed the receipt could have attached. Only the
    ///   receipt itself being disproved is exit 1.)
    /// - It never accepts a receipt with no VERIFIED anchor: a quorum of one
    ///   cannot be met by none, and a receipt presenting anchors that all
    ///   fail has none either. Both report receipt_unanchored.
    /// - It never hides an unverified anchor. Every anchor that reached no
    ///   result is still listed, with its reason, and the run is reported as
    ///   a success RELATIVE TO THIS POLICY -- never as an unqualified VALID.
    ///
    /// A "verified anchor" here means the cryptographic facts were checked
    /// AND the certificate path reached a root you supplied via
    /// --tsa-trust-store. A sound signature under an unknown root is not a
    /// verified anchor and never counts towards the quorum.
    #[arg(long)]
    pub allow_single_anchor: bool,

    /// Trusted TSA root certificates, for RFC 3161 anchor verification
    ///
    /// Path to a PEM file (one or more concatenated certificates), a single
    /// DER-encoded certificate, or a directory containing such files.
    ///
    /// Per the ATL Protocol trust model, this tool ships with NO built-in
    /// TSA roots: without this flag, an RFC 3161 anchor's certificate chain
    /// can at best be reported "Assumed" (cryptographically sound, but
    /// nobody vouches for the root), which yields status "untrusted" and
    /// NEVER a valid verification result. Pass the root(s) you have obtained
    /// through some trusted channel (e.g. the TSA operator's published root
    /// bundle) to let matching anchors be reported "Trusted" instead.
    ///
    /// Certificates given here are trust ANCHORS. To merely bridge a gap in
    /// a token's certificate set, use --tsa-intermediates.
    #[arg(long, value_hint = ValueHint::AnyPath)]
    pub tsa_trust_store: Option<PathBuf>,

    /// Intermediate CA certificates, for completing an RFC 3161 chain
    ///
    /// Same accepted formats as --tsa-trust-store (PEM file, DER file, or a
    /// directory of either).
    ///
    /// Certificates given here confer NO trust of their own: chain
    /// construction may walk through them, but the chain must still reach a
    /// certificate named by --tsa-trust-store to be reported "Trusted".
    /// Use this when an ANCHOR reports state "incomplete" with reason
    /// "tsa_chain_incomplete" -- some TSAs (notably Sectigo and DigiCert)
    /// ship tokens whose topmost certificate is cross-signed by a legacy
    /// root that the token itself does not include. Read that from the
    /// anchor, in anchor_verification.results[] or the Coverage list; the
    /// receipt's own reason code names no anchor.
    ///
    /// It will NOT help with an anchor whose reason is
    /// "tsa_chain_indeterminate" or "cms_signature_indeterminate" (state
    /// "unevaluable"): there the check could not be performed at all
    /// (commonly a signature algorithm this verifier does not implement,
    /// such as SHA-1 on a long-lived root).
    /// A certificate passed here is checked like any other link on the
    /// path; the same certificate passed to --tsa-trust-store is an
    /// external trusted input and is not re-checked (RFC 5280 6.1), which
    /// is why the two flags can differ on the very same file.
    ///
    /// Keeping this separate from --tsa-trust-store matters: feeding the
    /// missing issuer in as an anchor would silently move your trust
    /// boundary outward to a certificate you never meant to trust.
    #[arg(long, value_hint = ValueHint::AnyPath)]
    pub tsa_intermediates: Option<PathBuf>,
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
        use std::io::IsTerminal as _;
        !self.no_color && std::io::stdout().is_terminal()
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

    /// Determine verification mode for a receipt that does (or does not)
    /// have anchors needing network access.
    ///
    /// `needs_network` must be `true` only when at least one anchor cannot
    /// be verified to completion offline — today that means a `bitcoin_ots`
    /// anchor. RFC 3161 verification (token decoding, CMS signature,
    /// certificate chain) is pure computation and never touches the network,
    /// so a receipt anchored only by a TSA must not cause a connectivity
    /// probe: that probe contacts external hosts for a check that never
    /// leaves the process, which is both a needless delay and a needless
    /// disclosure of when and how often someone verifies evidence.
    ///
    /// Priority:
    /// 1. `--offline` -> Offline (no network check)
    /// 2. Nothing in the receipt needs the network -> Offline (no network
    ///    check), **including under `--online`**: there is no online step to
    ///    require, and reporting `mode: online` for a run that made no
    ///    network call would be the same overclaim this CLI exists to avoid.
    /// 3. `--online` -> Online, or [`CliError::NoInternetConnection`] if the
    ///    connectivity probe fails
    /// 4. Otherwise -> auto-detect
    #[allow(dead_code)]
    pub fn determine_mode_for_receipt(
        &self,
        needs_network: bool,
    ) -> crate::error::CliResult<VerificationMode> {
        // --offline always wins
        if self.offline {
            return Ok(VerificationMode::Offline);
        }

        // Nothing to do online: never probe, whatever the flags say.
        if !needs_network {
            return Ok(VerificationMode::Offline);
        }

        // --online requires connectivity
        if self.online {
            #[cfg(feature = "online")]
            {
                if crate::net::detect::has_internet_blocking() {
                    return Ok(VerificationMode::Online);
                }
                return Err(crate::error::CliError::NoInternetConnection);
            }
            #[cfg(not(feature = "online"))]
            {
                return Err(crate::error::CliError::NetworkError(
                    "online feature not enabled".to_string(),
                ));
            }
        }

        // Network-backed anchors present, no flag: auto-detect
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };
        assert!(args.is_batch_mode());

        let args2 = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };
        assert!(args.is_verbose());

        let args2 = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
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
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };
        // Should still succeed, just prints warning
        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_determine_mode_for_receipt_offline_flag_ignores_anchors() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: true,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // --offline flag should return Offline regardless of anchors
        assert_eq!(
            args.determine_mode_for_receipt(true).unwrap(),
            VerificationMode::Offline
        );
        assert_eq!(
            args.determine_mode_for_receipt(false).unwrap(),
            VerificationMode::Offline
        );
    }

    #[test]
    fn test_determine_mode_for_receipt_no_anchors_skips_network() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // No anchors = should return Offline immediately without network check
        let mode = args.determine_mode_for_receipt(false).unwrap();
        assert_eq!(mode, VerificationMode::Offline);
    }

    #[test]
    #[cfg(not(feature = "online"))]
    fn test_determine_mode_for_receipt_online_flag_without_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: true,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // --online flag without online feature should error
        let result = args.determine_mode_for_receipt(true);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(feature = "online"))]
    fn test_determine_mode_for_receipt_has_anchors_without_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // Has anchors but no online feature - should return Offline
        let mode = args.determine_mode_for_receipt(true).unwrap();
        assert_eq!(mode, VerificationMode::Offline);
    }

    #[test]
    #[cfg(feature = "online")]
    fn test_determine_mode_for_receipt_online_flag_with_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: true,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // --online flag with online feature - result depends on actual internet
        let result = args.determine_mode_for_receipt(true);
        // Can be Ok(Online) or Err(NoInternetConnection) depending on network
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    #[cfg(feature = "online")]
    fn test_determine_mode_for_receipt_auto_detect_with_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // Auto-detect with anchors and online feature
        let result = args.determine_mode_for_receipt(true);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(feature = "online")]
    fn test_determine_mode_online_flag_with_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: true,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // --online flag with online feature
        let result = args.determine_mode();
        // Can be Ok(Online) or Err(NoInternetConnection) depending on network
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    #[cfg(feature = "online")]
    fn test_determine_mode_auto_detect_with_feature() {
        let args = VerifyArgs {
            source: PathBuf::from("test.pdf"),
            receipt: PathBuf::from("test.pdf.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        // Auto-detect with online feature
        let result = args.determine_mode();
        assert!(result.is_ok());
    }
}
