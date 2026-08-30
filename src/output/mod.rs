//! Output formatting
//!
//! There is one renderer per format, used for both offline and online runs.
//! RFC 3161 anchors are verified identically either way, so a separate
//! "online" rendering path would only be a second place for the status to
//! be decided — exactly the drift this crate is built to avoid.

pub mod human;
pub mod json;

use crate::cli::{Args, VerificationMode};
use crate::error::CliResult;
use crate::verify::batch::BatchVerificationResult;
use crate::verify::single::SingleVerificationResult;

/// Print single file verification result
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_single_result(
    result: &SingleVerificationResult,
    args: &Args,
    mode: VerificationMode,
) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_single_result(result, mode)
    } else {
        human::print_single_result(result, args.use_color())
    }
}

/// Print batch verification result
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_batch_result(
    result: &BatchVerificationResult,
    args: &Args,
    mode: VerificationMode,
    source_dir: &std::path::Path,
    receipt_dir: &std::path::Path,
) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_batch_result(result, mode, source_dir, receipt_dir)
    } else {
        human::print_batch_result(result, args.use_color())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Args, Command, InspectArgs};
    use crate::verify::batch::BatchVerificationResult;
    use crate::verify::policy::AnchorPolicy;
    use crate::verify::single::SingleVerificationResult;
    use std::path::PathBuf;

    fn create_test_args(quiet: bool, json: bool) -> Args {
        Args {
            command: Command::Inspect(InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet,
            json,
            no_color: false,
        }
    }

    fn create_test_receipt() -> atl_core::Receipt {
        serde_json::from_str(include_str!(
            "../../test_data/receipts/valid/document.pdf.atl"
        ))
        .expect("Failed to parse test receipt")
    }

    fn create_test_verification_result() -> atl_core::VerificationResult {
        let receipt = create_test_receipt();
        atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt")
    }

    fn create_test_result() -> SingleVerificationResult {
        SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(),
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        }
    }

    fn create_test_batch() -> BatchVerificationResult {
        BatchVerificationResult {
            valid_count: 1,
            unanchored_count: 0,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
            consistency: None,
            items: vec![],
        }
    }

    #[test]
    fn quiet_mode_prints_nothing_and_still_succeeds() {
        let args = create_test_args(true, false);
        assert!(
            print_single_result(&create_test_result(), &args, VerificationMode::Offline).is_ok()
        );
        assert!(print_batch_result(
            &create_test_batch(),
            &args,
            VerificationMode::Offline,
            std::path::Path::new("/test/source"),
            std::path::Path::new("/test/receipts")
        )
        .is_ok());
    }

    #[test]
    fn json_mode_renders_single_and_batch() {
        let args = create_test_args(false, true);
        assert!(
            print_single_result(&create_test_result(), &args, VerificationMode::Offline).is_ok()
        );
        assert!(print_batch_result(
            &create_test_batch(),
            &args,
            VerificationMode::Offline,
            std::path::Path::new("/test/source"),
            std::path::Path::new("/test/receipts")
        )
        .is_ok());
    }

    #[test]
    fn human_mode_renders_single_and_batch() {
        let args = create_test_args(false, false);
        assert!(
            print_single_result(&create_test_result(), &args, VerificationMode::Online).is_ok()
        );
        assert!(print_batch_result(
            &create_test_batch(),
            &args,
            VerificationMode::Online,
            std::path::Path::new("/test/source"),
            std::path::Path::new("/test/receipts")
        )
        .is_ok());
    }
}
