//! Output formatting

pub mod human;
pub mod json;

use crate::cli::{Args, VerificationMode};
use crate::error::CliResult;
use crate::verify::batch::BatchVerificationResult;
use crate::verify::online::OnlineVerificationResult;
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

/// Print single file result with online verification
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_single_online_result(result: &OnlineVerificationResult, args: &Args) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_single_online_result(result)
    } else {
        human::print_single_online_result(result, args.use_color())
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
    use crate::verify::online::OnlineVerificationResult;
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

    #[test]
    fn test_print_single_result_quiet_mode() {
        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(),
        };

        let args = create_test_args(true, false);
        assert!(print_single_result(&result, &args, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_single_online_result_quiet_mode() {
        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(),
        };

        let online_result = OnlineVerificationResult {
            offline,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: VerificationMode::Online,
        };

        let args = create_test_args(true, false);
        assert!(print_single_online_result(&online_result, &args).is_ok());
    }

    #[test]
    fn test_print_batch_result_quiet_mode() {
        use std::path::Path;

        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        let args = create_test_args(true, false);
        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(print_batch_result(
            &result,
            &args,
            VerificationMode::Offline,
            source_dir,
            receipt_dir
        )
        .is_ok());
    }

    #[test]
    fn test_print_single_result_json_mode() {
        let result = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(),
        };

        let args = create_test_args(false, true);
        assert!(print_single_result(&result, &args, VerificationMode::Offline).is_ok());
    }

    #[test]
    fn test_print_single_online_result_json_mode() {
        let offline = SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(),
        };

        let online_result = OnlineVerificationResult {
            offline,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: VerificationMode::Online,
        };

        let args = create_test_args(false, true);
        assert!(print_single_online_result(&online_result, &args).is_ok());
    }

    #[test]
    fn test_print_batch_result_json_mode() {
        use std::path::Path;

        let result = BatchVerificationResult {
            valid_count: 1,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        };

        let args = create_test_args(false, true);
        let source_dir = Path::new("/test/source");
        let receipt_dir = Path::new("/test/receipts");
        assert!(print_batch_result(
            &result,
            &args,
            VerificationMode::Offline,
            source_dir,
            receipt_dir
        )
        .is_ok());
    }
}
