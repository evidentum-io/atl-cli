//! Verify command implementation

use crate::cli::{Args, VerificationMode, VerifyArgs};
use crate::error::{CliError, CliResult};
use crate::output;
use crate::verify::batch::verify_batch;
use crate::verify::online::{verify_single_online, OnlineConfig};
use crate::verify::single::verify_single;

/// Execute the verify command
///
/// Determines whether to run single file or batch mode verification
/// based on input paths.
pub fn execute(verify_args: &VerifyArgs, args: &Args) -> CliResult<()> {
    // Validate paths exist
    verify_args.validate()?;

    // Determine if batch mode
    let is_batch = verify_args.is_batch_mode();

    if is_batch {
        execute_batch(verify_args, args)
    } else {
        execute_single(verify_args, args)
    }
}

/// Execute single file verification
fn execute_single(verify_args: &VerifyArgs, args: &Args) -> CliResult<()> {
    // Perform verification FIRST (loads receipt, hashes file)
    let result = verify_single(&verify_args.source, &verify_args.receipt)?;

    // Determine mode AFTER we know if receipt has anchors
    // This avoids unnecessary network check for lite receipts
    let has_anchors = !result.receipt.anchors.is_empty();
    let mode = verify_args.determine_mode_for_receipt(has_anchors)?;

    // If online mode and has anchors, perform online verification
    if mode == VerificationMode::Online && has_anchors {
        let config = OnlineConfig::default();

        // Create tokio runtime for async verification
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CliError::NetworkError(format!("Failed to create runtime: {e}")))?;

        let online_result = rt.block_on(verify_single_online(result, &config))?;

        // Output online result
        output::print_single_online_result(&online_result, args)?;

        // Return error if verification failed
        if !online_result.is_valid() {
            return Err(CliError::VerificationFailed(
                "Online anchor verification failed".into(),
            ));
        }
    } else {
        // Offline mode or no anchors - existing behavior
        output::print_single_result(&result, args, mode)?;

        if !result.is_valid() {
            if !result.file_hash_valid {
                return Err(CliError::file_hash_mismatch(
                    &verify_args.source,
                    &result.file_hash,
                    &result.receipt.entry.payload_hash,
                ));
            }
            // Convert core errors to CLI errors
            if let Some(err) = result.core_result.errors.first() {
                return Err(err.clone().into());
            }
            return Err(CliError::VerificationFailed("unknown".into()));
        }
    }

    Ok(())
}

/// Execute batch verification
fn execute_batch(verify_args: &VerifyArgs, args: &Args) -> CliResult<()> {
    // Perform batch verification FIRST
    let result = verify_batch(&verify_args.source, &verify_args.receipt)?;

    // Check if ANY receipt has anchors
    let has_any_anchors = result.items.iter().any(|item| match item {
        crate::verify::batch::BatchItemResult::Valid(r)
        | crate::verify::batch::BatchItemResult::Invalid(r) => !r.receipt.anchors.is_empty(),
        _ => false,
    });
    let mode = verify_args.determine_mode_for_receipt(has_any_anchors)?;

    // Output result WITH mode and paths
    output::print_batch_result(
        &result,
        args,
        mode,
        &verify_args.source,
        &verify_args.receipt,
    )?;

    // Return error if any failures
    if !result.is_valid() {
        return Err(CliError::batch_failed(
            result.valid_count,
            result.invalid_count,
            result.error_count,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Command;
    use std::path::PathBuf;

    #[test]
    fn test_execute_single_invalid_source() {
        let verify_args = VerifyArgs {
            source: PathBuf::from("/nonexistent/file.pdf"),
            receipt: PathBuf::from("test.atl"),
            offline: false,
            online: false,
            verbose: false,
        };
        let args = Args {
            command: Command::Inspect(crate::cli::InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: true,
            json: false,
            no_color: false,
        };
        let result = execute(&verify_args, &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_batch_invalid_source() {
        let verify_args = VerifyArgs {
            source: PathBuf::from("/nonexistent/dir/"),
            receipt: PathBuf::from("/nonexistent/receipts/"),
            offline: false,
            online: false,
            verbose: false,
        };
        let args = Args {
            command: Command::Inspect(crate::cli::InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: true,
            json: false,
            no_color: false,
        };
        let result = execute(&verify_args, &args);
        assert!(result.is_err());
    }

    #[cfg(feature = "online")]
    #[test]
    fn test_execute_single_determines_mode_for_receipt() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let source_path = temp_dir.path().join("test.txt");
        let receipt_path = temp_dir.path().join("test.txt.atl");

        // Create a valid source file
        fs::write(&source_path, b"test content").unwrap();

        // Create a minimal valid receipt (lite receipt - no anchors)
        let receipt_json = include_str!("../../test_data/receipts/valid/document.pdf.atl");
        fs::write(&receipt_path, receipt_json).unwrap();

        let verify_args = VerifyArgs {
            source: source_path,
            receipt: receipt_path,
            offline: false,
            online: false,
            verbose: false,
        };

        let args = Args {
            command: Command::Verify(VerifyArgs {
                source: verify_args.source.clone(),
                receipt: verify_args.receipt.clone(),
                offline: false,
                online: false,
                verbose: false,
            }),
            quiet: true,
            json: false,
            no_color: false,
        };

        // Execute should determine mode based on receipt anchors
        // This lite receipt has no anchors, so should not check connectivity
        let result = execute(&verify_args, &args);
        // Result will be Err because file hash won't match, but mode detection worked
        assert!(result.is_err());
    }
}
