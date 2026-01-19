//! Verify command implementation

use crate::cli::{Args, VerifyArgs};
use crate::error::{CliError, CliResult};
use crate::output;
use crate::verify::batch::verify_batch;
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

    // Output result WITH mode
    output::print_single_result(&result, args, mode)?;

    // Return error if verification failed
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

    Ok(())
}

/// Execute batch verification
fn execute_batch(verify_args: &VerifyArgs, args: &Args) -> CliResult<()> {
    // Perform batch verification FIRST
    let result = verify_batch(&verify_args.source, &verify_args.receipt)?;

    // Check if ANY receipt has anchors
    let has_any_anchors = result.items.iter().any(|item| {
        match item {
            crate::verify::batch::BatchItemResult::Valid(r)
            | crate::verify::batch::BatchItemResult::Invalid(r) => !r.receipt.anchors.is_empty(),
            _ => false,
        }
    });
    let mode = verify_args.determine_mode_for_receipt(has_any_anchors)?;

    // Output result WITH mode
    output::print_batch_result(&result, args, mode)?;

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
}
