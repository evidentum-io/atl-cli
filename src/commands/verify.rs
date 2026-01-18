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
    // Perform verification
    let result = verify_single(&verify_args.source, &verify_args.receipt)?;

    // Output result
    output::print_single_result(&result, args)?;

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
    // Perform batch verification
    let result = verify_batch(&verify_args.source, &verify_args.receipt)?;

    // Output result
    output::print_batch_result(&result, args)?;

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
