//! Output formatting

pub mod human;
pub mod json;

use crate::cli::Args;
use crate::error::CliResult;
use crate::verify::batch::BatchVerificationResult;
use crate::verify::single::SingleVerificationResult;

/// Print single file verification result
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_single_result(result: &SingleVerificationResult, args: &Args) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_single_result(result)
    } else {
        human::print_single_result(result, args.use_color())
    }
}

/// Print batch verification result
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_batch_result(result: &BatchVerificationResult, args: &Args) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_batch_result(result)
    } else {
        human::print_batch_result(result, args.use_color())
    }
}
