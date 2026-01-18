//! Human-readable output formatting

use colored::Colorize;

use crate::error::CliResult;
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::consistency::ConsistencyResult;
use crate::verify::single::SingleVerificationResult;

/// Print single file result
pub fn print_single_result(
    result: &SingleVerificationResult,
    use_color: bool,
) -> CliResult<()> {
    println!("Verification Result");
    println!("===================");
    println!();

    // Mode indicator
    println!("Mode: OFFLINE");

    // File info
    println!("File: {}", result.source_path.display());
    println!("Receipt: {}", result.receipt_path.display());

    // Status
    print!("Status: ");
    if result.is_valid() {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }
    println!();

    // File hash comparison
    println!("File Hash:");
    println!("  Computed: {}", format_hash(&result.file_hash));
    println!("  Expected: {}", &result.receipt.entry.payload_hash);
    print!("  Match: ");
    if result.file_hash_valid {
        print_status("YES", true, use_color);
    } else {
        print_status("NO", false, use_color);
    }
    println!();

    // If hash doesn't match, show explanation and stop
    if !result.file_hash_valid {
        println!();
        println!("The file content does not match the receipt.");
        println!("The file may have been modified since the receipt was issued.");
        return Ok(());
    }

    // Receipt verification details
    println!();
    println!("Receipt Verification:");
    println!("  Entry ID: {}", result.receipt.entry.id);
    print!("  Inclusion Proof: ");
    if result.core_result.is_valid {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    // Errors
    if !result.core_result.errors.is_empty() {
        println!();
        println!("Errors:");
        for err in &result.core_result.errors {
            println!("  - {err:?}");
        }
    }

    Ok(())
}

/// Print batch result
pub fn print_batch_result(
    result: &BatchVerificationResult,
    use_color: bool,
) -> CliResult<()> {
    println!("Batch Verification Summary");
    println!("==========================");
    println!();

    println!("Mode: OFFLINE");

    // Summary
    let total =
        result.valid_count + result.invalid_count + result.error_count + result.unmatched_count;
    println!("Files: {total} total");
    println!();

    println!("Results:");
    print!("  Valid:     ");
    print_count(result.valid_count, result.valid_count > 0, use_color);
    print!("  Invalid:   ");
    print_count(result.invalid_count, result.invalid_count == 0, use_color);
    print!("  Errors:    ");
    print_count(result.error_count, result.error_count == 0, use_color);
    print!("  Unmatched: ");
    println!("{}", result.unmatched_count);
    println!();

    // Consistency
    if let Some(consistency) = &result.consistency {
        print_consistency(consistency, use_color);
    }

    // Individual results
    println!("Individual Results:");
    println!("------------------");
    println!();

    for (i, item) in result.items.iter().enumerate() {
        print_batch_item(i + 1, item, use_color);
    }

    // Overall status
    println!();
    print!("Overall: ");
    if result.is_valid() {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    Ok(())
}

fn print_consistency(consistency: &ConsistencyResult, use_color: bool) {
    print!("Log Consistency: ");
    if consistency.is_valid() {
        print_status(
            &format!("VERIFIED ({} receipts)", consistency.receipt_count),
            true,
            use_color,
        );
        if let Some(genesis) = &consistency.genesis_super_root {
            println!("  Genesis: {}", format_hash(genesis));
        }
        println!("  All receipts from same log instance");
    } else {
        print_status("FAILED", false, use_color);
        for err in &consistency.errors {
            println!("  Error: {err}");
        }
    }
    println!();
}

fn print_batch_item(index: usize, item: &BatchItemResult, use_color: bool) {
    match item {
        BatchItemResult::Valid(result) => {
            println!(
                "[{index}] {}",
                result
                    .source_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            print!("    Status: ");
            print_status("VALID", true, use_color);
        }
        BatchItemResult::Invalid(result) => {
            println!(
                "[{index}] {}",
                result
                    .source_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            print!("    Status: ");
            print_status("INVALID", false, use_color);
            if !result.file_hash_valid {
                println!("    Error: File hash mismatch");
            }
        }
        BatchItemResult::Error {
            source, error, ..
        } => {
            println!(
                "[{index}] {}",
                source.file_name().unwrap_or_default().to_string_lossy()
            );
            print!("    Status: ");
            print_status("ERROR", false, use_color);
            println!("    Error: {error}");
        }
        BatchItemResult::NoReceipt(path) => {
            println!(
                "[{index}] {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            print!("    Status: ");
            if use_color {
                println!("{}", "NO RECEIPT".yellow());
            } else {
                println!("NO RECEIPT");
            }
        }
        BatchItemResult::NoSource(path) => {
            println!(
                "[{index}] {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            print!("    Status: ");
            if use_color {
                println!("{}", "NO SOURCE FILE".yellow());
            } else {
                println!("NO SOURCE FILE");
            }
        }
    }
    println!();
}

fn print_status(text: &str, is_success: bool, use_color: bool) {
    if use_color {
        if is_success {
            println!("{}", text.green().bold());
        } else {
            println!("{}", text.red().bold());
        }
    } else {
        println!("{text}");
    }
}

fn print_count(count: usize, is_good: bool, use_color: bool) {
    if use_color {
        if is_good {
            println!("{}", count.to_string().green());
        } else {
            println!("{}", count.to_string().red());
        }
    } else {
        println!("{count}");
    }
}

fn format_hash(hash: &[u8; 32]) -> String {
    format!("sha256:{}...", hex::encode(&hash[..16]))
}
