//! Inspect command implementation

use crate::cli::{Args, InspectArgs};
use crate::error::CliError;
use crate::verify::single::load_receipt;

/// Execute the inspect command
pub fn execute(inspect_args: &InspectArgs, args: &Args) -> Result<(), CliError> {
    // Load the receipt
    let receipt = load_receipt(&inspect_args.receipt)?;

    // Output based on format
    if args.json {
        // JSON output - serialize the receipt
        let json_str = serde_json::to_string_pretty(&receipt)?;
        println!("{}", json_str);
    } else if !args.quiet {
        // Human-readable output
        println!("Receipt Contents");
        println!("================");
        println!();
        println!("Spec Version: {}", receipt.spec_version());
        println!();
        println!("Entry:");
        println!("  ID: {}", receipt.entry().id);
        println!("  Payload Hash: {}", receipt.entry().payload_hash);
        println!("  Metadata Hash: {}", receipt.entry().metadata_hash);
        println!(
            "  Metadata: {}",
            serde_json::to_string(&receipt.entry().metadata)?
        );
        println!();
        println!("Proof:");
        println!("  Tree Size: {}", receipt.proof().tree_size);
        println!("  Leaf Index: {}", receipt.proof().leaf_index);
        println!("  Root Hash: {}", receipt.proof().root_hash);
        println!(
            "  Inclusion Path: {} hashes",
            receipt.proof().inclusion_path.len()
        );
        println!();
        println!("Checkpoint:");
        println!("  Origin: {}", receipt.proof().checkpoint.origin);
        println!("  Tree Size: {}", receipt.proof().checkpoint.tree_size);
        println!("  Root Hash: {}", receipt.proof().checkpoint.root_hash);
        println!("  Timestamp: {}", receipt.proof().checkpoint.timestamp);
        println!("  Key ID: {}", receipt.proof().checkpoint.key_id);

        if let Some(super_proof) = &receipt.super_proof() {
            println!();
            println!("Super Proof:");
            println!("  Genesis Super Root: {}", super_proof.genesis_super_root);
            println!("  Super Tree Size: {}", super_proof.super_tree_size);
            println!("  Data Tree Index: {}", super_proof.data_tree_index);
            println!("  Super Root: {}", super_proof.super_root);
            println!("  Inclusion Path: {} hashes", super_proof.inclusion.len());
            println!(
                "  Consistency to Origin: {} hashes",
                super_proof.consistency_to_origin.len()
            );
        }

        if !receipt.anchors().is_empty() {
            println!();
            println!("Anchors: {}", receipt.anchors().len());
        }
    }

    Ok(())
}
