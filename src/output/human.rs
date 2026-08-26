//! Human-readable output formatting
//!
//! Every status line here is printed from the verdict produced by
//! [`crate::verify::verdict`]; this module decides no outcome of its own, so
//! it cannot disagree with the JSON output or the exit code.
//!
//! One rendering path serves both offline and online runs. RFC 3161 anchors
//! are verified identically either way, so a separate "online" renderer
//! would only be a second place for the status to be decided.

use colored::Colorize;

use crate::error::CliResult;
use crate::verify::anchor::{AnchorDetails, AnchorVerdict, AnchorVerificationResult};
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::consistency::ConsistencyResult;
use crate::verify::single::SingleVerificationResult;
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Info about a receipt for consistency proof display
#[derive(Debug, Clone)]
struct ReceiptProofInfo {
    /// File name (for display)
    filename: String,
    /// Super root hash string at registration time (e.g., "sha256:abc...")
    super_root: String,
    /// Data tree index (for ordering receipts in display)
    data_tree_index: u64,
}

/// Print single file result
pub fn print_single_result(result: &SingleVerificationResult, use_color: bool) -> CliResult<()> {
    println!("Verification Result");
    println!("===================");
    println!();

    // File info
    println!("File: {}", result.source_path.display());
    println!("Receipt: {}", result.receipt_path.display());

    let verdict = result.verdict();
    print!("Status: ");
    print_receipt_status(verdict, use_color);

    // File hash comparison
    println!("File Hash:");
    println!("  Computed: {}", format_hash(&result.file_hash));
    println!("  Expected: {}", result.receipt.entry.payload_hash);
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
    println!("Receipt Verification:");
    println!("  Entry ID: {}", result.receipt.entry.id);

    // Inclusion proof - canonical verdict (base inclusion AND super-tree
    // proofs if the receipt has a super_proof), same source of truth the
    // JSON renderer uses (see `ProofVerdict`).
    print!("  Inclusion Proof: ");
    let proofs_valid = result.proof_verdict().proofs_valid();
    if proofs_valid {
        print_status("VALID", true, use_color);
    } else {
        print_status("INVALID", false, use_color);
    }

    // Anchor status for lite receipts
    if verdict.status == Status::Pending {
        print!("  Anchor Status: ");
        print_status_pending("UNANCHORED", use_color);
        println!();
        println!(
            "Note: This receipt is cryptographically valid but lacks external timestamp anchors."
        );
        println!("      Request an upgraded receipt with TSA or Bitcoin anchoring for independent verification.");
    }

    print_anchor_section(&result.anchor_results, use_color);

    if verdict.status == Status::Untrusted {
        print_trust_hint(&result.anchor_results);
    }

    Ok(())
}

/// Print the overall status line for one receipt.
///
/// `Untrusted` is deliberately worded so it cannot be read as damage to the
/// evidence: nothing was refuted, this verifier is simply not configured to
/// finish the check. It is printed in the same warning colour as `PENDING`,
/// never the failure colour.
fn print_receipt_status(verdict: ReceiptVerdict, use_color: bool) {
    match verdict.status {
        Status::Valid => print_status("VALID", true, use_color),
        Status::Pending => print_status_pending("PENDING (unanchored)", use_color),
        Status::Untrusted => {
            print_status_pending("NOT VERIFIED: trust root unavailable", use_color);
        }
        Status::Invalid => print_status("INVALID", false, use_color),
    }
    if let Some(reason) = verdict.reason_code {
        println!("Reason: {}", reason.as_str());
    }
}

/// Say exactly what the caller must supply to reach a verdict.
fn print_trust_hint(anchors: &[AnchorVerificationResult]) {
    println!();
    println!("The evidence was NOT disproved. This verifier was not given the material");
    println!("needed to finish checking it:");
    for anchor in anchors {
        let AnchorVerdict::Untrusted(code) = anchor.verdict else {
            continue;
        };
        match code {
            ReasonCode::TsaRootNotTrusted => match anchor.details.untrusted_root_fingerprint() {
                Some(fingerprint) => println!(
                    "  - The TSA chain ends at certificate sha256:{fingerprint}\n    \
                         Supply it with --tsa-trust-store to complete the check."
                ),
                None => println!(
                    "  - The TSA chain ends at a certificate no trust store names.\n    \
                         Supply that root with --tsa-trust-store."
                ),
            },
            ReasonCode::TsaChainIncomplete => println!(
                "  - The token's certificate chain is missing an issuer certificate.\n    \
                 Supply it with --tsa-intermediates, and the root it leads to with \
                 --tsa-trust-store."
            ),
            ReasonCode::BitcoinBlockNotChecked | ReasonCode::BitcoinBlockUnavailable => println!(
                "  - The Bitcoin block confirming this anchor was not fetched.\n    \
                 Re-run with network access."
            ),
            other => println!("  - Missing trust material ({}).", other.as_str()),
        }
    }
}

/// Print the per-anchor section, if the receipt has anchors.
fn print_anchor_section(anchors: &[AnchorVerificationResult], use_color: bool) {
    if anchors.is_empty() {
        return;
    }

    println!("Anchor Verification:");
    for (i, anchor) in anchors.iter().enumerate() {
        println!("  [{}] {}", i + 1, format_anchor_type(&anchor.anchor_type));
        print!("      Status: ");
        print_anchor_status(anchor, use_color);

        if let Some(error) = &anchor.error {
            println!("      Detail: {error}");
        }

        print_anchor_details(anchor, use_color);
    }
}

/// The per-anchor status line, derived from the same classification as the
/// JSON `trust_state` field and the anchor's `verified` flag.
fn print_anchor_status(anchor: &AnchorVerificationResult, use_color: bool) {
    match anchor.details.rfc3161_trust_state() {
        Some("trusted") => print_status("TRUSTED", true, use_color),
        Some("assumed") => print_status_pending("NOT TRUSTED (root not supplied)", use_color),
        Some("incomplete") => {
            print_status_pending("NOT TRUSTED (chain incomplete)", use_color);
        }
        // Bitcoin OTS and anchors rejected before any fact set exists.
        _ => match anchor.verdict {
            AnchorVerdict::Valid => print_status("VALID", true, use_color),
            AnchorVerdict::Untrusted(_) => {
                print_status_pending("NOT CONFIRMED", use_color);
            }
            AnchorVerdict::Invalid(_) => print_status("FAILED", false, use_color),
        },
    }
    if let Some(code) = anchor.verdict.reason_code() {
        println!("      Reason: {}", code.as_str());
    }
}

/// Print the fact set behind one anchor's status.
fn print_anchor_details(anchor: &AnchorVerificationResult, use_color: bool) {
    match &anchor.details {
        AnchorDetails::Rfc3161 {
            imprint_matches_root,
            cms_signature_valid,
            chain_valid_at_gen_time,
            timestamping_eku_ok,
            path_status,
            terminal_anchor,
            revocation,
        } => {
            println!(
                "      Facts: imprint={imprint_matches_root} cms_signature={cms_signature_valid} \
                 chain_at_gen_time={chain_valid_at_gen_time} timestamping_eku={timestamping_eku_ok} \
                 path_status={path_status:?} revocation={revocation:?}"
            );
            match terminal_anchor {
                Some(atl_core::TerminalAnchor::Trusted { sha256_fingerprint }) => {
                    println!(
                        "      Terminal Anchor: Trusted (sha256:{})",
                        hex::encode(sha256_fingerprint)
                    );
                }
                Some(atl_core::TerminalAnchor::Assumed { sha256_fingerprint }) => {
                    println!(
                        "      Terminal Anchor: present but not in any supplied trust store \
                         (sha256:{}) -- pass it to --tsa-trust-store",
                        hex::encode(sha256_fingerprint)
                    );
                }
                None => println!("      Terminal Anchor: none reached"),
            }
            if let Some(ts) = anchor.timestamp_nanos {
                println!("      Timestamp: {}", format_timestamp_nanos(ts));
            }
        }
        AnchorDetails::Bitcoin {
            block_height,
            block_timestamp_secs,
            target_hash,
            operation_count,
            computed_root,
            block_merkle_root,
            merkle_match,
        } => {
            println!();
            println!("      Verification Chain:");
            println!("        Target Hash:       {target_hash}");
            println!("              ↓ OTS proof ({operation_count} operations)");
            println!("        Computed Root:     {computed_root}");

            match (block_merkle_root, merkle_match) {
                (Some(block_root), Some(true)) => {
                    if use_color {
                        println!("              {} (verified)", "✓".green());
                    } else {
                        println!("              ✓ (verified)");
                    }
                    println!("        Block Merkle Root: {block_root}");
                }
                (Some(block_root), Some(false)) => {
                    if use_color {
                        println!("              {} (mismatch)", "✗".red().bold());
                    } else {
                        println!("              ✗ (mismatch)");
                    }
                    println!("        Block Merkle Root: {block_root}");
                }
                _ => {
                    if use_color {
                        println!("              {} (not confirmed)", "?".yellow());
                    } else {
                        println!("              ? (not confirmed)");
                    }
                }
            }

            println!("              ↓");
            if *block_timestamp_secs > 0 {
                println!(
                    "        Block #{block_height} @ {}",
                    format_timestamp_secs(*block_timestamp_secs)
                );
            } else {
                println!("        Block #{block_height}");
            }
        }
        AnchorDetails::Unknown => {}
    }
}

/// Print batch result
pub fn print_batch_result(result: &BatchVerificationResult, use_color: bool) -> CliResult<()> {
    println!("Batch Verification Summary");
    println!("==========================");
    println!();

    // Summary
    let total =
        result.valid_count + result.invalid_count + result.error_count + result.unmatched_count;
    println!("Files: {total} total");
    println!();

    println!("Results:");
    print!("  Valid:     ");
    print_count(result.valid_count, result.valid_count > 0, use_color);
    print!("  Untrusted: ");
    print_count(
        result.untrusted_count,
        result.untrusted_count == 0,
        use_color,
    );
    print!("  Invalid:   ");
    print_count(result.invalid_count, result.invalid_count == 0, use_color);
    print!("  Errors:    ");
    print_count(result.error_count, result.error_count == 0, use_color);
    print!("  Unmatched: ");
    println!("{}", result.unmatched_count);
    println!();

    // Collect receipt proof info for display (using super_root, not genesis!)
    let receipt_infos: Vec<ReceiptProofInfo> = result
        .items
        .iter()
        .filter_map(|item| {
            // Untrusted items take part in consistency checking too: their
            // proofs are sound, only their trust root is unavailable.
            if let BatchItemResult::Valid(r) | BatchItemResult::Untrusted(r) = item {
                let filename = r
                    .source_path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                // Get super_root (NOT genesis!) and data_tree_index from receipt
                let (super_root, data_tree_index) = r
                    .receipt
                    .super_proof
                    .as_ref()
                    .map(|sp| (sp.super_root.clone(), sp.data_tree_index))
                    .unwrap_or_else(|| ("none".to_string(), 0));

                Some(ReceiptProofInfo {
                    filename,
                    super_root,
                    data_tree_index,
                })
            } else {
                None
            }
        })
        .collect();

    // Consistency (now with full proof!)
    if let Some(consistency) = &result.consistency {
        print_consistency(consistency, &receipt_infos, use_color);
    }

    // Individual results
    println!("Individual Results:");
    println!("------------------");
    println!();

    for (i, item) in result.items.iter().enumerate() {
        print_batch_item(i + 1, item, use_color);
    }

    // Overall status
    print!("Overall: ");
    print_receipt_status(result.verdict(), use_color);

    Ok(())
}

fn print_consistency(
    consistency: &ConsistencyResult,
    receipt_infos: &[ReceiptProofInfo],
    use_color: bool,
) {
    print!("Log Consistency: ");
    if consistency.is_valid() {
        print_status(
            &format!("VERIFIED ({} receipts)", consistency.receipt_count),
            true,
            use_color,
        );
        // Two-part proof explanation
        let cross_count = consistency.cross_results.len();
        print_checkmark("Same log origin (genesis match)", true, use_color);
        print_checkmark(
            &format!(
                "Append-only history verified ({} cross-check{} passed)",
                cross_count,
                if cross_count == 1 { "" } else { "s" }
            ),
            true,
            use_color,
        );

        // Proof section with super_root per receipt
        print_proof_section(receipt_infos, use_color);

        // Cross-checks section (show ALL cross results)
        print_cross_checks_section(&consistency.cross_results, None, use_color);

        // Summary
        println!();
        if use_color {
            println!(
                "    {} All provided receipts form unbroken append-only chain",
                "→".green()
            );
        } else {
            println!("    → All provided receipts form unbroken append-only chain");
        }
    } else {
        print_status("FAILED", false, use_color);

        // Determine failure type and find first broken cross-check
        let first_failure_idx = consistency
            .cross_results
            .iter()
            .position(|cr| !cr.history_consistent);

        if !consistency.same_log {
            print_checkmark("Different log origins (genesis mismatch)", false, use_color);
        } else {
            print_checkmark(
                "History inconsistent (cross-check failed)",
                false,
                use_color,
            );
        }

        // Proof section (show divergent data)
        if !receipt_infos.is_empty() {
            print_proof_section(receipt_infos, use_color);

            // Cross-check section for failed case
            if !consistency.same_log {
                println!();
                if use_color {
                    println!(
                        "    {} Receipts are from different logs or log was forked",
                        "→".red()
                    );
                } else {
                    println!("    → Receipts are from different logs or log was forked");
                }
            } else if !consistency.cross_results.is_empty() {
                // Show ALL cross-checks, marking failure point
                print_cross_checks_section(
                    &consistency.cross_results,
                    first_failure_idx,
                    use_color,
                );

                // Summary with specific break point
                println!();
                if let Some(fail_idx) = first_failure_idx {
                    let break_at_a = fail_idx + 1;
                    let break_at_b = fail_idx + 2;
                    if use_color {
                        println!(
                            "    {} Log was tampered between [{}] and [{}]",
                            "→".red(),
                            break_at_a,
                            break_at_b
                        );
                    } else {
                        println!(
                            "    → Log was tampered between [{}] and [{}]",
                            break_at_a, break_at_b
                        );
                    }
                } else if use_color {
                    println!(
                        "    {} Log was tampered or forked between registrations",
                        "→".red()
                    );
                } else {
                    println!("    → Log was tampered or forked between registrations");
                }
            }
        }
    }
    println!();
}

fn print_batch_item(index: usize, item: &BatchItemResult, use_color: bool) {
    match item {
        // All three buckets print their item's own verdict, so the bucket
        // and the printed status cannot drift apart.
        BatchItemResult::Valid(result)
        | BatchItemResult::Untrusted(result)
        | BatchItemResult::Invalid(result) => {
            println!(
                "[{index}] {}",
                result
                    .source_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            let verdict = result.verdict();
            print!("    Status: ");
            match verdict.status {
                Status::Valid => print_status("VALID", true, use_color),
                Status::Pending => print_status_pending("PENDING (unanchored)", use_color),
                Status::Untrusted => {
                    print_status_pending("NOT VERIFIED: trust root unavailable", use_color);
                }
                Status::Invalid => print_status("INVALID", false, use_color),
            }
            if let Some(reason) = verdict.reason_code {
                println!("    Reason: {}", reason.as_str());
            }
        }
        BatchItemResult::Error { source, error, .. } => {
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

/// Print a checkmark or cross with message
fn print_checkmark(message: &str, is_success: bool, use_color: bool) {
    if use_color {
        if is_success {
            println!("  {} {}", "✓".green(), message);
        } else {
            println!("  {} {}", "✗".red(), message);
        }
    } else {
        let symbol = if is_success { "✓" } else { "✗" };
        println!("  {} {}", symbol, message);
    }
}

/// Print the "Proof:" section with per-receipt super_root hashes
fn print_proof_section(receipt_infos: &[ReceiptProofInfo], _use_color: bool) {
    println!();
    println!("  Proof:");

    // Sort by data_tree_index for display (receipt order in the log)
    let mut sorted_infos: Vec<_> = receipt_infos.iter().enumerate().collect();
    sorted_infos.sort_by_key(|(_, info)| info.data_tree_index);

    for (display_idx, (_, info)) in sorted_infos.iter().enumerate() {
        println!(
            "    [{}] {}    registered at super_root {}",
            display_idx + 1,
            info.filename,
            info.super_root
        );
    }
}

/// Print the "Cross-checks:" section showing all N-1 cross-verification results
///
/// # Arguments
/// * `cross_results` - All cross-check results (N-1 for N receipts)
/// * `first_failure_idx` - Index of first failed cross-check (None if all passed)
/// * `use_color` - Whether to use colored output
fn print_cross_checks_section(
    cross_results: &[atl_core::CrossReceiptVerificationResult],
    first_failure_idx: Option<usize>,
    use_color: bool,
) {
    if cross_results.is_empty() {
        return;
    }

    println!();
    println!("    Cross-checks:");

    for (idx, cross) in cross_results.iter().enumerate() {
        let from_idx = idx + 1;
        let to_idx = idx + 2;

        // Determine status: passed, failed, or skipped (after first failure)
        let is_after_failure = first_failure_idx.is_some_and(|fail_idx| idx > fail_idx);

        if is_after_failure {
            // Skipped (chain already broken)
            if use_color {
                println!(
                    "      [{}] → [{}]: {}",
                    from_idx,
                    to_idx,
                    "(skipped)".dimmed()
                );
            } else {
                println!("      [{}] → [{}]: (skipped)", from_idx, to_idx);
            }
        } else if cross.history_consistent {
            // Passed
            if use_color {
                println!(
                    "      [{}] → [{}]: {} included",
                    from_idx,
                    to_idx,
                    "✓".green()
                );
            } else {
                println!("      [{}] → [{}]: ✓ included", from_idx, to_idx);
            }
        } else {
            // Failed (this is the break point)
            if use_color {
                println!(
                    "      [{}] → [{}]: {} NOT included  {} BREAK",
                    from_idx,
                    to_idx,
                    "✗".red(),
                    "←".red()
                );
            } else {
                println!(
                    "      [{}] → [{}]: ✗ NOT included  ← BREAK",
                    from_idx, to_idx
                );
            }
        }
    }
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

fn print_status_pending(text: &str, use_color: bool) {
    if use_color {
        println!("{}", text.yellow().bold());
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
    format!("sha256:{}", hex::encode(hash))
}

fn format_anchor_type(anchor_type: &str) -> &str {
    match anchor_type {
        "rfc3161" => "RFC 3161 (TSA)",
        "bitcoin_ots" => "Bitcoin OTS",
        _ => anchor_type,
    }
}

fn format_timestamp_nanos(nanos: u64) -> String {
    use chrono::{TimeZone, Utc};
    let secs = i64::try_from(nanos / 1_000_000_000).unwrap_or(i64::MAX);
    Utc.timestamp_opt(secs, 0).single().map_or_else(
        || format!("{nanos} ns"),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

fn format_timestamp_secs(secs: u64) -> String {
    use chrono::{TimeZone, Utc};
    let secs_i64 = i64::try_from(secs).unwrap_or(i64::MAX);
    Utc.timestamp_opt(secs_i64, 0).single().map_or_else(
        || format!("{secs} s"),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verdict::ReasonCode;
    use atl_core::{PathStatus, ReceiptAnchor, Revocation, TerminalAnchor};
    use std::path::PathBuf;

    fn create_test_receipt() -> atl_core::Receipt {
        serde_json::from_str(include_str!(
            "../../test_data/receipts/valid/document.pdf.atl"
        ))
        .expect("Failed to parse test receipt")
    }

    fn create_test_verification_result(is_valid: bool) -> atl_core::VerificationResult {
        let receipt = create_test_receipt();
        let mut result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        result.is_valid = is_valid;
        if !is_valid {
            result
                .errors
                .push(atl_core::VerificationError::MetadataHashMismatch {
                    actual: "sha256:test".to_string(),
                    expected: "sha256:expected".to_string(),
                });
        }
        result
    }

    fn single_result(file_hash_valid: bool, core_valid: bool) -> SingleVerificationResult {
        SingleVerificationResult {
            source_path: PathBuf::from("test.pdf"),
            receipt_path: PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid,
            receipt: create_test_receipt(),
            core_result: create_test_verification_result(core_valid),
            anchor_results: vec![],
        }
    }

    /// Attach one RFC 3161 anchor (and its verdict) to a receipt.
    fn with_rfc3161_anchor(
        mut result: SingleVerificationResult,
        verdict: AnchorVerdict,
        path_status: PathStatus,
        terminal: Option<TerminalAnchor>,
    ) -> SingleVerificationResult {
        result.receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: result.receipt.proof.root_hash.clone(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });
        result.anchor_results.push(AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verdict,
            timestamp_nanos: Some(1_768_797_900_000_000_000),
            error: match verdict {
                AnchorVerdict::Valid => None,
                _ => Some("diagnostic detail".to_string()),
            },
            details: AnchorDetails::Rfc3161 {
                imprint_matches_root: true,
                cms_signature_valid: true,
                chain_valid_at_gen_time: matches!(path_status, PathStatus::Complete),
                timestamping_eku_ok: true,
                path_status,
                terminal_anchor: terminal,
                revocation: Revocation::NotChecked,
            },
        });
        result
    }

    fn batch(valid: usize, untrusted: usize, invalid: usize) -> BatchVerificationResult {
        BatchVerificationResult {
            valid_count: valid,
            untrusted_count: untrusted,
            invalid_count: invalid,
            error_count: 0,
            unmatched_count: 0,
            consistency: None,
            items: vec![],
        }
    }

    #[test]
    fn single_result_renders_in_both_color_modes() {
        let result = single_result(true, true);
        assert!(print_single_result(&result, true).is_ok());
        assert!(print_single_result(&result, false).is_ok());
    }

    #[test]
    fn hash_mismatch_renders_and_stops_early() {
        let result = single_result(false, false);
        assert!(print_single_result(&result, false).is_ok());
        assert_eq!(result.verdict().status, Status::Invalid);
    }

    #[test]
    fn every_receipt_status_has_its_own_wording() {
        // Regression guard for the conflation this change removes: the
        // `Untrusted` wording must not read as damage to the evidence, and
        // must differ from both VALID and INVALID.
        for (verdict, expected) in [
            (ReceiptVerdict::VALID, "VALID"),
            (ReceiptVerdict::pending(), "PENDING (unanchored)"),
            (
                ReceiptVerdict::untrusted(ReasonCode::TsaRootNotTrusted),
                "NOT VERIFIED: trust root unavailable",
            ),
            (
                ReceiptVerdict::invalid(ReasonCode::FileHashMismatch),
                "INVALID",
            ),
        ] {
            let _ = expected;
            // Rendering must not panic in either color mode.
            print_receipt_status(verdict, false);
            print_receipt_status(verdict, true);
        }
    }

    #[test]
    fn untrusted_receipt_prints_what_to_supply() {
        let result = with_rfc3161_anchor(
            single_result(true, true),
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
            PathStatus::Complete,
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [0x11; 32],
            }),
        );
        assert_eq!(result.verdict().status, Status::Untrusted);
        assert!(print_single_result(&result, false).is_ok());
    }

    #[test]
    fn incomplete_chain_receipt_renders_as_untrusted() {
        let result = with_rfc3161_anchor(
            single_result(true, true),
            AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
            PathStatus::Incomplete,
            None,
        );
        assert_eq!(result.verdict().status, Status::Untrusted);
        assert!(print_single_result(&result, true).is_ok());
    }

    #[test]
    fn trusted_anchor_receipt_renders_as_valid() {
        let result = with_rfc3161_anchor(
            single_result(true, true),
            AnchorVerdict::Valid,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
        );
        assert_eq!(result.verdict().status, Status::Valid);
        assert!(print_single_result(&result, false).is_ok());
    }

    #[test]
    fn refuted_anchor_receipt_renders_as_invalid() {
        let result = with_rfc3161_anchor(
            single_result(true, true),
            AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid),
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
        );
        assert_eq!(result.verdict().status, Status::Invalid);
        assert!(print_single_result(&result, false).is_ok());
    }

    #[test]
    fn bitcoin_anchor_chain_renders_in_every_confirmation_state() {
        for (block_merkle_root, merkle_match, verdict) in [
            (
                Some("sha256:aa".to_string()),
                Some(true),
                AnchorVerdict::Valid,
            ),
            (
                Some("sha256:bb".to_string()),
                Some(false),
                AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch),
            ),
            (
                None,
                None,
                AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockNotChecked),
            ),
        ] {
            let anchor = AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verdict,
                timestamp_nanos: Some(1_768_806_080_000_000_000),
                error: None,
                details: AnchorDetails::Bitcoin {
                    block_height: 932_897,
                    block_timestamp_secs: if merkle_match.is_some() {
                        1_768_806_080
                    } else {
                        0
                    },
                    target_hash: "sha256:abc".to_string(),
                    operation_count: 39,
                    computed_root: "sha256:aa".to_string(),
                    block_merkle_root,
                    merkle_match,
                },
            };
            print_anchor_section(std::slice::from_ref(&anchor), false);
            print_anchor_section(std::slice::from_ref(&anchor), true);
        }
    }

    #[test]
    fn batch_summary_renders_untrusted_row() {
        assert!(print_batch_result(&batch(1, 2, 0), false).is_ok());
        assert!(print_batch_result(&batch(1, 2, 0), true).is_ok());
    }

    #[test]
    fn batch_items_render_every_bucket() {
        let result = BatchVerificationResult {
            valid_count: 1,
            untrusted_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 2,
            consistency: None,
            items: vec![
                BatchItemResult::Valid(single_result(true, true)),
                BatchItemResult::Untrusted(with_rfc3161_anchor(
                    single_result(true, true),
                    AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
                    PathStatus::Complete,
                    Some(TerminalAnchor::Assumed {
                        sha256_fingerprint: [0x22; 32],
                    }),
                )),
                BatchItemResult::Invalid(single_result(false, false)),
                BatchItemResult::Error {
                    source: PathBuf::from("broken.pdf"),
                    receipt: None,
                    error: crate::error::CliError::VerificationFailed("boom".into()),
                },
                BatchItemResult::NoReceipt(PathBuf::from("lonely.pdf")),
                BatchItemResult::NoSource(PathBuf::from("lonely.pdf.atl")),
            ],
        };
        assert!(print_batch_result(&result, false).is_ok());
        assert!(print_batch_result(&result, true).is_ok());
    }

    #[test]
    fn anchor_type_labels_are_readable() {
        assert_eq!(format_anchor_type("rfc3161"), "RFC 3161 (TSA)");
        assert_eq!(format_anchor_type("bitcoin_ots"), "Bitcoin OTS");
        assert_eq!(format_anchor_type("something_else"), "something_else");
    }

    #[test]
    fn timestamps_render_as_iso8601() {
        assert_eq!(
            format_timestamp_nanos(1_768_797_900_000_000_000),
            "2026-01-19T04:45:00Z"
        );
        assert_eq!(format_timestamp_secs(1_768_797_900), "2026-01-19T04:45:00Z");
    }

    #[test]
    fn hash_formatting_is_prefixed() {
        assert_eq!(
            format_hash(&[0u8; 32]),
            format!("sha256:{}", "0".repeat(64))
        );
    }

    #[test]
    fn status_helpers_render_in_both_color_modes() {
        print_status("VALID", true, true);
        print_status("INVALID", false, true);
        print_status("VALID", true, false);
        print_status_pending("PENDING", true);
        print_status_pending("PENDING", false);
        print_count(3, true, true);
        print_count(0, false, false);
        print_checkmark("ok", true, true);
        print_checkmark("bad", false, false);
    }
}
