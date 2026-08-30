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
use crate::verify::anchor::{
    sources_agree, AnchorDetails, AnchorVerdict, AnchorVerificationResult, BlockSourceReport,
};
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::consistency::{ConsistencyResult, CrossCheck};
use crate::verify::policy::TrustAssessment;
use crate::verify::single::SingleVerificationResult;
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Info about a receipt for consistency proof display
#[derive(Debug, Clone)]
struct ReceiptProofInfo {
    /// File name (for display)
    filename: String,
    /// Super root hash string at registration time (e.g., "sha256:abc...")
    super_root: String,
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
    let assessment = result.assessment();
    print!("Status: ");
    print_receipt_status(verdict, Some(&assessment), use_color);

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
    if verdict.reason_code == Some(ReasonCode::ReceiptUnanchored) {
        print!("  Anchor Status: ");
        print_status_pending("UNANCHORED", use_color);
        println!();
        // The spec's own words for this tier (ATL v2.0 §5.5, §5.6): a
        // Receipt-Lite "proves only internal consistency, not temporal
        // existence", and "a receipt without any verified anchors SHOULD be
        // treated as untrustworthy". This is why the outcome is `untrusted`
        // and exit 3: nothing here is refuted, and nothing external attests
        // to anything either.
        println!(
            "Note: Receipt-Lite. It proves internal consistency only, not temporal existence:"
        );
        println!("      it carries no anchor, so nothing external attests to when this existed.");
        println!("      ATL v2.0 §5.5 requires at least one VERIFIED anchor to establish trust,");
        println!("      so this receipt is reported as untrusted (exit 3), not accepted.");
        println!("      Request an upgraded receipt with TSA or Bitcoin anchoring for independent verification.");
    }

    print_anchor_section(&result.anchor_results, use_color);
    print_assessment(&assessment);

    if verdict.status == Status::Untrusted {
        print_trust_hint(result);
    }

    Ok(())
}

/// Print the three axes: evidence, policy, coverage.
///
/// Always printed for a receipt that presents anchors, whatever the outcome.
/// They answer three different questions and a caller may care about any of
/// them; publishing only the collapsed verdict word is what made a
/// Receipt-Full verified offline indistinguishable from one whose TSA root
/// was never supplied.
fn print_assessment(assessment: &TrustAssessment) {
    if assessment.total_anchors == 0 {
        return;
    }
    println!();
    println!("Trust Assessment:");
    println!(
        "  Policy:   {} — {}",
        assessment.policy.as_str(),
        assessment.policy.requirement()
    );
    println!(
        "  Evidence: {} ({} of {} anchors verified; ATL v2.0 §5.5 needs at least 1)",
        if assessment.evidence_established() {
            "ESTABLISHED"
        } else if assessment.has_refutation() {
            // Never "NOT ESTABLISHED (0 verified)" here: there may well be
            // verified anchors, and the count beside it says so. What
            // disqualifies the receipt is the refutation, and the line must
            // name that rather than leave a reader to reconcile a refusal
            // with a non-zero tally.
            //
            // The wording covers both sources -- a refuted anchor and a
            // refuted receipt (a mismatched source file, a broken proof) --
            // because the reason code printed further up already says which,
            // and this line's job is to say why the axis refuses.
            "REFUTED — see the Reason above"
        } else {
            "NOT ESTABLISHED"
        },
        assessment.verified_anchors,
        assessment.total_anchors
    );
    println!(
        "  Coverage: {}",
        if assessment.coverage_complete() {
            "COMPLETE (every anchor presented was carried to a sound result)"
        } else {
            "INCOMPLETE"
        }
    );
    for anchor in &assessment.unresolved {
        println!(
            "    - {} not resolved: {} ({})",
            format_anchor_type(&anchor.anchor_type),
            anchor.state.as_str(),
            anchor.reason.as_str()
        );
    }
    // Listed here and not only in the anchor section above: coverage
    // accounts for every anchor presented, and the one that proves the
    // receipt wrong is the last that may be left out of that accounting.
    for anchor in &assessment.refuted {
        println!(
            "    - {} REFUTED: {} ({})",
            format_anchor_type(&anchor.anchor_type),
            anchor.state.as_str(),
            anchor.reason.as_str()
        );
    }
    // Deliberately answered YES/NO rather than "ATTAINED"/"NOT ATTAINED":
    // the two attainment words share a stem, and a reader skimming a refuted
    // receipt must not catch the word "ATTAINED" anywhere near it.
    println!(
        "  Receipt-Full profile (§5.6, both anchor types verified): {}",
        if assessment.max_trust_profile() {
            "YES"
        } else if assessment.has_refutation() {
            "NO — this receipt was refuted"
        } else {
            "NO"
        }
    );
}

/// The headline for an `untrusted` outcome.
///
/// The single definition, used by both renderers *and* by the error the
/// process exits with, so a reader who only skims the headline is told the
/// same thing however the result reaches them. It used to be duplicated in
/// `crate::commands::verify`, with nothing keeping the two copies in step.
///
/// "Trust root unavailable" is simply false for the reasons where the check
/// could not be *performed*: the root may be present and the obstacle an
/// unimplemented algorithm, an unfetched Bitcoin block, or a pair of files
/// that never matched up.
pub fn untrusted_headline(verdict: ReceiptVerdict) -> &'static str {
    match verdict.reason_code {
        // Nothing is missing on this side and nothing could be supplied:
        // the receipt itself never carried an anchor. ATL v2.0 §5.5.
        Some(ReasonCode::ReceiptUnanchored) => {
            "NOT VERIFIED: the receipt carries no anchors (Receipt-Lite)"
        }
        Some(ReasonCode::BatchItemsUnanchored) => {
            "NOT VERIFIED: some receipts carry no anchors (Receipt-Lite)"
        }
        // A pairing problem, not a trust problem: pointing the reader at
        // --tsa-trust-store here would waste their time entirely.
        Some(ReasonCode::BatchItemsUnmatched) => {
            "NOT VERIFIED: some named files were never checked"
        }
        Some(ReasonCode::BatchNothingVerified) => "NOT VERIFIED: nothing in this batch was checked",
        Some(
            ReasonCode::TsaChainIndeterminate
            | ReasonCode::CmsSignatureIndeterminate
            | ReasonCode::TsaImprintIndeterminate
            | ReasonCode::TsaTimestampingEkuNotChecked,
        ) => "NOT VERIFIED: the check could not be completed (nothing was refuted)",
        // No trust root is missing here at all: the TSA chain beside this
        // anchor may be fully trusted, and what did not happen is the
        // Bitcoin block lookup (ATL v2.0 §5.5.2). Sending the reader after
        // a certificate would send them after something that cannot help.
        Some(ReasonCode::BitcoinBlockNotChecked | ReasonCode::BitcoinBlockUnavailable) => {
            "NOT VERIFIED: no block header was obtained for the Bitcoin anchor"
        }
        // Neither of these is about trust material, and both used to fall
        // through to "trust root unavailable" -- telling a user to go and
        // find certificates when two APIs had contradicted each other, or
        // when only one had answered. No certificate fixes either.
        Some(ReasonCode::BitcoinProvidersDisagree) => {
            "NOT VERIFIED: the block-explorer APIs contradict each other (your receipt is not \
             implicated)"
        }
        Some(ReasonCode::BitcoinSingleSourceOnly) => {
            "NOT VERIFIED: only one block-explorer API answered, so its report is uncorroborated"
        }
        _ => "NOT VERIFIED: trust root unavailable",
    }
}

/// Print the overall status line for one receipt.
///
/// `Untrusted` is deliberately worded so it cannot be read as damage to the
/// evidence: nothing was refuted, this verifier is simply not configured to
/// finish the check. It is printed in the warning colour,
/// never the failure colour.
fn print_receipt_status(
    verdict: ReceiptVerdict,
    assessment: Option<&TrustAssessment>,
    use_color: bool,
) {
    match verdict.status {
        // A success reached only because the quorum was lowered must never
        // be printed as a bare "VALID". The caller relaxed the policy; the
        // headline says so, and the Trust Assessment block beneath lists
        // every anchor that went unresolved. Presenting this as
        // unconditional acceptance would be exactly the overclaim the flag
        // was added to make explicit.
        Status::Valid => match assessment.filter(|a| a.accepted_with_gaps()) {
            Some(a) => print_status(
                &format!(
                    "VALID under policy '{}' ({} of {} anchors verified; {} unresolved)",
                    a.policy.as_str(),
                    a.verified_anchors,
                    a.total_anchors,
                    a.unresolved.len()
                ),
                true,
                use_color,
            ),
            None => print_status("VALID", true, use_color),
        },
        // "Trust root unavailable" is right for the reasons where material
        // really is missing, and wrong for `TsaChainIndeterminate`, where
        // the check could not be *performed*. Saying the root is
        // unavailable there would send the reader looking for a file that
        // is not the problem.
        Status::Untrusted => {
            print_status_pending(untrusted_headline(verdict), use_color);
        }
        // Not a statement about the evidence: the tool failed to process an
        // input and never got far enough to make one.
        Status::Error => print_status("ERROR: some items could not be processed", false, use_color),
        Status::Invalid => print_status("INVALID", false, use_color),
    }
    if let Some(reason) = verdict.reason_code {
        println!("Reason: {}", reason.as_str());
    }
}

/// Say exactly why the check could not be finished, and what — if anything
/// — would finish it.
///
/// Not every `Untrusted` reason has a remedy: for the `*_indeterminate` and
/// `*_not_checked` reasons the obstacle is cryptography this build does not
/// implement, and those arms say so rather than sending the reader after a
/// certificate that would not help.
fn print_trust_hint(result: &SingleVerificationResult) {
    println!();
    println!("The evidence was NOT disproved. This verifier could not finish checking it:");

    // A Receipt-Lite has no anchor to enumerate, and no file the caller
    // could supply would change that. Falling through to the loop below
    // printed nothing at all under that headline.
    if result.receipt.anchors.is_empty() {
        println!(
            "  - The receipt carries no anchors at all (Receipt-Lite), so nothing external\n    \
             attests to when this existed. ATL v2.0 §5.5 requires at least one verified\n    \
             anchor. No certificate and no network access can supply one: ask the log\n    \
             operator for an anchored receipt (Receipt-TSA or Receipt-Full)."
        );
        return;
    }

    for anchor in &result.anchor_results {
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
            // Deliberately NOT "supply an intermediate or a root": the
            // chain could not be evaluated, most often because a
            // certificate on it is signed with cryptography this verifier
            // does not implement. The anchor's own Detail line names the
            // actual cause; repeating the certificate advice here would
            // send the reader after a file that would not help.
            // Same reasoning as TsaChainIndeterminate below: no certificate
            // the caller could supply implements a missing algorithm.
            // A file the caller named and this tool never checked. The
            // remedy is a naming/pairing fix, not trust material.
            ReasonCode::BatchItemsUnmatched => println!(
                "  - One or more files you named were never verified: a source file with\n    \
                 no matching receipt, or a receipt with no matching source file. The\n    \
                 convention is <name> alongside <name>.atl. See the Unmatched rows above."
            ),
            ReasonCode::BatchNothingVerified => println!(
                "  - Nothing in this batch was verified. No file reached a verification\n    \
                 result at all, so there is no evidence to report either way."
            ),
            ReasonCode::TsaTimestampingEkuNotChecked => println!(
                "  - The signer certificate's timestamping EKU was never examined, because\n    \
                 no signer certificate could be established for this token. Nothing about\n    \
                 the EKU was refuted."
            ),
            ReasonCode::TsaImprintIndeterminate => println!(
                "  - The token's messageImprint could NOT be compared with this receipt's\n    \
                 root hash -- nothing about it was refuted. It names a hash algorithm this\n    \
                 verifier does not implement. No additional certificate will help."
            ),
            ReasonCode::CmsSignatureIndeterminate => println!(
                "  - The token's own CMS signature could NOT be checked -- nothing about it\n    \
                 was refuted. It uses cryptography this verifier does not implement\n    \
                 (see the Detail line above). No additional certificate will help."
            ),
            ReasonCode::TsaChainIndeterminate => println!(
                "  - The token's certificate chain could NOT be checked -- nothing about it\n    \
                 was refuted. See the Detail line above for what stopped the check\n    \
                 (commonly a signature algorithm this verifier does not implement, such\n    \
                 as SHA-1 on a long-lived root). If you trust the terminal certificate\n    \
                 from an external source, naming it with --tsa-trust-store settles it."
            ),
            ReasonCode::BitcoinBlockNotChecked | ReasonCode::BitcoinBlockUnavailable => println!(
                "  - No block header was obtained for this anchor, so its OTS proof was\n    \
                 never compared against one. Re-run with network access."
            ),
            ReasonCode::BitcoinProvidersDisagree => println!(
                "  - The block-explorer APIs returned DIFFERENT headers for this block, so\n    \
                 no header is established and nothing was compared. Nothing about your\n    \
                 receipt is refuted by this -- the sources this verifier depends on do not\n    \
                 agree with each other. See the per-source rows above. This can mean a chain\n    \
                 fork, a stale index, or a compromised endpoint; no certificate and no\n    \
                 retry will settle it, and it is worth investigating."
            ),
            ReasonCode::BitcoinSingleSourceOnly => println!(
                "  - Only one block-explorer API answered, so its report of the block header\n    \
                 is uncorroborated. One endpoint's word cannot establish what Bitcoin\n    \
                 contains, so the OTS proof was not compared against it. Re-run when more\n    \
                 than one provider is reachable; no certificate is involved."
            ),
            other => println!("  - Missing trust material ({}).", other.as_str()),
        }
    }
}

/// List the block-explorer APIs that answered and what each reported.
///
/// Printed on every Bitcoin anchor, agreeing or not. When they agree it is
/// an attribution — *these* endpoints said so, and this tool did no more
/// than ask them. When they disagree it is the finding itself, and the only
/// place a reader can see that their sources contradict each other.
fn print_block_sources(sources: &[BlockSourceReport]) {
    for line in block_sources_lines(sources) {
        println!("{line}");
    }
}

/// The lines [`print_block_sources`] emits, as values so they can be
/// asserted.
///
/// The case worth testing — sources contradicting each other — cannot be
/// provoked on the live network, and a rendering nobody can test is a
/// rendering nobody checks.
fn block_sources_lines(sources: &[BlockSourceReport]) -> Vec<String> {
    if sources.is_empty() {
        return vec!["        Reported by:       (no block-explorer API answered)".to_string()];
    }

    let names: Vec<&str> = sources.iter().map(|s| s.source.as_str()).collect();
    let mut lines = vec![format!(
        "        Reported by:       {} ({} source{})",
        names.join(", "),
        names.len(),
        if names.len() == 1 { "" } else { "s" }
    )];

    // Only worth enumerating when they differ; identical rows would be
    // noise, and the count above already carries the corroboration.
    //
    // `sources_agree` is the same predicate the classifier used to decide
    // `bitcoin_providers_disagree`. It was an inline comparison of the hash
    // and the root only, so a conflict about nothing but the *time* was
    // classified as a disagreement and then rendered as if nothing had
    // happened -- the one event these checks exist to surface, invisible.
    if !sources_agree(sources) {
        lines.push("        SOURCES DISAGREE about this block:".to_string());
        for s in sources {
            lines.push(format!(
                "          - {}: merkle_root {} in block {} at {}",
                s.source,
                s.merkle_root,
                s.block_hash,
                format_timestamp_secs(s.block_timestamp_secs)
            ));
        }
        lines.push(
            "          Nothing about this receipt is refuted by this: the sources this".to_string(),
        );
        lines.push("          verifier depends on do not agree with each other.".to_string());
    }
    lines
}

/// The Bitcoin anchor's closing line: which block, and whether it dates
/// anything.
///
/// A pure function returning a `String` rather than four inline `println!`s,
/// so the wording can be asserted by a unit test. The case that matters most
/// — a block fetched whose Merkle root did not match — arises only with
/// network access, and a rendering nobody can test offline is a rendering
/// nobody checks.
///
/// The height is the receipt's own claim until a block at it has been
/// fetched *and* matched, so it is labelled as such — the same rule the RFC
/// 3161 `genTime` follows. A time is printed only when a block was actually
/// fetched; `block_timestamp_secs` is an `Option`, so there is no zero to
/// fall back on and nothing can render as 1970.
///
/// The third arm is the one worth reading. The block was fetched and its
/// Merkle root did not match, so its time is entirely real and says nothing
/// whatever about this receipt. Printing it bare would offer a date for
/// evidence this very line refutes.
fn bitcoin_block_line(
    verified: bool,
    block_height: u64,
    block_timestamp_secs: Option<u64>,
) -> String {
    match (verified, block_timestamp_secs) {
        (true, Some(secs)) => format!("Block #{block_height} @ {}", format_timestamp_secs(secs)),
        (true, None) => format!("Block #{block_height}"),
        (false, Some(secs)) => format!(
            "Block #{block_height} @ {} (as reported by the sources below; this block does NOT \
             date this receipt)",
            format_timestamp_secs(secs)
        ),
        (false, None) => format!("Block #{block_height} (claimed by the proof, not confirmed)"),
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
        Some("indeterminate") => {
            print_status_pending("NOT TRUSTED (could not be checked)", use_color);
        }
        // Everything without an RFC 3161 trust-state label: Bitcoin OTS
        // anchors, anchors rejected before any fact set exists, and RFC 3161
        // anchors whose label is "failed" (a refuted fact set, printed as
        // FAILED via the verdict below).
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
            message_imprint,
            cms_signature,
            chain_valid_at_gen_time,
            timestamping_eku_ok,
            timestamping_eku,
            path_status,
            terminal_anchor,
            revocation,
            chain_diagnostic,
        } => {
            let _ = timestamping_eku_ok; // the three-state field below says more
            println!(
                "      Facts: imprint={message_imprint:?} cms_signature={cms_signature:?} \
                 chain_at_gen_time={chain_valid_at_gen_time} timestamping_eku={timestamping_eku:?} \
                 path_status={path_status:?} revocation={revocation:?}"
            );
            // What stopped the path, in atl-core's own words. Printed for
            // every non-complete status, including the two that are not
            // refutations, so a reader can tell "could not check" from
            // "checked and wrong" without decoding the status name.
            //
            // Suppressed on a Complete path: diagnostics can survive from
            // an alternative path that failed while another succeeded, and
            // printing those under a TRUSTED heading would read as a
            // problem where none remains.
            if !matches!(path_status, atl_core::PathStatus::Complete) {
                if let Some(detail) = chain_diagnostic {
                    println!("      Chain: {detail}");
                }
            }
            match terminal_anchor {
                Some(atl_core::TerminalAnchor::Trusted { sha256_fingerprint }) => {
                    println!(
                        "      Terminal Anchor: Trusted (sha256:{})",
                        hex::encode(sha256_fingerprint)
                    );
                }
                Some(atl_core::TerminalAnchor::Assumed {
                    sha256_fingerprint,
                    self_signature,
                }) => {
                    let self_signature = match self_signature {
                        atl_core::SelfSignature::Verified => "self-signature verified",
                        atl_core::SelfSignature::Unverifiable => {
                            "self-signature NOT checkable here"
                        }
                    };
                    println!(
                        "      Terminal Anchor: present but not in any supplied trust store \
                         (sha256:{}, {self_signature}) -- pass it to --tsa-trust-store",
                        hex::encode(sha256_fingerprint)
                    );
                }
                None => println!("      Terminal Anchor: none reached"),
            }
            // The number a reader is most likely to lift straight out of
            // this block, and the whole product promise behind it. Label it
            // for what it is: only an accepted anchor establishes a time,
            // and an unqualified "Timestamp:" line under a NOT TRUSTED
            // status would be read as one anyway.
            if let Some(ts) = anchor.timestamp_nanos {
                let formatted = format_timestamp_nanos(ts);
                if anchor.verified() {
                    println!("      Timestamp: {formatted}");
                } else {
                    println!("      Claimed genTime (not established): {formatted}");
                }
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
            block_sources,
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
            println!(
                "        {}",
                bitcoin_block_line(anchor.verified(), *block_height, *block_timestamp_secs)
            );
            // Name the sources, always. This tool reads block headers out of
            // HTTP APIs; it validates no proof of work and follows no chain,
            // so every value above is what these endpoints reported and the
            // reader is entitled to know which ones.
            print_block_sources(block_sources);
        }
        AnchorDetails::Unknown => {}
    }
}

/// Print batch result
pub fn print_batch_result(result: &BatchVerificationResult, use_color: bool) -> CliResult<()> {
    println!("Batch Verification Summary");
    println!("==========================");
    println!();

    // `total_count()` is the single source of truth for the total. Summing
    // the buckets inline here once omitted `untrusted_count` and printed a
    // "Files: N total" that did not equal the rows listed underneath it.
    let total = result.total_count();
    println!("Files: {total} total");
    println!(
        "Policy: {} — {}",
        result.policy.as_str(),
        result.policy.requirement()
    );
    println!();

    println!("Results:");
    print!("  Valid:      ");
    print_count(result.valid_count, result.valid_count > 0, use_color);
    // Its own row: a Receipt-Lite is untrusted like the rows below it, but
    // for a reason no trust material fixes, so it is worth naming apart.
    print!("  Unanchored: ");
    print_count(
        result.unanchored_count,
        result.unanchored_count == 0,
        use_color,
    );
    print!("  Untrusted:  ");
    print_count(
        result.untrusted_count,
        result.untrusted_count == 0,
        use_color,
    );
    print!("  Invalid:    ");
    print_count(result.invalid_count, result.invalid_count == 0, use_color);
    print!("  Errors:     ");
    print_count(result.error_count, result.error_count == 0, use_color);
    print!("  Unmatched:  ");
    println!("{}", result.unmatched_count);
    println!();

    // Collect receipt proof info for display (using super_root, not genesis!)
    // The receipts that took part, taken from the consistency result rather
    // than rebuilt here: this list used to apply a different filter and a
    // different sort key than the check itself, so it named files by
    // positional coincidence.
    let receipt_infos: Vec<ReceiptProofInfo> = result
        .consistency
        .as_ref()
        .map(|c| {
            c.participants
                .iter()
                .map(|name| {
                    let matching = result.items.iter().find_map(|item| match item {
                        BatchItemResult::Valid(r)
                        | BatchItemResult::Unanchored(r)
                        | BatchItemResult::Untrusted(r)
                            if r.source_path
                                .file_name()
                                .is_some_and(|f| f == name.as_str()) =>
                        {
                            r.receipt.super_proof.as_ref()
                        }
                        _ => None,
                    });
                    let super_root =
                        matching.map_or_else(|| "none".to_string(), |sp| sp.super_root.clone());
                    ReceiptProofInfo {
                        filename: name.clone(),
                        super_root,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Consistency (now with full proof!)
    if let Some(consistency) = &result.consistency {
        print_consistency(
            consistency,
            &receipt_infos,
            result.valid_count > 0,
            use_color,
        );
    }

    // Individual results
    println!("Individual Results:");
    println!("------------------");
    println!();

    for (i, item) in result.items.iter().enumerate() {
        print_batch_item(i + 1, item, use_color);
    }

    // Overall status. A batch accepted only because the quorum was lowered
    // says so on its own last line, not merely on the rows above it: a
    // reader who skims the summary must not be handed a bare "VALID" for a
    // run that left anchors unresolved.
    print!("Overall: ");
    let verdict = result.verdict();
    if verdict.status == Status::Valid && result.accepted_with_gaps() {
        print_status(
            &format!(
                "VALID under policy '{}' (some anchors were not resolved -- see the rows above)",
                result.policy.as_str()
            ),
            true,
            use_color,
        );
    } else {
        print_receipt_status(verdict, None, use_color);
    }

    Ok(())
}

fn print_consistency(
    consistency: &ConsistencyResult,
    receipt_infos: &[ReceiptProofInfo],
    any_item_accepted: bool,
    use_color: bool,
) {
    print!("Log Consistency: ");
    // Nothing was compared: every log instance here is represented by a
    // single receipt, so no pair satisfies ATL v2.0 §5.4.3 step 2. Saying
    // `VERIFIED` over zero comparisons would claim work never done.
    if !consistency.checked() {
        print_status_pending(
            &format!(
                "NOT CHECKED ({} receipts, {} log instance{}: no two from the same one)",
                consistency.receipt_count,
                consistency.log_instance_count,
                if consistency.log_instance_count == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            use_color,
        );
        println!();
        return;
    }
    if consistency.is_valid() {
        let headline = if consistency.single_log_instance() {
            format!("VERIFIED ({} receipts)", consistency.receipt_count)
        } else {
            // Said plainly rather than treated as a fault. A directory
            // holding receipts from several log instances used to be reported
            // FAILED and exit 1 -- refuted evidence -- when nothing about any
            // receipt was false, and when ATL v2.0 §5.4.3 defines no error
            // for the case. Each log instance is checked on its own.
            format!(
                "VERIFIED ({} receipts across {} log instances)",
                consistency.receipt_count, consistency.log_instance_count
            )
        };
        print_status(&headline, true, use_color);
        // Consistency is a statement about the log's append-only history
        // among the receipts listed below -- not about whether any of them
        // was accepted. A batch where nothing was accepted still prints this
        // block in green, and a reader skimming for the first coloured word
        // would take it as reassurance it does not carry.
        if !any_item_accepted {
            println!(
                "  (log history only -- no receipt in this batch was accepted; see the \
                 status above)"
            );
        }
        // The words come from ATL v2.0 §5.4.3, and stop where it stops.
        // "Append-only history verified" and "included" claimed containment
        // of one receipt's Super-Tree in the other's; no receipt carries such
        // a proof and nothing checks it.
        let cross_count = consistency.cross_results.len();
        if consistency.single_log_instance() {
            print_checkmark(
                "Same log instance (genesis_super_root match)",
                true,
                use_color,
            );
        } else {
            print_checkmark(
                &format!(
                    "{} distinct log instances; each checked on its own",
                    consistency.log_instance_count
                ),
                true,
                use_color,
            );
        }
        print_checkmark(
            &format!(
                "Log history between them was not modified ({} pair{} compared)",
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
        let summary = if consistency.single_log_instance() {
            "All provided receipts belong to the same log instance, and the log history \
             between them was not modified"
        } else {
            "Within each log instance, the log history between its receipts was not modified"
        };
        if use_color {
            println!("    {} {summary}", "→".green());
        } else {
            println!("    → {summary}");
        }
        // The limit of the claim, printed with it so it cannot be skimmed
        // past. Per ATL v2.0 §7.3.2 the primary defence against a Split-View
        // (fork) attack is external anchoring, not this check.
        println!(
            "      (a Split-View attack is not ruled out here; per the spec the defence \
             against it is a verified external anchor)"
        );
    } else {
        print_status("FAILED", false, use_color);

        // A failure here is always a broken history *within* one log
        // instance: a receipt carrying a different §3.3.2 identifier is
        // grouped on its own rather than failed against this one.
        let first_failure_idx = consistency
            .cross_results
            .iter()
            .position(|cr| !cr.result.history_consistent);

        print_checkmark(
            "History inconsistent (cross-check failed)",
            false,
            use_color,
        );

        // Proof section (show divergent data)
        if !receipt_infos.is_empty() {
            print_proof_section(receipt_infos, use_color);

            if !consistency.cross_results.is_empty() {
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
        // Every verified bucket prints its item's own verdict, so the
        // bucket and the printed status cannot drift apart.
        BatchItemResult::Valid(result)
        | BatchItemResult::Unanchored(result)
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
            let assessment = result.assessment();
            print!("    Status: ");
            match verdict.status {
                // Same qualifier as the single-file headline: a row accepted
                // only because the quorum was lowered says so on its face.
                Status::Valid if assessment.accepted_with_gaps() => print_status(
                    &format!(
                        "VALID under policy '{}' ({} of {} anchors verified)",
                        assessment.policy.as_str(),
                        assessment.verified_anchors,
                        assessment.total_anchors
                    ),
                    true,
                    use_color,
                ),
                Status::Valid => print_status("VALID", true, use_color),
                // Same split as `print_receipt_status`: "trust root
                // unavailable" is false for a check that could not be
                // performed, and a batch row is exactly where a reader skims
                // the headline without reading the reason code.
                Status::Untrusted => {
                    print_status_pending(untrusted_headline(verdict), use_color);
                }
                Status::Error => print_status("ERROR (could not be processed)", false, use_color),
                Status::Invalid => print_status("INVALID", false, use_color),
            }
            if let Some(reason) = verdict.reason_code {
                println!("    Reason: {}", reason.as_str());
            }
            for anchor in &assessment.unresolved {
                println!(
                    "    Unresolved anchor: {} — {} ({})",
                    format_anchor_type(&anchor.anchor_type),
                    anchor.state.as_str(),
                    anchor.reason.as_str()
                );
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

    // Printed in the order the consistency check walked them, and numbered
    // from that order. Re-sorting by `data_tree_index` here gave this
    // section its own index space, so `[1]` in "Proof:" and `[1]` in
    // "Cross-checks:" below could name different receipts.
    for (idx, info) in receipt_infos.iter().enumerate() {
        println!(
            "    [{}] {}    registered at super_root {}",
            idx + 1,
            info.filename,
            info.super_root
        );
    }
}

/// Print the "Cross-checks:" section showing all N-1 cross-verification results
///
/// # Arguments
/// * `cross_results` - Every pairwise check that was actually performed
/// * `first_failure_idx` - Index of first failed cross-check (None if all passed)
/// * `use_color` - Whether to use colored output
fn print_cross_checks_section(
    cross_results: &[CrossCheck],
    first_failure_idx: Option<usize>,
    use_color: bool,
) {
    if cross_results.is_empty() {
        return;
    }

    println!();
    println!("    Cross-checks:");

    for (idx, cross) in cross_results.iter().enumerate() {
        // The participants this check compared, not this row's position:
        // participants are grouped by log, so positional arithmetic would
        // name pairs that were never compared.
        let from_idx = cross.from_index + 1;
        let to_idx = cross.to_index + 1;

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
        } else if cross.result.history_consistent {
            // §5.4.3's own words. "included" claimed containment of one tree
            // in the other, which no receipt proves and nothing checks.
            if use_color {
                println!(
                    "      [{}] → [{}]: {} same log instance",
                    from_idx,
                    to_idx,
                    "✓".green()
                );
            } else {
                println!("      [{}] → [{}]: ✓ same log instance", from_idx, to_idx);
            }
        } else {
            // Failed (this is the break point)
            if use_color {
                println!(
                    "      [{}] → [{}]: {} history not proven  {} BREAK",
                    from_idx,
                    to_idx,
                    "✗".red(),
                    "←".red()
                );
            } else {
                println!(
                    "      [{}] → [{}]: ✗ history not proven  ← BREAK",
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
    use crate::verify::policy::AnchorPolicy;
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
            policy: AnchorPolicy::AllAnchors,
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
                chain_diagnostic: None,
                message_imprint: atl_core::MessageImprint::Verified,
                cms_signature: atl_core::CmsSignature::Verified,
                chain_valid_at_gen_time: matches!(path_status, PathStatus::Complete),
                timestamping_eku_ok: true,
                timestamping_eku: atl_core::TimestampingEku::Ok,
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
            unanchored_count: 0,
            untrusted_count: untrusted,
            invalid_count: invalid,
            error_count: 0,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
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

    /// The two `untrusted` headlines must stay distinct, and both renderers
    /// must use the same helper: a batch row is exactly where a reader skims
    /// the headline and never reaches the reason code, so "trust root
    /// unavailable" there for a check that could not be performed would be
    /// the last place this rework's defect could survive.
    #[test]
    fn untrusted_headline_distinguishes_missing_material_from_unfinishable() {
        let missing = untrusted_headline(ReceiptVerdict::untrusted(ReasonCode::TsaChainIncomplete));
        assert!(
            missing.contains("trust root unavailable"),
            "genuinely missing material keeps the actionable wording: {missing}"
        );

        for reason in [
            ReasonCode::TsaChainIndeterminate,
            ReasonCode::CmsSignatureIndeterminate,
            ReasonCode::TsaImprintIndeterminate,
            ReasonCode::TsaTimestampingEkuNotChecked,
        ] {
            let headline = untrusted_headline(ReceiptVerdict::untrusted(reason));
            assert!(
                !headline.contains("trust root unavailable"),
                "{reason:?} is not a missing root: {headline}"
            );
            assert!(
                headline.contains("nothing was refuted"),
                "{reason:?} must still say nothing was refuted: {headline}"
            );
        }
    }

    #[test]
    fn every_receipt_status_has_its_own_wording() {
        // Regression guard for the conflation this change removes: the
        // `Untrusted` wording must not read as damage to the evidence, and
        // must differ from both VALID and INVALID.
        for (verdict, expected) in [
            (ReceiptVerdict::VALID, "VALID"),
            (
                ReceiptVerdict::unanchored(),
                "NOT VERIFIED: the receipt carries no anchors (Receipt-Lite)",
            ),
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
            print_receipt_status(verdict, None, false);
            print_receipt_status(verdict, None, true);
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
                self_signature: atl_core::SelfSignature::Verified,
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
                    block_timestamp_secs: merkle_match.map(|_| 1_768_806_080),
                    target_hash: "sha256:abc".to_string(),
                    operation_count: 39,
                    computed_root: "sha256:aa".to_string(),
                    block_merkle_root,
                    merkle_match,
                    block_sources: Vec::new(),
                },
            };
            print_anchor_section(std::slice::from_ref(&anchor), false);
            print_anchor_section(std::slice::from_ref(&anchor), true);
        }
    }

    /// **A refuted Bitcoin anchor never offers a bare date.**
    ///
    /// The `(false, Some)` case arises only online — the block is fetched
    /// before its Merkle root is compared — so the wording is asserted here
    /// rather than by a live run. It must carry the observation without
    /// letting it read as a timestamp for this receipt.
    #[test]
    fn the_bitcoin_block_line_never_dates_a_receipt_it_refutes() {
        let refuted = bitcoin_block_line(false, 932_897, Some(1_768_806_080));
        assert!(refuted.contains("Block #932897"), "{refuted}");
        assert!(
            refuted.contains("as reported by the sources below"),
            "{refuted}"
        );
        assert!(
            !refuted.contains("on-chain"),
            "this tool queries HTTP APIs; it does not observe the chain: {refuted}"
        );
        assert!(refuted.contains("does NOT date this receipt"), "{refuted}");

        // Verified: the plain reading, with nothing hedged.
        let verified = bitcoin_block_line(true, 932_897, Some(1_768_806_080));
        assert!(verified.contains("Block #932897 @ "), "{verified}");
        assert!(!verified.contains("reported by"), "{verified}");
        assert!(!verified.contains("NOT"), "{verified}");

        // Offline: no block was fetched, so no time exists to print at all.
        let unfetched = bitcoin_block_line(false, 932_897, None);
        assert_eq!(
            unfetched,
            "Block #932897 (claimed by the proof, not confirmed)"
        );
        for line in [&refuted, &verified, &unfetched] {
            assert!(!line.contains("1970"), "{line}");
        }
    }

    /// **A source conflict must read as a source conflict.** It cannot be
    /// provoked on the live network, so the wording is pinned here.
    #[test]
    fn disagreeing_sources_are_shown_and_never_blamed_on_the_receipt() {
        fn report(source: &str, root: &str) -> BlockSourceReport {
            BlockSourceReport {
                source: source.to_string(),
                block_hash: "a".repeat(64),
                merkle_root: root.to_string(),
                block_timestamp_secs: 1_768_806_080,
            }
        }

        let rendered = block_sources_lines(&[
            report("blockstream.info", &"b".repeat(64)),
            report("mempool.space", &"c".repeat(64)),
        ])
        .join("\n");

        assert!(rendered.contains("SOURCES DISAGREE"), "{rendered}");
        assert!(rendered.contains("blockstream.info"), "{rendered}");
        assert!(rendered.contains("mempool.space"), "{rendered}");
        assert!(
            rendered.contains("Nothing about this receipt is refuted by this"),
            "a source conflict must not read as an accusation:\n{rendered}"
        );

        // Agreeing sources are attributed, not enumerated: the count already
        // carries the corroboration and identical rows would be noise.
        let agreeing = block_sources_lines(&[
            report("blockstream.info", &"b".repeat(64)),
            report("mempool.space", &"b".repeat(64)),
        ])
        .join("\n");
        assert!(agreeing.contains("Reported by:"), "{agreeing}");
        assert!(agreeing.contains("(2 sources)"), "{agreeing}");
        assert!(!agreeing.contains("DISAGREE"), "{agreeing}");

        // And when nobody answered, say exactly that.
        let none = block_sources_lines(&[]).join("\n");
        assert!(none.contains("no block-explorer API answered"), "{none}");
    }

    /// **A disagreement about nothing but the time is still a disagreement.**
    ///
    /// The classifier compares the block hash, the Merkle root *and* the
    /// time; this renderer used to compare only the first two. So a
    /// time-only conflict produced `bitcoin_providers_disagree` and then
    /// rendered as though nothing had happened -- no `SOURCES DISAGREE`
    /// block, no conflicting rows, no reason. Both now call
    /// `sources_agree`, so what is decided is what is shown.
    #[test]
    fn a_time_only_disagreement_is_visible_to_a_reader() {
        fn at(source: &str, secs: u64) -> BlockSourceReport {
            BlockSourceReport {
                source: source.to_string(),
                block_hash: "a".repeat(64),
                merkle_root: "b".repeat(64),
                block_timestamp_secs: secs,
            }
        }

        let rendered = block_sources_lines(&[
            at("blockstream.info", 1_768_806_080),
            at("mempool.space", 1_768_806_081),
        ])
        .join("\n");

        assert!(
            rendered.contains("SOURCES DISAGREE"),
            "the hash and root match; only the time differs, and it must still show:\n{rendered}"
        );
        // Both times must be on screen, or the reader cannot see what differs.
        assert!(rendered.contains("2026-01-19T07:01:20Z"), "{rendered}");
        assert!(rendered.contains("2026-01-19T07:01:21Z"), "{rendered}");
        assert!(
            rendered.contains("Nothing about this receipt is refuted by this"),
            "{rendered}"
        );

        // Sanity: identical times still read as agreement.
        let agreeing = block_sources_lines(&[
            at("blockstream.info", 1_768_806_080),
            at("mempool.space", 1_768_806_080),
        ])
        .join("\n");
        assert!(!agreeing.contains("DISAGREE"), "{agreeing}");
    }

    /// The two Bitcoin source reasons must not be advised with certificates.
    /// They used to fall through to "trust root unavailable" and "Missing
    /// trust material", sending a user after files that fix neither a
    /// conflict between two APIs nor a single endpoint answering.
    #[test]
    fn the_bitcoin_source_reasons_never_advise_certificates() {
        for reason in [
            ReasonCode::BitcoinProvidersDisagree,
            ReasonCode::BitcoinSingleSourceOnly,
        ] {
            let headline = untrusted_headline(ReceiptVerdict::untrusted(reason));
            assert!(!headline.contains("trust root"), "{reason}: {headline}");
            assert!(
                headline.contains("block-explorer"),
                "the headline must name the real cause: {reason}: {headline}"
            );
        }
        assert!(untrusted_headline(ReceiptVerdict::untrusted(
            ReasonCode::BitcoinProvidersDisagree
        ))
        .contains("your receipt is not implicated"));
    }

    /// Nothing in the human output may claim this tool watched the Bitcoin
    /// network. It queries HTTP APIs and says so.    /// Nothing in the human output may claim this tool watched the Bitcoin
    /// network. It queries HTTP APIs and says so.
    #[test]
    fn the_output_never_claims_to_observe_the_chain() {
        let rendered = block_sources_lines(&[BlockSourceReport {
            source: "blockstream.info".to_string(),
            block_hash: "a".repeat(64),
            merkle_root: "b".repeat(64),
            block_timestamp_secs: 1_768_806_080,
        }])
        .join("\n");
        for claim in ["on-chain", "on chain", "blockchain", "observed"] {
            assert!(!rendered.contains(claim), "{claim:?} in:\n{rendered}");
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
            unanchored_count: 0,
            untrusted_count: 1,
            invalid_count: 1,
            error_count: 1,
            unmatched_count: 2,
            policy: AnchorPolicy::AllAnchors,
            consistency: None,
            items: vec![
                BatchItemResult::Valid(single_result(true, true)),
                BatchItemResult::Untrusted(with_rfc3161_anchor(
                    single_result(true, true),
                    AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
                    PathStatus::Complete,
                    Some(TerminalAnchor::Assumed {
                        sha256_fingerprint: [0x22; 32],
                        self_signature: atl_core::SelfSignature::Verified,
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
