//! Cross-Receipt Verification, ATL Protocol v2.0 §5.4.3.
//!
//! # What the specification asks for
//!
//! §5.4.3 defines the check in three steps, and this module implements
//! exactly those three — no more, and no fewer:
//!
//! 1. *"Verify each receipt independently (previous steps)."* Done before
//!    this module is reached: [`crate::verify::single::verify_single`] runs
//!    §5.1–§5.4 over every receipt, and [`crate::verify::batch`] passes only
//!    receipts that survived those steps into the participant list. A refuted
//!    receipt is therefore never a participant. Note that anchor verification
//!    is §5.5, *not* one of the "previous steps": a receipt whose anchors
//!    reached no configured trust root has still passed §5.1–§5.4 and takes
//!    part here.
//! 2. *"Verify that `A.super_proof.genesis_super_root` equals
//!    `B.super_proof.genesis_super_root`."* Done by grouping — see below.
//! 3. *"If both receipts have the same `genesis_super_root` and valid
//!    `consistency_to_origin` proofs, the log history between them was not
//!    modified."*
//!
//! Receipts with no `super_proof` are excluded: §5.4 applies to Receipt-Full,
//! and §3.3.2 says only those carry `genesis_super_root`. A Receipt-Lite
//! makes no Super-Tree claim, so there is nothing here to check about it.
//!
//! # Why receipts are grouped by `genesis_super_root`
//!
//! §3.3.2: the genesis super root *"serves as the immutable identifier for
//! the log instance"*, and §4.2 carries it in every Receipt-Full precisely
//! *"to enable cross-receipt verification"*. The log a receipt belongs to is
//! therefore a fact the receipt states about itself.
//!
//! This module used to take the first receipt the directory walk happened to
//! yield, treat *its* genesis as the log every other receipt had to belong
//! to, and report a mismatch as `history_consistent: false` — which the batch
//! verdict turns into `invalid`, exit code 1, *the evidence was refuted*.
//! That both broke §3.3.2 (the log identity came from filesystem ordering
//! rather than from the receipt) and refuted evidence that nothing had
//! disproved. §5.4.3 defines what to do when two genesis values agree; it
//! defines no error for the case where they differ, because the identifier
//! exists to keep receipts from different log instances from being compared
//! in the first place.
//!
//! So participants are grouped by the identifier §3.3.2 gives them, and
//! §5.4.3 is applied within each group. Each receipt is then judged on its
//! own merits, exactly as it would be on its own.
//!
//! # The limit of the claim
//!
//! §5.4.3 step 3 concludes that *"the log history between them was not
//! modified"*, and that is the claim this module reports — no stronger. In
//! particular it is not a defence against a Split-View (fork) attack: §7.3.2
//! names *external anchoring* as the primary defence and scopes consistency
//! proofs to "Within a Tree", and §5.4.2 proves only that *"the genesis state
//! is a prefix of the current state"* for each receipt separately. No receipt
//! carries a proof about another receipt's tree. Both renderers say so.

use std::collections::BTreeMap;

use atl_core::{verify_cross_receipts, CrossReceiptVerificationResult};

use crate::error::CliResult;
use crate::verify::single::SingleVerificationResult;

/// One §5.4.3 comparison, with the participants it actually compared.
///
/// The indices are carried rather than recomputed by each renderer. Both
/// renderers used to derive them positionally (`idx` → `idx + 1`), which
/// held only while every participant belonged to one log instance; with
/// receipts grouped by §3.3.2 identifier it would name pairs that were never
/// compared.
#[derive(Debug)]
pub struct CrossCheck {
    /// Index into [`ConsistencyResult::participants`] of the earlier receipt.
    pub from_index: usize,
    /// Index into [`ConsistencyResult::participants`] of the later receipt.
    pub to_index: usize,
    /// What `atl-core` made of the pair.
    pub result: CrossReceiptVerificationResult,
}

/// Result of Cross-Receipt Verification (§5.4.3) over a batch.
#[derive(Debug)]
pub struct ConsistencyResult {
    /// How many distinct log instances the participants came from, counted
    /// by the §3.3.2 identifier `genesis_super_root`.
    ///
    /// More than one is a fact about the batch, not a fault in it: see the
    /// module docs. Renderers say so; the verdict ignores it.
    pub log_instance_count: usize,
    /// For every log instance represented here, §5.4.3 step 3 holds across
    /// the receipts that testify to it: the log history between them was not
    /// modified.
    pub history_consistent: bool,
    /// The genesis super root shared by every participant — `None` when they
    /// did not all come from one log instance, because then there is no
    /// single §3.3.2 identifier to name.
    pub genesis_super_root: Option<[u8; 32]>,
    /// Number of receipts checked
    pub receipt_count: usize,
    /// The receipts that took part, by source file name, grouped by log
    /// instance and ordered within each one the way the comparisons walked
    /// them.
    ///
    /// Carried here rather than reconstructed by each renderer. Both
    /// renderers used to rebuild this list from the batch items with a
    /// different filter and a different sort key than the check itself used,
    /// so the `[i] -> [j]` rows named files by positional coincidence rather
    /// than identity — and dropped names entirely when the two lists
    /// differed in length.
    pub participants: Vec<String>,
    /// §5.4.3 comparisons, within one log instance only.
    pub cross_results: Vec<CrossCheck>,
    /// Specific errors
    pub errors: Vec<String>,
}

impl ConsistencyResult {
    /// §5.4.3 step 3 holds for every log instance represented here.
    ///
    /// Deliberately says nothing about *how many* log instances there were.
    /// §5.4.3 defines no error for receipts whose §3.3.2 identifiers differ,
    /// and this predicate feeds a verdict that would call such a batch
    /// refuted evidence.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.history_consistent && self.errors.is_empty()
    }

    /// Every participant carries the same §3.3.2 log-instance identifier.
    #[must_use]
    pub const fn single_log_instance(&self) -> bool {
        self.log_instance_count <= 1
    }

    /// At least one §5.4.3 comparison was actually performed.
    ///
    /// Grouping by log instance makes "two participants, no comparison"
    /// reachable — one receipt from each of two log instances has no pair to
    /// compare. Reporting that as `VERIFIED (0 cross-checks passed)` would
    /// claim a check that never ran, so both renderers ask this first.
    #[must_use]
    pub fn checked(&self) -> bool {
        !self.cross_results.is_empty()
    }
}

/// Apply Cross-Receipt Verification (§5.4.3) within each log instance.
///
/// # Algorithm
///
/// 1. Drop receipts with no `super_proof`. §5.4 applies to Receipt-Full;
///    §3.3.2 says only those carry `genesis_super_root`. A Receipt-Lite
///    proves internal consistency only, so §5.4.3 has nothing to compare —
///    and handing one to `verify_cross_receipts` manufactures a failure out
///    of a check that was never performed.
/// 2. Group the rest by `genesis_super_root`, the §3.3.2 identifier of the
///    log instance. This *is* §5.4.3 step 2: two receipts are compared only
///    when their identifiers are equal.
/// 3. Within each group, order by `super_tree_size` and apply §5.4.3 to
///    consecutive pairs.
///
/// §5.4.3 step 1 — "verify each receipt independently" — is the caller's
/// precondition: see the module docs.
///
/// # Arguments
///
/// * `results` - Array of single verification results
///
/// # Returns
///
/// Consistency result with detailed error information
///
/// # Errors
///
/// Returns error only if internal verification fails unexpectedly.
/// Consistency failures are reported in the result structure.
pub fn verify_consistency(results: &[SingleVerificationResult]) -> CliResult<ConsistencyResult> {
    // §5.4.3 step 2, applied as a grouping: receipts are compared only with
    // receipts carrying the same §3.3.2 identifier. Ordered by the
    // identifier itself, so nothing depends on which name the directory walk
    // yielded first -- that ordering used to decide which log instance got to
    // be "the right one".
    let mut log_instances: BTreeMap<&str, Vec<&SingleVerificationResult>> = BTreeMap::new();
    for result in results {
        let Some(super_proof) = result.receipt.super_proof.as_ref() else {
            continue;
        };
        log_instances
            .entry(super_proof.genesis_super_root.as_str())
            .or_default()
            .push(result);
    }

    let mut participants: Vec<String> = Vec::new();
    let mut cross_results: Vec<CrossCheck> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut history_consistent = true;

    for group in log_instances.values() {
        let mut sorted: Vec<&SingleVerificationResult> = group.clone();
        sorted.sort_by_key(|r| {
            r.receipt
                .super_proof
                .as_ref()
                .map_or(0, |sp| sp.super_tree_size)
        });

        // Where this log instance's participants begin in the shared list,
        // so the indices a renderer prints name the receipts compared.
        let base = participants.len();
        participants.extend(sorted.iter().map(|r| file_name(r)));

        for (offset, window) in sorted.windows(2).enumerate() {
            let (a, b) = (window[0], window[1]);
            let result = verify_cross_receipts(&a.receipt, &b.receipt);
            if !result.is_valid() {
                history_consistent = false;
                for err in &result.errors {
                    errors.push(format!("Cross-receipt error: {err:?}"));
                }
            }
            cross_results.push(CrossCheck {
                from_index: base + offset,
                to_index: base + offset + 1,
                result,
            });
        }
    }

    // Only meaningful when there is exactly one log instance to name.
    let genesis_super_root = match log_instances.keys().collect::<Vec<_>>().as_slice() {
        [genesis] => Some(parse_hash(genesis)),
        _ => None,
    };

    Ok(ConsistencyResult {
        log_instance_count: log_instances.len(),
        history_consistent,
        genesis_super_root,
        receipt_count: participants.len(),
        participants,
        cross_results,
        errors,
    })
}

/// The source file's name, for display.
fn file_name(result: &SingleVerificationResult) -> String {
    result
        .source_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Parse hash string to bytes
///
/// # Arguments
///
/// * `hash_str` - Hash string in "sha256:hex" format
///
/// # Returns
///
/// 32-byte array. Returns zeros if parsing fails.
fn parse_hash(hash_str: &str) -> [u8; 32] {
    let hex_part = hash_str.strip_prefix("sha256:").unwrap_or(hash_str);
    let mut bytes = [0u8; 32];
    if let Ok(decoded) = hex::decode(hex_part) {
        if decoded.len() == 32 {
            bytes.copy_from_slice(&decoded);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistency_empty() {
        let results: Vec<SingleVerificationResult> = vec![];
        let consistency = verify_consistency(&results).unwrap();
        assert!(consistency.is_valid());
        assert_eq!(consistency.receipt_count, 0);
        assert_eq!(consistency.log_instance_count, 0);
        assert!(consistency.single_log_instance());
    }

    #[test]
    fn test_parse_hash_valid() {
        let hash_str = "sha256:abababababababababababababababababababababababababababababababab";
        let parsed = parse_hash(hash_str);
        assert_eq!(parsed[0], 0xab);
        assert_eq!(parsed[31], 0xab);
    }

    #[test]
    fn test_parse_hash_without_prefix() {
        let hash_str = "abababababababababababababababababababababababababababababababab";
        let parsed = parse_hash(hash_str);
        assert_eq!(parsed[0], 0xab);
    }

    #[test]
    fn test_parse_hash_invalid() {
        let hash_str = "invalid";
        let parsed = parse_hash(hash_str);
        assert_eq!(parsed, [0u8; 32]);
    }

    // Note: Full consistency tests with valid receipts are in integration tests
    // Unit tests here focus on simple cases and helper functions
}
