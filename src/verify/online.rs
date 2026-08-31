//! Online verification: the one thing that genuinely needs the network.
//!
//! RFC 3161 anchors are verified in full by [`crate::verify::anchor`], with
//! no network access at all. The only anchor type that needs to go online is
//! `bitcoin_ots`, and only to ask block-explorer APIs for the header whose
//! Merkle root is compared against the
//! OTS proof. This module does exactly that, in place, replacing each
//! `bitcoin_ots` anchor's network-free verdict with the confirmed one.

use std::time::Duration;

use atl_core::core::verify::iso8601::parse_iso8601_to_nanos;
use atl_core::ReceiptAnchor;

use crate::error::CliResult;
use crate::net::bitcoin::BlockLookup;
use crate::verify::anchor::BlockSourceReport;
use crate::verify::anchor::PreparedOts;
use crate::verify::anchor::{
    prepare_bitcoin_ots, requires_network, AnchorDetails, AnchorVerdict, AnchorVerificationResult,
    ClaimedTimeCheck,
};
use crate::verify::single::SingleVerificationResult;
use crate::verify::verdict::ReasonCode;

/// Configuration for online verification
#[derive(Debug, Clone)]
pub struct OnlineConfig {
    /// Per-request timeout for Bitcoin block lookups.
    pub request_timeout: Duration,
}

impl Default for OnlineConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// `true` if any anchor in `receipt` needs network access to be verified to
/// completion.
///
/// A receipt anchored only by RFC 3161 is fully verifiable offline, so the
/// CLI must not probe connectivity for it — that probe was contacting
/// external hosts for a check that never leaves the process.
#[must_use]
pub fn receipt_requires_network(receipt: &atl_core::Receipt) -> bool {
    receipt.anchors.iter().any(requires_network)
}

/// Check one `bitcoin_ots` anchor against the block header that the
/// configured block-explorer APIs report for the height its OTS proof names.
///
/// Deliberately not "confirm against the blockchain": this contacts HTTP
/// endpoints, validates no proof of work and follows no chain. What it can
/// establish is that two or more of the configured sources report the same
/// header
/// and that the OTS proof's computed root equals that header's Merkle root.
/// That is a real and useful statement; it is just not the one the old
/// wording made.
///
/// # The four source outcomes
///
/// | sources | outcome | why |
/// |---|---|---|
/// | two or more, agreeing | compare, then `Valid` or `Invalid` | the header is corroborated |
/// | two or more, disagreeing | `Untrusted(BitcoinProvidersDisagree)` | no established header exists to compare against |
/// | exactly one | `Untrusted(BitcoinSingleSourceOnly)` | one endpoint's word settles nothing |
/// | none | `Untrusted(BitcoinBlockUnavailable)` | nothing to compare against |
///
/// Only the first row may produce a refutation, and that is the whole point
/// of the table. A mismatch reported by a single uncorroborated endpoint is
/// **not** a refutation: if one source is not enough to accept evidence, it
/// is not enough to accuse it either, and a wrong or compromised API would
/// otherwise be able to turn sound evidence into `invalid`. That is the
/// worst failure this tool has, and it is now unreachable through one
/// endpoint.
async fn verify_bitcoin_ots_online(
    target: &str,
    target_hash: &str,
    ots_proof: &str,
    super_root: Option<&str>,
    receipt_block_height: u64,
    receipt_block_time: &str,
    config: &OnlineConfig,
) -> AnchorVerificationResult {
    // Every network-free check first, sharing exactly the offline rules --
    // including §5.5.2 step 5's height half, which needs no network and so
    // refutes a receipt whose stated height its own proof contradicts before
    // a single request is made.
    let prepared = match prepare_bitcoin_ots(
        target,
        target_hash,
        ots_proof,
        super_root,
        receipt_block_height,
        receipt_block_time,
    ) {
        Ok(p) => p,
        Err(result) => return result,
    };

    let lookup = crate::net::bitcoin::lookup_block(
        prepared.attestation.block_height,
        config.request_timeout,
    )
    .await;

    anchor_from_lookup(&prepared, target_hash, lookup)
}

/// Turn one block lookup into the anchor's result.
///
/// Split out of [`verify_bitcoin_ots_online`] and kept free of I/O so that
/// three of the four source outcomes can be tested deterministically. Only
/// the HTTP call itself is untestable offline; the decisions made about its
/// outcome — which is where a verifier overclaims — are not.
fn anchor_from_lookup(
    prepared: &PreparedOts,
    target_hash: &str,
    lookup: BlockLookup,
) -> AnchorVerificationResult {
    // The proof's height. It equals the receipt's -- `prepare_bitcoin_ots`
    // refutes the anchor outright when they differ -- so a lookup by this
    // number is a lookup for the block both of them name.
    let claimed_height = prepared.attestation.block_height;

    // Everything a not-yet-compared outcome reports: the local computation,
    // whatever the sources said, and no header presented as established.
    let unconfirmed_details = |reports: Vec<BlockSourceReport>| AnchorDetails::Bitcoin {
        proof_block_height: Some(claimed_height),
        proof_block_heights: prepared.attested_block_heights.clone(),
        receipt_block_height: prepared.receipt_block_height,
        receipt_block_time: prepared.receipt_block_time.clone(),
        // No corroborated header was obtained, so §5.5.2 step 5's time half
        // had nothing to compare against. An inability, and it must not read
        // as a finding about the receipt.
        claimed_time_check: ClaimedTimeCheck::NotCompared,
        block_timestamp_secs: None,
        target_hash: target_hash.to_string(),
        operation_count: Some(prepared.operation_count),
        computed_root: Some(prepared.computed_root.clone()),
        block_merkle_root: None,
        merkle_match: None,
        block_sources: reports,
    };

    let (info, reports) = match lookup {
        BlockLookup::Corroborated { info, reports } => (info, reports),

        // Sources contradict each other. There is no header to compare
        // against, so nothing is compared -- and nothing is refuted. The
        // conflicting reports travel out in `block_sources` and in the
        // prose, because a user must be told that their sources disagree.
        BlockLookup::Disagreement { reports } => {
            let detail = reports
                .iter()
                .map(|r| {
                    // Every field the agreement predicate compares, so the
                    // reader can see which of them the sources differ on --
                    // including the time, which this message used to omit
                    // while a time-only conflict was what produced it.
                    format!(
                        "{} reported merkle_root {} in block {} at {}",
                        r.source, r.merkle_root, r.block_hash, r.block_timestamp_secs
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinProvidersDisagree),
                timestamp_nanos: None,
                error: Some(format!(
                    "block-explorer APIs disagree about block {claimed_height}, so no block \
                     header is established and nothing was compared -- this is NOT a finding \
                     about your receipt: {detail}"
                )),
                details: unconfirmed_details(reports),
            };
        }

        // One endpoint answered. It can neither accept nor accuse.
        BlockLookup::Uncorroborated { reports, failures } => {
            let named = reports
                .first()
                .map_or_else(|| "one source".to_string(), |r| r.source.clone());
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinSingleSourceOnly),
                timestamp_nanos: None,
                error: Some(format!(
                    "only {named} reported block {claimed_height}; a single uncorroborated \
                     source cannot establish a block header, so the OTS proof was not compared \
                     against it. Others did not answer: {}",
                    failures.join("; ")
                )),
                details: unconfirmed_details(reports),
            };
        }

        // Nobody answered: the lookup was attempted and failed.
        BlockLookup::Unavailable { failures } => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockUnavailable),
                timestamp_nanos: None,
                error: Some(format!(
                    "no block-explorer API returned block {claimed_height}: {}",
                    failures.join("; ")
                )),
                details: unconfirmed_details(Vec::new()),
            };
        }
    };

    // CRITICAL, and only reachable with a corroborated header: the OTS
    // proof's root must equal the Merkle root two or more sources agree on.
    let merkle_match = prepared.attestation.verify_against_block(&info.merkle_root);
    let source_count = reports.len();

    // ATL v2.0 §5.5.2 step 5, time half -- possible only here, because this
    // is the only branch in which a block header exists to compare against.
    let claimed_time_check = check_claimed_time(&prepared.receipt_block_time, info.timestamp_secs);

    let details = AnchorDetails::Bitcoin {
        proof_block_height: Some(info.height),
        proof_block_heights: prepared.attested_block_heights.clone(),
        receipt_block_height: prepared.receipt_block_height,
        receipt_block_time: prepared.receipt_block_time.clone(),
        claimed_time_check,
        block_timestamp_secs: Some(info.timestamp_secs),
        target_hash: target_hash.to_string(),
        operation_count: Some(prepared.operation_count),
        computed_root: Some(prepared.computed_root.clone()),
        block_merkle_root: Some(format!("sha256:{}", info.merkle_root)),
        merkle_match: Some(merkle_match),
        block_sources: reports,
    };

    // Refutations first, inabilities after -- the same rule the RFC 3161
    // classifier follows. A time the sources contradict is a refutation in
    // its own right, and must not be swallowed by an unreadable-string
    // inability found beside it; equally, an unreadable string must not
    // suppress a Merkle-root mismatch.
    if !merkle_match {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            // Reported ahead of a time contradiction when both hold: the
            // Merkle root is what binds this proof to that block at all, so
            // it is the more informative cause. Either one alone is enough
            // for `Invalid`.
            verdict: AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch),
            timestamp_nanos: None,
            error: Some(format!(
                "Merkle root mismatch: the OTS proof does not match the header that \
                 {source_count} block-explorer APIs agree on for block {}",
                info.height
            )),
            details,
        };
    }

    match claimed_time_check {
        ClaimedTimeCheck::Contradicted => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedTimeContradictsBlock),
            timestamp_nanos: None,
            error: Some(format!(
                "the receipt states bitcoin_block_time {}, but the header that {source_count} \
                 block-explorer APIs agree on for block {} is timestamped {}",
                prepared.receipt_block_time,
                info.height,
                format_block_time(info.timestamp_secs),
            )),
            details,
        },

        // Nothing refuted, and a step the specification requires was not
        // performed. That is `untrusted`, not acceptance: the receipt's
        // stated time went unchecked, and saying `valid` would report a
        // check that never ran.
        ClaimedTimeCheck::Unreadable => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinClaimedTimeUnreadable),
            timestamp_nanos: None,
            error: Some(format!(
                "the receipt's bitcoin_block_time {:?} could not be read as a timestamp by this \
                 build, so it was not compared with the block header -- this is a limitation of \
                 this verifier, NOT a finding about your receipt",
                prepared.receipt_block_time
            )),
            details,
        },

        // `NotCompared` is unreachable in this branch (a corroborated header
        // is in hand, so the comparison ran), and is accepted here rather
        // than asserted away: were it ever produced, treating it as success
        // would be the overclaim, so it is grouped with the outcome that
        // establishes the anchor only because `Matches` is what actually
        // arrives.
        ClaimedTimeCheck::Matches | ClaimedTimeCheck::NotCompared => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Valid,
            timestamp_nanos: Some(info.timestamp_secs * 1_000_000_000),
            error: None,
            details,
        },
    }
}

/// Compare the receipt's `bitcoin_block_time` with a block header's time.
///
/// # Instants, not strings
///
/// ATL v2.0 §4.2 types this field only as `<ISO8601>`, and RFC 3339 admits
/// several spellings of one moment — Evidentum's own production receipts
/// write `+00:00` where a `Z` would do. The comparison is therefore between
/// *instants*, at the full nanosecond resolution
/// [`parse_iso8601_to_nanos`] returns: two spellings of one moment are a
/// match, and declaring them a mismatch would refute sound evidence over
/// formatting.
///
/// The parser is `atl-core`'s, not a second one kept here. A verifier and
/// the library it verifies with must not disagree about what a timestamp
/// means.
///
/// # Sub-second precision
///
/// A Bitcoin block header carries a whole-second time; there is no
/// sub-second component in it to match. A receipt claiming
/// `07:01:20.000000001` therefore names an instant the header does not
/// contain, and the comparison must come out [`ClaimedTimeCheck::Contradicted`].
///
/// This is the case an earlier version got wrong: it compared only whole
/// seconds, so a receipt could name a different instant and be told it
/// matched — in the very check added to stop unverified claims being
/// republished as verified. **Two different instants may never be reported
/// as equal.** An explicit zero fraction (`.0`, `.000000000`) names the same
/// instant and does match; precision finer than a nanosecond cannot be
/// represented, so `atl-core` refuses it and it arrives here as
/// [`ClaimedTimeCheck::Unreadable`] rather than being truncated into a false
/// match.
///
/// # Why an unreadable string is not a refutation
///
/// A string this build cannot parse is a fact about this build's coverage of
/// RFC 3339 first. Nothing about the receipt has been shown false, so it is
/// an inability — though it still costs the anchor its acceptance, because a
/// step the specification requires did not happen.
fn check_claimed_time(receipt_block_time: &str, block_timestamp_secs: u64) -> ClaimedTimeCheck {
    let Some(claimed_nanos) = parse_iso8601_to_nanos(receipt_block_time) else {
        return ClaimedTimeCheck::Unreadable;
    };
    // The header's own instant, at the same resolution. A block time too
    // large to express in nanoseconds is not comparable, and saying so is
    // better than comparing something else.
    let Some(block_nanos) = block_timestamp_secs.checked_mul(1_000_000_000) else {
        return ClaimedTimeCheck::Unreadable;
    };
    if claimed_nanos == block_nanos {
        ClaimedTimeCheck::Matches
    } else {
        ClaimedTimeCheck::Contradicted
    }
}

/// A block header's time as an ISO 8601 instant, for prose only.
///
/// Falls back to the raw seconds rather than inventing a date: a value that
/// cannot be rendered must not be rendered as something else.
fn format_block_time(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map_or_else(
            || format!("{secs} seconds since the epoch"),
            |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        )
}

/// Upgrade every `bitcoin_ots` anchor in `result` from its network-free
/// verdict to a block-confirmed one.
///
/// RFC 3161 anchors are left exactly as they were: their verification is
/// complete already and going online could not change it. Callers re-read
/// [`SingleVerificationResult::verdict`] afterwards — the receipt status
/// follows from the updated anchors automatically.
///
/// # Errors
///
/// Never returns `Err` today; the signature keeps a `CliResult` so a future
/// hard failure (as opposed to an unconfirmed anchor) can be surfaced
/// without changing every caller.
pub async fn verify_anchors_online(
    result: &mut SingleVerificationResult,
    config: &OnlineConfig,
) -> CliResult<()> {
    let super_root = result
        .receipt
        .super_proof
        .as_ref()
        .map(|sp| sp.super_root.clone());

    for (index, anchor) in result.receipt.anchors.iter().enumerate() {
        let ReceiptAnchor::BitcoinOts {
            target,
            target_hash,
            ots_proof,
            bitcoin_block_height,
            bitcoin_block_time,
            ..
        } = anchor
        else {
            continue;
        };

        let confirmed = verify_bitcoin_ots_online(
            target,
            target_hash,
            ots_proof,
            super_root.as_deref(),
            *bitcoin_block_height,
            bitcoin_block_time,
            config,
        )
        .await;

        if let Some(slot) = result.anchor_results.get_mut(index) {
            *slot = confirmed;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::policy::AnchorPolicy;
    use crate::verify::verdict::Status;
    use atl_core::{
        CheckpointJson, Receipt, ReceiptEntry, ReceiptProof, SignatureStatus, VerificationResult,
    };
    use std::path::PathBuf;

    const TEST_ROOT_HASH: &str =
        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const OTHER_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn create_test_receipt() -> Receipt {
        let test_uuid = "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("Valid UUID");

        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: test_uuid,
                payload_hash: TEST_ROOT_HASH.to_string(),
                metadata_hash:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: TEST_ROOT_HASH.to_string(),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    tree_size: 1,
                    root_hash: TEST_ROOT_HASH.to_string(),
                    timestamp: 1_234_567_890,
                    signature: "base64:signature".to_string(),
                    key_id:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                },
                consistency_proof: None,
            },
            super_proof: None,
            anchors: vec![],
        }
    }

    fn create_test_single_result(valid: bool) -> SingleVerificationResult {
        SingleVerificationResult {
            source_path: PathBuf::from("test.txt"),
            receipt_path: PathBuf::from("test.atl"),
            file_hash: [0x12; 32],
            receipt: create_test_receipt(),
            file_hash_valid: valid,
            core_result: VerificationResult {
                is_valid: valid,
                leaf_hash: [0x12; 32],
                root_hash: [0x34; 32],
                tree_size: 1,
                timestamp: 1_234_567_890,
                signature_valid: valid,
                signature_status: if valid {
                    SignatureStatus::Verified
                } else {
                    SignatureStatus::Failed
                },
                inclusion_valid: valid,
                consistency_valid: None,
                super_inclusion_valid: valid,
                super_consistency_valid: valid,
                genesis_super_root: [0x00; 32],
                super_root: [0x56; 32],
                data_tree_index: 0,
                super_tree_size: 1,
                anchor_results: vec![],
                errors: vec![],
            },
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        }
    }

    use crate::net::bitcoin::{BitcoinBlockInfo, BlockLookup};

    /// Everything the real Receipt-Full `bitcoin_ots` anchor states: target,
    /// target hash, proof, and the two fields ATL v2.0 §5.5.2 step 5 checks.
    struct FixtureAnchor {
        target: String,
        target_hash: String,
        ots_proof: String,
        super_root: Option<String>,
        block_height: u64,
        block_time: String,
    }

    fn fixture_anchor() -> FixtureAnchor {
        let receipt: atl_core::Receipt =
            serde_json::from_str(include_str!("../../real-data/receipt-full.atl"))
                .expect("fixture receipt");
        let super_root = receipt.super_proof.as_ref().map(|sp| sp.super_root.clone());
        receipt
            .anchors
            .iter()
            .find_map(|a| match a {
                atl_core::ReceiptAnchor::BitcoinOts {
                    target,
                    target_hash,
                    ots_proof,
                    bitcoin_block_height,
                    bitcoin_block_time,
                    ..
                } => Some(FixtureAnchor {
                    target: target.clone(),
                    target_hash: target_hash.clone(),
                    ots_proof: ots_proof.clone(),
                    super_root: super_root.clone(),
                    block_height: *bitcoin_block_height,
                    block_time: bitcoin_block_time.clone(),
                }),
                atl_core::ReceiptAnchor::Rfc3161 { .. } => None,
            })
            .expect("fixture carries a bitcoin_ots anchor")
    }

    /// The real anchor prepared exactly as the offline pass prepares it, with
    /// the receipt's own claims optionally overridden — which is how the
    /// step-5 tests state a height or a time that the production receipt does
    /// not.
    // Same reason `prepare_bitcoin_ots` itself carries the allow: a rejected
    // anchor must report the same shape as an accepted one, and boxing it
    // would buy stack bytes on a path that runs once per test.
    #[allow(clippy::result_large_err)]
    fn prepare_fixture(
        claimed_height: Option<u64>,
        claimed_time: Option<&str>,
    ) -> Result<PreparedOts, AnchorVerificationResult> {
        let anchor = fixture_anchor();
        crate::verify::anchor::prepare_bitcoin_ots(
            &anchor.target,
            &anchor.target_hash,
            &anchor.ots_proof,
            anchor.super_root.as_deref(),
            claimed_height.unwrap_or(anchor.block_height),
            claimed_time.unwrap_or(&anchor.block_time),
        )
    }

    fn ots_fixture() -> PreparedOts {
        prepare_fixture(None, None).expect("the fixture's OTS proof is sound")
    }

    fn header(ts: u64, root: &str) -> BitcoinBlockInfo {
        BitcoinBlockInfo {
            height: 932_897,
            timestamp_secs: ts,
            block_hash: "a".repeat(64),
            merkle_root: root.to_string(),
        }
    }

    const REAL_ROOT: &str = "2f826dce65159ccc8f74da5305cb28267ef04161d92fb798f293e62670a8206f";
    const BLOCK_TS: u64 = 1_768_806_080;

    fn bitcoin_details(result: &AnchorVerificationResult) -> (Option<u64>, Option<bool>, usize) {
        match &result.details {
            AnchorDetails::Bitcoin {
                block_timestamp_secs,
                merkle_match,
                block_sources,
                ..
            } => (*block_timestamp_secs, *merkle_match, block_sources.len()),
            _ => panic!("expected a Bitcoin fact set"),
        }
    }

    /// **Two agreeing sources are the only route to `Valid`.** Success must
    /// stay reachable, or the corroboration requirement becomes a refusal.
    #[test]
    fn a_corroborated_matching_header_verifies_the_anchor() {
        let prepared = ots_fixture();
        let info = header(BLOCK_TS, REAL_ROOT);
        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            },
        );
        assert_eq!(result.verdict, AnchorVerdict::Valid);
        let (ts, merkle_match, sources) = bitcoin_details(&result);
        assert_eq!(ts, Some(BLOCK_TS));
        assert_eq!(merkle_match, Some(true));
        assert_eq!(sources, 2);
    }

    /// A corroborated header that does **not** match is the one route to a
    /// refutation. Two sources agreed on what the block contains, and it is
    /// not what the proof computes.
    #[test]
    fn a_corroborated_mismatching_header_refutes_the_anchor() {
        let prepared = ots_fixture();
        let info = header(BLOCK_TS, &"9".repeat(64));
        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            },
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch)
        );
        assert_eq!(bitcoin_details(&result).1, Some(false));
    }

    /// **Sources disagree.** Not a refutation: the conflict is among the
    /// sources, the receipt is not implicated, and no header is published.
    #[test]
    fn disagreeing_sources_never_refute_the_receipt() {
        let prepared = ots_fixture();
        let a = header(BLOCK_TS, REAL_ROOT);
        let b = header(BLOCK_TS, &"9".repeat(64));
        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Disagreement {
                reports: vec![
                    a.to_source_report("blockstream.info"),
                    b.to_source_report("mempool.space"),
                ],
            },
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinProvidersDisagree)
        );
        assert_eq!(
            result.state(),
            crate::verify::anchor::AnchorState::Contested
        );
        // No header was established, so none is published -- not even the
        // one that happens to match.
        let (ts, merkle_match, sources) = bitcoin_details(&result);
        assert_eq!(ts, None);
        assert_eq!(merkle_match, None);
        // ... but both reports survive: the conflict is the finding, and
        // this is the only place the user can see it.
        assert_eq!(sources, 2);
        let error = result.error.expect("the disagreement must be described");
        assert!(error.contains("blockstream.info"), "{error}");
        assert!(error.contains("mempool.space"), "{error}");
        assert!(
            error.contains("NOT a finding about your receipt"),
            "the user must not read a source conflict as an accusation: {error}"
        );
    }

    /// A conflict about nothing but the time reaches the same outcome, and
    /// its prose names both times -- the message used to list only the root
    /// and the hash, which are identical in exactly this case, so the reader
    /// was shown two rows that looked the same and told they disagreed.
    #[test]
    fn a_time_only_disagreement_is_described_with_the_times() {
        let prepared = ots_fixture();
        let a = header(BLOCK_TS, REAL_ROOT);
        let b = header(BLOCK_TS + 1, REAL_ROOT);
        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Disagreement {
                reports: vec![
                    a.to_source_report("blockstream.info"),
                    b.to_source_report("mempool.space"),
                ],
            },
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinProvidersDisagree)
        );
        let error = result
            .error
            .clone()
            .expect("the conflict must be described");
        assert!(error.contains(&BLOCK_TS.to_string()), "{error}");
        assert!(error.contains(&(BLOCK_TS + 1).to_string()), "{error}");
        assert!(
            error.contains("NOT a finding about your receipt"),
            "{error}"
        );
        // No header was established, so none is published.
        let (ts, merkle_match, sources) = bitcoin_details(&result);
        assert_eq!(ts, None);
        assert_eq!(merkle_match, None);
        assert_eq!(sources, 2);
    }

    /// **One source.** It can neither accept nor accuse    /// **One source.** It can neither accept nor accuse — including when it
    /// reports a mismatch. If one endpoint is not enough to trust evidence,
    /// it is not enough to condemn it either.
    #[test]
    fn a_single_source_can_neither_verify_nor_refute() {
        let prepared = ots_fixture();
        for root in [REAL_ROOT, &"9".repeat(64)] {
            let info = header(BLOCK_TS, root);
            let result = anchor_from_lookup(
                &prepared,
                "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
                BlockLookup::Uncorroborated {
                    reports: vec![info.to_source_report("blockstream.info")],
                    failures: vec!["mempool.space: HTTP error".to_string()],
                },
            );
            assert_eq!(
                result.verdict,
                AnchorVerdict::Untrusted(ReasonCode::BitcoinSingleSourceOnly),
                "root {root}"
            );
            assert_eq!(
                result.state(),
                crate::verify::anchor::AnchorState::Uncorroborated
            );
            let (ts, merkle_match, sources) = bitcoin_details(&result);
            assert_eq!(ts, None, "an uncorroborated time is not published");
            assert_eq!(merkle_match, None);
            assert_eq!(sources, 1);
        }
    }

    /// **Nobody answered.** Unchanged behaviour, and still never a
    /// refutation.
    #[test]
    fn no_source_is_unavailable_not_refuted() {
        let prepared = ots_fixture();
        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Unavailable {
                failures: vec!["blockstream.info: down".to_string()],
            },
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockUnavailable)
        );
        let (ts, merkle_match, sources) = bitcoin_details(&result);
        assert_eq!(ts, None);
        assert_eq!(merkle_match, None);
        assert_eq!(sources, 0);
    }

    #[test]
    fn test_online_config_default() {
        let config = OnlineConfig::default();
        assert_eq!(config.request_timeout.as_secs(), 10);
    }

    #[test]
    fn test_online_config_clone_and_debug() {
        let config = OnlineConfig::default();
        let cloned = config.clone();
        assert_eq!(config.request_timeout, cloned.request_timeout);
        assert!(format!("{config:?}").contains("OnlineConfig"));
    }

    #[test]
    fn rfc3161_only_receipt_needs_no_network() {
        let mut receipt = create_test_receipt();
        receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: TEST_ROOT_HASH.to_string(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });
        assert!(!receipt_requires_network(&receipt));
    }

    #[test]
    fn bitcoin_anchor_needs_network() {
        let mut receipt = create_test_receipt();
        receipt.anchors.push(ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: TEST_ROOT_HASH.to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            bitcoin_block_height: 800_000,
            bitcoin_block_time: "2024-01-01T00:00:00Z".to_string(),
            ots_proof: "base64:proof".to_string(),
        });
        assert!(receipt_requires_network(&receipt));
    }

    #[tokio::test]
    async fn online_pass_leaves_non_bitcoin_anchors_untouched() {
        // A receipt with no bitcoin anchors must come out of the online pass
        // byte-for-byte identical -- and, crucially, without any network
        // call having been made.
        let mut result = create_test_single_result(true);
        result.receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: OTHER_HASH.to_string(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });
        result.anchor_results =
            crate::verify::anchor::verify_anchors_offline(&result.receipt, None);
        let before = result.anchor_results[0].verdict;

        verify_anchors_online(&mut result, &OnlineConfig::default())
            .await
            .expect("online pass must not fail");

        assert_eq!(result.anchor_results[0].verdict, before);
        assert_eq!(
            before,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch)
        );
    }

    #[test]
    fn unanchored_receipt_is_untrusted() {
        let result = create_test_single_result(true);
        assert_eq!(result.verdict().status, Status::Untrusted);
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::ReceiptUnanchored)
        );
        assert_eq!(result.verdict().exit_code().code(), 3);
        assert!(result.is_lite());
        assert!(!result.is_valid());
    }

    #[test]
    fn file_hash_mismatch_outranks_everything() {
        let result = create_test_single_result(false);
        let verdict = result.verdict();
        assert_eq!(verdict.status, Status::Invalid);
        assert_eq!(verdict.reason_code, Some(ReasonCode::FileHashMismatch));
    }

    // ===== ATL v2.0 §5.5.2 step 5: the receipt's own claims =====
    //
    // "Verify that bitcoin_block_height and bitcoin_block_time match the
    // proof." The two halves are not symmetrical, and the tests below exist
    // to keep them from being treated as if they were: the height is inside
    // the proof and is checkable with no network, while the time is in no
    // proof at all and is checkable only against a header that was actually
    // obtained. Conflating them would either miss a real refutation or
    // manufacture one out of an offline run.

    /// **The height half, offline.** The receipt states one block, its own
    /// OTS proof attests to another. Nothing here needs the network, so this
    /// is a fact that was checked and is false — a refutation, reported
    /// before any lookup is even attempted.
    #[test]
    fn a_height_the_proof_contradicts_is_refuted_with_no_network() {
        let rejection = prepare_fixture(Some(900_000), None)
            .err()
            .expect("a height the proof contradicts must be rejected");

        assert_eq!(
            rejection.verdict,
            AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedHeightContradictsProof)
        );
        assert_eq!(
            rejection.state(),
            crate::verify::anchor::AnchorState::Refuted
        );

        // Both numbers travel with the refutation: a reader cannot audit the
        // finding without seeing which claim came from where.
        let AnchorDetails::Bitcoin {
            proof_block_height,
            proof_block_heights,
            receipt_block_height,
            claimed_time_check,
            ..
        } = &rejection.details
        else {
            panic!("a refuted Bitcoin anchor must still carry a Bitcoin fact set");
        };
        assert_eq!(*receipt_block_height, 900_000);
        // No attestation was selected, so no single height is named as
        // "the proof's" -- picking one would be inventing a criterion.
        assert_eq!(*proof_block_height, None);
        // What the proof does attest to, which is the evidence for the
        // refusal.
        assert_eq!(proof_block_heights, &vec![932_897]);
        // And the time was still not compared -- a height refutation says
        // nothing whatever about the time.
        assert_eq!(*claimed_time_check, ClaimedTimeCheck::NotCompared);
    }

    /// **The height half, online.** The same refutation, through the online
    /// entry point, reached *before* any block-explorer request — so the
    /// answer cannot depend on connectivity, and this test makes no network
    /// call despite exercising the online path.
    #[tokio::test]
    async fn the_online_path_refutes_a_contradicted_height_before_any_lookup() {
        let anchor = fixture_anchor();

        let result = verify_bitcoin_ots_online(
            &anchor.target,
            &anchor.target_hash,
            &anchor.ots_proof,
            anchor.super_root.as_deref(),
            900_000,
            &anchor.block_time,
            // A timeout short enough that a lookup, if one were attempted,
            // could not quietly succeed and make this test pass for the
            // wrong reason.
            &OnlineConfig {
                request_timeout: Duration::from_millis(1),
            },
        )
        .await;

        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedHeightContradictsProof)
        );
    }

    /// **The time half, offline: not a refutation.** No OTS proof carries a
    /// block time, so offline there is nothing to compare the receipt's
    /// against. The honest report is "not compared" — and the anchor stays
    /// `untrusted` for the reason it already was, never `invalid`.
    #[test]
    fn an_unfetched_block_leaves_the_claimed_time_uncompared() {
        let anchor = fixture_anchor();

        let result = crate::verify::anchor::verify_bitcoin_ots_offline(
            &anchor.target,
            &anchor.target_hash,
            &anchor.ots_proof,
            anchor.super_root.as_deref(),
            anchor.block_height,
            // A time that is nowhere near the real block's. Offline it must
            // make no difference whatsoever: an unperformed comparison
            // cannot fail.
            "1999-12-31T23:59:59Z",
        );

        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockNotChecked)
        );
        let (_, _, _, claimed_time_check) = bitcoin_claims(&result);
        assert_eq!(claimed_time_check, ClaimedTimeCheck::NotCompared);
    }

    /// **The time half, online: a refutation.** A corroborated header was
    /// obtained, its Merkle root matches the proof, and the time the receipt
    /// states is not the time of that header. That is a fact that was
    /// checked and is false.
    #[test]
    fn a_claimed_time_the_block_contradicts_refutes_the_anchor() {
        let prepared = prepare_fixture(None, Some("2026-01-19T08:01:20+00:00"))
            .expect("only the claimed time differs; the proof is untouched");
        let info = header(BLOCK_TS, REAL_ROOT);

        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            },
        );

        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedTimeContradictsBlock)
        );
        // A refuted anchor establishes no time, whatever the header said.
        assert_eq!(result.timestamp_nanos, None);
        let (_, _, _, claimed_time_check) = bitcoin_claims(&result);
        assert_eq!(claimed_time_check, ClaimedTimeCheck::Contradicted);
    }

    /// **A time this build cannot parse is an inability, not a refutation.**
    /// ISO 8601 admits forms this verifier does not read, so the failure is
    /// a fact about the parser. It still costs the anchor its `Valid` — a
    /// required step did not happen — but it must never come out `invalid`.
    #[test]
    fn an_unreadable_claimed_time_is_untrusted_never_refuted() {
        let prepared = prepare_fixture(None, Some("Tuesday teatime"))
            .expect("an unreadable time is not a preparation failure");
        let info = header(BLOCK_TS, REAL_ROOT);

        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            },
        );

        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinClaimedTimeUnreadable)
        );
        assert_eq!(
            result.state(),
            crate::verify::anchor::AnchorState::Unevaluable,
            "a string this build cannot parse is this build's limitation"
        );
        let (_, _, _, claimed_time_check) = bitcoin_claims(&result);
        assert_eq!(claimed_time_check, ClaimedTimeCheck::Unreadable);
    }

    /// **Two spellings of one instant are a match.** Evidentum's production
    /// receipts write `+00:00` where a `Z` would do; refuting evidence over
    /// formatting would be the mirror-image defect of not checking at all.
    #[test]
    fn the_same_instant_spelled_differently_still_matches() {
        for spelling in [
            "2026-01-19T07:01:20+00:00",
            "2026-01-19T07:01:20Z",
            "2026-01-19T08:01:20+01:00",
        ] {
            let prepared = prepare_fixture(None, Some(spelling)).expect("proof untouched");
            let info = header(BLOCK_TS, REAL_ROOT);
            let result = anchor_from_lookup(
                &prepared,
                "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
                BlockLookup::Corroborated {
                    reports: vec![
                        info.to_source_report("blockstream.info"),
                        info.to_source_report("mempool.space"),
                    ],
                    info,
                },
            );
            assert_eq!(result.verdict, AnchorVerdict::Valid, "{spelling}");
        }
    }

    /// **A refutation is never suppressed by a neighbouring one.** With both
    /// the Merkle root and the claimed time wrong, the verdict stays
    /// `Invalid`; the Merkle root is reported because it is the more
    /// informative cause, not because the time was forgiven.
    #[test]
    fn a_merkle_mismatch_outranks_a_time_mismatch_and_both_refute() {
        let prepared =
            prepare_fixture(None, Some("2026-01-19T08:01:20+00:00")).expect("proof untouched");
        let info = header(BLOCK_TS, &"9".repeat(64));

        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            },
        );

        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch)
        );
        // The time comparison still ran and still says what it found.
        let (_, _, _, claimed_time_check) = bitcoin_claims(&result);
        assert_eq!(claimed_time_check, ClaimedTimeCheck::Contradicted);
    }

    /// **The blocker this test exists for.** A receipt claiming
    /// `07:01:20.000000001` names a *different instant* from a block stamped
    /// `07:01:20`, and a Bitcoin header has no sub-second component that
    /// could match it. Comparing whole seconds only — which this code did —
    /// reported those two instants as equal and returned `valid`, exit 0:
    /// the check added to stop unverified claims being republished as
    /// verified was itself republishing one.
    #[test]
    fn a_sub_second_offset_is_a_contradiction_not_a_match() {
        for claimed in [
            "2026-01-19T07:01:20.000000001+00:00",
            "2026-01-19T07:01:20.000000001Z",
            "2026-01-19T07:01:20.5Z",
            "2026-01-19T07:01:20.999999999Z",
        ] {
            let prepared = prepare_fixture(None, Some(claimed)).expect("proof untouched");
            let info = header(BLOCK_TS, REAL_ROOT);
            let result = anchor_from_lookup(
                &prepared,
                "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
                BlockLookup::Corroborated {
                    reports: vec![
                        info.to_source_report("blockstream.info"),
                        info.to_source_report("mempool.space"),
                    ],
                    info,
                },
            );

            assert_eq!(
                result.verdict,
                AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedTimeContradictsBlock),
                "{claimed} names a different instant from the block header"
            );
            let (_, _, _, check) = bitcoin_claims(&result);
            assert_eq!(check, ClaimedTimeCheck::Contradicted, "{claimed}");
        }
    }

    /// An *explicit zero* fraction names the same instant, and must still
    /// match: the rule is about instants, not about the presence of a dot.
    #[test]
    fn an_explicit_zero_fraction_still_matches() {
        for claimed in [
            "2026-01-19T07:01:20.0Z",
            "2026-01-19T07:01:20.000000000Z",
            "2026-01-19T07:01:20.000000000+00:00",
            "2026-01-19T08:01:20.0+01:00",
        ] {
            let prepared = prepare_fixture(None, Some(claimed)).expect("proof untouched");
            let info = header(BLOCK_TS, REAL_ROOT);
            let result = anchor_from_lookup(
                &prepared,
                "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
                BlockLookup::Corroborated {
                    reports: vec![
                        info.to_source_report("blockstream.info"),
                        info.to_source_report("mempool.space"),
                    ],
                    info,
                },
            );
            assert_eq!(result.verdict, AnchorVerdict::Valid, "{claimed}");
        }
    }

    /// Precision finer than a nanosecond is refused rather than truncated,
    /// and arrives as an inability. Truncating would put a different instant
    /// back into the `matches` branch by the back door.
    #[test]
    fn sub_nanosecond_precision_is_unreadable_not_a_match() {
        let prepared = prepare_fixture(None, Some("2026-01-19T07:01:20.0000000001Z"))
            .expect("proof untouched");
        let info = header(BLOCK_TS, REAL_ROOT);
        let result = anchor_from_lookup(
            &prepared,
            "sha256:d7b9361804864352cba323e3e5fa56aa2b64bf9299fa71b1df8b48cc97c5eebb",
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            },
        );

        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinClaimedTimeUnreadable)
        );
        let (_, _, _, check) = bitcoin_claims(&result);
        assert_eq!(check, ClaimedTimeCheck::Unreadable);
    }

    /// The four claim-bearing fields of a Bitcoin fact set.
    fn bitcoin_claims(
        result: &AnchorVerificationResult,
    ) -> (Option<u64>, u64, String, ClaimedTimeCheck) {
        match &result.details {
            AnchorDetails::Bitcoin {
                proof_block_height,
                receipt_block_height,
                receipt_block_time,
                claimed_time_check,
                ..
            } => (
                *proof_block_height,
                *receipt_block_height,
                receipt_block_time.clone(),
                *claimed_time_check,
            ),
            _ => panic!("expected a Bitcoin fact set"),
        }
    }
}
