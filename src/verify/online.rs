//! Online verification: the one thing that genuinely needs the network.
//!
//! RFC 3161 anchors are verified in full by [`crate::verify::anchor`], with
//! no network access at all. The only anchor type that needs to go online is
//! `bitcoin_ots`, and only to ask block-explorer APIs for the header whose
//! Merkle root is compared against the
//! OTS proof. This module does exactly that, in place, replacing each
//! `bitcoin_ots` anchor's network-free verdict with the confirmed one.

use std::time::Duration;

use atl_core::ReceiptAnchor;

use crate::error::CliResult;
use crate::net::bitcoin::BlockLookup;
use crate::verify::anchor::BlockSourceReport;
use crate::verify::anchor::PreparedOts;
use crate::verify::anchor::{
    prepare_bitcoin_ots, requires_network, AnchorDetails, AnchorVerdict, AnchorVerificationResult,
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
    config: &OnlineConfig,
) -> AnchorVerificationResult {
    // Every network-free check first, sharing exactly the offline rules.
    let prepared = match prepare_bitcoin_ots(target, target_hash, ots_proof, super_root) {
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
    let claimed_height = prepared.attestation.block_height;

    // Everything a not-yet-compared outcome reports: the local computation,
    // whatever the sources said, and no header presented as established.
    let unconfirmed_details = |reports: Vec<BlockSourceReport>| AnchorDetails::Bitcoin {
        block_height: claimed_height,
        block_timestamp_secs: None,
        target_hash: target_hash.to_string(),
        operation_count: prepared.operation_count,
        computed_root: prepared.computed_root.clone(),
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

    let details = AnchorDetails::Bitcoin {
        block_height: info.height,
        block_timestamp_secs: Some(info.timestamp_secs),
        target_hash: target_hash.to_string(),
        operation_count: prepared.operation_count,
        computed_root: prepared.computed_root.clone(),
        block_merkle_root: Some(format!("sha256:{}", info.merkle_root)),
        merkle_match: Some(merkle_match),
        block_sources: reports,
    };

    if merkle_match {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Valid,
            timestamp_nanos: Some(info.timestamp_secs * 1_000_000_000),
            error: None,
            details,
        }
    } else {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch),
            timestamp_nanos: None,
            error: Some(format!(
                "Merkle root mismatch: the OTS proof does not match the header that \
                 {source_count} block-explorer APIs agree on for block {}",
                info.height
            )),
            details,
        }
    }
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

    fn ots_fixture() -> PreparedOts {
        // The real Receipt-Full anchor, prepared exactly as the offline pass
        // prepares it, so the assertions below run against production data.
        let receipt: atl_core::Receipt =
            serde_json::from_str(include_str!("../../real-data/receipt-full.atl"))
                .expect("fixture receipt");
        let super_root = receipt
            .super_proof
            .as_ref()
            .map(|sp| sp.super_root.as_str());
        let anchor = receipt
            .anchors
            .iter()
            .find_map(|a| match a {
                atl_core::ReceiptAnchor::BitcoinOts {
                    target,
                    target_hash,
                    ots_proof,
                    ..
                } => Some((target.clone(), target_hash.clone(), ots_proof.clone())),
                atl_core::ReceiptAnchor::Rfc3161 { .. } => None,
            })
            .expect("fixture carries a bitcoin_ots anchor");
        crate::verify::anchor::prepare_bitcoin_ots(&anchor.0, &anchor.1, &anchor.2, super_root)
            .expect("the fixture's OTS proof is sound")
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
}
