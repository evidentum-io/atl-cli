//! JSON output formatting
//!
//! Every `status` and `reason_code` printed here comes from
//! [`crate::verify::verdict`] via `verdict()`; nothing in this module
//! decides an outcome of its own. The human renderer reads the same verdict,
//! so the two cannot disagree, and the process exit code is derived from it
//! as well.

use serde::Serialize;

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::anchor::{AnchorDetails, AnchorVerificationResult};
use crate::verify::batch::{BatchItemResult, BatchVerificationResult};
use crate::verify::policy::{TrustAssessment, UnresolvedAnchor};
use crate::verify::single::SingleVerificationResult;
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

#[derive(Serialize)]
struct SingleResultJson {
    /// `"valid"` / `"untrusted"` / `"invalid"`.
    ///
    /// `"untrusted"` means nothing about the evidence was refuted and the
    /// check could not be finished — either this verifier was not given the
    /// trust material, or a fact could not be evaluated at all (cryptography
    /// this verifier does not implement). It is never a success. Read
    /// `reason_code` before telling anyone what to supply: for the
    /// `*_indeterminate` and `*_not_checked` reasons there is nothing to
    /// supply.
    status: &'static str,
    /// Stable machine-readable reason; absent when `status` is `"valid"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    anchor_status: &'static str,
    mode: &'static str,
    source_file: String,
    receipt_file: String,
    file_hash: FileHashJson,
    verification: Option<VerificationJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_verification: Option<AnchorVerificationJson>,
    /// The three axes -- evidence (§5.5), policy (the selected quorum) and
    /// coverage -- reported separately from `status`, which can only carry
    /// one of them. Absent for a receipt with no anchors.
    #[serde(skip_serializing_if = "Option::is_none")]
    assessment: Option<AssessmentJson>,
    errors: Vec<ErrorJson>,
}

#[derive(Serialize)]
struct FileHashJson {
    computed: String,
    expected: String,
    #[serde(rename = "match")]
    is_match: bool,
}

#[derive(Serialize)]
struct VerificationJson {
    entry_id: String,
    inclusion_valid: bool,
    super_inclusion_valid: Option<bool>,
    super_consistency_valid: Option<bool>,
    /// Honest single-number aggregate over what was actually checked:
    /// `inclusion_valid` AND (super proofs, if the receipt has a
    /// `super_proof`). This is a statement about **proofs**, not about
    /// **trust** — it can be `true` for an unanchored receipt, an
    /// unverified checkpoint signature, or a timestamp no external anchor
    /// corroborates. Consumers must look at `status` and
    /// `anchor_verification` to judge trust; do not read `proofs_valid:
    /// true` as "this receipt is verified". See `ProofVerdict::proofs_valid`.
    proofs_valid: bool,
}

impl VerificationJson {
    fn from_verdict(entry_id: String, verdict: crate::verify::ProofVerdict) -> Self {
        Self {
            entry_id,
            inclusion_valid: verdict.inclusion_valid,
            super_inclusion_valid: verdict.super_proof.map(|s| s.inclusion_valid),
            super_consistency_valid: verdict.super_proof.map(|s| s.consistency_valid),
            proofs_valid: verdict.proofs_valid(),
        }
    }
}

#[derive(Serialize)]
struct ErrorJson {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

/// Build the JSON representation of a single-file verification result.
///
/// One shape for both modes: RFC 3161 anchors are verified identically
/// offline and online, so there is no reason for the two to report
/// differently-shaped documents. `mode` says whether any network-backed
/// check ran.
///
/// Split out from [`print_single_result`] so tests can inspect the resulting
/// fields directly instead of parsing captured stdout.
fn build_single_result_json(
    result: &SingleVerificationResult,
    mode: VerificationMode,
) -> SingleResultJson {
    let verdict = result.verdict();

    SingleResultJson {
        status: verdict.status.as_str(),
        reason_code: verdict.reason_code.map(ReasonCode::as_str),
        anchor_status: if result.receipt.anchors.is_empty() {
            "unanchored"
        } else {
            "anchored"
        },
        mode: match mode {
            VerificationMode::Online => "online",
            VerificationMode::Offline => "offline",
        },
        source_file: result.source_path.display().to_string(),
        receipt_file: result.receipt_path.display().to_string(),
        file_hash: FileHashJson {
            computed: format!("sha256:{}", hex::encode(result.file_hash)),
            expected: result.receipt.entry.payload_hash.clone(),
            is_match: result.file_hash_valid,
        },
        verification: if result.file_hash_valid {
            Some(VerificationJson::from_verdict(
                result.receipt.entry.id.to_string(),
                result.proof_verdict(),
            ))
        } else {
            None
        },
        anchor_verification: build_anchor_verification(&result.anchor_results),
        assessment: build_assessment(&result.assessment()),
        errors: build_errors(verdict, result),
    }
}

/// The `errors` array, derived from the verdict rather than from a second
/// pass over `atl-core`'s error list, so it can never name a problem the
/// status does not reflect (or stay silent about one it does).
fn build_errors(verdict: ReceiptVerdict, result: &SingleVerificationResult) -> Vec<ErrorJson> {
    let Some(reason) = verdict.reason_code else {
        return Vec::new();
    };
    // Branched on the status, not on the reason: a run that exits 0 must not
    // hand a machine consumer a populated `errors` array to act on, and
    // `Valid` is the only status that exits 0. Same rule as
    // `batch_item_json`.
    if matches!(verdict.status, Status::Valid) {
        return Vec::new();
    }

    let mut errors = vec![ErrorJson {
        error_type: reason.as_str().to_string(),
        message: describe(reason),
    }];

    for anchor in &result.anchor_results {
        if let (Some(code), Some(message)) = (anchor.verdict.reason_code(), anchor.error.as_ref()) {
            if code != reason {
                continue;
            }
            errors.push(ErrorJson {
                error_type: format!("{}_detail", code.as_str()),
                message: message.clone(),
            });
        }
    }

    errors
}

/// One-line prose for a reason code. The code is the contract; this text is
/// not, and may be reworded freely.
fn describe(reason: ReasonCode) -> String {
    match reason {
        ReasonCode::FileHashMismatch => "File hash does not match receipt",
        ReasonCode::TsaRootNotTrusted => {
            "TSA certificate chain terminates in a root no trust store names"
        }
        ReasonCode::TsaChainIncomplete => "TSA certificate chain is missing an issuer certificate",
        ReasonCode::TsaChainIndeterminate => {
            "TSA certificate chain could not be evaluated; nothing was refuted"
        }
        ReasonCode::CmsSignatureIndeterminate => {
            "CMS signature could not be evaluated; nothing was refuted"
        }
        ReasonCode::TsaImprintIndeterminate => {
            "messageImprint could not be compared; nothing was refuted"
        }
        ReasonCode::TsaImprintMalformed => {
            "messageImprint is malformed: its hash length contradicts the algorithm it names"
        }
        ReasonCode::TsaTimestampingEkuNotChecked => {
            "the signer's timestamping EKU was never examined; no signer was established"
        }
        ReasonCode::BitcoinBlockNotChecked => "Bitcoin block header was not fetched",
        ReasonCode::BitcoinBlockUnavailable => "no block-explorer API returned the block header",
        ReasonCode::BitcoinProvidersDisagree => {
            "block-explorer APIs contradicted each other about the block header; nothing about \
             the receipt was refuted"
        }
        ReasonCode::BitcoinSingleSourceOnly => {
            "only one block-explorer API answered, so the block header is uncorroborated"
        }
        ReasonCode::BatchItemsInvalid => "One or more items failed verification",
        ReasonCode::BatchItemsUntrusted => {
            "One or more items could not be verified to completion; none was refuted"
        }
        ReasonCode::BatchItemsUnmatched => {
            "One or more named files were never verified: no matching receipt or source file"
        }
        ReasonCode::BatchNothingVerified => "No file in this batch was verified",
        ReasonCode::BatchItemsUnanchored => {
            "One or more receipts carry no anchors at all, so they have no verified anchor \
             (ATL v2.0 5.5)"
        }
        ReasonCode::ReceiptUnanchored => {
            "The receipt carries no anchors at all, so it has no verified anchor (ATL v2.0 5.5)"
        }
        ReasonCode::BatchItemsErrored => "One or more items could not be processed",
        ReasonCode::LogConsistencyFailed => "Cross-receipt log consistency verification failed",
        other => return other.as_str().replace('_', " "),
    }
    .to_string()
}

pub fn print_single_result(
    result: &SingleVerificationResult,
    mode: VerificationMode,
) -> CliResult<()> {
    let output = build_single_result_json(result, mode);
    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

#[derive(Serialize)]
struct BatchResultJson {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    mode: &'static str,
    /// The anchor quorum every item was judged against: `"all-anchors"`
    /// (default) or `"single-anchor"` (`--allow-single-anchor`).
    policy_profile: &'static str,
    source_dir: String,
    receipt_dir: String,
    summary: SummaryJson,
    consistency: Option<ConsistencyJson>,
    items: Vec<BatchItemJson>,
    errors: Vec<ErrorJson>,
}

#[derive(Serialize)]
struct SummaryJson {
    total: usize,
    valid: usize,
    /// Items whose receipts carry no anchors at all (Receipt-Lite).
    ///
    /// A sub-count of the untrusted outcome, not of the valid one: ATL v2.0
    /// §5.5 says a receipt without any verified anchors should be treated as
    /// untrustworthy, and such an item's own `status` is `"untrusted"` with
    /// `reason_code` `"receipt_unanchored"`. It is counted apart only
    /// because no trust material a caller could supply would change it.
    ///
    /// Renamed from `pending`, which named an exit-0 success this outcome is
    /// not.
    unanchored: usize,
    /// Items that were not refuted but could not be verified to completion
    /// — no configured trust root, or a check that could not be performed.
    untrusted: usize,
    invalid: usize,
    errors: usize,
    unmatched: usize,
}

#[derive(Serialize)]
struct ConsistencyJson {
    status: &'static str,
    /// How many distinct log instances the participants came from, counted
    /// by the ATL v2.0 §3.3.2 identifier `genesis_super_root`.
    ///
    /// More than one is reported, never punished: §5.4.3 defines no error
    /// for receipts whose identifiers differ, and calling that `failed` made
    /// the batch exit 1 on evidence that is entirely sound. Each log
    /// instance is checked separately; `status` covers all of them.
    log_instances: usize,
    /// The §3.3.2 identifier all participants share — absent when
    /// `log_instances > 1`, because then there is no single one to name.
    genesis_super_root: Option<String>,
    receipt_count: usize,
    cross_checks_passed: usize,
    cross_checks: Vec<CrossCheckJson>,
}

#[derive(Serialize)]
struct CrossCheckJson {
    from_index: usize,
    to_index: usize,
    from_file: String,
    to_file: String,
    /// ATL v2.0 §5.4.3 holds for this pair: both receipts carry the same
    /// `genesis_super_root` and valid `consistency_to_origin` proofs, so
    /// "the log history between them was not modified".
    ///
    /// This field was `included`, which said one receipt's Super-Tree had
    /// been shown to contain the other's. No receipt carries such a proof
    /// and nothing checks it; §5.4.2 proves only that the genesis state is a
    /// prefix of each receipt's own current state. A Split-View (fork) is
    /// not ruled out here — per §7.3.2 that defence is a verified external
    /// anchor.
    same_log_instance: bool,
}

/// One row of a batch report.
///
/// `status` is the item's own verdict word for every bucket that reached a
/// verdict (`valid` / `pending` / `untrusted` / `invalid`), so a row can
/// never say something the summary contradicts. Two extra words appear for
/// items that never reached a verdict at all -- `no_receipt` and `no_source`
/// -- plus `error` for one that could not be processed; all three carry the
/// aggregate's `reason_code` so they can be joined to the top-level status.
#[derive(Serialize)]
struct BatchItemJson {
    file: String,
    receipt: Option<String>,
    status: &'static str,
    /// The item's own three axes, so a row can be judged without re-running
    /// the tool on it. Absent for a receipt with no anchors.
    #[serde(skip_serializing_if = "Option::is_none")]
    assessment: Option<AssessmentJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_hash_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    super_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_tree_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Render one verified batch item, whatever bucket it landed in. The status
/// string comes from the item's own verdict, so a `Valid` bucket can never
/// print anything but `"valid"`/`"pending"`.
fn batch_item_json(result: &SingleVerificationResult) -> BatchItemJson {
    let verdict = result.verdict();
    let (super_root, data_tree_index) = result
        .receipt
        .super_proof
        .as_ref()
        .map_or((None, None), |sp| {
            (Some(sp.super_root.clone()), Some(sp.data_tree_index))
        });

    BatchItemJson {
        file: file_name(&result.source_path),
        receipt: Some(file_name(&result.receipt_path)),
        status: verdict.status.as_str(),
        assessment: build_assessment(&result.assessment()),
        reason_code: verdict.reason_code.map(ReasonCode::as_str),
        file_hash_match: Some(result.file_hash_valid),
        super_root,
        data_tree_index,
        // `error` is for outcomes that did not reach acceptance. Only
        // `valid` exits 0, and a run that exits 0 must never hand a machine
        // consumer a populated error field to act on.
        error: verdict
            .reason_code
            .filter(|_| !matches!(verdict.status, Status::Valid))
            .map(describe),
    }
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

pub fn print_batch_result(
    result: &BatchVerificationResult,
    mode: VerificationMode,
    source_dir: &std::path::Path,
    receipt_dir: &std::path::Path,
) -> CliResult<()> {
    // Single source of truth for the total: computing it inline here
    // once omitted `untrusted_count` and printed a total that did not
    // match the rows beneath it.
    let total = result.total_count();

    // The receipts that took part come from the consistency result itself,
    // in the order it walked them. Rebuilding the list here -- with a
    // different filter and a different sort key than the check used -- made
    // the `[i] -> [j]` rows name files by positional coincidence, and emit
    // empty names whenever the two lists differed in length.
    let consistency = result.consistency.as_ref().map(|c| {
        let cross_checks_passed = c
            .cross_results
            .iter()
            .filter(|cr| cr.result.history_consistent)
            .count();

        // Indices come from the check itself, not from this list's position:
        // participants are grouped by log instance, so `idx` / `idx + 1`
        // would name pairs that were never compared.
        let cross_checks: Vec<CrossCheckJson> = c
            .cross_results
            .iter()
            .map(|cr| CrossCheckJson {
                from_index: cr.from_index + 1,
                to_index: cr.to_index + 1,
                from_file: c
                    .participants
                    .get(cr.from_index)
                    .cloned()
                    .unwrap_or_default(),
                to_file: c.participants.get(cr.to_index).cloned().unwrap_or_default(),
                same_log_instance: cr.result.history_consistent,
            })
            .collect();

        ConsistencyJson {
            // `not_checked` is not a third kind of failure: it is the
            // honest word for a run where no two participants shared a log
            // instance, so no pair satisfied ATL v2.0 §5.4.3 step 2 and no
            // comparison existed to pass or fail. Calling it `verified`
            // would report a check that never ran.
            status: if c.checked() {
                if c.is_valid() {
                    "verified"
                } else {
                    "failed"
                }
            } else {
                "not_checked"
            },
            log_instances: c.log_instance_count,
            genesis_super_root: c
                .genesis_super_root
                .map(|h| format!("sha256:{}", hex::encode(h))),
            receipt_count: c.receipt_count,
            cross_checks_passed,
            cross_checks,
        }
    });

    let items: Vec<BatchItemJson> = result
        .items
        .iter()
        .map(|item| match item {
            BatchItemResult::Valid(r)
            | BatchItemResult::Unanchored(r)
            | BatchItemResult::Untrusted(r)
            | BatchItemResult::Invalid(r) => batch_item_json(r),
            BatchItemResult::Error { source, error, .. } => BatchItemJson {
                file: file_name(source),
                receipt: None,
                status: "error",
                assessment: None,
                reason_code: Some(ReasonCode::BatchItemsErrored.as_str()),
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: Some(error.to_string()),
            },
            // `status` here is deliberately more specific than the four
            // `Status` words -- it says which side of the pair is missing.
            // `reason_code` carries the aggregate's own code so a consumer
            // can join the item rows to the top-level verdict; without it,
            // `.items[].reason_code` never yielded `batch_items_unmatched`
            // and the rows could not explain the status they produced.
            BatchItemResult::NoReceipt(path) => BatchItemJson {
                file: file_name(path),
                receipt: None,
                status: "no_receipt",
                assessment: None,
                reason_code: Some(ReasonCode::BatchItemsUnmatched.as_str()),
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: None,
            },
            BatchItemResult::NoSource(path) => BatchItemJson {
                file: file_name(path),
                receipt: None,
                status: "no_source",
                assessment: None,
                reason_code: Some(ReasonCode::BatchItemsUnmatched.as_str()),
                file_hash_match: None,
                super_root: None,
                data_tree_index: None,
                error: None,
            },
        })
        .collect();

    let verdict = result.verdict();
    let output = BatchResultJson {
        status: verdict.status.as_str(),
        reason_code: verdict.reason_code.map(ReasonCode::as_str),
        mode: match mode {
            VerificationMode::Online => "online",
            VerificationMode::Offline => "offline",
        },
        policy_profile: result.policy.as_str(),
        source_dir: source_dir.display().to_string(),
        receipt_dir: receipt_dir.display().to_string(),
        summary: SummaryJson {
            total,
            valid: result.valid_count,
            unanchored: result.unanchored_count,
            untrusted: result.untrusted_count,
            invalid: result.invalid_count,
            errors: result.error_count,
            unmatched: result.unmatched_count,
        },
        consistency,
        items,
        // Same rule as the per-item field: a run that exits 0 must not also
        // hand back a non-empty `errors`. Only `valid` exits 0, so the test
        // is now simply "was this accepted".
        errors: match verdict.reason_code {
            Some(reason) if !matches!(verdict.status, Status::Valid) => {
                vec![ErrorJson {
                    error_type: reason.as_str().to_string(),
                    message: describe(reason),
                }]
            }
            _ => Vec::new(),
        },
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

#[derive(Serialize)]
struct AnchorResultJson {
    #[serde(rename = "type")]
    anchor_type: String,
    /// `true` only when the anchor is a **verified anchor** in the ATL v2.0
    /// §5.5 sense: its cryptographic facts were checked AND its certificate
    /// path reached a root the caller supplied. An anchor whose root is
    /// merely `assumed` is `false` here, however sound its cryptography.
    verified: bool,
    /// The anchor's state, uniform across anchor types:
    ///
    /// - `"verified"` — checked, and a caller-supplied trust root reached;
    /// - `"cryptographically_consistent"` — every checkable fact holds, and
    ///   the path terminates in a certificate no trust store names. NOT
    ///   verified: a sound signature under an unknown root establishes only
    ///   that some key signed it;
    /// - `"incomplete"` — an issuer certificate is missing (supply it);
    /// - `"not_checked"` — the selected mode does not perform this check
    ///   (an offline run does not fetch the Bitcoin block);
    /// - `"unavailable"` — the check was attempted and did not complete;
    /// - `"unevaluable"` — the check cannot be performed by this build at
    ///   all (an algorithm it does not implement);
    /// - `"refuted"` — a checkable fact is false.
    ///
    /// Derived from the same verdict as `verified` and `reason_code`, so the
    /// three can never disagree. Prefer this over the RFC 3161-only
    /// `trust_state`, which is kept for compatibility.
    state: &'static str,
    /// Stable machine-readable reason; absent when `verified` is `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    /// The time this anchor **establishes** — emitted only when `verified`
    /// is `true`.
    ///
    /// A timestamp anchor exists to answer "when did this exist", so this is
    /// the single number a consumer is most likely to lift straight out and
    /// act on. Emitting it for an unverified anchor would hand over the
    /// token's own unchecked claim wearing the name of a verified fact. When
    /// the anchor is not accepted the key is **absent**, not annotated: a
    /// script reading `timestamp` gets nothing and fails loudly rather than
    /// silently trusting a number nobody established.
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_nanos: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    /// The time this anchor **asserts**, emitted only when `verified` is
    /// `false` — the same value the fields above would have carried, under a
    /// name that cannot be mistaken for an established fact. Attacker-
    /// controlled until the anchor verifies: useful for diagnostics and for
    /// reporting *what was claimed*, never admissible as when something
    /// existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_timestamp_nanos: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_timestamp: Option<String>,
    /// The block's height, emitted **only** when `verified` is `true` — that
    /// is, when two or more sources reported the same header at that height
    /// and its Merkle root matched the one the OTS proof computes.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
    /// The block's time, emitted only when a corroborated header was
    /// obtained and matched. Absent otherwise — never a zero rendered as
    /// `"1970-01-01T00:00:00Z"`, which is a value a script would parse and
    /// act on for a check that never ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_timestamp: Option<String>,
    /// The block height the **OTS proof's** earliest Bitcoin attestation
    /// carries, emitted only when `verified` is `false`.
    ///
    /// Named for its claimant. It was `claimed_block_height`, which said
    /// that *something* claimed it without saying what — and the prose
    /// beside it attributed it to the receipt, which was simply wrong: the
    /// receipt's own `bitcoin_block_height` was read nowhere in this crate
    /// and is now published separately as `receipt_block_height`. Two
    /// distinct assertions had one name between them, and the one that could
    /// be attacked independently was invisible.
    ///
    /// Attacker-controlled until a block at that height has been fetched and
    /// matched, so it keeps the un-established marking an unverified
    /// anchor's `genTime` gets: never admissible as where in the chain this
    /// receipt landed.
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_block_height: Option<u64>,
    /// Every block height the OTS proof attests to, in proof order.
    ///
    /// The evidence for `bitcoin_claimed_height_contradicts_proof`. A proof
    /// may carry several Bitcoin attestations, and the receipt's claim holds
    /// if it matches **any** of them (ATL v2.0 §5.5.2 step 5 says "match the
    /// proof" and sets no rule preferring one attestation over another). A
    /// reader told the claim matches nothing must be able to see this set,
    /// or the finding cannot be checked.
    ///
    /// Empty — and so omitted — only when no attestation was read at all,
    /// which means the anchor was rejected before its proof decoded.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    proof_block_heights: Vec<u64>,
    /// The block height **the receipt itself states**, in its
    /// `bitcoin_block_height` field.
    ///
    /// Emitted for every `bitcoin_ots` anchor, verified or not — and,
    /// deliberately, for one rejected before its proof ever decoded. Those
    /// are the anchors where a reader most wants to see what the receipt
    /// asserted, and they used to publish nothing: the early rejections
    /// built an `AnchorDetails::Unknown`, whose serialization drops every
    /// Bitcoin field, so this documented promise was false exactly where it
    /// mattered.
    ///
    /// It is the receipt's own assertion, checked against
    /// `proof_block_heights` (ATL v2.0 §5.5.2 step 5); a claim matching none
    /// of them is `bitcoin_claimed_height_contradicts_proof` — a refutation
    /// reachable offline, since an OTS attestation carries the height in its
    /// own bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_block_height: Option<u64>,
    /// The block time **the receipt itself states**, in its
    /// `bitcoin_block_time` field, verbatim.
    ///
    /// Verbatim rather than normalised: beside `claimed_time_check:
    /// "unreadable"` the exact string is the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_block_time: Option<String>,
    /// What became of that claimed time: `"matches"`, `"contradicted"`,
    /// `"not_compared"` or `"unreadable"`.
    ///
    /// Four-valued because "compared and different" and "never compared" are
    /// different findings and only the first refutes anything. The block
    /// time is in no OTS proof, so offline — and whenever no corroborated
    /// header was obtained — the value is `"not_compared"`, and the anchor
    /// is untrusted for the reason it already was, never invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_time_check: Option<&'static str>,
    /// The block time that named sources **reported**, for an anchor that is
    /// not verified — in practice, one refuted by
    /// `bitcoin_merkle_root_mismatch`.
    ///
    /// `reported_`, not `claimed_`: nobody asserted it, this run asked and
    /// was told. Not `observed_` either, which was the previous name and
    /// went too far in the other direction — this tool queries HTTP APIs, it
    /// does not observe the Bitcoin network, and `observed` invited exactly
    /// the reading the `on-chain` prose beside it used to make explicit.
    ///
    /// What it is not is a fact about *this receipt*: the block's Merkle
    /// root did not match the one the OTS proof computes, so the block
    /// attests to nothing here. It is kept, and kept renamed, because it is
    /// real diagnostic material that must not be readable as "this is when
    /// your evidence existed". `block_sources` says who reported it.
    #[serde(skip_serializing_if = "Option::is_none")]
    reported_block_timestamp: Option<String>,
    /// Every block-explorer API that answered, and what each one reported.
    ///
    /// Always emitted when any source answered, whatever the outcome. This
    /// tool reads block headers out of HTTP APIs; it validates no proof of
    /// work and follows no chain of headers, so every Bitcoin value in this
    /// object is *what these endpoints said*, and a consumer is entitled to
    /// know which ones and how many.
    ///
    /// More than one entry with differing `merkle_root` values means the
    /// sources contradicted each other: `reason_code` is then
    /// `bitcoin_providers_disagree`, and no header was established, so
    /// nothing was compared. That is a finding about the sources, never
    /// about the receipt.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    block_sources: Vec<BlockSourceJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    // Bitcoin OTS verification chain (only for bitcoin_ots type)
    #[serde(skip_serializing_if = "Option::is_none")]
    target_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_count: Option<usize>,
    /// The Merkle root computed from the OTS proof. Kept under its plain
    /// name for a refuted anchor too: it is a deterministic local
    /// computation over the receipt's own bytes, its name says exactly that,
    /// and it is one half of the evidence for a mismatch.
    #[serde(skip_serializing_if = "Option::is_none")]
    computed_root: Option<String>,
    /// The Merkle root that two or more configured sources report for that
    /// block. Kept under its plain name for the same reason as
    /// `computed_root`, and one more: it describes the *block*, never the
    /// receipt; it is emitted only when a corroborated header was obtained;
    /// and it never appears without `merkle_match` and `block_sources`
    /// beside it. It is the other half of the mismatch evidence, and
    /// renaming it would hide the one field a reader needs in order to see
    /// the refutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_merkle_root: Option<String>,
    /// Whether the two roots above agree. Kept plain: `false` **is** the
    /// refutation, and it is the most honest field in the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_match: Option<bool>,
    // RFC 3161 facts (only for rfc3161 type) -- see `Rfc3161AnchorFacts` in
    // atl-core. Reported as *facts*, not a collapsed verdict.
    // `trust_state` is the one summary label the human renderer uses too --
    // `"trusted"`, `"assumed"` (a self-issued terminal nobody vouched for),
    // `"incomplete"` (material missing on this side), `"indeterminate"` (a
    // check that could not be performed at all) or `"failed"` (something was
    // refuted) -- derived from the same classification as `verified` and
    // `reason_code`, so the three can never disagree.
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_state: Option<&'static str>,
    /// `"verified"`, `"mismatch"`, `"malformed"`, or `"indeterminate"`.
    /// Replaces the former `imprint_matches_root` boolean: an imprint whose
    /// hash algorithm this verifier does not implement was never compared at
    /// all, and a boolean forced that to be reported as a mismatch.
    /// `"mismatch"` and `"malformed"` are both refutations but are kept
    /// apart — a hash length contradicting its own algorithm could never be
    /// compared, so calling it a mismatch would explain a proven defect with
    /// the wrong cause.
    #[serde(skip_serializing_if = "Option::is_none")]
    message_imprint: Option<&'static str>,
    /// `"verified"`, `"refuted"`, or `"indeterminate"`. Replaces the former
    /// `cms_signature_valid` boolean: an algorithm this verifier does not
    /// implement is neither a valid nor an invalid signature, and a boolean
    /// forced it to be reported as invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    cms_signature: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_valid_at_gen_time: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamping_eku_ok: Option<bool>,
    /// *Which* RFC 3161 2.3 condition the EKU check landed on: `"ok"`,
    /// `"absent"`, `"malformed"`, `"not_critical"`, `"not_exclusive"`, or
    /// `"not_checked"`. `timestamping_eku_ok` keeps the yes/no; this says
    /// which, because "the TSA issued a signer with no EKU at all" and "the
    /// extension is duplicated" are different problems.
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamping_eku: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_anchor: Option<TerminalAnchorJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation: Option<&'static str>,
}

/// One block-explorer API's report of a block header.
#[derive(Serialize)]
struct BlockSourceJson {
    /// The endpoint's name, e.g. `"blockstream.info"`.
    source: String,
    block_hash: String,
    merkle_root: String,
    /// Absent if the reported time did not survive plausibility validation —
    /// which cannot happen for a value that reached this far, since such a
    /// response is discarded at intake.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_timestamp: Option<String>,
}

#[derive(Serialize)]
struct TerminalAnchorJson {
    /// `"trusted"` if the fingerprint was matched against the caller's
    /// `--tsa-trust-store`, `"assumed"` if the chain merely terminates in
    /// a self-issued certificate nobody vouched for.
    kind: &'static str,
    /// SHA-256 fingerprint of the terminal certificate, with `sha256:`
    /// prefix, regardless of `kind`.
    sha256_fingerprint: String,
    /// For `kind: "assumed"` only: `"verified"` when that certificate's
    /// signature over itself was checked and holds, `"unverifiable"` when
    /// this verifier could not check it at all (an unsupported signature
    /// algorithm — SHA-1-self-signed roots are the common case). Absent for
    /// `kind: "trusted"`, where the caller vouched for the certificate and
    /// its self-signature is beside the point.
    #[serde(skip_serializing_if = "Option::is_none")]
    self_signature: Option<&'static str>,
}

#[derive(Serialize)]
struct AnchorVerificationJson {
    all_verified: bool,
    results: Vec<AnchorResultJson>,
}

/// `atl_core::PathStatus` -> a stable lowercase JSON string.
fn path_status_str(status: atl_core::PathStatus) -> &'static str {
    match status {
        atl_core::PathStatus::Complete => "complete",
        atl_core::PathStatus::Incomplete => "incomplete",
        atl_core::PathStatus::Indeterminate => "indeterminate",
        atl_core::PathStatus::Invalid => "invalid",
    }
}

/// `atl_core::MessageImprint` -> a stable lowercase JSON string. Written as
/// a `match` so a future variant fails to compile here rather than silently
/// acquiring a wrong label.
fn message_imprint_str(imprint: atl_core::MessageImprint) -> &'static str {
    match imprint {
        atl_core::MessageImprint::Verified => "verified",
        atl_core::MessageImprint::Mismatch => "mismatch",
        atl_core::MessageImprint::Malformed => "malformed",
        atl_core::MessageImprint::Indeterminate => "indeterminate",
    }
}

/// `atl_core::CmsSignature` -> a stable lowercase JSON string. Written as a
/// `match` so a future variant fails to compile here rather than silently
/// falling through to a wrong label.
fn cms_signature_str(signature: atl_core::CmsSignature) -> &'static str {
    match signature {
        atl_core::CmsSignature::Verified => "verified",
        atl_core::CmsSignature::Refuted => "refuted",
        atl_core::CmsSignature::Indeterminate => "indeterminate",
    }
}

/// `atl_core::TimestampingEku` -> a stable `snake_case` JSON string.
fn timestamping_eku_str(eku: atl_core::TimestampingEku) -> &'static str {
    match eku {
        atl_core::TimestampingEku::Ok => "ok",
        atl_core::TimestampingEku::NotChecked => "not_checked",
        atl_core::TimestampingEku::Absent => "absent",
        atl_core::TimestampingEku::Malformed => "malformed",
        atl_core::TimestampingEku::NotCritical => "not_critical",
        atl_core::TimestampingEku::NotExclusive => "not_exclusive",
    }
}

/// `atl_core::Revocation` -> a stable lowercase JSON string. Only
/// `NotChecked` exists today (see the type's own docs), but this is written
/// as a `match` so a future variant fails to compile here instead of
/// silently falling through.
fn revocation_str(revocation: atl_core::Revocation) -> &'static str {
    match revocation {
        atl_core::Revocation::NotChecked => "not_checked",
    }
}

/// `atl_core::TerminalAnchor` -> its JSON representation.
fn terminal_anchor_json(anchor: atl_core::TerminalAnchor) -> TerminalAnchorJson {
    let (kind, fingerprint, self_signature) = match anchor {
        atl_core::TerminalAnchor::Trusted { sha256_fingerprint } => {
            ("trusted", sha256_fingerprint, None)
        }
        atl_core::TerminalAnchor::Assumed {
            sha256_fingerprint,
            self_signature,
        } => (
            "assumed",
            sha256_fingerprint,
            Some(match self_signature {
                atl_core::SelfSignature::Verified => "verified",
                atl_core::SelfSignature::Unverifiable => "unverifiable",
            }),
        ),
    };
    TerminalAnchorJson {
        kind,
        sha256_fingerprint: format!("sha256:{}", hex::encode(fingerprint)),
        self_signature,
    }
}

/// Format nanoseconds timestamp to ISO 8601 string
fn format_timestamp_iso(nanos: u64) -> Option<String> {
    use chrono::{TimeZone, Utc};
    let secs = i64::try_from(nanos / 1_000_000_000).ok()?;
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Format seconds timestamp to ISO 8601 string
fn format_timestamp_secs_iso(secs: u64) -> Option<String> {
    use chrono::{TimeZone, Utc};
    let secs_i64 = i64::try_from(secs).ok()?;
    Utc.timestamp_opt(secs_i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Every `bitcoin_ots` field of [`AnchorResultJson`], gathered before the
/// object is assembled.
///
/// A named struct rather than a tuple: the fields are numbers and strings of
/// the same shapes, several of them differ only in *whose claim they are*,
/// and a positional tuple is how a value ends up published under a
/// neighbour's name. [`Default`] supplies the all-absent case for an anchor
/// that is not `bitcoin_ots`.
#[derive(Default)]
struct BitcoinJson {
    block_height: Option<u64>,
    block_timestamp: Option<String>,
    proof_block_height: Option<u64>,
    proof_block_heights: Vec<u64>,
    reported_block_timestamp: Option<String>,
    receipt_block_height: Option<u64>,
    receipt_block_time: Option<String>,
    claimed_time_check: Option<&'static str>,
    target_hash: Option<String>,
    operation_count: Option<usize>,
    computed_root: Option<String>,
    block_merkle_root: Option<String>,
    merkle_match: Option<bool>,
    block_sources: Vec<BlockSourceJson>,
}

/// Render one anchor's fact set.
fn anchor_result_json(anchor: &AnchorVerificationResult) -> AnchorResultJson {
    // Both of the anchor's numbers follow the same rule as the RFC 3161
    // `genTime` above: a plain name is reserved for a fact this run
    // established ABOUT THIS RECEIPT, and anything short of that is renamed
    // so it cannot be lifted out and acted on.
    //
    // They are renamed differently, because they are different kinds of
    // not-established:
    //
    // - the height is the *OTS proof's* attestation about where in the chain
    //   this anchor lands, so it becomes `proof_block_height`. The receipt's
    //   own `bitcoin_block_height` is a separate assertion and travels under
    //   `receipt_block_height`; this comment used to conflate the two and
    //   name a field, `claimed_block_height`, that said neither;
    // - the time is *our observation* of a block we really did fetch, so it
    //   becomes `reported_block_timestamp`. Calling it "claimed" would be a
    //   second falsehood -- nobody claimed it, we asked and were told -- and
    //   calling it "observed" overstates it in the other direction, since
    //   this tool queries HTTP APIs rather than watching the chain.
    //
    // The time used to be serialized unconditionally, and the online path
    // fetches the block *before* deciding whether its Merkle root matches.
    // So a refuted anchor -- `bitcoin_merkle_root_mismatch`, the block
    // proving nothing whatever about this receipt -- still published
    // `block_timestamp` under the plain name, beside `merkle_match: false`.
    // "Named sources reported this block" and "this block dates your
    // evidence" are the distinction this whole tool exists to keep.
    let bitcoin = match &anchor.details {
        AnchorDetails::Bitcoin {
            proof_block_height,
            proof_block_heights,
            receipt_block_height,
            receipt_block_time,
            claimed_time_check,
            block_timestamp_secs,
            target_hash,
            operation_count,
            computed_root,
            block_merkle_root,
            merkle_match,
            block_sources,
        } => {
            let established = anchor.verified();
            let block_time = block_timestamp_secs.and_then(format_timestamp_secs_iso);
            BitcoinJson {
                block_height: established.then_some(*proof_block_height).flatten(),
                block_timestamp: established.then(|| block_time.clone()).flatten(),
                proof_block_height: (!established).then_some(*proof_block_height).flatten(),
                proof_block_heights: proof_block_heights.clone(),
                reported_block_timestamp: (!established).then_some(block_time).flatten(),
                // The receipt's own two assertions, published whatever the
                // outcome: they are what step 5 checks, and a reader cannot
                // audit that check without seeing them.
                receipt_block_height: Some(*receipt_block_height),
                receipt_block_time: Some(receipt_block_time.clone()),
                claimed_time_check: Some(claimed_time_check.as_str()),
                target_hash: Some(target_hash.clone()),
                operation_count: *operation_count,
                computed_root: computed_root.clone(),
                block_merkle_root: block_merkle_root.clone(),
                merkle_match: *merkle_match,
                block_sources: block_sources
                    .iter()
                    .map(|r| BlockSourceJson {
                        source: r.source.clone(),
                        block_hash: r.block_hash.clone(),
                        merkle_root: r.merkle_root.clone(),
                        block_timestamp: format_timestamp_secs_iso(r.block_timestamp_secs),
                    })
                    .collect(),
            }
        }
        AnchorDetails::Rfc3161 { .. } | AnchorDetails::Unknown => BitcoinJson::default(),
    };

    let (
        message_imprint,
        cms_signature,
        chain_valid_at_gen_time,
        timestamping_eku_ok,
        timestamping_eku,
        path_status,
        terminal_anchor,
        revocation,
    ) = match &anchor.details {
        AnchorDetails::Rfc3161 {
            message_imprint,
            cms_signature,
            chain_valid_at_gen_time,
            timestamping_eku_ok,
            timestamping_eku,
            path_status,
            terminal_anchor,
            revocation,
            ..
        } => (
            Some(message_imprint_str(*message_imprint)),
            Some(cms_signature_str(*cms_signature)),
            Some(*chain_valid_at_gen_time),
            Some(*timestamping_eku_ok),
            Some(timestamping_eku_str(*timestamping_eku)),
            Some(path_status_str(*path_status)),
            terminal_anchor.map(terminal_anchor_json),
            Some(revocation_str(*revocation)),
        ),
        _ => (None, None, None, None, None, None, None, None),
    };

    let (established_time, claimed_time) = if anchor.verified() {
        (anchor.timestamp_nanos, None)
    } else {
        (None, anchor.timestamp_nanos)
    };

    AnchorResultJson {
        anchor_type: anchor.anchor_type.clone(),
        verified: anchor.verified(),
        state: anchor.state().as_str(),
        reason_code: anchor.verdict.reason_code().map(ReasonCode::as_str),
        // Established vs. claimed: the same value, but only one of the two
        // names is ever emitted, decided by the verdict.
        timestamp_nanos: established_time,
        timestamp: established_time.and_then(format_timestamp_iso),
        claimed_timestamp_nanos: claimed_time,
        claimed_timestamp: claimed_time.and_then(format_timestamp_iso),
        block_height: bitcoin.block_height,
        block_timestamp: bitcoin.block_timestamp,
        proof_block_height: bitcoin.proof_block_height,
        proof_block_heights: bitcoin.proof_block_heights,
        reported_block_timestamp: bitcoin.reported_block_timestamp,
        receipt_block_height: bitcoin.receipt_block_height,
        receipt_block_time: bitcoin.receipt_block_time,
        claimed_time_check: bitcoin.claimed_time_check,
        block_sources: bitcoin.block_sources,
        error: anchor.error.clone(),
        target_hash: bitcoin.target_hash,
        operation_count: bitcoin.operation_count,
        computed_root: bitcoin.computed_root,
        block_merkle_root: bitcoin.block_merkle_root,
        merkle_match: bitcoin.merkle_match,
        trust_state: anchor.details.rfc3161_trust_state(),
        message_imprint,
        cms_signature,
        chain_valid_at_gen_time,
        timestamping_eku_ok,
        timestamping_eku,
        path_status,
        terminal_anchor,
        revocation,
    }
}

fn build_anchor_verification(
    anchors: &[AnchorVerificationResult],
) -> Option<AnchorVerificationJson> {
    if anchors.is_empty() {
        return None;
    }
    Some(AnchorVerificationJson {
        all_verified: anchors.iter().all(AnchorVerificationResult::verified),
        results: anchors.iter().map(anchor_result_json).collect(),
    })
}

/// The three axes, as JSON.
///
/// `None` for a receipt with no anchors: there is no quorum to report on,
/// and the `receipt_unanchored` reason code already says everything there is
/// to say.
fn build_assessment(assessment: &TrustAssessment) -> Option<AssessmentJson> {
    if assessment.total_anchors == 0 {
        return None;
    }
    Some(AssessmentJson {
        evidence: EvidenceJson {
            established: assessment.evidence_established(),
            verified_anchors: assessment.verified_anchors,
            refuted_anchors: assessment.refuted_anchors(),
            total_anchors: assessment.total_anchors,
            refuted_by: assessment.refuted_by().map(ReasonCode::as_str),
        },
        policy: PolicyJson {
            profile: assessment.policy.as_str(),
            requirement: assessment.policy.requirement(),
            satisfied: assessment.policy_satisfied(),
            max_trust_profile: assessment.max_trust_profile(),
        },
        coverage: CoverageJson {
            complete: assessment.coverage_complete(),
            accepted_with_gaps: assessment.accepted_with_gaps(),
            unresolved: anchor_list(&assessment.unresolved),
            refuted: anchor_list(&assessment.refuted),
        },
    })
}

/// The three axes a receipt's anchors are reported on, published separately
/// because they answer different questions.
#[derive(Serialize)]
struct AssessmentJson {
    evidence: EvidenceJson,
    policy: PolicyJson,
    coverage: CoverageJson,
}

/// ATL v2.0 §5.5: is trust established at all?
#[derive(Serialize)]
struct EvidenceJson {
    /// At least one anchor is a verified anchor.
    established: bool,
    /// How many anchors are verified — cryptographic facts checked AND a
    /// caller-supplied trust root reached. Nothing weaker is counted.
    verified_anchors: usize,
    /// How many **anchors** were checked and found false.
    ///
    /// Counts anchors only. A receipt can be refuted with this at `0` — by a
    /// source file whose hash does not match, or a broken inclusion proof —
    /// and `refuted_by` is what names that case.
    refuted_anchors: usize,
    total_anchors: usize,
    /// The reason code that disqualifies this receipt, from whatever source:
    /// a refuted anchor, or the receipt itself. Absent when nothing was
    /// refuted, and always equal to the top-level `reason_code` when
    /// present.
    ///
    /// This is what makes `established: false` beside `verified_anchors: 1`
    /// legible rather than contradictory: an anchor really did reach a
    /// trusted root, and a refutation outranks it.
    #[serde(skip_serializing_if = "Option::is_none")]
    refuted_by: Option<&'static str>,
}

/// Is the anchor quorum the caller selected met?
#[derive(Serialize)]
struct PolicyJson {
    /// `"all-anchors"` (default) or `"single-anchor"`
    /// (`--allow-single-anchor`).
    profile: &'static str,
    /// The requirement in prose, with its spec citation.
    requirement: &'static str,
    satisfied: bool,
    /// ATL v2.0 §5.6: both an RFC 3161 and a Bitcoin OTS anchor are
    /// verified **and nothing was refuted**. Reported on every run whatever
    /// the profile, because §5.6 describes the maximum-trust tier rather
    /// than this tool's acceptance threshold.
    ///
    /// The refutation clause is not pedantry. Without it a receipt with two
    /// verified anchors and a third refuted one reported `status: "invalid"`
    /// and `max_trust_profile: true` side by side.
    max_trust_profile: bool,
}

/// Render one of the coverage lists.
fn anchor_list(anchors: &[UnresolvedAnchor]) -> Vec<UnresolvedAnchorJson> {
    anchors
        .iter()
        .map(|a| UnresolvedAnchorJson {
            anchor_type: a.anchor_type.clone(),
            state: a.state.as_str(),
            reason_code: a.reason.as_str(),
        })
        .collect()
}

/// Was every anchor the receipt presents carried to a sound result?
#[derive(Serialize)]
struct CoverageJson {
    /// `true` only when `unresolved` and `refuted` are both empty.
    complete: bool,
    /// The run was accepted **because** the quorum was lowered: the policy
    /// is satisfied while coverage is not. Only `--allow-single-anchor` can
    /// produce this, and every renderer must qualify its success line when
    /// it holds.
    accepted_with_gaps: bool,
    /// Anchors that reached no result at all. Each may be fixable by
    /// supplying trust material, going online, or not at all — read `state`.
    unresolved: Vec<UnresolvedAnchorJson>,
    /// Anchors that were checked and found false. Never empty beside
    /// `status: "invalid"` caused by an anchor, and never non-empty beside
    /// `status: "valid"`.
    refuted: Vec<UnresolvedAnchorJson>,
}

#[derive(Serialize)]
struct UnresolvedAnchorJson {
    #[serde(rename = "type")]
    anchor_type: String,
    /// The same vocabulary as an anchor result's `state`.
    state: &'static str,
    reason_code: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::anchor::{AnchorVerdict, BlockSourceReport, ClaimedTimeCheck};
    use crate::verify::policy::AnchorPolicy;
    use atl_core::{PathStatus, Revocation, TerminalAnchor};
    use std::path::{Path, PathBuf};

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

    fn rfc3161_anchor(
        verdict: AnchorVerdict,
        terminal: Option<TerminalAnchor>,
    ) -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verdict,
            timestamp_nanos: Some(1_768_797_900_000_000_000),
            error: match verdict {
                AnchorVerdict::Valid => None,
                _ => Some("detail".to_string()),
            },
            details: AnchorDetails::Rfc3161 {
                chain_diagnostic: None,
                message_imprint: atl_core::MessageImprint::Verified,
                cms_signature: atl_core::CmsSignature::Verified,
                chain_valid_at_gen_time: terminal.is_some(),
                timestamping_eku_ok: true,
                timestamping_eku: atl_core::TimestampingEku::Ok,
                // A terminal certificate exists only for a complete path;
                // keep the fixture internally consistent with what atl-core
                // would actually report.
                path_status: if terminal.is_some() {
                    PathStatus::Complete
                } else {
                    PathStatus::Incomplete
                },
                terminal_anchor: terminal,
                revocation: Revocation::NotChecked,
            },
        }
    }

    /// ATL v2.0 §5.5: a receipt with no anchors has no verified anchor, so
    /// it is `untrusted` and never exit 0. `anchor_status` keeps the plain
    /// description of the state -- "unanchored" -- which is where a machine
    /// consumer should read the Receipt-Lite tier from.
    #[test]
    fn unanchored_receipt_reports_untrusted() {
        let result = single_result(true, true);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "untrusted");
        assert_eq!(json.reason_code, Some("receipt_unanchored"));
        assert_eq!(json.anchor_status, "unanchored");
        assert_eq!(
            json.errors.len(),
            1,
            "an outcome that exits non-zero must say why in `errors`"
        );
        assert_eq!(json.errors[0].error_type, "receipt_unanchored");
        assert!(json.anchor_verification.is_none());
        assert!(
            json.assessment.is_none(),
            "there is no quorum to report on when no anchor was presented"
        );
    }

    #[test]
    fn file_hash_mismatch_reports_invalid_with_reason() {
        let result = single_result(false, false);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "invalid");
        assert_eq!(json.reason_code, Some("file_hash_mismatch"));
        assert!(json.verification.is_none());
        assert_eq!(json.errors[0].error_type, "file_hash_mismatch");
    }

    #[test]
    fn assumed_root_reports_untrusted_never_valid() {
        // THE contract this whole change exists for: sound cryptography plus
        // an unvouched-for root is `untrusted`, not `invalid` and never
        // `valid`.
        let mut result = single_result(true, true);
        result
            .receipt
            .anchors
            .push(atl_core::ReceiptAnchor::Rfc3161 {
                target: "data_tree_root".to_string(),
                target_hash: result.receipt.proof.root_hash.clone(),
                tsa_url: "https://example.invalid/tsa".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                token_der: "base64:token".to_string(),
            });
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [0x11; 32],
                self_signature: atl_core::SelfSignature::Verified,
            }),
        ));

        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "untrusted");
        assert_eq!(json.reason_code, Some("tsa_root_not_trusted"));
        assert_eq!(json.anchor_status, "anchored");

        let anchors = json.anchor_verification.expect("anchors must be reported");
        assert!(!anchors.all_verified);
        assert!(!anchors.results[0].verified);
        assert_eq!(anchors.results[0].trust_state, Some("assumed"));
        assert_eq!(anchors.results[0].reason_code, Some("tsa_root_not_trusted"));
    }

    #[test]
    fn incomplete_chain_reports_untrusted_not_invalid() {
        let mut result = single_result(true, true);
        result
            .receipt
            .anchors
            .push(atl_core::ReceiptAnchor::Rfc3161 {
                target: "data_tree_root".to_string(),
                target_hash: result.receipt.proof.root_hash.clone(),
                tsa_url: "https://example.invalid/tsa".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                token_der: "base64:token".to_string(),
            });
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
            None,
        ));

        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "untrusted");
        assert_eq!(json.reason_code, Some("tsa_chain_incomplete"));
        let anchors = json.anchor_verification.expect("anchors must be reported");
        assert_eq!(anchors.results[0].trust_state, Some("incomplete"));
    }

    #[test]
    fn refuted_anchor_outranks_untrusted_anchor() {
        let mut result = single_result(true, true);
        for _ in 0..2 {
            result
                .receipt
                .anchors
                .push(atl_core::ReceiptAnchor::Rfc3161 {
                    target: "data_tree_root".to_string(),
                    target_hash: result.receipt.proof.root_hash.clone(),
                    tsa_url: "https://example.invalid/tsa".to_string(),
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                    token_der: "base64:token".to_string(),
                });
        }
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [0x11; 32],
                self_signature: atl_core::SelfSignature::Verified,
            }),
        ));
        result.anchor_results.push(rfc3161_anchor(
            AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid),
            None,
        ));

        let json = build_single_result_json(&result, VerificationMode::Offline);
        assert_eq!(json.status, "invalid");
        assert_eq!(json.reason_code, Some("cms_signature_invalid"));
    }

    #[test]
    fn mode_is_reported_verbatim() {
        let result = single_result(true, true);
        assert_eq!(
            build_single_result_json(&result, VerificationMode::Online).mode,
            "online"
        );
        assert_eq!(
            build_single_result_json(&result, VerificationMode::Offline).mode,
            "offline"
        );
    }

    #[test]
    fn print_single_result_succeeds_for_every_mode() {
        let result = single_result(true, true);
        assert!(print_single_result(&result, VerificationMode::Offline).is_ok());
        assert!(print_single_result(&result, VerificationMode::Online).is_ok());
    }

    #[test]
    fn batch_summary_counts_untrusted_separately() {
        let result = BatchVerificationResult {
            valid_count: 1,
            unanchored_count: 0,
            untrusted_count: 2,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
            consistency: None,
            items: vec![],
        };
        assert_eq!(result.verdict().status.as_str(), "untrusted");
        assert!(print_batch_result(
            &result,
            VerificationMode::Offline,
            Path::new("/src"),
            Path::new("/rcpt")
        )
        .is_ok());
    }

    #[test]
    fn batch_with_failures_is_invalid() {
        let result = BatchVerificationResult {
            valid_count: 1,
            unanchored_count: 0,
            untrusted_count: 1,
            invalid_count: 1,
            error_count: 0,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
            consistency: None,
            items: vec![],
        };
        assert_eq!(result.verdict().status.as_str(), "invalid");
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::BatchItemsInvalid)
        );
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
                BatchItemResult::Untrusted(single_result(true, true)),
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
        assert!(print_batch_result(
            &result,
            VerificationMode::Offline,
            Path::new("/src"),
            Path::new("/rcpt")
        )
        .is_ok());
    }

    #[test]
    fn batch_item_status_comes_from_the_item_verdict() {
        // Even sitting in the `Untrusted` bucket, the printed status is the
        // item's own verdict -- the bucket cannot lie about it.
        let item = batch_item_json(&single_result(false, false));
        assert_eq!(item.status, "invalid");
        assert_eq!(item.reason_code, Some("file_hash_mismatch"));
        assert_eq!(item.file_hash_match, Some(false));
    }

    /// Build the exact fact set the **online** path produces when a block
    /// was corroborated and its Merkle root did not match: a genuinely
    /// reported block time and root sitting on a refuted anchor.
    ///
    /// This composition needs the network to arise for real, so it is
    /// constructed here instead. It is not a hypothetical shape: it is
    /// literally what `crate::verify::online` writes on the
    /// `merkle_match == false` branch, which builds `details` *before* it
    /// decides the verdict.
    fn refuted_bitcoin_anchor() -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch),
            timestamp_nanos: None,
            error: Some("Merkle root mismatch: OTS proof does not match block 932897".to_string()),
            details: AnchorDetails::Bitcoin {
                proof_block_height: Some(932_897),
                proof_block_heights: vec![932_897],
                receipt_block_height: 932_897,
                receipt_block_time: "2026-01-19T07:01:20+00:00".to_string(),
                claimed_time_check: ClaimedTimeCheck::Matches,
                block_timestamp_secs: Some(1_768_806_080),
                target_hash: "sha256:abc123".to_string(),
                operation_count: Some(39),
                computed_root: Some("sha256:def456".to_string()),
                block_merkle_root: Some("sha256:999999".to_string()),
                merkle_match: Some(false),
                // Non-empty on purpose: a refutation is only reachable from
                // a corroborated header, so this fact set never arises with
                // fewer than two sources.
                block_sources: vec![
                    source_report("blockstream.info", "999999", 1_768_806_080),
                    source_report("mempool.space", "999999", 1_768_806_080),
                ],
            },
        }
    }

    fn source_report(source: &str, root: &str, secs: u64) -> BlockSourceReport {
        BlockSourceReport {
            source: source.to_string(),
            block_hash: "a".repeat(64),
            merkle_root: root.to_string(),
            block_timestamp_secs: secs,
        }
    }

    /// A Bitcoin anchor whose sources contradicted each other, exactly as
    /// `verify::online::anchor_from_lookup` builds it: no header was
    /// established, so none is published, and every conflicting report
    /// survives.
    fn contested_bitcoin_anchor(reports: Vec<BlockSourceReport>) -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinProvidersDisagree),
            timestamp_nanos: None,
            error: Some("block-explorer APIs disagree about block 932897".to_string()),
            details: AnchorDetails::Bitcoin {
                proof_block_height: Some(932_897),
                proof_block_heights: vec![932_897],
                receipt_block_height: 932_897,
                receipt_block_time: "2026-01-19T07:01:20+00:00".to_string(),
                claimed_time_check: ClaimedTimeCheck::Matches,
                block_timestamp_secs: None,
                target_hash: "sha256:abc123".to_string(),
                operation_count: Some(39),
                computed_root: Some("sha256:def456".to_string()),
                block_merkle_root: None,
                merkle_match: None,
                block_sources: reports,
            },
        }
    }

    /// **A source conflict publishes the conflict and nothing else.**
    ///
    /// The JSON renderer had no test for either new state, so the claim that
    /// they were covered "in both renderers" was true only of the
    /// human-readable one.
    #[test]
    fn a_contested_bitcoin_anchor_publishes_the_conflict_and_no_header() {
        let json = serde_json::to_value(anchor_result_json(&contested_bitcoin_anchor(vec![
            source_report("blockstream.info", &"b".repeat(64), 1_768_806_080),
            source_report("mempool.space", &"c".repeat(64), 1_768_806_080),
        ])))
        .unwrap();

        assert_eq!(json["verified"], false);
        assert_eq!(json["state"], "contested");
        assert_eq!(json["reason_code"], "bitcoin_providers_disagree");

        // No header was established, so none is published -- not even the
        // one that happens to be reported by the first source.
        for absent in [
            "block_height",
            "block_timestamp",
            "reported_block_timestamp",
            "block_merkle_root",
            "merkle_match",
            "timestamp",
            "timestamp_nanos",
        ] {
            assert!(
                json.get(absent).is_none(),
                "`{absent}` must not be published when the sources conflict: {json}"
            );
        }

        // But every conflicting report survives: the conflict is the finding,
        // and this array is the only place a machine consumer can see it.
        let sources = json["block_sources"].as_array().expect("block_sources");
        assert_eq!(sources.len(), 2, "{json}");
        assert_eq!(sources[0]["source"], "blockstream.info");
        assert_eq!(sources[0]["merkle_root"], "b".repeat(64));
        assert_eq!(sources[1]["source"], "mempool.space");
        assert_eq!(sources[1]["merkle_root"], "c".repeat(64));
        assert_eq!(json["proof_block_height"], 932_897);
        // Both claimants, distinguishable. The receipt states a
        // height of its own, and it used to be published nowhere.
        assert_eq!(json["receipt_block_height"], 932_897);
        assert_eq!(json["receipt_block_time"], "2026-01-19T07:01:20+00:00");
    }

    /// A conflict about nothing but the *time* must reach the JSON too. The
    /// roots and hashes match here, so a renderer comparing only those would
    /// show two identical-looking rows.
    #[test]
    fn a_time_only_conflict_is_visible_in_the_json() {
        let json = serde_json::to_value(anchor_result_json(&contested_bitcoin_anchor(vec![
            source_report("blockstream.info", &"b".repeat(64), 1_768_806_080),
            source_report("mempool.space", &"b".repeat(64), 1_768_806_081),
        ])))
        .unwrap();

        let sources = json["block_sources"].as_array().expect("block_sources");
        assert_eq!(sources[0]["block_timestamp"], "2026-01-19T07:01:20Z");
        assert_eq!(
            sources[1]["block_timestamp"], "2026-01-19T07:01:21Z",
            "the differing times must both be published, or the conflict is \
             invisible to a machine consumer: {json}"
        );
        assert_eq!(json["state"], "contested");
    }

    /// **One source settles nothing**, and the JSON says so: the state names
    /// it, the single report is attributed, and no header is published.
    #[test]
    fn an_uncorroborated_bitcoin_anchor_publishes_no_header() {
        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinSingleSourceOnly),
            timestamp_nanos: None,
            error: Some("only blockstream.info reported block 932897".to_string()),
            details: AnchorDetails::Bitcoin {
                proof_block_height: Some(932_897),
                proof_block_heights: vec![932_897],
                receipt_block_height: 932_897,
                receipt_block_time: "2026-01-19T07:01:20+00:00".to_string(),
                claimed_time_check: ClaimedTimeCheck::Matches,
                block_timestamp_secs: None,
                target_hash: "sha256:abc123".to_string(),
                operation_count: Some(39),
                computed_root: Some("sha256:def456".to_string()),
                block_merkle_root: None,
                merkle_match: None,
                block_sources: vec![source_report(
                    "blockstream.info",
                    &"b".repeat(64),
                    1_768_806_080,
                )],
            },
        };
        let json = serde_json::to_value(anchor_result_json(&anchor)).unwrap();

        assert_eq!(json["verified"], false);
        assert_eq!(json["state"], "uncorroborated");
        assert_eq!(json["reason_code"], "bitcoin_single_source_only");
        for absent in [
            "block_height",
            "block_timestamp",
            "reported_block_timestamp",
            "block_merkle_root",
            "merkle_match",
            "timestamp",
        ] {
            assert!(json.get(absent).is_none(), "`{absent}`: {json}");
        }
        assert_eq!(json["block_sources"].as_array().map(Vec::len), Some(1));
        assert_eq!(json["block_sources"][0]["source"], "blockstream.info");
        assert_eq!(json["proof_block_height"], 932_897);
        // Both claimants, distinguishable. The receipt states a
        // height of its own, and it used to be published nowhere.
        assert_eq!(json["receipt_block_height"], 932_897);
        assert_eq!(json["receipt_block_time"], "2026-01-19T07:01:20+00:00");
    }

    /// An anchor with no sources at all emits no `block_sources` key, rather
    /// than an empty array a consumer might read as "asked, nobody said
    /// anything about the header".
    #[test]
    fn no_sources_means_no_block_sources_key() {
        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockUnavailable),
            timestamp_nanos: None,
            error: Some("no block-explorer API returned block 932897".to_string()),
            details: AnchorDetails::Bitcoin {
                proof_block_height: Some(932_897),
                proof_block_heights: vec![932_897],
                receipt_block_height: 932_897,
                receipt_block_time: "2026-01-19T07:01:20+00:00".to_string(),
                claimed_time_check: ClaimedTimeCheck::Matches,
                block_timestamp_secs: None,
                target_hash: "sha256:abc123".to_string(),
                operation_count: Some(39),
                computed_root: Some("sha256:def456".to_string()),
                block_merkle_root: None,
                merkle_match: None,
                block_sources: Vec::new(),
            },
        };
        let json = serde_json::to_value(anchor_result_json(&anchor)).unwrap();
        assert_eq!(json["state"], "unavailable");
        assert!(json.get("block_sources").is_none(), "{json}");
    }

    /// **A refuted Bitcoin anchor publishes no established fact.**
    ///
    /// The block was really fetched, so its time is real — and it says
    /// nothing whatever about this receipt, because the Merkle root did not
    /// match. `block_timestamp` used to be serialized unconditionally, so
    /// this value went out under the plain name beside `merkle_match:
    /// false`: a date offered for evidence the same object refutes.
    #[test]
    fn a_refuted_bitcoin_anchor_publishes_no_established_time() {
        let json = serde_json::to_value(anchor_result_json(&refuted_bitcoin_anchor())).unwrap();

        assert_eq!(json["verified"], false);
        assert_eq!(json["state"], "refuted");
        assert_eq!(json["reason_code"], "bitcoin_merkle_root_mismatch");

        for established in [
            "block_height",
            "block_timestamp",
            "timestamp",
            "timestamp_nanos",
        ] {
            assert!(
                json.get(established).is_none(),
                "`{established}` must not be published for a refuted anchor: {json}"
            );
        }

        // The observation itself is kept, under a name that says what it is.
        // Not `claimed_`: nobody asserted it, this run read it off the chain.
        assert_eq!(json["reported_block_timestamp"], "2026-01-19T07:01:20Z");
        assert_eq!(json["proof_block_height"], 932_897);
        // Both claimants, distinguishable. The receipt states a
        // height of its own, and it used to be published nowhere.
        assert_eq!(json["receipt_block_height"], 932_897);
        assert_eq!(json["receipt_block_time"], "2026-01-19T07:01:20+00:00");

        // The three fields that keep their plain names, because each is
        // either a local computation or the evidence OF the refutation, and
        // none of them is presented as a fact about the receipt.
        assert_eq!(json["merkle_match"], false);
        assert_eq!(json["computed_root"], "sha256:def456");
        assert_eq!(json["block_merkle_root"], "sha256:999999");
    }

    /// The same anchor, verified: every value returns to its plain name. The
    /// split must not have made the honest case unreportable.
    #[test]
    fn a_verified_bitcoin_anchor_keeps_the_plain_names() {
        let mut anchor = refuted_bitcoin_anchor();
        anchor.verdict = AnchorVerdict::Valid;
        anchor.timestamp_nanos = Some(1_768_806_080_000_000_000);
        let json = serde_json::to_value(anchor_result_json(&anchor)).unwrap();

        assert_eq!(json["block_height"], 932_897);
        assert_eq!(json["block_timestamp"], "2026-01-19T07:01:20Z");
        assert!(json.get("claimed_block_height").is_none(), "{json}");
        assert!(json.get("reported_block_timestamp").is_none(), "{json}");
    }

    #[test]
    fn bitcoin_anchor_reports_its_chain() {
        let anchor = AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Valid,
            timestamp_nanos: Some(1_768_806_080_000_000_000),
            error: None,
            details: AnchorDetails::Bitcoin {
                proof_block_height: Some(932_897),
                proof_block_heights: vec![932_897],
                receipt_block_height: 932_897,
                receipt_block_time: "2026-01-19T07:01:20+00:00".to_string(),
                claimed_time_check: ClaimedTimeCheck::Matches,
                block_timestamp_secs: Some(1_768_806_080),
                target_hash: "sha256:abc123".to_string(),
                operation_count: Some(39),
                computed_root: Some("sha256:def456".to_string()),
                block_merkle_root: Some("sha256:def456".to_string()),
                merkle_match: Some(true),
                block_sources: Vec::new(),
            },
        };
        let json = serde_json::to_value(anchor_result_json(&anchor)).unwrap();
        assert_eq!(json["type"], "bitcoin_ots");
        assert_eq!(json["verified"], true);
        assert_eq!(json["block_height"], 932_897);
        assert_eq!(json["merkle_match"], true);
        assert_eq!(json["timestamp"], "2026-01-19T07:01:20Z");
        // RFC 3161 fields must not appear for a Bitcoin anchor.
        assert!(json.get("trust_state").is_none());
        assert!(json.get("path_status").is_none());
        // A valid anchor carries no reason code.
        assert!(json.get("reason_code").is_none());
    }

    #[test]
    fn rfc3161_anchor_omits_bitcoin_fields() {
        let anchor = rfc3161_anchor(
            AnchorVerdict::Valid,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
        );
        let json_str = serde_json::to_string(&anchor_result_json(&anchor)).unwrap();
        assert!(!json_str.contains("target_hash"));
        assert!(!json_str.contains("operation_count"));
        assert!(!json_str.contains("block_merkle_root"));
        assert!(json_str.contains("\"trust_state\":\"trusted\""));
        assert!(json_str.contains("\"kind\":\"trusted\""));
    }

    #[test]
    fn timestamp_helpers_render_iso8601() {
        assert_eq!(
            format_timestamp_iso(1_768_797_900_000_000_000),
            Some("2026-01-19T04:45:00Z".to_string())
        );
        assert_eq!(
            format_timestamp_secs_iso(1_768_797_900),
            Some("2026-01-19T04:45:00Z".to_string())
        );
        assert_eq!(
            format_timestamp_iso(0),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn stable_string_maps_cover_every_variant() {
        assert_eq!(path_status_str(PathStatus::Complete), "complete");
        assert_eq!(path_status_str(PathStatus::Incomplete), "incomplete");
        assert_eq!(path_status_str(PathStatus::Indeterminate), "indeterminate");
        assert_eq!(path_status_str(PathStatus::Invalid), "invalid");
        assert_eq!(revocation_str(Revocation::NotChecked), "not_checked");
        assert_eq!(
            terminal_anchor_json(TerminalAnchor::Assumed {
                sha256_fingerprint: [0u8; 32],
                self_signature: atl_core::SelfSignature::Verified,
            })
            .kind,
            "assumed"
        );
        // The self-signature fact rides along with `assumed`, and is absent
        // for `trusted` (where the caller vouched for the certificate).
        assert_eq!(
            terminal_anchor_json(TerminalAnchor::Assumed {
                sha256_fingerprint: [0u8; 32],
                self_signature: atl_core::SelfSignature::Unverifiable,
            })
            .self_signature,
            Some("unverifiable")
        );
        assert_eq!(
            terminal_anchor_json(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32]
            })
            .self_signature,
            None
        );
    }

    #[test]
    fn verification_block_mirrors_the_proof_verdict() {
        let result = single_result(true, true);
        let json = build_single_result_json(&result, VerificationMode::Offline);
        let verification = json.verification.expect("hash matched, so proofs reported");
        assert_eq!(verification.entry_id, result.receipt.entry.id.to_string());
        assert_eq!(
            verification.proofs_valid,
            result.proof_verdict().proofs_valid()
        );
    }
}
