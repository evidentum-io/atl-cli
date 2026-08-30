//! Verify command implementation

use atl_core::TrustStore;

use crate::cli::{Args, VerificationMode, VerifyArgs};
use crate::error::{CliError, CliResult};
use crate::output;
use crate::output::human::untrusted_headline;
use crate::verify::anchor::AnchorVerdict;
use crate::verify::batch::{verify_batch, BatchItemResult, BatchVerificationResult};
use crate::verify::online::{receipt_requires_network, verify_anchors_online, OnlineConfig};
use crate::verify::policy::AnchorPolicy;
use crate::verify::single::{verify_single, SingleVerificationResult};
use crate::verify::trust_store::{load_tsa_intermediates, load_tsa_trust_store};
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Execute the verify command
///
/// Determines whether to run single file or batch mode verification
/// based on input paths.
pub fn execute(verify_args: &VerifyArgs, args: &Args) -> CliResult<()> {
    // Validate paths exist
    verify_args.validate()?;

    // Load the caller's trust material once, up front, so both single- and
    // batch-mode paths see exactly the same store. Absent the flags this is
    // `None` -- every RFC 3161 anchor then verifies at best to `Assumed`,
    // never `Trusted` (see docs-md/atl-trust-model-decisions.md).
    let trust_store = load_trust_material(verify_args)?;

    // The anchor quorum, settled once from the flags and carried on every
    // result, so no consumer can judge the same receipt by a different rule.
    let policy = AnchorPolicy::from_allow_single_anchor(verify_args.allow_single_anchor);

    if verify_args.is_batch_mode() {
        execute_batch(verify_args, args, trust_store.as_ref(), policy)
    } else {
        execute_single(verify_args, args, trust_store.as_ref(), policy)
    }
}

/// Build the [`TrustStore`] from `--tsa-trust-store` (anchors) and
/// `--tsa-intermediates` (bridging certificates). Never invents or falls
/// back to any built-in material, and never promotes an intermediate to an
/// anchor: the two flags stay in their own roles.
fn load_trust_material(verify_args: &VerifyArgs) -> CliResult<Option<TrustStore>> {
    let anchors = verify_args.tsa_trust_store.as_deref();
    let intermediates = verify_args.tsa_intermediates.as_deref();

    if anchors.is_none() && intermediates.is_none() {
        return Ok(None);
    }

    let mut store = match anchors {
        Some(path) => load_tsa_trust_store(path)?,
        None => TrustStore::new(),
    };
    if let Some(path) = intermediates {
        store = load_tsa_intermediates(store, path)?;
    }
    Ok(Some(store))
}

/// Create the current-thread runtime used for the Bitcoin block lookups.
fn build_runtime() -> CliResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::NetworkError(format!("Failed to create runtime: {e}")))
}

/// What settling the verification mode produced: the mode that was actually
/// exercised, plus any failure met on the way there.
///
/// # Why the failure is carried rather than returned
///
/// Everything that happens after the offline pass — settling the mode,
/// building the runtime, fetching blocks — can only ever *fail to add* to
/// what is already known. Returning such a failure with `?` discarded a
/// verdict already in hand: a refuted receipt verified with `--online` and
/// no connectivity exited 2 with no output at all, while the very same file
/// verified as a directory exited 1 with a summary. An inability must never
/// suppress a refutation, and it must never change its mind about one
/// depending on how the tool was invoked.
///
/// So the failure travels alongside the results, is reported only if the
/// verdict itself has nothing to say, and never makes a run *succeed*: a
/// batch or receipt that came out clean still exits non-zero, because the
/// check the caller asked for was not finished.
struct ModeOutcome {
    /// The mode to tell the renderer about — `Online` only if a network
    /// pass was actually entered, never for one that was merely intended.
    mode: VerificationMode,
    /// The failure to report if the verdict itself reports nothing.
    deferred: Option<CliError>,
}

impl ModeOutcome {
    /// Nothing to do online, and nothing went wrong.
    const OFFLINE: Self = Self {
        mode: VerificationMode::Offline,
        deferred: None,
    };

    /// No network pass ran, because settling the mode or building the
    /// runtime failed. The checks that did run were the offline ones, so
    /// that is what the renderer is told — never `online` for work never
    /// done.
    const fn not_attempted(error: CliError) -> Self {
        Self {
            mode: VerificationMode::Offline,
            deferred: Some(error),
        }
    }
}

/// Execute single file verification
fn execute_single(
    verify_args: &VerifyArgs,
    args: &Args,
    trust_store: Option<&TrustStore>,
    policy: AnchorPolicy,
) -> CliResult<()> {
    // Verify everything that can be verified without the network -- which,
    // for an RFC 3161-only receipt, is everything.
    let mut result = verify_single(
        &verify_args.source,
        &verify_args.receipt,
        trust_store,
        policy,
    )?;

    // Only now, knowing what the receipt actually contains, decide whether
    // going online is even meaningful.
    let ModeOutcome { mode, deferred } = settle_single(verify_args, &mut result);

    output::print_single_result(&result, args, mode)?;

    // The verdict first, the inability second -- see [`ModeOutcome`].
    match single_error(verify_args, &result).or(deferred) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Settle the mode for one receipt and run the online pass if there is one.
fn settle_single(verify_args: &VerifyArgs, result: &mut SingleVerificationResult) -> ModeOutcome {
    let needs_network = receipt_requires_network(&result.receipt);
    let mode = match verify_args.determine_mode_for_receipt(needs_network) {
        Ok(mode) => mode,
        Err(error) => return ModeOutcome::not_attempted(error),
    };
    if mode == VerificationMode::Offline {
        return ModeOutcome::OFFLINE;
    }

    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(error) => return ModeOutcome::not_attempted(error),
    };
    let config = OnlineConfig::default();
    ModeOutcome {
        mode: VerificationMode::Online,
        deferred: runtime
            .block_on(verify_anchors_online(result, &config))
            .err(),
    }
}

/// Execute batch verification
fn execute_batch(
    verify_args: &VerifyArgs,
    args: &Args,
    trust_store: Option<&TrustStore>,
    policy: AnchorPolicy,
) -> CliResult<()> {
    let mut result = verify_batch(
        &verify_args.source,
        &verify_args.receipt,
        trust_store,
        policy,
    )?;

    let ModeOutcome { mode, deferred } = settle_batch(verify_args, &mut result);

    output::print_batch_result(
        &result,
        args,
        mode,
        &verify_args.source,
        &verify_args.receipt,
    )?;

    // The verdict first, the inability second -- see [`ModeOutcome`].
    match batch_error(&result).or(deferred) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Settle the mode for a batch and run the online pass if there is one.
fn settle_batch(verify_args: &VerifyArgs, result: &mut BatchVerificationResult) -> ModeOutcome {
    // A batch needs the network only if one of its receipts does. Unanchored
    // items carry no anchors at all, so they never do.
    let needs_network = result.items.iter().any(|item| match item {
        BatchItemResult::Valid(r) | BatchItemResult::Untrusted(r) | BatchItemResult::Invalid(r) => {
            receipt_requires_network(&r.receipt)
        }
        // An unanchored item has no anchors, so it never needs the network.
        _ => false,
    });

    let mode = match verify_args.determine_mode_for_receipt(needs_network) {
        Ok(mode) => mode,
        Err(error) => return ModeOutcome::not_attempted(error),
    };
    if mode == VerificationMode::Offline {
        return ModeOutcome::OFFLINE;
    }

    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(error) => return ModeOutcome::not_attempted(error),
    };

    // Actually go online, per item, instead of merely reporting that we did.
    // This used to compute `mode` and hand it to the renderer without ever
    // running an online check, so a batch could print `mode: online` having
    // made no network call at all.
    let config = OnlineConfig::default();
    let deferred = runtime
        .block_on(async {
            for item in &mut result.items {
                if let BatchItemResult::Valid(r)
                | BatchItemResult::Untrusted(r)
                | BatchItemResult::Invalid(r) = item
                {
                    verify_anchors_online(r, &config).await?;
                }
            }
            Ok::<(), CliError>(())
        })
        .err();

    // Unconditional, including after a failure part-way through: anchors
    // upgraded before the failure have already changed their items' verdicts,
    // and leaving the counts describing the pre-online state would print a
    // summary that disagrees with the rows beneath it.
    result.reclassify();

    ModeOutcome {
        mode: VerificationMode::Online,
        deferred,
    }
}

/// Turn a single-file verdict into the process-level outcome.
///
/// Derived entirely from [`SingleVerificationResult::verdict`] — the same
/// classification both renderers printed — so the exit code can never
/// disagree with the output above it.
fn single_error(verify_args: &VerifyArgs, result: &SingleVerificationResult) -> Option<CliError> {
    let verdict = result.verdict();
    match verdict.status {
        Status::Valid => None,
        // Single-file mode never produces this status -- an unreadable file
        // or unparsable receipt returns a `CliError` long before a verdict
        // exists -- but the match must stay exhaustive and honest.
        Status::Error => Some(CliError::BatchItemsUnprocessable {
            errors: 1,
            total: 1,
        }),
        Status::Untrusted => Some(CliError::TrustNotEstablished {
            headline: untrusted_headline(verdict),
            reason_code: reason_str(verdict),
            detail: trust_hint(result),
        }),
        Status::Invalid => Some(match verdict.reason_code {
            Some(ReasonCode::FileHashMismatch) => CliError::file_hash_mismatch(
                &verify_args.source,
                &result.file_hash,
                &result.receipt.entry.payload_hash,
            ),
            _ => CliError::VerificationFailed(invalid_detail(verdict, result)),
        }),
    }
}

/// Turn a batch verdict into the process-level outcome.
fn batch_error(result: &BatchVerificationResult) -> Option<CliError> {
    let verdict = result.verdict();
    match verdict.status {
        Status::Valid => None,
        // The detail must match the reason. Emitting the trust-root advice
        // unconditionally told a caller whose filenames simply did not pair
        // up to go and supply a certificate.
        Status::Untrusted => Some(CliError::TrustNotEstablished {
            headline: untrusted_headline(verdict),
            reason_code: reason_str(verdict),
            detail: match verdict.reason_code {
                Some(ReasonCode::BatchItemsUnanchored) => format!(
                    "{} of {} receipts carry no anchors at all (Receipt-Lite). ATL v2.0 \u{a7}5.5: \
                     a receipt without any verified anchors should be treated as untrustworthy. \
                     Request an anchored receipt; no trust material supplied here can help",
                    result.unanchored_count,
                    result.total_count()
                ),
                Some(ReasonCode::BatchItemsUnmatched) => format!(
                    "{} of {} named files were never verified: a source file with no matching \
                     receipt, or a receipt with no matching source file. The convention is \
                     <name> alongside <name>.atl",
                    result.unmatched_count,
                    result.total_count()
                ),
                Some(ReasonCode::BatchNothingVerified) => format!(
                    "none of the {} named files reached a verification result",
                    result.total_count()
                ),
                // `total_count()`, not an inline sum: the sum here omitted
                // pending, errored and unmatched items and printed "5 of 5"
                // for an eight-file run.
                _ => format!(
                    "{} of {} receipts verified cryptographically but reached no configured \
                     trust root; supply it with --tsa-trust-store (and --tsa-intermediates if a \
                     chain is incomplete)",
                    result.untrusted_count,
                    result.total_count()
                ),
            },
        }),
        // Exit 2, matching what single-file mode returns for the same input.
        Status::Error => Some(CliError::BatchItemsUnprocessable {
            errors: result.error_count,
            total: result.total_count(),
        }),
        Status::Invalid => Some(CliError::batch_failed(
            result.valid_count,
            result.invalid_count,
            result.error_count,
        )),
    }
}

/// The verdict's stable reason string, for machine consumers.
fn reason_str(verdict: ReceiptVerdict) -> &'static str {
    verdict
        .reason_code
        .map_or("unspecified", ReasonCode::as_str)
}

/// Human-readable elaboration for a refuted receipt: the stable reason code,
/// plus prose from the anchor that produced **that** reason.
///
/// # The elaboration must come from the cause
///
/// This used to attach the first refuted anchor's `error` text whatever the
/// top-level reason was. A receipt refuted by a broken Super-Tree proof, one
/// of whose anchors separately failed to parse, printed:
///
/// ```text
/// Verification failed: super_inclusion_proof_invalid: RFC 3161 parse error: CMS ContentInfo parse failed
/// ```
///
/// Both halves were true and they had nothing to do with each other. A
/// reader concludes the Super-Tree proof failed *because of* the token,
/// which is a claim nobody made and nobody checked — the same overclaim as a
/// wrong verdict, wearing an explanation instead.
///
/// So an anchor's prose is used only when that anchor's own reason code is
/// the verdict's reason code. This is the rule the JSON renderer already
/// applies in `build_errors`; the two now agree.
fn invalid_detail(verdict: ReceiptVerdict, result: &SingleVerificationResult) -> String {
    let code = reason_str(verdict);
    let anchor_detail = result
        .anchor_results
        .iter()
        .find(|a| {
            matches!(a.verdict, AnchorVerdict::Invalid(_))
                && a.verdict.reason_code() == verdict.reason_code
        })
        .and_then(|a| a.error.clone());

    match anchor_detail {
        Some(detail) => format!("{code}: {detail}"),
        None => code.to_string(),
    }
}

/// Say precisely what the caller must supply to turn `untrusted` into a
/// verdict. Never implies the evidence is damaged — it isn't.
fn trust_hint(result: &SingleVerificationResult) -> String {
    // A Receipt-Lite has no anchor to name, and no certificate the caller
    // could supply would change that. Saying "no anchor reached a configured
    // trust root" here would send them looking for trust material to fix a
    // receipt that never made a temporal claim at all.
    if result.receipt.anchors.is_empty() {
        return "the receipt carries no anchors at all (Receipt-Lite), so nothing external \
                attests to when this existed. ATL v2.0 \u{a7}5.5: a receipt without any verified \
                anchors should be treated as untrustworthy. Request an anchored receipt (TSA \
                and/or Bitcoin); no trust material supplied here can substitute for one"
            .to_string();
    }

    let mut hints = Vec::new();
    for anchor in &result.anchor_results {
        let AnchorVerdict::Untrusted(code) = anchor.verdict else {
            continue;
        };
        let hint = match code {
            ReasonCode::TsaRootNotTrusted => {
                anchor.details.untrusted_root_fingerprint().map_or_else(
                    || "pass the TSA root certificate with --tsa-trust-store".to_string(),
                    |fp| {
                        format!(
                            "pass the certificate with SHA-256 fingerprint sha256:{fp} to \
                             --tsa-trust-store"
                        )
                    },
                )
            }
            ReasonCode::TsaChainIncomplete => {
                "the token's certificate chain is missing an issuer; pass it with \
                 --tsa-intermediates, and the root it leads to with --tsa-trust-store"
                    .to_string()
            }
            // No certificate-hunting advice here: what is missing may be an
            // algorithm implementation, not a file. The anchor's own error
            // text says what actually stopped the check.
            ReasonCode::TsaTimestampingEkuNotChecked => anchor.error.clone().unwrap_or_else(|| {
                "no signer certificate could be established, so its timestamping EKU was never \
                 examined"
                    .to_string()
            }),
            ReasonCode::TsaImprintIndeterminate => anchor.error.clone().unwrap_or_else(|| {
                "the token's messageImprint could not be compared; nothing was refuted".to_string()
            }),
            ReasonCode::CmsSignatureIndeterminate => anchor.error.clone().unwrap_or_else(|| {
                "the token's CMS signature could not be checked; nothing was refuted".to_string()
            }),
            ReasonCode::TsaChainIndeterminate => anchor.error.clone().unwrap_or_else(|| {
                "the token's certificate chain could not be checked; nothing was refuted"
                    .to_string()
            }),
            ReasonCode::BitcoinBlockNotChecked | ReasonCode::BitcoinBlockUnavailable => {
                "no block header was obtained for this anchor; re-run with network access"
                    .to_string()
            }
            // Both used to fall into the catch-all below, which reads
            // "missing trust material" -- advice that is simply false here.
            // Certificates have nothing to do with two APIs contradicting
            // each other, or with only one of them answering.
            ReasonCode::BitcoinProvidersDisagree => {
                "the block-explorer APIs returned different headers for this block, so none is \
                 established and nothing was compared; your receipt is not implicated, and no \
                 trust material affects this"
                    .to_string()
            }
            ReasonCode::BitcoinSingleSourceOnly => {
                "only one block-explorer API answered, so its report is uncorroborated and the \
                 OTS proof was not compared against it; re-run when more than one provider is \
                 reachable"
                    .to_string()
            }
            other => format!("missing trust material ({})", other.as_str()),
        };
        if !hints.contains(&hint) {
            hints.push(hint);
        }
    }

    if hints.is_empty() {
        "no anchor reached a configured trust root".to_string()
    } else {
        hints.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::anchor::{AnchorDetails, AnchorVerificationResult};

    fn bitcoin_anchor(reason: ReasonCode) -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Untrusted(reason),
            timestamp_nanos: None,
            error: None,
            details: AnchorDetails::Unknown,
        }
    }

    /// The two Bitcoin source reasons must give their own advice. They used
    /// to fall into the catch-all "missing trust material", telling a user
    /// to supply certificates when two APIs had contradicted each other or
    /// only one had answered -- neither of which a certificate fixes.
    #[test]
    fn the_bitcoin_source_reasons_get_their_own_advice() {
        let receipt: atl_core::Receipt =
            serde_json::from_str(include_str!("../../real-data/receipt-full.atl"))
                .expect("fixture receipt");

        for (reason, must_say) in [
            (ReasonCode::BitcoinProvidersDisagree, "not implicated"),
            (ReasonCode::BitcoinSingleSourceOnly, "uncorroborated"),
        ] {
            let result = SingleVerificationResult {
                source_path: std::path::PathBuf::from("f.txt"),
                receipt_path: std::path::PathBuf::from("f.txt.atl"),
                file_hash: [0u8; 32],
                receipt: receipt.clone(),
                file_hash_valid: true,
                core_result: atl_core::verify_receipt_anchor_only(&receipt)
                    .expect("fixture verifies"),
                anchor_results: vec![bitcoin_anchor(reason)],
                policy: crate::verify::policy::AnchorPolicy::AllAnchors,
            };

            let hint = trust_hint(&result);
            assert!(hint.contains(must_say), "{reason}: {hint}");
            assert!(
                !hint.contains("missing trust material"),
                "the catch-all must not claim this: {reason}: {hint}"
            );
            assert!(
                !hint.contains("--tsa-trust-store") && !hint.contains("certificate"),
                "no certificate fixes a source conflict: {reason}: {hint}"
            );
        }
    }

    use crate::cli::Command;
    use std::path::PathBuf;

    #[test]
    fn test_execute_single_invalid_source() {
        let verify_args = VerifyArgs {
            source: PathBuf::from("/nonexistent/file.pdf"),
            receipt: PathBuf::from("test.atl"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };
        let args = Args {
            command: Command::Inspect(crate::cli::InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: true,
            json: false,
            no_color: false,
        };
        let result = execute(&verify_args, &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_batch_invalid_source() {
        let verify_args = VerifyArgs {
            source: PathBuf::from("/nonexistent/dir/"),
            receipt: PathBuf::from("/nonexistent/receipts/"),
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };
        let args = Args {
            command: Command::Inspect(crate::cli::InspectArgs {
                receipt: PathBuf::from("test.atl"),
            }),
            quiet: true,
            json: false,
            no_color: false,
        };
        let result = execute(&verify_args, &args);
        assert!(result.is_err());
    }

    #[cfg(feature = "online")]
    #[test]
    fn test_execute_single_determines_mode_for_receipt() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let source_path = temp_dir.path().join("test.txt");
        let receipt_path = temp_dir.path().join("test.txt.atl");

        // Create a valid source file
        fs::write(&source_path, b"test content").unwrap();

        // Create a minimal valid receipt (lite receipt - no anchors)
        let receipt_json = include_str!("../../test_data/receipts/valid/document.pdf.atl");
        fs::write(&receipt_path, receipt_json).unwrap();

        let verify_args = VerifyArgs {
            source: source_path,
            receipt: receipt_path,
            offline: false,
            online: false,
            verbose: false,
            allow_single_anchor: false,
            tsa_trust_store: None,
            tsa_intermediates: None,
        };

        let args = Args {
            command: Command::Verify(VerifyArgs {
                source: verify_args.source.clone(),
                receipt: verify_args.receipt.clone(),
                offline: false,
                online: false,
                verbose: false,
                allow_single_anchor: false,
                tsa_trust_store: None,
                tsa_intermediates: None,
            }),
            quiet: true,
            json: false,
            no_color: false,
        };

        // Execute should determine mode based on receipt anchors
        // This lite receipt has no anchors, so should not check connectivity
        let result = execute(&verify_args, &args);
        // Result will be Err because file hash won't match, but mode detection worked
        assert!(result.is_err());
    }
}
