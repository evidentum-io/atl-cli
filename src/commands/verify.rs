//! Verify command implementation

use atl_core::TrustStore;

use crate::cli::{Args, VerificationMode, VerifyArgs};
use crate::error::{CliError, CliResult};
use crate::output;
use crate::verify::anchor::AnchorVerdict;
use crate::verify::batch::{verify_batch, BatchItemResult, BatchVerificationResult};
use crate::verify::online::{receipt_requires_network, verify_anchors_online, OnlineConfig};
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

    if verify_args.is_batch_mode() {
        execute_batch(verify_args, args, trust_store.as_ref())
    } else {
        execute_single(verify_args, args, trust_store.as_ref())
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

/// Execute single file verification
fn execute_single(
    verify_args: &VerifyArgs,
    args: &Args,
    trust_store: Option<&TrustStore>,
) -> CliResult<()> {
    // Verify everything that can be verified without the network -- which,
    // for an RFC 3161-only receipt, is everything.
    let mut result = verify_single(&verify_args.source, &verify_args.receipt, trust_store)?;

    // Only now, knowing what the receipt actually contains, decide whether
    // going online is even meaningful.
    let mode = verify_args.determine_mode_for_receipt(receipt_requires_network(&result.receipt))?;

    if mode == VerificationMode::Online {
        let config = OnlineConfig::default();
        build_runtime()?.block_on(verify_anchors_online(&mut result, &config))?;
    }

    output::print_single_result(&result, args, mode)?;

    match single_error(verify_args, &result) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Execute batch verification
fn execute_batch(
    verify_args: &VerifyArgs,
    args: &Args,
    trust_store: Option<&TrustStore>,
) -> CliResult<()> {
    let mut result = verify_batch(&verify_args.source, &verify_args.receipt, trust_store)?;

    // A batch needs the network only if one of its receipts does.
    let needs_network = result.items.iter().any(|item| match item {
        BatchItemResult::Valid(r) | BatchItemResult::Untrusted(r) | BatchItemResult::Invalid(r) => {
            receipt_requires_network(&r.receipt)
        }
        _ => false,
    });
    // Verification has already run at this point, so a failure to settle the
    // mode must not throw the results away. If the batch already refutes
    // something, that refutation outranks our inability to go online -- the
    // same rule the per-anchor classifier follows. Reporting only the mode
    // error would let an inability suppress a finding we already hold.
    let mode = match verify_args.determine_mode_for_receipt(needs_network) {
        Ok(mode) => mode,
        Err(mode_error) => {
            // The checks that did run were offline ones, so that is what the
            // renderer is told -- never `online` for work never done.
            output::print_batch_result(
                &result,
                args,
                VerificationMode::Offline,
                &verify_args.source,
                &verify_args.receipt,
            )?;
            return Err(batch_error(&result).unwrap_or(mode_error));
        }
    };

    // Actually go online, per item, instead of merely reporting that we did.
    // This used to compute `mode` and hand it to the renderer without ever
    // running an online check, so a batch could print `mode: online` having
    // made no network call at all.
    if mode == VerificationMode::Online {
        let config = OnlineConfig::default();
        let runtime = build_runtime()?;
        runtime.block_on(async {
            for item in &mut result.items {
                if let BatchItemResult::Valid(r)
                | BatchItemResult::Untrusted(r)
                | BatchItemResult::Invalid(r) = item
                {
                    verify_anchors_online(r, &config).await?;
                }
            }
            Ok::<(), CliError>(())
        })?;
        result.reclassify();
    }

    output::print_batch_result(
        &result,
        args,
        mode,
        &verify_args.source,
        &verify_args.receipt,
    )?;

    match batch_error(&result) {
        Some(error) => Err(error),
        None => Ok(()),
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
        Status::Valid | Status::Pending => None,
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
        Status::Valid | Status::Pending => None,
        // The detail must match the reason. Emitting the trust-root advice
        // unconditionally told a caller whose filenames simply did not pair
        // up to go and supply a certificate.
        Status::Untrusted => Some(CliError::TrustNotEstablished {
            headline: untrusted_headline(verdict),
            reason_code: reason_str(verdict),
            detail: match verdict.reason_code {
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

/// The leading phrase for an `untrusted` outcome.
///
/// "Trust root unavailable" is only true of the reasons where trust material
/// really is what is missing. For the `*_indeterminate` / `*_not_checked`
/// reasons the root may be right there and the obstacle is an unimplemented
/// algorithm; for the batch reasons the files were never paired up at all.
/// Naming a missing trust root in either case sends the reader after
/// something that would not help.
fn untrusted_headline(verdict: ReceiptVerdict) -> &'static str {
    match verdict.reason_code {
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
        _ => "NOT VERIFIED: trust root unavailable",
    }
}

/// The verdict's stable reason string, for machine consumers.
fn reason_str(verdict: ReceiptVerdict) -> &'static str {
    verdict
        .reason_code
        .map_or("unspecified", ReasonCode::as_str)
}

/// Human-readable elaboration for a refuted receipt: the stable reason code
/// plus whatever the failing anchor had to say.
fn invalid_detail(verdict: ReceiptVerdict, result: &SingleVerificationResult) -> String {
    let code = reason_str(verdict);
    let anchor_detail = result
        .anchor_results
        .iter()
        .find(|a| matches!(a.verdict, AnchorVerdict::Invalid(_)))
        .and_then(|a| a.error.clone());

    match anchor_detail {
        Some(detail) => format!("{code}: {detail}"),
        None => code.to_string(),
    }
}

/// Say precisely what the caller must supply to turn `untrusted` into a
/// verdict. Never implies the evidence is damaged — it isn't.
fn trust_hint(result: &SingleVerificationResult) -> String {
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
                "the Bitcoin block confirming this anchor was not fetched; re-run with network \
                 access"
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
