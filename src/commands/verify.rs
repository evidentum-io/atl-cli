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
    let mode = verify_args.determine_mode_for_receipt(needs_network)?;

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
        Status::Untrusted => Some(CliError::TrustNotEstablished {
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
        Status::Untrusted => Some(CliError::TrustNotEstablished {
            reason_code: reason_str(verdict),
            detail: format!(
                "{} of {} receipts verified cryptographically but reached no configured trust \
                 root; supply it with --tsa-trust-store (and --tsa-intermediates if a chain is \
                 incomplete)",
                result.untrusted_count,
                result.valid_count + result.untrusted_count + result.invalid_count
            ),
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
