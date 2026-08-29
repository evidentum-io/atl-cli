//! Batch/directory verification logic

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use atl_core::TrustStore;

use crate::error::{CliError, CliResult};
use crate::verify::consistency::{verify_consistency, ConsistencyResult};
use crate::verify::single::{verify_single, SingleVerificationResult};
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Result of a single file in batch mode
#[derive(Debug)]
pub enum BatchItemResult {
    /// Verification succeeded: every anchor reached a configured trust root.
    Valid(SingleVerificationResult),
    /// Cryptographically sound but carrying no anchors at all
    /// (Receipt-Lite), so it makes no external-time claim.
    ///
    /// Kept out of [`Self::Valid`] on purpose: folding it in made a batch of
    /// Receipt-Lites report `valid` while single-file mode called the very
    /// same receipt `pending`.
    Pending(SingleVerificationResult),
    /// Nothing refuted, but the item's anchors did not reach a configured
    /// trust root
    Untrusted(SingleVerificationResult),
    /// Verification failed (cryptographic or hash)
    Invalid(SingleVerificationResult),
    /// Error during verification
    Error {
        source: PathBuf,
        #[allow(dead_code)]
        receipt: Option<PathBuf>,
        error: CliError,
    },
    /// No receipt found for file
    NoReceipt(PathBuf),
    /// No source file found for receipt
    NoSource(PathBuf),
}

/// Result of batch verification
#[derive(Debug)]
pub struct BatchVerificationResult {
    /// Individual results for each file
    pub items: Vec<BatchItemResult>,
    /// Log consistency result (if enough valid receipts)
    pub consistency: Option<ConsistencyResult>,
    /// Count of valid files
    pub valid_count: usize,
    /// Count of files whose receipts carry no anchors (Receipt-Lite)
    pub pending_count: usize,
    /// Count of files whose anchors reached no configured trust root
    pub untrusted_count: usize,
    /// Count of invalid files
    pub invalid_count: usize,
    /// Count of errors
    pub error_count: usize,
    /// Count of unmatched items
    pub unmatched_count: usize,
}

impl BatchVerificationResult {
    /// The batch's aggregate verdict, derived from the same per-receipt
    /// classification every item used — never re-derived here.
    ///
    /// A single refuted item makes the whole batch refuted. Failing that, a
    /// single item that could not be verified to completion makes the batch
    /// untrusted. A batch is accepted only when every path the caller named
    /// was verified and accepted.
    ///
    /// # Unmatched files are part of the verdict
    ///
    /// They did not used to be, and the consequence was the worst possible
    /// failure of this tool's central promise: point it at a source
    /// directory and a receipt directory whose filenames do not follow the
    /// `X` / `X.atl` convention, and **every** file lands in `unmatched`,
    /// nothing is verified at all, and the batch reported `VALID` with exit
    /// code 0. A CI job whose naming had drifted went green while checking
    /// nothing.
    ///
    /// A caller who names a file has asked about that file. Failing to find
    /// its counterpart means the question was not answered, so it cannot be
    /// answered "yes". Nothing about such a file is *refuted* — it was never
    /// examined — which is exactly [`Status::Untrusted`]: not refuted, not
    /// accepted, and a non-zero exit code.
    ///
    /// # Order of judgement
    ///
    /// Refutations first, then inabilities, mirroring
    /// [`crate::verify::single::SingleVerificationResult::verdict`] and the
    /// per-anchor classifier: a proven defect must never be concealed behind
    /// something that merely could not be checked.
    #[must_use]
    pub fn verdict(&self) -> ReceiptVerdict {
        // --- Refutations, before anything that merely could not be done ---
        //
        // A neighbouring file that would not open must never conceal a
        // receipt that was checked and refuted.
        if self.invalid_count > 0 {
            return ReceiptVerdict::invalid(ReasonCode::BatchItemsInvalid);
        }
        if self.consistency.as_ref().is_some_and(|c| !c.is_valid()) {
            return ReceiptVerdict::invalid(ReasonCode::LogConsistencyFailed);
        }

        // --- Operational failure: exit 2, as in single-file mode ---
        //
        // Reporting this as `Invalid` claimed the evidence had been refuted
        // when the tool had merely failed to read a file, and made the exit
        // code depend on whether the caller passed a file or a directory.
        if self.error_count > 0 {
            return ReceiptVerdict::new(Status::Error, ReasonCode::BatchItemsErrored);
        }

        // --- Nothing refuted; report what could not be finished ---
        //
        // Unmatched comes first: "this file was never checked" is a more
        // fundamental gap than "this file was checked and lacks a trust
        // root", and it is the one a caller is least likely to expect.
        if self.unmatched_count > 0 {
            return ReceiptVerdict::untrusted(ReasonCode::BatchItemsUnmatched);
        }
        if self.untrusted_count > 0 {
            return ReceiptVerdict::untrusted(ReasonCode::BatchItemsUntrusted);
        }

        // --- Backstop ---
        //
        // With every bucket above routed correctly this is unreachable:
        // `total` is the sum of the buckets, so no file reaching a
        // verification result in a non-empty batch means some other bucket
        // was non-zero. It stands because the counts are maintained by
        // mutation (see [`Self::reclassify`]), and no future drift in them
        // may be allowed to produce a `valid` verdict backed by zero
        // verifications.
        if self.valid_count == 0 && self.pending_count == 0 {
            return ReceiptVerdict::untrusted(ReasonCode::BatchNothingVerified);
        }

        // --- Unanchored items ---
        //
        // `Valid` is defined as "every anchor reached a configured trust
        // root". An item with no anchors has none to reach one, so a batch
        // containing any such item is `pending`, not `valid` -- including a
        // mixture of the two. The exit code stays 0, matching single-file
        // mode and the documented Receipt-Lite decision; it is the *word*
        // that must not change meaning with the calling convention.
        if self.pending_count > 0 {
            return ReceiptVerdict::new(Status::Pending, ReasonCode::BatchItemsPending);
        }

        ReceiptVerdict::VALID
    }

    /// Total number of paths the caller named, across every bucket.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.valid_count
            + self.pending_count
            + self.untrusted_count
            + self.invalid_count
            + self.error_count
            + self.unmatched_count
    }

    /// Check if overall batch is valid (all files valid + consistent)
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; kept as the readable predicate
    pub fn is_valid(&self) -> bool {
        matches!(self.verdict().status, Status::Valid | Status::Pending)
    }

    /// Re-bucket every verified item and recompute the counts from each
    /// item's current [`SingleVerificationResult::verdict`].
    ///
    /// Called after the online pass has upgraded `bitcoin_ots` anchors in
    /// place: an item that was `Untrusted` only because no block had been
    /// fetched becomes `Valid` (or `Invalid`) once it has been. `error_count`
    /// and the unmatched items are untouched -- going online cannot change
    /// whether a file could be read or matched.
    pub fn reclassify(&mut self) {
        let mut valid_count = 0;
        let mut pending_count = 0;
        let mut untrusted_count = 0;
        let mut invalid_count = 0;
        // Counted from the item list, not seeded from the previous total: an
        // item filed as `Error` is passed through untouched below, so
        // counting it here is the only place it is counted. Seeding instead
        // would double-count any item that both carried an error and was
        // re-walked.
        let mut error_count = 0;

        let items = std::mem::take(&mut self.items);
        self.items = items
            .into_iter()
            .map(|item| match item {
                BatchItemResult::Valid(result)
                | BatchItemResult::Pending(result)
                | BatchItemResult::Untrusted(result)
                | BatchItemResult::Invalid(result) => match result.verdict().status {
                    Status::Valid => {
                        valid_count += 1;
                        BatchItemResult::Valid(result)
                    }
                    Status::Pending => {
                        pending_count += 1;
                        BatchItemResult::Pending(result)
                    }
                    // Single-file mode never yields `Error` (it returns a
                    // CliError instead), so an item can only reach this arm
                    // via a future change; bucket it honestly rather than
                    // letting it fall into a success.
                    Status::Error => {
                        error_count += 1;
                        BatchItemResult::Error {
                            source: result.source_path.clone(),
                            receipt: Some(result.receipt_path.clone()),
                            error: CliError::BatchItemsUnprocessable {
                                errors: 1,
                                total: 1,
                            },
                        }
                    }
                    Status::Untrusted => {
                        untrusted_count += 1;
                        BatchItemResult::Untrusted(result)
                    }
                    Status::Invalid => {
                        invalid_count += 1;
                        BatchItemResult::Invalid(result)
                    }
                },
                // Items that failed to be read are not re-walked -- going
                // online cannot change whether a file could be opened -- but
                // they are counted here so the count has exactly one source.
                // Seeding `error_count` from the previous total instead
                // would double-count anything the arm above files as an
                // `Error` item.
                item @ BatchItemResult::Error { .. } => {
                    error_count += 1;
                    item
                }
                other => other,
            })
            .collect();

        self.valid_count = valid_count;
        self.pending_count = pending_count;
        self.untrusted_count = untrusted_count;
        self.invalid_count = invalid_count;
        self.error_count = error_count;
    }
}

/// The source filename a `<name>.atl` receipt claims to accompany.
///
/// Works on `OsStr` throughout so non-UTF-8 names survive intact; see the
/// keying comment in [`match_files_to_receipts`] for why that matters.
fn strip_atl_suffix(name: &std::ffi::OsStr) -> Option<OsString> {
    let path = Path::new(name);
    if path.extension() == Some(std::ffi::OsStr::new("atl")) {
        path.file_stem().map(OsString::from)
    } else {
        None
    }
}

/// Whether `path` names a regular file, following symlinks, without ever
/// swallowing the answer.
///
/// `Path::is_file()` collapses "this is a directory" and "I could not find
/// out" into the same `false`, which would drop an unreadable entry from the
/// batch accounting entirely. A directory or a symlink to one is genuinely
/// not a named file and is skipped; anything we cannot determine is an error.
fn is_regular_file(entry: &std::fs::DirEntry, path: &Path) -> CliResult<bool> {
    let file_type = entry
        .file_type()
        .map_err(|e| CliError::file_read_error(path, e))?;
    if file_type.is_dir() {
        return Ok(false);
    }
    if file_type.is_file() {
        return Ok(true);
    }
    // A symlink: resolve it. A dangling one is an entry the caller placed in
    // this directory and we cannot check -- that is worth failing loudly for,
    // not skipping.
    let metadata = std::fs::metadata(path).map_err(|e| CliError::file_read_error(path, e))?;
    Ok(metadata.is_file())
}

/// Match files to receipts by name pattern
///
/// # Matching Rules
///
/// 1. `document.pdf` matches `document.pdf.atl`
/// 2. Exact basename match in different directories
///
/// # Arguments
///
/// * `source_dir` - Directory containing source files
/// * `receipt_dir` - Directory containing .atl receipt files
///
/// # Returns
///
/// Tuple of:
/// - Vector of matched (source, receipt) pairs
/// - Vector of unmatched source files
/// - Vector of unmatched receipt files
///
/// # Errors
///
/// Returns error if:
/// - Directories cannot be read
/// - No files found in source directory
/// - No receipts found in receipt directory
#[allow(clippy::type_complexity)]
pub fn match_files_to_receipts(
    source_dir: &Path,
    receipt_dir: &Path,
) -> CliResult<(Vec<(PathBuf, PathBuf)>, Vec<PathBuf>, Vec<PathBuf>)> {
    // Scan source directory for files.
    //
    // Directory-walk errors are propagated, never dropped. An entry that
    // vanishes silently here is a file the caller named and we never checked,
    // and it would land in no bucket at all -- not `matched`, not
    // `unmatched` -- so the batch could report success having skipped it.
    // That is the exact "reported more than was verified" failure this whole
    // verdict model exists to prevent.
    let mut source_files: Vec<PathBuf> = Vec::new();
    for entry in
        std::fs::read_dir(source_dir).map_err(|e| CliError::file_read_error(source_dir, e))?
    {
        let entry = entry.map_err(|e| CliError::file_read_error(source_dir, e))?;
        let path = entry.path();
        if !is_regular_file(&entry, &path)? {
            continue;
        }
        if path.extension() == Some(std::ffi::OsStr::new("atl")) {
            continue;
        }
        source_files.push(path);
    }

    if source_files.is_empty() {
        return Err(CliError::EmptySourceDirectory(source_dir.to_path_buf()));
    }

    // Scan receipt directory for .atl files. Same rule as above: a receipt we
    // cannot even enumerate must not disappear from the accounting.
    let mut receipt_files: Vec<PathBuf> = Vec::new();
    for entry in
        std::fs::read_dir(receipt_dir).map_err(|e| CliError::file_read_error(receipt_dir, e))?
    {
        let entry = entry.map_err(|e| CliError::file_read_error(receipt_dir, e))?;
        let path = entry.path();
        if path.extension() != Some(std::ffi::OsStr::new("atl")) {
            continue;
        }
        if !is_regular_file(&entry, &path)? {
            continue;
        }
        receipt_files.push(path);
    }

    if receipt_files.is_empty() {
        return Err(CliError::EmptyReceiptDirectory(receipt_dir.to_path_buf()));
    }

    // Build receipt lookup by expected source name
    // Keyed by `OsString`, not by `to_string_lossy()`: lossy conversion maps
    // every invalid UTF-8 byte to U+FFFD, so two genuinely different filenames
    // can collapse onto one key. One receipt would then match a file that is
    // not its own, and a file whose real pair is absent would never be
    // reported unmatched.
    let mut receipt_map: HashMap<OsString, PathBuf> = HashMap::new();
    for receipt_path in &receipt_files {
        if let Some(name) = receipt_path.file_name() {
            if let Some(source_name) = strip_atl_suffix(name) {
                receipt_map.insert(source_name, receipt_path.clone());
            }
        }
    }

    // Match files
    let mut matched = Vec::new();
    let mut unmatched_sources = Vec::new();
    let mut used_receipts = HashSet::new();

    for source_path in &source_files {
        if let Some(name) = source_path.file_name() {
            if let Some(receipt_path) = receipt_map.get(name) {
                matched.push((source_path.clone(), receipt_path.clone()));
                used_receipts.insert(receipt_path.clone());
            } else {
                unmatched_sources.push(source_path.clone());
            }
        }
    }

    // Find unmatched receipts
    let unmatched_receipts: Vec<PathBuf> = receipt_files
        .into_iter()
        .filter(|r| !used_receipts.contains(r))
        .collect();

    Ok((matched, unmatched_sources, unmatched_receipts))
}

/// Verify a batch of files
///
/// # Process
///
/// 1. Match files to receipts by name
/// 2. Verify each matched pair individually
/// 3. Collect unmatched files/receipts
/// 4. Verify log consistency across valid receipts (if 2+)
///
/// # Arguments
///
/// * `source_dir` - Directory containing source files
/// * `receipt_dir` - Directory containing .atl receipt files
///
/// # Returns
///
/// Batch verification result with individual and consistency results
///
/// # Errors
///
/// Returns error if:
/// - Directories cannot be read
/// - No files or receipts found
///
/// `trust_store` is forwarded unchanged to every [`verify_single`] call --
/// see its docs for why RFC 3161 trust verification runs even in this
/// (offline) batch path.
pub fn verify_batch(
    source_dir: &Path,
    receipt_dir: &Path,
    trust_store: Option<&TrustStore>,
) -> CliResult<BatchVerificationResult> {
    // Match files to receipts
    let (matched, unmatched_sources, unmatched_receipts) =
        match_files_to_receipts(source_dir, receipt_dir)?;

    let mut items = Vec::new();
    let mut consistency_candidates = Vec::new();
    let mut valid_count = 0;
    let mut pending_count = 0;
    let mut untrusted_count = 0;
    let mut invalid_count = 0;
    let mut error_count = 0;

    // Verify each matched pair
    for (source_path, receipt_path) in matched {
        match verify_single(&source_path, &receipt_path, trust_store) {
            Ok(result) => match result.verdict().status {
                Status::Valid => {
                    valid_count += 1;
                    consistency_candidates.push(result.clone());
                    items.push(BatchItemResult::Valid(result));
                }
                // Sound proofs, no anchors: not counted as accepted, since
                // it makes no external-time claim at all.
                Status::Pending => {
                    pending_count += 1;
                    consistency_candidates.push(result.clone());
                    items.push(BatchItemResult::Pending(result));
                }
                // Unreachable today: `SingleVerificationResult::verdict`
                // has no path to `Status::Error`. Filed as an `Error` item
                // rather than an `Invalid` one so the bucket and the row
                // cannot disagree if that ever changes.
                Status::Error => {
                    error_count += 1;
                    items.push(BatchItemResult::Error {
                        source: source_path,
                        receipt: Some(receipt_path),
                        error: CliError::BatchItemsUnprocessable {
                            errors: 1,
                            total: 1,
                        },
                    });
                }
                Status::Untrusted => {
                    untrusted_count += 1;
                    // Still a structurally sound receipt from this log, so
                    // it may take part in cross-receipt consistency checking.
                    consistency_candidates.push(result.clone());
                    items.push(BatchItemResult::Untrusted(result));
                }
                Status::Invalid => {
                    invalid_count += 1;
                    items.push(BatchItemResult::Invalid(result));
                }
            },
            Err(e) => {
                error_count += 1;
                items.push(BatchItemResult::Error {
                    source: source_path,
                    receipt: Some(receipt_path),
                    error: e,
                });
            }
        }
    }

    // Add unmatched items
    for source in unmatched_sources {
        items.push(BatchItemResult::NoReceipt(source));
    }
    for receipt in unmatched_receipts {
        items.push(BatchItemResult::NoSource(receipt));
    }

    let unmatched_count = items
        .iter()
        .filter(|i| {
            matches!(
                i,
                BatchItemResult::NoReceipt(_) | BatchItemResult::NoSource(_)
            )
        })
        .count();

    // Cross-receipt consistency is a *super-tree* property, so only
    // receipts that actually carry a `super_proof` can take part.
    //
    // `atl-core::verify_cross_receipts` says so itself: handed a receipt
    // without one it returns `history_consistent: false` and the error
    // "Receipt-Lite cannot be cross-verified". Feeding such a receipt in
    // therefore manufactured a consistency *failure* out of a check that was
    // never performed -- and `verdict()` turns a consistency failure into
    // `Invalid`. Two Receipt-Lites, each `pending` and exit 0 on their own,
    // came back as refuted evidence at exit 1 the moment they shared a
    // directory. That is the same mode-dependent re-labelling as the
    // unmatched, errored and pending defects before it, and the sharpest
    // form of it: a false accusation rather than a false success.
    //
    // A receipt with no super-tree claim has no cross-receipt history to be
    // inconsistent with. It is excluded from the check, not failed by it.
    let consistency_participants: Vec<SingleVerificationResult> = consistency_candidates
        .into_iter()
        .filter(|r| r.receipt.super_proof.is_some())
        .collect();

    let consistency = if consistency_participants.len() >= 2 {
        Some(verify_consistency(&consistency_participants)?)
    } else {
        None
    };

    Ok(BatchVerificationResult {
        items,
        consistency,
        valid_count,
        pending_count,
        untrusted_count,
        invalid_count,
        error_count,
        unmatched_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_match_files_to_receipts() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        // Create test files
        std::fs::write(source_dir.path().join("doc1.pdf"), b"content1").unwrap();
        std::fs::write(source_dir.path().join("doc2.pdf"), b"content2").unwrap();
        std::fs::write(receipt_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();
        // doc2.pdf has no receipt

        let (matched, unmatched_src, unmatched_rcpt) =
            match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(matched.len(), 1);
        assert_eq!(unmatched_src.len(), 1);
        assert_eq!(unmatched_rcpt.len(), 0);
    }

    #[test]
    fn test_match_empty_source_directory() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();
        std::fs::write(receipt_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();

        let result = match_files_to_receipts(source_dir.path(), receipt_dir.path());
        assert!(matches!(result, Err(CliError::EmptySourceDirectory(_))));
    }

    #[test]
    fn test_match_empty_receipt_directory() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("doc1.pdf"), b"content1").unwrap();

        let result = match_files_to_receipts(source_dir.path(), receipt_dir.path());
        assert!(matches!(result, Err(CliError::EmptyReceiptDirectory(_))));
    }

    #[test]
    fn test_match_ignores_atl_files_in_source() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        std::fs::write(source_dir.path().join("doc1.pdf"), b"content1").unwrap();
        std::fs::write(source_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();
        std::fs::write(receipt_dir.path().join("doc1.pdf.atl"), b"{}").unwrap();

        let (matched, _, _) =
            match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn test_batch_verification_result_is_valid() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 5,
            pending_count: 0,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
        };
        assert!(result.is_valid());
    }

    #[test]
    fn test_batch_verification_result_invalid_count() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 3,
            pending_count: 0,
            untrusted_count: 0,
            invalid_count: 2,
            error_count: 0,
            unmatched_count: 0,
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_batch_verification_result_error_count() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 3,
            pending_count: 0,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 1,
            unmatched_count: 0,
        };
        assert!(!result.is_valid());
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::BatchItemsErrored),
            "an item that could not be processed must not be reported as a refuted item"
        );
    }

    fn counts(
        valid: usize,
        pending: usize,
        untrusted: usize,
        invalid: usize,
        errors: usize,
        unmatched: usize,
    ) -> BatchVerificationResult {
        BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: valid,
            pending_count: pending,
            untrusted_count: untrusted,
            invalid_count: invalid,
            error_count: errors,
            unmatched_count: unmatched,
        }
    }

    /// **The regression.** Point the tool at two directories whose filenames
    /// do not pair up and every file lands in `unmatched`: nothing at all is
    /// verified. Reporting `VALID` and exit 0 there is the worst form of
    /// this tool's central defect — a CI job whose naming drifted goes green
    /// while checking nothing.
    #[test]
    fn nothing_matched_is_never_valid() {
        let result = counts(0, 0, 0, 0, 0, 4);
        let verdict = result.verdict();

        assert_eq!(verdict.status, Status::Untrusted);
        assert_eq!(verdict.reason_code, Some(ReasonCode::BatchItemsUnmatched));
        assert!(!result.is_valid());
        assert_ne!(
            verdict.exit_code().code(),
            0,
            "zero files verified must never exit 0"
        );
        assert_eq!(result.total_count(), 4);
    }

    /// A single unmatched file among otherwise accepted ones still blocks
    /// acceptance: the caller asked about that file and got no answer.
    #[test]
    fn one_unmatched_file_blocks_a_batch_of_valid_ones() {
        let result = counts(9, 0, 0, 0, 0, 1);
        let verdict = result.verdict();

        assert_eq!(verdict.status, Status::Untrusted);
        assert_eq!(verdict.reason_code, Some(ReasonCode::BatchItemsUnmatched));
        assert_ne!(verdict.exit_code().code(), 0);
        assert_eq!(result.total_count(), 10);
    }

    /// Unmatched is an inability, so a refutation anywhere still outranks
    /// it -- the same ordering rule as everywhere else in this crate.
    #[test]
    fn a_refuted_item_outranks_unmatched_files() {
        assert_eq!(
            counts(0, 0, 0, 1, 0, 3).verdict().reason_code,
            Some(ReasonCode::BatchItemsInvalid)
        );
        assert_eq!(
            counts(0, 0, 0, 0, 1, 3).verdict().reason_code,
            Some(ReasonCode::BatchItemsErrored)
        );
    }

    /// Every file failing to be processed is not a success — and it is an
    /// operational failure (exit 2), not a refutation. The tool never got
    /// far enough to make a statement about the evidence.
    #[test]
    fn all_items_errored_is_an_operational_failure_not_a_refutation() {
        let result = counts(0, 0, 0, 0, 3, 0);
        let verdict = result.verdict();

        assert!(!result.is_valid());
        assert_eq!(verdict.status, Status::Error);
        assert_eq!(
            verdict.exit_code().code(),
            2,
            "the same code single-file mode returns"
        );
        assert_ne!(
            verdict.exit_code().code(),
            1,
            "an unreadable file is not refuted evidence"
        );
    }

    /// A genuine refutation still outranks a neighbouring file that could
    /// not be read: an inability must never conceal a proven defect.
    #[test]
    fn a_refutation_outranks_a_neighbouring_read_error() {
        // valid, pending, untrusted, invalid, errors, unmatched
        let result = counts(0, 0, 0, 1, 5, 0);
        assert_eq!(result.verdict().status, Status::Invalid);
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::BatchItemsInvalid)
        );
    }

    /// **Blocker regression.** `Pending` must never be folded into the valid
    /// count. A batch of Receipt-Lites is `pending`, not `valid`: `Valid`
    /// means every anchor reached a configured trust root, and these items
    /// have no anchors at all.
    #[test]
    fn a_batch_of_unanchored_receipts_is_pending_not_valid() {
        let result = counts(0, 3, 0, 0, 0, 0);
        let verdict = result.verdict();

        assert_eq!(verdict.status, Status::Pending);
        assert_ne!(verdict.status, Status::Valid);
        assert_eq!(verdict.reason_code, Some(ReasonCode::BatchItemsPending));
        // The documented Receipt-Lite decision: exit 0, as in single mode.
        assert_eq!(verdict.exit_code().code(), 0);
        assert_eq!(result.total_count(), 3);
    }

    /// A mixture of accepted and unanchored items is not `valid` either --
    /// the batch still contains a receipt making no external-time claim.
    #[test]
    fn a_mixture_of_valid_and_pending_is_not_valid() {
        let verdict = counts(5, 1, 0, 0, 0, 0).verdict();
        assert_eq!(verdict.status, Status::Pending);
        assert_ne!(verdict.status, Status::Valid);
    }

    /// Pending items count as verified for the backstop: they *were*
    /// checked, they simply make no time claim. A batch of them must not be
    /// reported as "nothing verified".
    #[test]
    fn pending_items_are_not_nothing_verified() {
        assert_eq!(
            counts(0, 2, 0, 0, 0, 0).verdict().reason_code,
            Some(ReasonCode::BatchItemsPending)
        );
        assert_eq!(
            counts(0, 0, 0, 0, 0, 2).verdict().reason_code,
            Some(ReasonCode::BatchItemsUnmatched)
        );
    }

    /// The backstop: no combination of counts may yield `valid` while zero
    /// files were verified. Exhaustive over small counts, so a future change
    /// to the buckets cannot quietly reopen the hole.
    #[test]
    fn no_count_combination_yields_valid_without_a_verified_file() {
        for untrusted in 0..3 {
            for invalid in 0..3 {
                for errors in 0..3 {
                    for unmatched in 0..3 {
                        let result = counts(0, 0, untrusted, invalid, errors, unmatched);
                        assert!(
                            !result.is_valid(),
                            "valid_count = 0 must never be accepted \
                             (untrusted={untrusted} invalid={invalid} errors={errors} \
                             unmatched={unmatched})"
                        );
                        assert_ne!(result.verdict().exit_code().code(), 0);
                    }
                }
            }
        }
    }

    /// And the converse: a batch where every named file was verified and
    /// accepted is still `VALID`. The fix must not make success
    /// unreachable.
    #[test]
    fn a_fully_verified_batch_is_still_valid() {
        let result = counts(5, 0, 0, 0, 0, 0);
        assert!(result.is_valid());
        assert_eq!(result.verdict().exit_code().code(), 0);
        assert_eq!(result.total_count(), 5);
    }
}
