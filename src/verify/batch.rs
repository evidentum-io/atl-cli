//! Batch/directory verification logic

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use atl_core::TrustStore;

use crate::error::{CliError, CliResult};
use crate::verify::consistency::{verify_consistency, ConsistencyResult};
use crate::verify::policy::AnchorPolicy;
use crate::verify::single::{verify_single, SingleVerificationResult};
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Result of a single file in batch mode
#[derive(Debug)]
pub enum BatchItemResult {
    /// Verification succeeded: every anchor reached a configured trust root.
    Valid(SingleVerificationResult),
    /// Cryptographically sound but carrying no anchors at all
    /// (Receipt-Lite) **as it reached this tool**, so it has zero verified
    /// anchors.
    ///
    /// A sub-kind of untrusted, not of valid: ATL v2.0 §5.5 says a receipt
    /// without any verified anchors should be treated as untrustworthy, and
    /// the item's own status word is `untrusted` with reason
    /// `receipt_unanchored` — the same code an item whose anchors all failed
    /// reports, because those are the same fact and this tool cannot tell
    /// them apart. The bucket is kept distinct only so the report can
    /// explain the Receipt-Lite tier instead of sending the reader after a
    /// certificate that would not help, and it feeds no aggregate reason: a
    /// relay can move an item out of it by appending an anchor.
    Unanchored(SingleVerificationResult),
    /// The receipt was not refuted, and trust in it was not established:
    /// its anchors reached no configured trust root, a check could not be
    /// finished, or one of its anchors was checked and found false — which
    /// refutes that anchor and not the receipt, since a receipt's `anchors`
    /// array is signed and hashed by nothing.
    Untrusted(SingleVerificationResult),
    /// The receipt itself was refuted (cryptographic or hash). Never reached
    /// from an anchor — see [`Self::Untrusted`].
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
    /// Count of files whose receipts **presented** no anchors
    /// (Receipt-Lite). These are untrusted items, counted separately only
    /// for reporting: the batch's own reason code does not depend on this
    /// number, because an `anchors` array is authenticated by nothing and a
    /// relay can move an item out of this bucket by appending to it.
    pub unanchored_count: usize,
    /// Count of files that were not refuted and were not accepted: their
    /// anchors reached no configured trust root, a check could not be
    /// finished, or an anchor was checked and found false.
    pub untrusted_count: usize,
    /// Count of invalid files
    pub invalid_count: usize,
    /// Count of errors
    pub error_count: usize,
    /// Count of unmatched items
    pub unmatched_count: usize,
    /// The anchor quorum every item in this batch was judged against.
    pub policy: AnchorPolicy,
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
        // A proven break in one log instance's history is a refutation and
        // outranks everything below.
        //
        // Honest note on reach: through `verify_batch` this branch is not
        // currently taken. `verify_cross_receipts` fails only when the two
        // `genesis_super_root` values differ -- which no longer reaches here,
        // since ATL v2.0 §5.4.3 step 2 is applied as a grouping -- or when a
        // §5.4.2 consistency-to-origin proof does not hold, and `atl-core`
        // already ran that same proof per receipt, so such an item is
        // `Invalid` on its own and never becomes a participant. The branch
        // stands because the *rule* is right: if a cross-receipt check ever
        // does refute something, it must land here and not below the
        // inabilities.
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
        // One code for every item that reached a verdict and was not
        // accepted, Receipt-Lite included.
        //
        // These used to be two: `batch_items_unanchored` was reported ahead
        // of `batch_items_untrusted` whenever any item carried no anchors at
        // all. But bucket membership is decided by the item's `anchors`
        // array, which is authenticated by nothing -- so appending one
        // rubbish anchor to one Receipt-Lite in the directory moved that
        // item from `unanchored` to `untrusted` and changed the whole
        // BATCH's reported reason. That is the single-receipt defect one
        // storey up, and it is closed the same way: the aggregate reason is
        // a function of what was *verified*, and both buckets verified
        // nothing.
        //
        // The distinction survives where it belongs -- as `summary.unanchored`,
        // a count of the items that presented no anchors, and as the
        // per-item `Unanchored` bucket the report uses to explain the
        // Receipt-Lite tier rather than send a reader after trust material.
        if self.unanchored_count > 0 || self.untrusted_count > 0 {
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
        if self.valid_count == 0 {
            return ReceiptVerdict::untrusted(ReasonCode::BatchNothingVerified);
        }

        ReceiptVerdict::VALID
    }

    /// `true` when at least one accepted item was accepted only because the
    /// anchor quorum was lowered: its policy is satisfied while some anchor
    /// it presented went unresolved.
    ///
    /// The renderers use this to qualify the batch's own success line. A
    /// bare "VALID" over a run in which anchors were left unresolved would
    /// be the overclaim `--allow-single-anchor` exists to make explicit,
    /// and a reader who skims only the last line must not be misled by it.
    #[must_use]
    pub fn accepted_with_gaps(&self) -> bool {
        self.items.iter().any(|item| match item {
            BatchItemResult::Valid(result) => result.assessment().accepted_with_gaps(),
            _ => false,
        })
    }

    /// Total number of paths the caller named, across every bucket.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.valid_count
            + self.unanchored_count
            + self.untrusted_count
            + self.invalid_count
            + self.error_count
            + self.unmatched_count
    }

    /// Check if overall batch was accepted (every named file verified and
    /// accepted, and the log consistent).
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; kept as the readable predicate
    pub fn is_valid(&self) -> bool {
        matches!(self.verdict().status, Status::Valid)
    }

    /// Re-bucket every verified item and recompute the counts from each
    /// item's current [`SingleVerificationResult::verdict`].
    ///
    /// Called after the online pass has upgraded `bitcoin_ots` anchors in
    /// place: an item that was `Untrusted` only because no block had been
    /// fetched becomes `Valid` (or `Invalid`) once it has been. `error_count`
    /// and the unmatched items are untouched -- going online cannot change
    /// whether a file could be read or matched.
    ///
    /// The consistency result is not recomputed either, and does not need
    /// to be: ATL v2.0 §5.4.3 rests on each receipt's `genesis_super_root`
    /// and its own §5.4.2 proof, neither of which a Bitcoin block lookup
    /// can alter.
    pub fn reclassify(&mut self) {
        let mut valid_count = 0;
        let mut unanchored_count = 0;
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
                | BatchItemResult::Unanchored(result)
                | BatchItemResult::Untrusted(result)
                | BatchItemResult::Invalid(result) => match result.verdict().status {
                    Status::Valid => {
                        valid_count += 1;
                        BatchItemResult::Valid(result)
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
                    // An item that presented no anchors keeps its own
                    // bucket so the report can name the Receipt-Lite tier;
                    // it is an untrusted item either way, exits 3 either
                    // way, and reports the same reason code either way.
                    Status::Untrusted => {
                        if result.presents_no_anchors() {
                            unanchored_count += 1;
                            BatchItemResult::Unanchored(result)
                        } else {
                            untrusted_count += 1;
                            BatchItemResult::Untrusted(result)
                        }
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
        self.unanchored_count = unanchored_count;
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

/// A directory entry the walk could neither classify nor check.
///
/// Kept as a value instead of being returned as an error, for the same
/// reason [`crate::commands`] defers a mode failure: aborting the whole run
/// would discard receipts already refuted elsewhere in the batch, which is
/// an inability suppressing a refutation. Each of these becomes a
/// [`BatchItemResult::Error`] row, so the entry can neither vanish from the
/// accounting nor be mistaken for refuted evidence.
#[derive(Debug)]
pub struct UnreadableEntry {
    /// The entry, or the directory itself when the walk failed before a
    /// path was known.
    pub path: PathBuf,
    /// What stopped it from being classified.
    pub error: CliError,
}

/// What one directory entry turned out to be.
enum EntryKind {
    /// A regular file (or a symlink resolving to one): a path the batch owns.
    RegularFile,
    /// A directory, or a symlink to one: genuinely not a named file.
    Skip,
}

/// Classify `path`, following symlinks, without ever swallowing the answer.
///
/// `Path::is_file()` collapses "this is a directory" and "I could not find
/// out" into the same `false`, which dropped an unreadable entry from the
/// batch accounting entirely — landing it in no bucket at all, so the batch
/// could report success having skipped it.
///
/// A directory or a symlink to one is skipped. A dangling symlink, or an
/// entry whose type cannot be read, is reported: it is a path the caller put
/// in this directory and we could not check.
fn classify_entry(entry: &std::fs::DirEntry, path: &Path) -> CliResult<EntryKind> {
    let file_type = entry
        .file_type()
        .map_err(|e| CliError::file_read_error(path, e))?;
    if file_type.is_dir() {
        return Ok(EntryKind::Skip);
    }
    if file_type.is_file() {
        return Ok(EntryKind::RegularFile);
    }
    // A symlink, or a device/socket/FIFO: resolve it and ask again. Anything
    // that resolves to neither a file nor a directory (a FIFO, say) is not a
    // named file either, and is skipped exactly as it was before.
    let metadata = std::fs::metadata(path).map_err(|e| CliError::file_read_error(path, e))?;
    Ok(if metadata.is_file() {
        EntryKind::RegularFile
    } else {
        EntryKind::Skip
    })
}

/// Walk one directory, returning the paths that passed `keep` and the
/// entries that could not be classified.
///
/// Failure to open the directory at all is still returned as an error —
/// there is no listing to report against. Failures on individual entries are
/// collected instead, so one unreadable neighbour cannot silence the rest of
/// the batch.
fn walk_directory(
    dir: &Path,
    keep: impl Fn(&Path) -> bool,
) -> CliResult<(Vec<PathBuf>, Vec<UnreadableEntry>)> {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();

    for entry in std::fs::read_dir(dir).map_err(|e| CliError::file_read_error(dir, e))? {
        // An error from the iterator itself has no path attached: the
        // listing broke, and an unknown entry was lost. Recorded against the
        // directory so the run can still never come out clean.
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                unreadable.push(UnreadableEntry {
                    path: dir.to_path_buf(),
                    error: CliError::file_read_error(dir, e),
                });
                continue;
            }
        };
        let path = entry.path();
        match classify_entry(&entry, &path) {
            Ok(EntryKind::Skip) => continue,
            Ok(EntryKind::RegularFile) => {
                if keep(&path) {
                    files.push(path);
                }
            }
            Err(error) => unreadable.push(UnreadableEntry { path, error }),
        }
    }

    Ok((files, unreadable))
}

/// Whether `path` carries the `.atl` receipt extension.
fn has_atl_extension(path: &Path) -> bool {
    path.extension() == Some(std::ffi::OsStr::new("atl"))
}

/// Every path the two directories yielded, sorted into the buckets the batch
/// accounts for. Every entry seen ends up in exactly one of these fields —
/// that is the invariant the batch verdict rests on.
#[derive(Debug)]
pub struct FileMatching {
    /// Source files paired with their receipts.
    pub matched: Vec<(PathBuf, PathBuf)>,
    /// Source files with no receipt of the expected name.
    pub unmatched_sources: Vec<PathBuf>,
    /// Receipts with no source file of the expected name.
    pub unmatched_receipts: Vec<PathBuf>,
    /// Entries neither directory walk could classify.
    pub unreadable: Vec<UnreadableEntry>,
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
/// A [`FileMatching`]: matched pairs, the two kinds of unmatched path, and
/// every entry that could not be classified.
///
/// # Errors
///
/// Returns error if:
/// - Directories cannot be opened
/// - No files found in source directory
/// - No receipts found in receipt directory
pub fn match_files_to_receipts(source_dir: &Path, receipt_dir: &Path) -> CliResult<FileMatching> {
    // Scan the source directory. An entry that vanishes silently here is a
    // file the caller named and we never checked, and it would land in no
    // bucket at all -- not `matched`, not `unmatched` -- so the batch could
    // report success having skipped it. That is the exact "reported more
    // than was verified" failure this whole verdict model exists to prevent.
    //
    // Reported, though, is not the same as fatal: aborting here would throw
    // away every other file in the directory, including any this run had
    // already refuted, which is the same defect wearing the other face. Each
    // unclassifiable entry becomes an `Error` item instead.
    let (source_files, mut unreadable) =
        walk_directory(source_dir, |path| !has_atl_extension(path))?;

    // "Empty" must mean empty, not "everything in it was unreadable": that
    // reading would name the wrong problem and hide the entries entirely.
    if source_files.is_empty() && unreadable.is_empty() {
        return Err(CliError::EmptySourceDirectory(source_dir.to_path_buf()));
    }

    // Same rule for the receipt directory.
    let (receipt_files, receipt_unreadable) = walk_directory(receipt_dir, has_atl_extension)?;
    unreadable.extend(receipt_unreadable);

    if receipt_files.is_empty() && unreadable.is_empty() {
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

    Ok(FileMatching {
        matched,
        unmatched_sources,
        unmatched_receipts,
        unreadable,
    })
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
    policy: AnchorPolicy,
) -> CliResult<BatchVerificationResult> {
    // Match files to receipts
    let FileMatching {
        matched,
        unmatched_sources,
        unmatched_receipts,
        unreadable,
    } = match_files_to_receipts(source_dir, receipt_dir)?;

    let mut items = Vec::new();
    let mut consistency_candidates = Vec::new();
    let mut valid_count = 0;
    let mut unanchored_count = 0;
    let mut untrusted_count = 0;
    let mut invalid_count = 0;
    let mut error_count = 0;

    // Verify each matched pair
    for (source_path, receipt_path) in matched {
        match verify_single(&source_path, &receipt_path, trust_store, policy) {
            Ok(result) => match result.verdict().status {
                Status::Valid => {
                    valid_count += 1;
                    consistency_candidates.push(result.clone());
                    items.push(BatchItemResult::Valid(result));
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
                    // ATL v2.0 §5.4.3 step 1 is "verify each receipt
                    // independently (previous steps)" -- §5.1 to §5.4. Anchor
                    // verification is §5.5, so a receipt whose anchors reached
                    // no configured trust root -- or which carries none at
                    // all -- has still satisfied step 1 and takes part. A
                    // refuted receipt has not, and does not.
                    consistency_candidates.push(result.clone());
                    // Sound proofs and no anchors keeps its own bucket, so
                    // the report can name the Receipt-Lite tier rather than
                    // send the reader after trust material.
                    if result.presents_no_anchors() {
                        unanchored_count += 1;
                        items.push(BatchItemResult::Unanchored(result));
                    } else {
                        untrusted_count += 1;
                        items.push(BatchItemResult::Untrusted(result));
                    }
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

    // Entries the walk could not classify. They are neither matched nor
    // unmatched -- nothing is known about them at all -- so they are filed
    // as errors: exit 2, never a refutation, and never invisible.
    for entry in unreadable {
        error_count += 1;
        items.push(BatchItemResult::Error {
            source: entry.path,
            receipt: None,
            error: entry.error,
        });
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

    // Cross-Receipt Verification (ATL v2.0 §5.4.3) is a Super-Tree
    // property, so only Receipt-Full documents can take part: §3.3.2 says
    // only they carry the `genesis_super_root` the comparison is made on.
    //
    // `atl-core::verify_cross_receipts` says so itself: handed a receipt
    // without one it returns `history_consistent: false` and the error
    // "Receipt-Lite cannot be cross-verified". Feeding such a receipt in
    // therefore manufactured a consistency *failure* out of a check that was
    // never performed -- and `verdict()` turns a consistency failure into
    // `Invalid`. Two Receipt-Lites, each merely untrusted on their own, came
    // back as refuted evidence at exit 1 the moment they shared a directory.
    // That is the same mode-dependent re-labelling as the unmatched and
    // errored defects before it, and the sharpest form of it: a false
    // accusation rather than a false success.
    //
    // A receipt with no super-tree claim has no cross-receipt history to be
    // inconsistent with. It is excluded from the check, not failed by it.
    let consistency_participants: Vec<SingleVerificationResult> = consistency_candidates
        .into_iter()
        .filter(|r| r.receipt.super_proof().is_some())
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
        unanchored_count,
        untrusted_count,
        invalid_count,
        error_count,
        unmatched_count,
        policy,
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

        let m = match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(m.matched.len(), 1);
        assert_eq!(m.unmatched_sources.len(), 1);
        assert_eq!(m.unmatched_receipts.len(), 0);
        assert!(m.unreadable.is_empty());
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

        let m = match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(m.matched.len(), 1);
    }

    /// The receipt-to-source name mapping, at the boundaries where the old
    /// `strip_suffix(".atl")` on a lossy string and the current
    /// `Path::extension` / `file_stem` pair can disagree.
    #[test]
    fn strip_atl_suffix_boundaries() {
        use std::ffi::OsStr;

        let strip = |name: &str| {
            strip_atl_suffix(OsStr::new(name)).map(|s| s.to_string_lossy().into_owned())
        };

        assert_eq!(strip("doc.pdf.atl").as_deref(), Some("doc.pdf"));
        // A receipt for a receipt: the source name keeps its own `.atl`.
        assert_eq!(strip("a.atl.atl").as_deref(), Some("a.atl"));
        // Dotfiles: the leading dot belongs to the stem, not the extension.
        assert_eq!(strip(".hidden.atl").as_deref(), Some(".hidden"));
        assert_eq!(strip(".atl.atl").as_deref(), Some(".atl"));
        // A bare `.atl` has no extension at all by Rust's rule, so it names
        // no source. It never reaches here either -- the receipt walk keeps
        // only entries whose extension *is* `atl` -- but the two must agree.
        assert_eq!(strip(".atl"), None);
        assert!(!has_atl_extension(Path::new(".atl")));
        // Not receipts.
        assert_eq!(strip("doc.pdf"), None);
        assert_eq!(strip("noextension"), None);
        assert_eq!(strip("doc.ATL"), None);
    }

    /// A source file may legitimately be named `x.atl`; its receipt is then
    /// `x.atl.atl`. The source walk skips every `.atl` entry, so the pair
    /// cannot match and the receipt is reported unmatched -- exit 3, never a
    /// silent success. Pinned because it is the one place the two walks
    /// deliberately disagree about what a `.atl` name means.
    #[test]
    fn a_receipt_for_a_receipt_is_reported_unmatched() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        std::fs::write(source_dir.path().join("a.atl"), b"content").unwrap();
        std::fs::write(source_dir.path().join("b.pdf"), b"content").unwrap();
        std::fs::write(receipt_dir.path().join("a.atl.atl"), b"{}").unwrap();
        std::fs::write(receipt_dir.path().join("b.pdf.atl"), b"{}").unwrap();

        let m = match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(m.matched.len(), 1);
        assert_eq!(m.unmatched_receipts.len(), 1, "a.atl.atl has no source");
        assert!(m.unmatched_sources.is_empty());
    }

    /// A subdirectory is not a named file and is skipped, exactly as before
    /// the walk started reporting failures. Only entries that cannot be
    /// *classified* are reported.
    #[test]
    fn subdirectories_are_skipped_not_reported() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        std::fs::write(source_dir.path().join("doc.pdf"), b"content").unwrap();
        std::fs::create_dir(source_dir.path().join("nested")).unwrap();
        std::fs::create_dir(receipt_dir.path().join("nested.atl")).unwrap();
        std::fs::write(receipt_dir.path().join("doc.pdf.atl"), b"{}").unwrap();

        let m = match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(m.matched.len(), 1);
        assert!(m.unmatched_sources.is_empty());
        assert!(
            m.unmatched_receipts.is_empty(),
            "{:?}",
            m.unmatched_receipts
        );
        assert!(m.unreadable.is_empty(), "a directory is not an error");
    }

    /// A symlink to a real file is a named file; a symlink to a directory is
    /// not; a dangling one can be neither confirmed nor denied and is
    /// reported rather than dropped.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_resolved_and_dangling_ones_reported() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();
        let target_dir = TempDir::new().unwrap();

        let real_file = target_dir.path().join("real.pdf");
        std::fs::write(&real_file, b"content").unwrap();
        std::os::unix::fs::symlink(&real_file, source_dir.path().join("link.pdf")).unwrap();
        std::os::unix::fs::symlink(target_dir.path(), source_dir.path().join("dirlink")).unwrap();
        std::os::unix::fs::symlink("/nonexistent/target", source_dir.path().join("ghost")).unwrap();
        std::fs::write(receipt_dir.path().join("link.pdf.atl"), b"{}").unwrap();

        let m = match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();

        assert_eq!(m.matched.len(), 1, "a symlink to a file is a named file");
        assert!(
            m.unmatched_sources.is_empty(),
            "a symlink to a directory is not a named file: {:?}",
            m.unmatched_sources
        );
        assert_eq!(m.unreadable.len(), 1, "the dangling link must be reported");
        assert!(m.unreadable[0].path.ends_with("ghost"));
    }

    /// A directory holding nothing but entries we cannot classify is not an
    /// *empty* directory, and saying so would name the wrong problem while
    /// hiding the entries entirely.
    #[cfg(unix)]
    #[test]
    fn a_directory_of_unreadable_entries_is_not_reported_empty() {
        let source_dir = TempDir::new().unwrap();
        let receipt_dir = TempDir::new().unwrap();

        std::os::unix::fs::symlink("/nonexistent/target", source_dir.path().join("ghost")).unwrap();
        std::fs::write(receipt_dir.path().join("doc.pdf.atl"), b"{}").unwrap();

        let m = match_files_to_receipts(source_dir.path(), receipt_dir.path()).unwrap();
        assert_eq!(m.unreadable.len(), 1);
        assert_eq!(m.unmatched_receipts.len(), 1);
    }

    #[test]
    fn test_batch_verification_result_is_valid() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 5,
            unanchored_count: 0,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 0,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
        };
        assert!(result.is_valid());
    }

    #[test]
    fn test_batch_verification_result_invalid_count() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 3,
            unanchored_count: 0,
            untrusted_count: 0,
            invalid_count: 2,
            error_count: 0,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_batch_verification_result_error_count() {
        let result = BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: 3,
            unanchored_count: 0,
            untrusted_count: 0,
            invalid_count: 0,
            error_count: 1,
            unmatched_count: 0,
            policy: AnchorPolicy::AllAnchors,
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
        unanchored: usize,
        untrusted: usize,
        invalid: usize,
        errors: usize,
        unmatched: usize,
    ) -> BatchVerificationResult {
        BatchVerificationResult {
            items: vec![],
            consistency: None,
            valid_count: valid,
            unanchored_count: unanchored,
            untrusted_count: untrusted,
            invalid_count: invalid,
            error_count: errors,
            unmatched_count: unmatched,
            policy: AnchorPolicy::AllAnchors,
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
        // valid, unanchored, untrusted, invalid, errors, unmatched
        let result = counts(0, 0, 0, 1, 5, 0);
        assert_eq!(result.verdict().status, Status::Invalid);
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::BatchItemsInvalid)
        );
    }

    /// ATL v2.0 §5.5. A batch of Receipt-Lites has zero verified anchors,
    /// so it is `untrusted` and exit 3 -- exactly what single-file mode says
    /// about each of those receipts on its own. It exited 0 under the word
    /// `pending` until that was recognised as accepting what §5.5 says to
    /// treat as untrustworthy.
    #[test]
    fn a_batch_of_unanchored_receipts_is_untrusted_not_valid() {
        let result = counts(0, 3, 0, 0, 0, 0);
        let verdict = result.verdict();

        assert_eq!(verdict.status, Status::Untrusted);
        assert_ne!(verdict.status, Status::Valid);
        assert_eq!(verdict.reason_code, Some(ReasonCode::BatchItemsUntrusted));
        assert_eq!(verdict.exit_code().code(), 3);
        assert_eq!(result.total_count(), 3);
    }

    /// A mixture of accepted and unanchored items is not `valid` either --
    /// the batch still contains a receipt with no verified anchor.
    #[test]
    fn a_mixture_of_valid_and_unanchored_is_untrusted() {
        let verdict = counts(5, 1, 0, 0, 0, 0).verdict();
        assert_eq!(verdict.status, Status::Untrusted);
        assert_eq!(verdict.reason_code, Some(ReasonCode::BatchItemsUntrusted));
        assert_eq!(verdict.exit_code().code(), 3);
    }

    /// An unanchored item is reported as such, not as "nothing verified":
    /// it *was* checked, and what it lacks is an anchor, not a check.
    #[test]
    fn unanchored_items_are_not_nothing_verified() {
        assert_eq!(
            counts(0, 2, 0, 0, 0, 0).verdict().reason_code,
            Some(ReasonCode::BatchItemsUntrusted)
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
        for unanchored in 0..3 {
            for untrusted in 0..3 {
                for invalid in 0..3 {
                    for errors in 0..3 {
                        for unmatched in 0..3 {
                            let result =
                                counts(0, unanchored, untrusted, invalid, errors, unmatched);
                            assert!(
                                !result.is_valid(),
                                "valid_count = 0 must never be accepted \
                                 (unanchored={unanchored} untrusted={untrusted} \
                                 invalid={invalid} errors={errors} unmatched={unmatched})"
                            );
                            assert_ne!(result.verdict().exit_code().code(), 0);
                        }
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
