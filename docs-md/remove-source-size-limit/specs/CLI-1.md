# CLI-1: Remove the 1 GiB Source File Bound

## Metadata

- **Status**: APPROVED (owner, 2026-10-16)
- **Author**: Dmitrii Zatona <dmitrii@zatona.dev>
- **Created**: 2026-10-16
- **Blocked By**: None
- **Blocks**: None

> **CONSTRAINT**: No file this task creates or changes may exceed 500 lines; split
> into modules if needed. The crate already holds twelve files above that line under
> `src/` (651 to 2135 lines) and three under `tests/` (514 to 1256), every one of
> them already so before this task. This task changes two of them —
> `src/cli/args.rs` (955 lines) and `src/verify/single.rs` (1244) — and splits
> neither: the budget here is the minimal change for Required Behaviour 3, and
> refactoring those two files is out of scope.

---

## Overview

`atl-cli` refuses to verify a source file larger than 1 GiB. `hash_file` reads the
size from the file's metadata and returns `CliError::FileTooLarge` before reading a
byte, so no hash is computed, no comparison is made and no verdict is produced.

The bound protects nothing. `hash_file` already streams the file through a 64 KiB
buffer, so its memory use is constant at any file size, and it is the only place in
the crate that hashes a source file. Nothing in the ATL protocol imposes a source
file bound either: the entry's leaf is `SHA-256` of the payload, and the only
resource-limits clause in the Internet-Draft bounds external evidence documents, not
payloads. The number was written into the first CLI task (`docs-md/start/`, VERIFY-1)
as one line of an input-validation list, without a stated reason, and has never been
revisited.

The effect today is that a correctly anchored payload above 1 GiB cannot be checked
with this tool. The receipt is valid and any streaming verifier confirms it; `atl-cli`
alone declines.

**Goal**: verify a source file of any size.

---

## Scope

### In Scope

- Delete the constant `MAX_SOURCE_FILE_SIZE` (`src/verify/file.rs:11`).
- Delete the size gate it guards in `hash_file` (`src/verify/file.rs:41-49`),
  including the `std::fs::metadata` call made only for that gate.
- Drop the constant from the module re-export (`src/verify/mod.rs:24`).
- Delete the unit test that asserts the constant's value
  (`src/verify/file.rs:176`).
- Correct the `hash_file` doc comment, which states that the function "enforces a
  1 GB file size limit" and lists "File exceeds size limit" among its errors.
- Add the regression test named in Acceptance Criteria below.
- Replace the source existence check in `hash_file` (`src/verify/file.rs:33`) so
  that an absent path and a path whose existence cannot be determined are told
  apart, per Required Behaviour 3.
- Do the same for both checks in `VerifyArgs::validate`: the source
  (`src/cli/args.rs:432`) and the receipt (`src/cli/args.rs:437`). `validate` is
  called from `src/commands/verify.rs:23`; that call site itself is not edited.
- Do the same for the receipt existence check in `load_receipt`
  (`src/verify/single.rs:551`). The rest of the function is left alone.
- Add the two tests named in AC6 and AC7.

### Out of Scope

- `MAX_RECEIPT_SIZE` (10 MiB, receipt documents) — unchanged, including its gate in
  `load_receipt` (`src/verify/single.rs:556-563`).
- `CliError::FileTooLarge` — the variant **stays**: it is still raised for the
  receipt bound. Its exit-code classification (`ExitCode::Error`, exit 2) and its
  own unit test (`src/error.rs:840`) stay as they are.
- Every other input-validation bound (UTF-8 validation, JSON depth).
- Progress reporting during hashing. The crate has none, and a large file is
  therefore silent until the verdict. Out of scope here; raise separately.
- `atl-core`, `atl-server`, the protocol text, and the delivered `docs-md/start/`
  record. That record's line "File size limit: 1 GB (for hashing)"
  (`docs-md/start/PLAN.md:529`) is superseded by this task and is **not** edited:
  VERIFY-1 is a delivered spec and delivered specs are frozen.

---

## Impact Analysis / Related Files

| File | Impact | Description |
|------|--------|-------------|
| `src/verify/file.rs` | PRIMARY | Remove constant, gate and its test; correct doc comment; add regression test; fix the source existence check (`:33`) |
| `src/verify/mod.rs` | MINOR | Drop one name from the `pub use` list |
| `src/cli/args.rs` | SECONDARY | Both existence checks in `validate` — source (`:432`) and receipt (`:437`): distinguish an absent path from one whose existence cannot be determined (RB3) |
| `src/verify/single.rs` | SECONDARY | The same for the receipt existence check in `load_receipt` (`:551`); nothing else in the function changes |

The four checks named in Required Behaviour 3 are the only `Path::exists()` calls
in the crate. No other file references `MAX_SOURCE_FILE_SIZE`. Verified: the only
other `std::fs::metadata` calls in the crate are the receipt bound
(`src/verify/single.rs:556`) and file-type classification in batch mode
(`src/verify/batch.rs:385`), and the only whole-file reads are the receipt
(`src/verify/single.rs:567`, after its own bound) and the trust store
(`src/verify/trust_store.rs:170`). `hash_file` is called from exactly one place,
`src/verify/single.rs:667`, through which batch verification also runs.

---

## Required Behaviour

1. `hash_file` streams the file through its existing 64 KiB buffer and returns the
   `SHA-256` digest, for a regular file of any size.
2. A path that does not exist still returns `CliError::SourceNotFound`.
3. `SourceNotFound` and `ReceiptNotFound` are raised only for a path determined not
   to exist; any other failure to determine existence, or to open the file, returns
   `CliError::FileReadError` carrying the underlying `io` error. Four checks decide
   this, each on `Path::exists()`, which is `false` both for an absent path and for
   one it could not stat: `src/verify/file.rs:33` (source, `hash_file`),
   `src/cli/args.rs:432` (source) and `:437` (receipt) in `validate` — the first
   barrier the user meets, from `src/commands/verify.rs:23` — and
   `src/verify/single.rs:551` (receipt, `load_receipt`). All three variants are
   already `ExitCode::Error` (`src/error.rs:362-365`), so exit 2 is unchanged and
   only the diagnosis changes. `Path::try_exists` returns `io::Result<bool>` and
   draws exactly this distinction (crate `rust-version` is 1.92.0).
4. `hash_file` no longer returns `CliError::FileTooLarge` for any input. The variant
   remains reachable from `load_receipt` only.
5. Nothing else in `load_receipt` changes: its 10 MiB bound, the JSON parse and the
   `spec_version` check stay exactly as they are.

---

## Acceptance Criteria

- **AC1:** A source file one byte larger than the former bound (1 GiB + 1) is hashed
  successfully. The test creates the file sparsely with `File::set_len` so that it
  costs no real disk space, and asserts `hash_file` returns `Ok`. Before this change
  the same input returned `Err(FileTooLarge)`, so the test fails on the old code and
  passes on the new one.
- **AC2:** No test and no source file references `MAX_SOURCE_FILE_SIZE`; the crate
  compiles with the name gone.
- **AC3:** The existing `hash_file` tests still pass, unchanged: `test_hash_file`
  (small file), `test_hash_empty_file`, `test_hash_file_large` (1 MiB) and
  `test_hash_file_not_found` (absent path, `SourceNotFound`). `test_constants`
  passes too, with only the deleted assertion gone from it. The crate has no
  `hash_file` test for a file that exists but cannot be read.
- **AC4:** `load_receipt` still rejects a receipt document above 10 MiB with
  `FileTooLarge` and exit code 2.
- **AC5:** `cargo test -p atl-cli --no-fail-fast`, `cargo fmt --check` and
  `cargo clippy -p atl-cli` are clean for the changed crate.
- **AC6:** With `F` a temporary regular file, `F/child` returns `FileReadError`, not
  `SourceNotFound`, from `hash_file` and from `VerifyArgs::validate` as the source.
  `Path::exists()` is `false` there while `try_exists()` fails with `NotADirectory`
  (`ENOTDIR`, os error 20, observed on macOS) — deterministic for any user, root
  included, with no permission setup and no platform guard.
- **AC7:** `F/child` as the receipt returns `FileReadError`, not `ReceiptNotFound`,
  from `VerifyArgs::validate` and from `load_receipt`.

---

## Notes for the Implementer

The sparse file in AC1 must not be written byte by byte: `File::set_len` on APFS and
ext4 allocates no blocks, so the test stays fast. If the platform does not support
sparse files the test still passes, only slower; do not add a platform guard that
skips it.
