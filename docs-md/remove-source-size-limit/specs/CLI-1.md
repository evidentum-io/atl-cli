# CLI-1: Remove the 1 GiB Source File Bound

## Metadata

- **Status**: APPROVED (owner, 2026-10-16)
- **Author**: Dmitrii Zatona <dmitrii@zatona.dev>
- **Created**: 2026-10-16
- **Blocked By**: None
- **Blocks**: None

> **CONSTRAINT**: No implementation file may exceed 500 lines. Split into modules if needed.

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
| `src/verify/file.rs` | PRIMARY | Remove constant, gate and its test; correct doc comment; add regression test |
| `src/verify/mod.rs` | MINOR | Drop one name from the `pub use` list |

No other file references `MAX_SOURCE_FILE_SIZE`. Verified: the only other
`std::fs::metadata` calls in the crate are the receipt bound
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
3. A file that cannot be read still returns `CliError::FileReadError`, from the same
   read path as before.
4. `hash_file` no longer returns `CliError::FileTooLarge` for any input. The variant
   remains reachable from `load_receipt` only.
5. No behaviour of `load_receipt` changes.

---

## Acceptance Criteria

- **AC1:** A source file one byte larger than the former bound (1 GiB + 1) is hashed
  successfully. The test creates the file sparsely with `File::set_len` so that it
  costs no real disk space, and asserts `hash_file` returns `Ok`. Before this change
  the same input returned `Err(FileTooLarge)`, so the test fails on the old code and
  passes on the new one.
- **AC2:** No test and no source file references `MAX_SOURCE_FILE_SIZE`; the crate
  compiles with the name gone.
- **AC3:** The existing `hash_file` tests (small file, missing file, unreadable file)
  still pass unchanged.
- **AC4:** `load_receipt` still rejects a receipt document above 10 MiB with
  `FileTooLarge` and exit code 2.
- **AC5:** `cargo test -p atl-cli --no-fail-fast`, `cargo fmt --check` and
  `cargo clippy -p atl-cli` are clean for the changed crate.

---

## Notes for the Implementer

The sparse file in AC1 must not be written byte by byte: `File::set_len` on APFS and
ext4 allocates no blocks, so the test stays fast. If the platform does not support
sparse files the test still passes, only slower; do not add a platform guard that
skips it.
