# Remove the 1 GiB Source File Bound

**Initiative**: let `atl-cli` verify a source file of any size.

**Why**: `hash_file` streams through a 64 KiB buffer, so its memory use is constant at
any file size, and nothing in the protocol bounds a payload. The 1 GiB number came in
with the first CLI task as one line of an input-validation list, with no stated reason.
Its only effect is that a correctly anchored payload above 1 GiB cannot be checked with
this tool, while the receipt stays valid and any streaming verifier confirms it.

**Owner decision (2026-10-16)**: remove the bound, do not replace it with a larger one.

---

## Specs Index

| Status | Spec File | Task Summary |
|--------|-----------|--------------|
| [ ] | [CLI-1.md](specs/CLI-1.md) | Remove `MAX_SOURCE_FILE_SIZE` and its gate in `hash_file` |

---

## Review budget (Rust policy, `~/.claude/policies/rust.md`)

Budget: up to 10 independent Codex code reviews. Spec reviews do not count.

| Round | Verdict | Findings | Notes |
|-------|---------|----------|-------|
| 1 | NO | 2 BLOCKER, 0 QUESTION | Both were defects of the spec text, not of the code: a pasted 500-line constraint that bound twelve pre-existing files, and a Required Behaviour clause promising `FileReadError` for a file whose existence cannot be determined, which the crate has never done. `review/codex-round-1.md` |

---

## Definition of Done

1. [x] `MAX_SOURCE_FILE_SIZE` and its gate are gone; the name is referenced nowhere
2. [x] A file one byte above the former bound hashes successfully (AC1)
3. [x] `CliError::FileTooLarge`, its exit code and the 10 MiB receipt bound are unchanged
4. [ ] A path whose existence cannot be determined reports `FileReadError`, not absence, at all four sites (AC6, AC7)
5. [ ] `cargo test -p atl-cli --no-fail-fast`, `cargo fmt --check`, `cargo clippy -p atl-cli` clean
6. [ ] Codex code review: APPROVE
7. [ ] Full gate set green (after code approval), then CI

Items 1–3 verified by the orchestrator on commit `18e53ba`: diff inspected, the name
absent from `src`/`tests`/`benches`, `cargo fmt --check` and `cargo clippy -p atl-cli
--all-targets` clean, `cargo test -p atl-cli --no-fail-fast` green with
`verify::file::tests::test_hash_file_above_former_size_bound ... ok`. Item 4 is the
scope the owner added on 2026-10-16 and is not implemented yet.

---

## Out of Scope

Progress reporting during hashing. The crate has none, so verifying a very large file
is silent until the verdict; on files of this size that becomes noticeable. Separate
task, not this one.

Splitting the two files this task edits that already exceed 500 lines
(`src/cli/args.rs`, 955; `src/verify/single.rs`, 1244). The budget here is the minimal
edit; that debt is older than this task.

---

## Revision History

| Date | Change |
|------|--------|
| 2026-10-16 | Initial draft; owner approved removing the bound outright |
| 2026-10-16 | Code review round 1 returned NO on two defects of the spec text; spec amended |
| 2026-10-16 | Owner widened the scope: the `Path::exists()` defect found during review is fixed in this task, not deferred. An existing path that cannot be reached is reported as a read failure instead of as absence, at all four sites — two for the source, two for the receipt |
