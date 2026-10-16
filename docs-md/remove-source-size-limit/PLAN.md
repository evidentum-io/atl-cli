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
| — | — | — | not started |

---

## Definition of Done

1. [ ] `MAX_SOURCE_FILE_SIZE` and its gate are gone; the name is referenced nowhere
2. [ ] A file one byte above the former bound hashes successfully (AC1)
3. [ ] `CliError::FileTooLarge`, its exit code and the 10 MiB receipt bound are unchanged
4. [ ] `cargo test -p atl-cli --no-fail-fast`, `cargo fmt --check`, `cargo clippy -p atl-cli` clean
5. [ ] Codex code review: APPROVE
6. [ ] Full gate set green (after code approval), then CI

---

## Out of Scope

Progress reporting during hashing. The crate has none, so verifying a very large file
is silent until the verdict; on files of this size that becomes noticeable. Separate
task, not this one.

---

## Revision History

| Date | Change |
|------|--------|
| 2026-10-16 | Initial draft; owner approved removing the bound outright |
