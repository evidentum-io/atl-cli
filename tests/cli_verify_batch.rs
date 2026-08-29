#![allow(deprecated)]
//! Batch verification tests

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

/// The consistent fixture is three Receipt-Lites from one log: every proof
/// checks out and every item is `pending`, because none carries an anchor.
///
/// The name says "all valid" for historical reasons and the loose `VALID`
/// predicate used to pass by accident, when `pending` items were folded into
/// the valid count. They are not, so this asserts what the fixture actually
/// is: exit 0 (the documented Receipt-Lite decision) with a `pending` status,
/// never `valid`.
#[test]
fn test_batch_all_pending_consistent() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("batch/consistent/files/").to_str().unwrap(),
            test_data_path("batch/consistent/receipts/")
                .to_str()
                .unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "pending");
    assert_ne!(
        json["status"], "valid",
        "receipts with no anchors make no external-time claim"
    );
    assert_eq!(json["summary"]["pending"], 3);
    assert_eq!(json["summary"]["valid"], 0);
    // Cross-receipt consistency still holds for them.
    assert_eq!(json["consistency"]["status"], "verified");
}

#[test]
fn test_batch_inconsistent_logs() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/inconsistent/files/")
            .to_str()
            .unwrap(),
        test_data_path("batch/inconsistent/receipts/")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(1) // INVALID - consistency failed
    .stdout(
        predicate::str::contains("FAILED")
            .or(predicate::str::contains("different"))
            .or(predicate::str::contains("inconsistent")),
    );
}

#[test]
fn test_batch_partial_failures() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/partial/files/").to_str().unwrap(),
        test_data_path("batch/partial/receipts/").to_str().unwrap(),
    ])
    .assert()
    .code(1); // INVALID
}

#[test]
fn test_batch_empty_source_directory() {
    let tmp = TempDir::new().unwrap();
    let receipts_dir = test_data_path("batch/consistent/receipts/");

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        tmp.path().to_str().unwrap(),
        receipts_dir.to_str().unwrap(),
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("No files found").or(predicate::str::contains("empty")));
}

#[test]
fn test_batch_empty_receipt_directory() {
    let tmp = TempDir::new().unwrap();
    let source_dir = test_data_path("batch/consistent/files/");

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        source_dir.to_str().unwrap(),
        tmp.path().to_str().unwrap(),
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("No receipts found").or(predicate::str::contains("empty")));
}

#[test]
fn test_batch_json_output() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("batch/consistent/files/").to_str().unwrap(),
            test_data_path("batch/consistent/receipts/")
                .to_str()
                .unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json.is_object());
    // Check that status field exists
    assert!(json.get("status").is_some());
}

#[test]
fn test_batch_with_unmatched_files() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/partial/files/").to_str().unwrap(),
        test_data_path("batch/partial/receipts/").to_str().unwrap(),
    ])
    .assert()
    .code(1);
}

#[test]
fn test_batch_json_has_items() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("batch/consistent/files/").to_str().unwrap(),
            test_data_path("batch/consistent/receipts/")
                .to_str()
                .unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    // Check that items array exists
    if let Some(items) = json.get("items") {
        assert!(items.is_array());
    }
}

#[test]
fn test_batch_json_has_summary() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("batch/consistent/files/").to_str().unwrap(),
            test_data_path("batch/consistent/receipts/")
                .to_str()
                .unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    // Check that summary exists
    if let Some(summary) = json.get("summary") {
        assert!(summary.is_object());
    }
}

#[test]
fn test_batch_quiet_mode() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/consistent/files/").to_str().unwrap(),
        test_data_path("batch/consistent/receipts/")
            .to_str()
            .unwrap(),
        "--quiet",
    ])
    .assert()
    .success()
    .stdout(predicate::str::is_empty());
}

#[test]
fn test_batch_with_offline_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/consistent/files/").to_str().unwrap(),
        test_data_path("batch/consistent/receipts/")
            .to_str()
            .unwrap(),
        "--offline",
    ])
    .assert()
    .success();
}

#[test]
fn test_batch_verbose_mode() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/consistent/files/").to_str().unwrap(),
        test_data_path("batch/consistent/receipts/")
            .to_str()
            .unwrap(),
        "--verbose",
    ])
    .assert()
    .success();
}

// ---------------------------------------------------------------------
// Nothing verified must never be a success
// ---------------------------------------------------------------------
//
// Batch mode pairs `<name>` with `<name>.atl`. When the naming does not
// follow that convention every file lands in `unmatched`, and the aggregate
// verdict used to ignore that bucket entirely: zero files verified,
// `status: "valid"`, exit code 0. A CI job whose filenames had drifted went
// green while checking nothing — the worst possible failure of a tool whose
// whole promise is that it never claims more than it checked.

fn real_data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// Build a source dir and a receipt dir, returning both paths. Each entry is
/// `(filename_in_dir, real_data_file_to_copy)`.
fn dirs(sources: &[(&str, &str)], receipts: &[(&str, &str)]) -> (TempDir, PathBuf, PathBuf) {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    let rcp = dir.path().join("rcp");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&rcp).unwrap();
    for (name, from) in sources {
        std::fs::copy(real_data(from), src.join(name)).unwrap();
    }
    for (name, from) in receipts {
        std::fs::copy(real_data(from), rcp.join(name)).unwrap();
    }
    (dir, src, rcp)
}

fn batch_json(
    src: &std::path::Path,
    rcp: &std::path::Path,
    expected_code: i32,
) -> serde_json::Value {
    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            src.to_str().unwrap(),
            rcp.to_str().unwrap(),
            "--offline",
            "--json",
        ])
        .assert()
        .code(expected_code)
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

/// **The regression.** No file pairs up, so nothing is verified at all. The
/// batch must not be `valid` and must not exit 0.
#[test]
fn a_batch_where_nothing_matched_is_never_valid() {
    // `X.payload` does not pair with `X.atl` -- the convention is `X`/`X.atl`.
    let (_dir, src, rcp) = dirs(
        &[
            ("X.payload", "testfile.txt"),
            ("Y.payload", "testfile2.txt"),
        ],
        &[("X.atl", "receipt-tsa.atl"), ("Y.atl", "receipt2-tsa.atl")],
    );

    let json = batch_json(&src, &rcp, 3);

    assert_ne!(
        json["status"], "valid",
        "zero files verified must never be reported as valid: {json}"
    );
    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "batch_items_unmatched");
    assert_eq!(json["summary"]["valid"], 0);
    assert_eq!(json["summary"]["unmatched"], 4);
    // The total must account for every named path, in both directions.
    assert_eq!(json["summary"]["total"], 4);
}

/// A mix: one pair that verifies as far as it can, plus one source file with
/// no receipt. The unverified file must still reach the aggregate verdict.
#[test]
fn one_unmatched_file_blocks_an_otherwise_complete_batch() {
    let (_dir, src, rcp) = dirs(
        &[
            ("testfile.txt", "testfile.txt"),
            ("orphan.txt", "testfile2.txt"),
        ],
        &[("testfile.txt.atl", "receipt-tsa.atl")],
    );

    let json = batch_json(&src, &rcp, 3);

    assert_ne!(json["status"], "valid");
    assert_eq!(json["reason_code"], "batch_items_unmatched");
    assert_eq!(json["summary"]["unmatched"], 1);
    assert_eq!(json["summary"]["total"], 2);
}

/// Every file failing to be read is not a success — and it is reported as an
/// item that could not be *processed*, at the operational exit code, not as
/// an item whose evidence was refuted (`invalid` is 0 in the very same
/// summary).
#[test]
#[cfg(unix)]
fn a_batch_where_every_file_errored_is_never_valid() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, src, rcp) = dirs(
        &[("testfile.txt", "testfile.txt")],
        &[("testfile.txt.atl", "receipt-tsa.atl")],
    );
    let unreadable = src.join("testfile.txt");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            src.to_str().unwrap(),
            rcp.to_str().unwrap(),
            "--offline",
            "--json",
        ])
        .assert()
        // Exit 2, exactly as single-file mode returns for the same input --
        // an operational failure, not a refutation.
        .code(2)
        .get_output()
        .stdout
        .clone();

    // Restore permissions before asserting, so a failure cannot leave an
    // unreadable file behind in the temp dir.
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_ne!(json["status"], "valid");
    assert_ne!(
        json["status"], "invalid",
        "a file this tool could not open must not be called refuted evidence"
    );
    assert_eq!(json["status"], "error");
    assert_eq!(json["summary"]["valid"], 0);
    assert_eq!(json["summary"]["errors"], 1);
    assert_eq!(
        json["reason_code"], "batch_items_errored",
        "the reason must name the bucket that actually fired; `invalid` is 0 here"
    );
}

/// The human output must not blame missing trust material for what is a
/// filename-pairing problem — no certificate would help.
#[test]
fn human_output_for_unmatched_files_does_not_ask_for_trust_material() {
    let (_dir, src, rcp) = dirs(
        &[("X.payload", "testfile.txt")],
        &[("X.atl", "receipt-tsa.atl")],
    );

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            src.to_str().unwrap(),
            rcp.to_str().unwrap(),
            "--offline",
            "--no-color",
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let human = String::from_utf8(output).unwrap();
    assert!(
        !human.contains("trust root unavailable"),
        "an unmatched-files batch is not a missing-trust-root problem: {human}"
    );
    assert!(
        !human.contains("--tsa-trust-store"),
        "and no certificate would help: {human}"
    );
    assert!(
        human.contains("never checked") || human.contains("never verified"),
        "the output must say the files were not checked: {human}"
    );
}

/// The summary counts and the item rows must agree.
///
/// They are maintained separately — the buckets are incremented as items are
/// classified, the rows render each item's own verdict — so nothing but a
/// test stops them drifting. Every defect found in this aggregate so far was
/// exactly such a drift: a bucket that said something the item did not.
#[test]
fn summary_counts_match_the_item_rows() {
    // The consistent fixture is three Receipt-Lites from one log; adding an
    // unmatched file gives a mixture of two buckets plus a total to check.
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    let rcp = dir.path().join("rcp");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&rcp).unwrap();
    for name in ["doc1.pdf", "doc2.pdf", "doc3.pdf"] {
        std::fs::copy(
            test_data_path(&format!("batch/consistent/files/{name}")),
            src.join(name),
        )
        .unwrap();
        std::fs::copy(
            test_data_path(&format!("batch/consistent/receipts/{name}.atl")),
            rcp.join(format!("{name}.atl")),
        )
        .unwrap();
    }
    std::fs::write(src.join("orphan.txt"), b"no receipt for this").unwrap();

    let json = batch_json(&src, &rcp, 3);
    let summary = &json["summary"];
    let items = json["items"].as_array().expect("items array");

    let count_of = |status: &str| items.iter().filter(|i| i["status"] == status).count();

    assert_eq!(summary["valid"], count_of("valid"));
    assert_eq!(summary["pending"], count_of("pending"));
    assert_eq!(summary["untrusted"], count_of("untrusted"));
    assert_eq!(summary["invalid"], count_of("invalid"));
    assert_eq!(
        summary["unmatched"],
        count_of("no_receipt") + count_of("no_source")
    );
    assert_eq!(
        summary["total"].as_u64().unwrap() as usize,
        items.len(),
        "the total must equal the number of rows beneath it"
    );

    // And the specific mixture this fixture builds: unanchored receipts get
    // their own bucket and are never counted as accepted.
    assert_eq!(summary["pending"], 3);
    assert_eq!(summary["valid"], 0);
    assert_eq!(summary["unmatched"], 1);
    assert_eq!(json["reason_code"], "batch_items_unmatched");
}
