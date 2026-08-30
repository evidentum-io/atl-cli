#![allow(deprecated)]
//! Exit code validation tests

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

/// The bundled `document.pdf` receipt is a Receipt-Lite: sound proofs, no
/// anchors. Since ATL v2.0 §5.5 that is exit 3, not exit 0.
#[test]
fn test_exit_code_3_unanchored_test_fixture() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(3);
}

#[test]
fn test_exit_code_0_help() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("--help").assert().code(0);
}

#[test]
fn test_exit_code_0_version() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("--version").assert().code(0);
}

#[test]
fn test_exit_code_1_invalid_hash() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/modified-document.pdf")
            .to_str()
            .unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(1);
}

#[test]
fn test_exit_code_1_invalid_proof() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/tampered_proof.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(1);
}

#[test]
fn test_exit_code_1_wrong_hash() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/wrong_hash.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(1);
}

#[test]
fn test_exit_code_1_batch_failure() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/partial/files/").to_str().unwrap(),
        test_data_path("batch/partial/receipts/").to_str().unwrap(),
    ])
    .assert()
    .code(1);
}

/// Two receipts from two different log instances are not refuted evidence.
///
/// This directory used to exit 1 — `invalid`, *the evidence was disproved* —
/// because the check took whichever receipt the directory walk yielded first
/// as the log instance every other receipt had to belong to. ATL v2.0 §3.3.2
/// makes `genesis_super_root` the identifier of the log instance, so that
/// identity belongs to the receipt, not to filesystem ordering; and §5.4.3
/// defines what to conclude when two identifiers agree, defining no error
/// for the case where they differ. Nothing about either receipt is false:
/// each is a sound Receipt-Lite that exits 0 on its own, and a *tampered*
/// genesis is caught per receipt as a broken §5.4.2 proof long before this
/// check.
///
/// §5.4.3 is now applied within each log instance, and the batch verdict
/// comes from the receipts themselves: two unanchored ones, so `untrusted`
/// with reason `batch_items_unanchored` (ATL v2.0 §5.5) -- and crucially
/// NOT `invalid`, which would assert the evidence had been disproved.
#[test]
fn receipts_from_two_log_instances_are_reported_not_refuted() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/inconsistent/files/")
            .to_str()
            .unwrap(),
        test_data_path("batch/inconsistent/receipts/")
            .to_str()
            .unwrap(),
        "--json",
    ])
    .assert()
    .code(3)
    .stdout(predicate::str::contains("\"status\": \"untrusted\""))
    .stdout(predicate::str::contains(
        "\"reason_code\": \"batch_items_unanchored\"",
    ))
    .stdout(predicate::str::contains("\"log_instances\": 2"))
    // No pair satisfied §5.4.3 step 2, so no comparison ran -- and a check
    // that never ran must not be reported as one that passed.
    .stdout(predicate::str::contains("\"not_checked\""));
}

/// And the same input verified one file at a time agrees: each receipt on
/// its own is `untrusted`, exit 3. The two modes must not disagree.
#[test]
fn each_receipt_of_a_two_log_instance_batch_is_untrusted_on_its_own() {
    for name in ["file-a.pdf", "file-b.pdf"] {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        cmd.args([
            "verify",
            test_data_path(&format!("batch/inconsistent/files/{name}"))
                .to_str()
                .unwrap(),
            test_data_path(&format!("batch/inconsistent/receipts/{name}.atl"))
                .to_str()
                .unwrap(),
            "--json",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("\"status\": \"untrusted\""))
        .stdout(predicate::str::contains(
            "\"reason_code\": \"receipt_unanchored\"",
        ));
    }
}

#[test]
fn test_exit_code_2_file_not_found() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        "/nonexistent/file.pdf",
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2);
}

#[test]
fn test_exit_code_2_receipt_not_found() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        "/nonexistent/receipt.atl",
    ])
    .assert()
    .code(2);
}

#[test]
fn test_exit_code_2_parse_error() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/malformed_json.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2);
}

#[test]
fn test_exit_code_2_missing_fields() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/missing_fields.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2);
}

#[test]
fn test_exit_code_2_wrong_version() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/wrong_version.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2);
}

#[test]
fn test_exit_code_2_mismatched_types() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(), // file
        test_data_path("receipts/valid/").to_str().unwrap(),    // directory
    ])
    .assert()
    .code(2);
}

#[test]
fn test_exit_code_2_inspect_not_found() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["inspect", "/nonexistent.atl"]).assert().code(2);
}

// ============================================================================
// Exit code 3: UNTRUSTED
// ============================================================================
//
// Exit 3 exists so a caller can distinguish "this evidence is broken" (1)
// from "bring me the trust root" (3) without parsing JSON. `real-data/
// receipt-tsa.atl` is a genuine Sectigo-anchored receipt whose chain is
// cryptographically sound but ends at a certificate the token does not carry
// the issuer for -- exactly the second case.

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

#[test]
fn test_exit_code_3_untrusted_single() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        real_data_path("testfile.txt").to_str().unwrap(),
        real_data_path("receipt-tsa.atl").to_str().unwrap(),
    ])
    .assert()
    .code(3);
}

/// The exit code is the whole point in `--quiet` mode: no output, but a
/// caller must still be able to tell untrusted from invalid.
#[test]
fn test_exit_code_3_untrusted_quiet() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        real_data_path("testfile.txt").to_str().unwrap(),
        real_data_path("receipt-tsa.atl").to_str().unwrap(),
        "--quiet",
    ])
    .assert()
    .code(3)
    .stdout("")
    .stderr("");
}

/// A refuted receipt still exits 1, not 3 -- the two states must not be
/// collapsed back together from either direction.
#[test]
fn test_exit_code_1_still_used_for_refuted_evidence() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/modified-document.pdf")
            .to_str()
            .unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--quiet",
    ])
    .assert()
    .code(1);
}

/// **ATL v2.0 §5.5.** An unanchored (Receipt-Lite) receipt has no verified
/// anchor, and "a receipt without any verified anchors SHOULD be treated as
/// untrustworthy". It is `untrusted`, exit 3 — not the historical exit 0,
/// which accepted precisely what §5.5 says to refuse.
#[test]
fn test_exit_code_3_unanchored_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        real_data_path("testfile.txt").to_str().unwrap(),
        real_data_path("receipt-lite.atl").to_str().unwrap(),
        "--quiet",
    ])
    .assert()
    .code(3);
}

/// And relaxing the anchor quorum does not change it: a quorum of one
/// verified anchor cannot be met by a receipt that presents none.
#[test]
fn allow_single_anchor_does_not_rescue_an_unanchored_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        real_data_path("testfile.txt").to_str().unwrap(),
        real_data_path("receipt-lite.atl").to_str().unwrap(),
        "--allow-single-anchor",
        "--json",
    ])
    .assert()
    .code(3)
    .stdout(predicate::str::contains("\"status\": \"untrusted\""))
    .stdout(predicate::str::contains(
        "\"reason_code\": \"receipt_unanchored\"",
    ));
}

/// **The rule that is not policy-dependent.** One refuted fact makes the
/// receipt `invalid` (exit 1) however lenient the anchor quorum is, and
/// however many other anchors are trusted.
///
/// The fixture is a real Receipt-Full whose RFC 3161 anchor has been repointed
/// at a hash that is not this receipt's Data Tree root: ATL v2.0 §5.5.1 step 2
/// ("verify that anchor.target_hash equals proof.root_hash") is checked and
/// false, so the token attests to some *other* data.
#[test]
fn a_refuted_anchor_is_invalid_under_every_anchor_policy() {
    let dir = tempfile::TempDir::new().unwrap();
    let source = real_data_path("testfile.txt");
    let receipt_path = dir.path().join("tampered.atl");

    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data_path("receipt-full.atl")).unwrap())
            .unwrap();
    for anchor in receipt["anchors"].as_array_mut().unwrap() {
        if anchor["type"] == "rfc3161" {
            anchor["target_hash"] =
                serde_json::Value::String(format!("sha256:{}", "ab".repeat(32)));
        }
    }
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        cmd.args([
            "verify",
            source.to_str().unwrap(),
            receipt_path.to_str().unwrap(),
            "--offline",
            "--json",
        ])
        .args(extra)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"status\": \"invalid\""))
        .stdout(predicate::str::contains(
            "\"reason_code\": \"anchor_target_hash_mismatch\"",
        ));
    }
}
