#![allow(deprecated)]
//! Exit code validation tests

use assert_cmd::Command;
use std::path::PathBuf;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

#[test]
fn test_exit_code_0_valid() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(0);
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

#[test]
fn test_exit_code_1_consistency_failure() {
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
    .code(1);
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

/// An unanchored (Receipt-Lite) receipt keeps its historical exit code 0.
#[test]
fn test_exit_code_0_unanchored_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        real_data_path("testfile.txt").to_str().unwrap(),
        real_data_path("receipt-lite.atl").to_str().unwrap(),
        "--quiet",
    ])
    .assert()
    .code(0);
}
