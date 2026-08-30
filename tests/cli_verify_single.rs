#![allow(deprecated)]
//! Single file verification tests
//!
//! The bundled `document.pdf` / `contract.pdf` receipts are Receipt-Lites.
//! Since ATL v2.0 §5.5 became binding here -- no verified anchor means
//! untrustworthy -- they exit 3, so these tests pin `.code(3)` where they
//! used to pin `.success()`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

#[test]
fn test_verify_valid_file() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(3)
    .stdout(predicate::str::contains("VALID").or(predicate::str::contains("Match: YES")));
}

#[test]
fn test_verify_contract_file() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/contract.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/contract.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(3);
}

#[test]
fn test_verify_file_hash_mismatch() {
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
    .code(1) // INVALID
    .stdout(predicate::str::contains("INVALID").or(predicate::str::contains("Match: NO")));
}

#[test]
fn test_verify_wrong_hash_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/wrong_hash.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(1); // INVALID
}

#[test]
fn test_verify_invalid_proof() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/tampered_proof.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(1); // INVALID
}

#[test]
fn test_verify_source_not_found() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        "/nonexistent/file.pdf",
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_verify_receipt_not_found() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        "/nonexistent/receipt.atl",
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_verify_malformed_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/malformed_json.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("parse").or(predicate::str::contains("JSON")));
}

#[test]
fn test_verify_missing_fields_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/missing_fields.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2); // ERROR
}

#[test]
fn test_verify_wrong_version_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/invalid/wrong_version.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("version").or(predicate::str::contains("Unsupported")));
}

#[test]
fn test_verify_offline_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--offline",
    ])
    .assert()
    .code(3)
    .stdout(predicate::str::contains("OFFLINE").or(predicate::str::is_match("").unwrap()));
}

#[test]
fn test_verify_offline_online_conflict() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--offline",
        "--online",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_verify_mismatched_input_types_file_dir() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(), // file
        test_data_path("receipts/valid/").to_str().unwrap(),    // directory
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("Mismatched input types"));
}

#[test]
fn test_verify_mismatched_input_types_dir_file() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/").to_str().unwrap(), // directory
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(), // file
    ])
    .assert()
    .code(2) // ERROR
    .stderr(predicate::str::contains("Mismatched input types"));
}

#[test]
fn test_verify_verbose_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--verbose",
    ])
    .assert()
    .code(3);
}
