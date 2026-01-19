#![allow(deprecated)]
//! Inspect command tests

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

#[test]
fn test_inspect_basic() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .success()
    .stdout(
        predicate::str::contains("Receipt")
            .or(predicate::str::contains("Entry"))
            .or(predicate::str::contains("Proof")),
    );
}

#[test]
fn test_inspect_contract_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/valid/contract.pdf.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .success();
}

#[test]
fn test_inspect_json() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "inspect",
            test_data_path("receipts/valid/document.pdf.atl")
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
    // Check for entry field
    assert!(json.get("entry").is_some());
}

#[test]
fn test_inspect_json_has_proof() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "inspect",
            test_data_path("receipts/valid/document.pdf.atl")
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
    // Check for proof field
    assert!(json.get("proof").is_some());
}

#[test]
fn test_inspect_not_found() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["inspect", "/nonexistent.atl"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_inspect_malformed_receipt() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/invalid/malformed_json.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("parse").or(predicate::str::contains("JSON")));
}

#[test]
fn test_inspect_missing_fields() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/invalid/missing_fields.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2);
}

#[test]
fn test_inspect_wrong_version() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/invalid/wrong_version.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("version").or(predicate::str::contains("Unsupported")));
}

#[test]
fn test_inspect_with_quiet_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--quiet",
    ])
    .assert()
    .success()
    .stdout(predicate::str::is_empty());
}

#[test]
fn test_inspect_with_no_color() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "inspect",
            test_data_path("receipts/valid/document.pdf.atl")
                .to_str()
                .unwrap(),
            "--no-color",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8(output).unwrap();
    // Should not contain ANSI escape codes
    assert!(!output_str.contains("\x1b["));
}

#[test]
fn test_inspect_tampered_proof() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/invalid/tampered_proof.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .success(); // Inspect should succeed even for invalid proofs
}

#[test]
fn test_inspect_wrong_hash() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "inspect",
        test_data_path("receipts/invalid/wrong_hash.atl")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .success(); // Inspect should succeed, it's just displaying content
}
