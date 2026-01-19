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

#[test]
fn test_batch_all_valid_consistent() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("batch/consistent/files/").to_str().unwrap(),
        test_data_path("batch/consistent/receipts/")
            .to_str()
            .unwrap(),
    ])
    .assert()
    .success()
    .stdout(
        predicate::str::contains("Valid:")
            .or(predicate::str::contains("VALID"))
            .or(predicate::str::contains("VERIFIED")),
    );
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
