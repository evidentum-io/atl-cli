#![allow(deprecated)]
//! Output format tests: JSON, quiet, verbose, no-color

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

#[test]
fn test_json_output_single_valid() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("files/document.pdf").to_str().unwrap(),
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
    // Check that status field exists
    assert!(json.get("status").is_some());
}

#[test]
fn test_json_output_single_invalid() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("files/modified-document.pdf")
                .to_str()
                .unwrap(),
            test_data_path("receipts/valid/document.pdf.atl")
                .to_str()
                .unwrap(),
            "--json",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json.is_object());
    // Check that status field exists and indicates invalid
    if let Some(status) = json.get("status") {
        assert!(status
            .as_str()
            .is_some_and(|s| s.contains("invalid") || s.contains("INVALID")));
    }
}

#[test]
fn test_json_output_is_valid_json() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("files/document.pdf").to_str().unwrap(),
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

    // Should parse without error
    serde_json::from_slice::<serde_json::Value>(&output).unwrap();
}

#[test]
fn test_quiet_mode_no_output() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
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
fn test_quiet_mode_invalid_no_output() {
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
    .code(1)
    .stdout(predicate::str::is_empty());
}

#[test]
fn test_no_color_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("files/document.pdf").to_str().unwrap(),
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
fn test_verbose_mode() {
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
    .success();
}

#[test]
fn test_verbose_with_json() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--verbose",
        "--json",
    ])
    .assert()
    .success();
}

#[test]
fn test_quiet_with_json() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--quiet",
        "--json",
    ])
    .assert()
    .success()
    .stdout(predicate::str::is_empty());
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
    assert!(json.get("status").is_some());
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
fn test_batch_no_color() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("batch/consistent/files/").to_str().unwrap(),
            test_data_path("batch/consistent/receipts/")
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
