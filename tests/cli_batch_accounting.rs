//! Every file the caller names must land in the batch accounting.
//!
//! The batch aggregate produced four defects of one family, all of them
//! "reported more than was verified": a directory entry that could not be
//! read vanished from every bucket, two different non-UTF-8 filenames
//! collapsed onto one match key, and a successful `pending` run handed back a
//! populated `errors` array. These tests pin the corrected behaviour.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// A batch directory holding one genuine unanchored (Receipt-Lite) pair.
fn lite_batch() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("s")).unwrap();
    std::fs::create_dir(dir.path().join("r")).unwrap();
    std::fs::copy(
        real_data_path("testfile.txt"),
        dir.path().join("s").join("testfile.txt"),
    )
    .unwrap();
    std::fs::copy(
        real_data_path("receipt-lite.atl"),
        dir.path().join("r").join("testfile.txt.atl"),
    )
    .unwrap();
    dir
}

fn run(dir: &TempDir) -> (i32, serde_json::Value) {
    let s = dir.path().join("s").to_str().unwrap().to_string();
    let r = dir.path().join("r").to_str().unwrap().to_string();
    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args(["--json", "verify", s.as_str(), r.as_str()])
        .assert()
        .get_output()
        .clone();
    let code = output.status.code().unwrap();
    let json = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    (code, json)
}

#[test]
fn a_successful_pending_batch_reports_no_errors() {
    let dir = lite_batch();
    let (code, json) = run(&dir);

    // A run that exits 0 must not simultaneously hand a machine consumer a
    // populated `errors` array -- that contract cannot be acted on.
    assert_eq!(code, 0, "an unanchored batch is a documented success");
    assert_eq!(json["status"], "pending");
    assert_eq!(
        json["errors"].as_array().map(Vec::len),
        Some(0),
        "exit 0 must not carry errors: {}",
        json["errors"]
    );
    assert_eq!(json["summary"]["errors"], 0);
    for item in json["items"].as_array().unwrap() {
        assert!(
            item["error"].is_null(),
            "a pending item is not an errored item: {item}"
        );
        assert_eq!(item["status"], "pending");
    }
}

#[test]
fn an_unreadable_entry_is_never_silently_dropped() {
    let dir = lite_batch();
    // A dangling symlink is an entry the caller placed in the directory and
    // that we cannot check. Skipping it would remove it from `total`, so a
    // batch could report success having never looked at it.
    #[cfg(unix)]
    std::os::unix::fs::symlink("/nonexistent/target", dir.path().join("s").join("ghost")).unwrap();

    #[cfg(unix)]
    {
        let (code, _json) = run(&dir);
        assert_eq!(
            code, 2,
            "an entry we cannot resolve must fail loudly, not vanish"
        );
    }
}

// Linux only, and not out of laziness: APFS enforces valid UTF-8 in
// filenames, so macOS returns EILSEQ when the fixture is created and the
// scenario cannot exist there. On Linux such names are legal, which is
// exactly where lossy keying would bite.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_names_do_not_collapse_onto_one_match_key() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("s")).unwrap();
    std::fs::create_dir(dir.path().join("r")).unwrap();

    // Two names differing only in bytes that `to_string_lossy` maps to the
    // same U+FFFD. Under lossy keying these become one key, so one receipt
    // would match a file that is not its own.
    let a = OsString::from_vec(b"file\xff.bin".to_vec());
    let b = OsString::from_vec(b"file\xfe.bin".to_vec());

    std::fs::copy(
        real_data_path("testfile.txt"),
        dir.path().join("s").join(&a),
    )
    .unwrap();
    std::fs::copy(
        real_data_path("testfile.txt"),
        dir.path().join("s").join(&b),
    )
    .unwrap();

    // Only `a` gets a receipt; `b` must therefore be reported unmatched.
    let mut receipt_name = a.clone();
    receipt_name.push(".atl");
    std::fs::copy(
        real_data_path("receipt-lite.atl"),
        dir.path().join("r").join(&receipt_name),
    )
    .unwrap();

    let (code, json) = run(&dir);
    assert_eq!(
        json["summary"]["unmatched"], 1,
        "the file whose exact pair is absent must be unmatched: {json}"
    );
    assert_eq!(json["status"], "untrusted");
    assert_eq!(code, 3);
}
