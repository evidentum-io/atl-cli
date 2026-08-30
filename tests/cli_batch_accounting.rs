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

/// ATL v2.0 §5.5: a batch of Receipt-Lites has no verified anchor anywhere,
/// so it is untrusted (exit 3), not a success. What it is NOT is an
/// operational failure: nothing failed to be processed, and `summary.errors`
/// stays zero.
#[test]
fn an_unanchored_batch_is_untrusted_but_not_an_operational_failure() {
    let dir = lite_batch();
    let (code, json) = run(&dir);

    assert_eq!(code, 3, "no verified anchor anywhere: {json}");
    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "batch_items_unanchored");
    assert_eq!(
        json["summary"]["errors"], 0,
        "an unanchored receipt was processed fine; it simply has no anchor"
    );
    assert_eq!(json["summary"]["unanchored"], 1, "{json}");
    assert_eq!(json["summary"]["valid"], 0);
    for item in json["items"].as_array().unwrap() {
        assert_eq!(item["status"], "untrusted", "{item}");
        assert_eq!(item["reason_code"], "receipt_unanchored", "{item}");
    }
}

#[cfg(unix)]
#[test]
fn an_unreadable_entry_is_never_silently_dropped() {
    let dir = lite_batch();
    // A dangling symlink is an entry the caller placed in the directory and
    // that we cannot check. Skipping it would remove it from `total`, so a
    // batch could report success having never looked at it.
    std::os::unix::fs::symlink("/nonexistent/target", dir.path().join("s").join("ghost")).unwrap();

    let (code, json) = run(&dir);
    assert_eq!(
        code, 2,
        "an entry we cannot resolve must fail loudly, not vanish"
    );
    // Loudly, but not fatally: aborting the walk threw away every other
    // file in the directory, so an entry we could not stat suppressed
    // findings about the ones we could. It gets a row of its own, and its
    // readable neighbour is still verified.
    assert_eq!(json["summary"]["errors"], 1, "{json}");
    assert_eq!(json["summary"]["unanchored"], 1, "{json}");
    assert_eq!(json["summary"]["total"], 2, "{json}");
    let ghost = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["file"] == "ghost")
        .expect("the entry we could not read must appear in the report");
    assert_eq!(ghost["status"], "error");
    assert!(ghost["error"].is_string(), "{ghost}");
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
