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
    run_with(dir, &[])
}

fn run_with(dir: &TempDir, extra: &[&str]) -> (i32, serde_json::Value) {
    let s = dir.path().join("s").to_str().unwrap().to_string();
    let r = dir.path().join("r").to_str().unwrap().to_string();
    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args(["--json", "verify", s.as_str(), r.as_str()])
        .args(extra)
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
    assert_eq!(json["reason_code"], "batch_items_untrusted");
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

/// **The same defect one storey up: a batch's reason must not depend on one
/// item's anchor array.**
///
/// `batch_items_unanchored` used to be reported ahead of
/// `batch_items_untrusted` whenever any item presented no anchors. Bucket
/// membership is decided by that item's `anchors` array, which is signed and
/// hashed by nothing — so appending one rubbish anchor to one Receipt-Lite
/// in the directory changed what the whole BATCH said its reason was.
///
/// The batch reason is now a function of what was verified, and both buckets
/// verified nothing. The `unanchored` summary count still moves, because it
/// describes the documents that arrived and is exactly where the appended
/// anchor must show up.
#[test]
fn appending_an_anchor_to_one_item_does_not_move_the_batch_reason() {
    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let clean = lite_batch();
        let (clean_code, clean_json) = run_with(&clean, extra);

        let tampered = lite_batch();
        let receipt = tampered.path().join("r").join("testfile.txt.atl");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        value["anchors"] = serde_json::json!([{
            "type": "rfc3161",
            "target": "data_tree_root",
            "target_hash": format!("sha256:{}", "ab".repeat(32)),
            "tsa_url": "https://example.invalid/tsa",
            "timestamp": "2024-01-01T00:00:00Z",
            "token_der": "base64:bm90YXRva2Vu"
        }]);
        std::fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
        let (code, json) = run_with(&tampered, extra);

        assert_eq!(code, clean_code, "{extra:?}\n{clean_json}\n{json}");
        assert_eq!(json["status"], clean_json["status"], "{extra:?}");
        assert_eq!(
            json["reason_code"], clean_json["reason_code"],
            "appending to one item moved the batch's reason ({extra:?})\n\
             clean: {clean_json}\ntampered: {json}"
        );
        assert_eq!(json["reason_code"], "batch_items_untrusted", "{json}");
        assert_eq!(json["summary"]["total"], clean_json["summary"]["total"]);
        assert_eq!(json["summary"]["valid"], 0, "{json}");
        assert_eq!(json["summary"]["invalid"], 0, "{json}");

        // The appended anchor is not concealed: the item moves between the
        // two descriptive buckets, and that is where it must be visible.
        assert_eq!(clean_json["summary"]["unanchored"], 1, "{clean_json}");
        assert_eq!(json["summary"]["unanchored"], 0, "{json}");
        assert_eq!(json["summary"]["untrusted"], 1, "{json}");
        // The item's own reason is the same either way, for the same reason
        // the batch's is.
        assert_eq!(
            json["items"][0]["reason_code"], "receipt_unanchored",
            "{json}"
        );
    }
}
