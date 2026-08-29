//! The same input must mean the same thing in single-file and batch mode.
//!
//! Both of the last two defects in the batch aggregate had one root cause:
//! an item's status changed meaning when it entered the summary. A receipt
//! that would not parse returned exit 2 as a file and exit 1 as a directory
//! — the batch calling "I could not read this" a *refutation*. A
//! Receipt-Lite reported `pending` as a file and `valid` as a directory —
//! the batch calling "makes no time claim at all" an *acceptance*.
//!
//! Neither was a defect in the checks. Both were the aggregate re-labelling
//! results on their way into the summary, which is exactly the class of
//! defect this crate is built to refuse. These tests pin the two modes
//! together so the next one cannot pass unnoticed.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn real_data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// One source file and its receipt, laid out so the pair can be verified
/// either as two paths or as two directories.
struct Pair {
    _dir: TempDir,
    source: PathBuf,
    receipt: PathBuf,
    source_dir: PathBuf,
    receipt_dir: PathBuf,
}

/// `receipt_bytes` overrides the receipt's contents when given, for the
/// deliberately-unparsable case.
fn pair(source_file: &str, receipt_file: &str, receipt_bytes: Option<&[u8]>) -> Pair {
    let dir = TempDir::new().unwrap();
    let source_dir = dir.path().join("src");
    let receipt_dir = dir.path().join("rcp");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&receipt_dir).unwrap();

    let source = source_dir.join("f.txt");
    let receipt = receipt_dir.join("f.txt.atl");
    std::fs::copy(real_data(source_file), &source).unwrap();
    match receipt_bytes {
        Some(bytes) => std::fs::write(&receipt, bytes).unwrap(),
        None => {
            std::fs::copy(real_data(receipt_file), &receipt).unwrap();
        }
    }

    Pair {
        _dir: dir,
        source,
        receipt,
        source_dir,
        receipt_dir,
    }
}

/// Run a verification and return `(exit_code, status_string)`. `status` is
/// `None` when the run produced no JSON at all (single-file mode bails out
/// with a `CliError` before any result exists).
fn run(
    source: &std::path::Path,
    receipt: &std::path::Path,
    extra: &[&str],
) -> (i32, Option<String>) {
    let mut args = vec![
        "verify".to_string(),
        source.to_string_lossy().into_owned(),
        receipt.to_string_lossy().into_owned(),
        "--offline".to_string(),
        "--json".to_string(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args(&args)
        .output()
        .unwrap();
    let code = output.status.code().unwrap_or(-1);
    let status = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .and_then(|v| v["status"].as_str().map(str::to_string));
    (code, status)
}

fn single(p: &Pair, extra: &[&str]) -> (i32, Option<String>) {
    run(&p.source, &p.receipt, extra)
}

fn batch(p: &Pair, extra: &[&str]) -> (i32, Option<String>) {
    run(&p.source_dir, &p.receipt_dir, extra)
}

/// **Blocker regression.** A receipt that will not parse is an operational
/// failure in both modes — exit 2 — and never "the evidence was refuted".
///
/// CI and retry systems legitimately read 1 as a substantive refutation and
/// 2 as an operational problem. Returning 1 for a file the tool could not
/// even read, and only when invoked on a directory, told them the opposite
/// of the truth depending on the calling convention.
#[test]
fn an_unparsable_receipt_exits_2_in_both_modes() {
    let p = pair(
        "testfile.txt",
        "receipt-tsa.atl",
        Some(b"not a receipt at all"),
    );

    let (single_code, _) = single(&p, &[]);
    let (batch_code, batch_status) = batch(&p, &[]);

    assert_eq!(
        single_code, 2,
        "single mode: an unreadable receipt is a runtime error"
    );
    assert_eq!(
        batch_code, single_code,
        "batch mode must return the same code for the same input, not {batch_code}"
    );
    assert_ne!(
        batch_status.as_deref(),
        Some("invalid"),
        "a receipt the tool could not parse was never refuted"
    );
    assert_eq!(batch_status.as_deref(), Some("error"));
}

/// **Blocker regression.** A Receipt-Lite carries no anchors, so it makes no
/// external-time claim. Both modes must say `pending`; the batch must not
/// promote it to `valid` by folding it into the valid count.
#[test]
fn an_unanchored_receipt_is_pending_in_both_modes() {
    let p = pair("testfile.txt", "receipt-lite.atl", None);

    let (single_code, single_status) = single(&p, &[]);
    let (batch_code, batch_status) = batch(&p, &[]);

    assert_eq!(single_status.as_deref(), Some("pending"));
    assert_eq!(
        batch_status.as_deref(),
        Some("pending"),
        "a batch of unanchored receipts is not an accepted batch"
    );
    assert_ne!(
        batch_status.as_deref(),
        Some("valid"),
        "`valid` means every anchor reached a trust root; this receipt has no anchors"
    );
    // The documented Receipt-Lite decision: exit 0 in both modes.
    assert_eq!(single_code, 0);
    assert_eq!(batch_code, 0);
}

/// The `pending` count must be visible in its own right, not hidden inside
/// `valid`.
#[test]
fn an_unanchored_receipt_is_counted_in_its_own_bucket() {
    let p = pair("testfile.txt", "receipt-lite.atl", None);

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            p.source_dir.to_str().unwrap(),
            p.receipt_dir.to_str().unwrap(),
            "--offline",
            "--json",
        ])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(json["summary"]["pending"], 1);
    assert_eq!(
        json["summary"]["valid"], 0,
        "an unanchored receipt must not be counted as accepted"
    );
    assert_eq!(json["summary"]["total"], 1);
    assert_eq!(json["reason_code"], "batch_items_pending");
}

/// An anchored receipt with no trust material is `untrusted` in both modes,
/// at the same exit code.
#[test]
fn an_untrusted_receipt_agrees_across_modes() {
    let p = pair("testfile.txt", "receipt-tsa.atl", None);

    let (single_code, single_status) = single(&p, &[]);
    let (batch_code, batch_status) = batch(&p, &[]);

    assert_eq!(single_status.as_deref(), Some("untrusted"));
    assert_eq!(batch_status.as_deref(), Some("untrusted"));
    assert_eq!(single_code, 3);
    assert_eq!(batch_code, 3);
}

/// And the case that must keep working: a fully verified receipt is `valid`
/// with exit 0 in both modes. The aggregate fixes must not make success
/// unreachable.
#[test]
fn a_fully_verified_receipt_agrees_across_modes_and_still_succeeds() {
    let p = pair("testfile.txt", "receipt-tsa.atl", None);

    // The trust material this real Sectigo chain needs, from the same
    // fixtures `cli_tsa_intermediates.rs` uses.
    let dir = TempDir::new().unwrap();
    let anchor = dir.path().join("anchor.pem");
    let intermediate = dir.path().join("inter.pem");
    std::fs::write(&anchor, AAA_ROOT_PEM).unwrap();
    std::fs::write(&intermediate, USERTRUST_CROSS_SIGNED_PEM).unwrap();
    let extra = [
        "--tsa-trust-store",
        anchor.to_str().unwrap(),
        "--tsa-intermediates",
        intermediate.to_str().unwrap(),
    ];

    let (single_code, single_status) = single(&p, &extra);
    let (batch_code, batch_status) = batch(&p, &extra);

    assert_eq!(single_status.as_deref(), Some("valid"));
    assert_eq!(batch_status.as_deref(), Some("valid"));
    assert_eq!(
        single_code, 0,
        "success must remain reachable in single mode"
    );
    assert_eq!(batch_code, 0, "success must remain reachable in batch mode");
}

/// "AAA Certificate Services" — the Comodo root this receipt's chain leads
/// to, supplied as caller material exactly as a user would.
const AAA_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow
GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj
YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua
BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe
3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4
YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR
rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm
ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU
oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t
b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF
AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q
GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2
G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----
";

/// "USERTrust RSA Certification Authority", cross-signed by the root above:
/// the intermediate that bridges the gap the token itself does not include.
const USERTRUST_CROSS_SIGNED_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sI
s9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnG
vDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQ
Ijy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfb
IWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0
tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97E
xwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNV
icQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5
D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJ
WBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ
5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzG
KAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSMEGDAWgBSg
EQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rID
ZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAG
BgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t
L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUA
A4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+cli3vA0p+
rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCRlv79Q2R+
/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHxW/BBC5gA
CiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w52z97GA1F
zZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEUxOipakyA
vGp4z7h/jnZymQyd/teRCBaho1+V
-----END CERTIFICATE-----
";
