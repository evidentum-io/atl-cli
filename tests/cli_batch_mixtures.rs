//! What a batch does when its items disagree with each other.
//!
//! The aggregate's whole job is ordering: a refutation must outrank every
//! inability, an inability must never be reported as a refutation, and a run
//! in which everything was checked and accepted must still be able to
//! succeed. Each test here builds a directory pair holding a deliberate
//! mixture and pins the resulting status and exit code.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// A source/receipt directory pair being assembled item by item.
struct Batch {
    dir: TempDir,
    trust: Option<(PathBuf, PathBuf)>,
    allow_single_anchor: bool,
}

impl Batch {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("s")).unwrap();
        std::fs::create_dir(dir.path().join("r")).unwrap();
        Self {
            dir,
            trust: None,
            allow_single_anchor: false,
        }
    }

    /// Lower the anchor quorum to the ATL v2.0 §5.5 floor.
    const fn allow_single_anchor(mut self) -> Self {
        self.allow_single_anchor = true;
        self
    }

    /// Copy `source` under `name`, and `receipt` under `name.atl`.
    fn pair(self, name: &str, source: &str, receipt: &str) -> Self {
        std::fs::copy(real_data_path(source), self.dir.path().join("s").join(name)).unwrap();
        std::fs::copy(
            real_data_path(receipt),
            self.dir.path().join("r").join(format!("{name}.atl")),
        )
        .unwrap();
        self
    }

    /// An accepted item: a real Sectigo-anchored receipt plus the caller
    /// material its chain needs.
    fn valid_item(mut self, name: &str) -> Self {
        let anchor = self.dir.path().join("anchor.pem");
        let intermediate = self.dir.path().join("inter.pem");
        std::fs::write(&anchor, AAA_ROOT_PEM).unwrap();
        std::fs::write(&intermediate, USERTRUST_CROSS_SIGNED_PEM).unwrap();
        self.trust = Some((anchor, intermediate));
        self.pair(name, "testfile.txt", "receipt-tsa.atl")
    }

    /// An unanchored item: sound proofs, no anchor at all, so no verified
    /// anchor and no external-time claim (ATL v2.0 §5.5).
    fn unanchored_item(self, name: &str) -> Self {
        self.pair(name, "testfile.txt", "receipt-lite.atl")
    }

    /// An item nothing refutes and nothing finishes: its `bitcoin_ots`
    /// anchor needs a block this offline run never fetched, so it stays
    /// `untrusted` whatever TSA trust material is supplied.
    fn untrusted_item(self, name: &str) -> Self {
        self.pair(name, "testfile.txt", "receipt-full.atl")
    }

    /// A refuted item: the receipt attests to a different file.
    fn invalid_item(self, name: &str) -> Self {
        self.pair(name, "testfile.txt", "receipt2-lite.atl")
    }

    /// A source file whose receipt is absent.
    fn unmatched_item(self, name: &str) -> Self {
        std::fs::copy(
            real_data_path("testfile.txt"),
            self.dir.path().join("s").join(name),
        )
        .unwrap();
        self
    }

    /// An entry that cannot be resolved at all.
    #[cfg(unix)]
    fn unreadable_item(self, name: &str) -> Self {
        std::os::unix::fs::symlink("/nonexistent/target", self.dir.path().join("s").join(name))
            .unwrap();
        self
    }

    fn run(&self) -> (i32, serde_json::Value) {
        let source = self.dir.path().join("s");
        let receipt = self.dir.path().join("r");
        let mut args = vec![
            "--json".to_string(),
            "verify".to_string(),
            source.to_string_lossy().into_owned(),
            receipt.to_string_lossy().into_owned(),
            "--offline".to_string(),
        ];
        if let Some((anchor, intermediate)) = &self.trust {
            args.push("--tsa-trust-store".to_string());
            args.push(anchor.to_string_lossy().into_owned());
            args.push("--tsa-intermediates".to_string());
            args.push(intermediate.to_string_lossy().into_owned());
        }
        if self.allow_single_anchor {
            args.push("--allow-single-anchor".to_string());
        }

        let output = Command::cargo_bin("atl-cli")
            .unwrap()
            .args(&args)
            .assert()
            .get_output()
            .clone();
        let code = output.status.code().unwrap();
        let json = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
        (code, json)
    }
}

/// Success must stay reachable. Every other test here checks that some
/// mixture is *refused*; without this one, "refuse everything" would pass
/// them all.
#[test]
fn a_fully_accepted_batch_still_exits_zero() {
    let (code, json) = Batch::new().valid_item("a.txt").run();
    assert_eq!(json["status"], "valid", "{json}");
    assert_eq!(code, 0);
    assert_eq!(json["summary"]["valid"], 1);
    assert_eq!(json["summary"]["total"], 1);
    assert_eq!(json["errors"].as_array().map(Vec::len), Some(0));
}

/// **The §5.5 change, in a mixture.** One receipt with no anchors at all
/// keeps the whole batch out of `valid` AND out of exit 0: the batch
/// contains a receipt with no verified anchor, which §5.5 says to treat as
/// untrustworthy. This used to exit 0 under the word `pending`.
#[test]
fn an_unanchored_item_beside_a_valid_one_is_untrusted() {
    let (code, json) = Batch::new()
        .valid_item("a.txt")
        .unanchored_item("b.txt")
        .run();
    assert_eq!(json["status"], "untrusted", "{json}");
    assert_eq!(json["reason_code"], "batch_items_unanchored");
    assert_eq!(code, 3, "not 0: one receipt has no verified anchor");
    assert_eq!(json["summary"]["valid"], 1);
    assert_eq!(json["summary"]["unanchored"], 1);
    assert_eq!(json["summary"]["total"], 2);
}

/// Relaxing the quorum does not rescue an unanchored receipt: a quorum of
/// one cannot be met by none.
#[test]
fn allow_single_anchor_does_not_accept_an_unanchored_item() {
    let (code, json) = Batch::new()
        .allow_single_anchor()
        .unanchored_item("a.txt")
        .run();
    assert_eq!(json["status"], "untrusted", "{json}");
    assert_eq!(json["reason_code"], "batch_items_unanchored");
    assert_eq!(code, 3);
    assert_eq!(json["policy_profile"], "single-anchor");
}

/// A Receipt-Full verified offline: its TSA anchor reaches a supplied root,
/// its Bitcoin anchor was never confirmed. Under the default quorum the
/// batch is untrusted; under `--allow-single-anchor` it is accepted, and the
/// unresolved anchor is still reported on the item's coverage axis.
#[test]
fn a_partly_resolved_item_flips_on_the_quorum() {
    let strict = Batch::new().valid_item("a.txt").untrusted_item("b.txt");
    let (code, json) = strict.run();
    assert_eq!(json["status"], "untrusted", "{json}");
    assert_eq!(json["reason_code"], "batch_items_untrusted");
    assert_eq!(code, 3);
    assert_eq!(json["policy_profile"], "all-anchors");

    let relaxed = Batch::new()
        .allow_single_anchor()
        .valid_item("a.txt")
        .untrusted_item("b.txt");
    let (code, json) = relaxed.run();
    assert_eq!(json["status"], "valid", "{json}");
    assert_eq!(code, 0);
    assert_eq!(json["policy_profile"], "single-anchor");

    let full = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["file"] == "b.txt")
        .expect("the Receipt-Full row must be listed");
    assert_eq!(full["status"], "valid", "{full}");
    assert_eq!(
        full["assessment"]["coverage"]["complete"], false,
        "acceptance under a lowered quorum must still report the gap: {full}"
    );
    assert_eq!(full["assessment"]["coverage"]["accepted_with_gaps"], true);
    assert_eq!(
        full["assessment"]["coverage"]["unresolved"][0]["reason_code"],
        "bitcoin_block_not_checked"
    );
    assert_eq!(
        full["assessment"]["policy"]["max_trust_profile"], false,
        "ATL v2.0 §5.6 is not attained when the Bitcoin anchor is unconfirmed"
    );
}

/// A refutation outranks an item that merely makes no claim.
#[test]
fn invalid_beside_unanchored_is_invalid() {
    let (code, json) = Batch::new()
        .unanchored_item("a.txt")
        .invalid_item("b.txt")
        .run();
    assert_eq!(json["status"], "invalid", "{json}");
    assert_eq!(json["reason_code"], "batch_items_invalid");
    assert_eq!(code, 1);
}

/// **The regression this file exists for.** An entry the walk could not
/// resolve used to abort the run before any file was verified, so a
/// directory holding both a refuted receipt and one unreadable neighbour
/// exited 2 and never mentioned the refutation. An inability must never
/// suppress a finding already in hand.
#[cfg(unix)]
#[test]
fn a_refutation_outranks_an_unreadable_neighbour() {
    let (code, json) = Batch::new()
        .invalid_item("a.txt")
        .unreadable_item("ghost")
        .run();

    assert_eq!(json["status"], "invalid", "{json}");
    assert_eq!(code, 1, "a refuted receipt is exit 1, not exit 2");
    assert_eq!(json["summary"]["invalid"], 1);
    assert_eq!(
        json["summary"]["errors"], 1,
        "and the unreadable entry is still reported, not swallowed"
    );
    assert_eq!(json["summary"]["total"], 2);

    let statuses: Vec<&str> = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"invalid"), "{json}");
    assert!(statuses.contains(&"error"), "{json}");
}

/// With nothing refuted, an unreadable entry is an operational failure —
/// exit 2, the code single-file mode returns for a file it cannot read —
/// and the readable pair beside it is still verified and still listed.
#[cfg(unix)]
#[test]
fn an_unreadable_entry_does_not_stop_the_rest_of_the_batch() {
    let (code, json) = Batch::new()
        .unanchored_item("a.txt")
        .unreadable_item("ghost")
        .run();

    assert_eq!(json["status"], "error", "{json}");
    assert_eq!(json["reason_code"], "batch_items_errored");
    assert_eq!(code, 2, "not 1: nothing here was refuted");
    assert_eq!(
        json["summary"]["unanchored"], 1,
        "the readable pair was verified rather than abandoned"
    );
    assert_eq!(json["summary"]["errors"], 1);
    assert_eq!(json["summary"]["total"], 2);
}

/// A file the caller named and we never paired up blocks acceptance, even
/// when every file we did check was accepted.
#[test]
fn unmatched_beside_valid_is_untrusted() {
    let (code, json) = Batch::new()
        .valid_item("a.txt")
        .unmatched_item("b.txt")
        .run();
    assert_eq!(json["status"], "untrusted", "{json}");
    assert_eq!(json["reason_code"], "batch_items_unmatched");
    assert_eq!(code, 3);
    assert_eq!(json["summary"]["unmatched"], 1);
    assert_eq!(json["summary"]["total"], 2);
}

/// Everything at once: the refutation wins, and every other item is still
/// accounted for in the summary.
#[cfg(unix)]
#[test]
fn every_bucket_at_once_is_still_refuted() {
    let (code, json) = Batch::new()
        .valid_item("a.txt")
        .unanchored_item("b.txt")
        .untrusted_item("c.txt")
        .invalid_item("d.txt")
        .unmatched_item("e.txt")
        .unreadable_item("ghost")
        .run();

    assert_eq!(json["status"], "invalid", "{json}");
    assert_eq!(code, 1);
    assert_eq!(json["summary"]["valid"], 1, "{json}");
    assert_eq!(json["summary"]["unanchored"], 1);
    assert_eq!(json["summary"]["untrusted"], 1);
    assert_eq!(json["summary"]["invalid"], 1);
    assert_eq!(json["summary"]["errors"], 1);
    assert_eq!(json["summary"]["unmatched"], 1);
    assert_eq!(
        json["summary"]["total"], 6,
        "every named path lands in exactly one bucket"
    );
    assert_eq!(
        json["items"].as_array().map(Vec::len),
        Some(6),
        "and every one of them gets a row"
    );
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
