//! Loading caller-supplied TSA trust material from disk
//!
//! Per the ATL trust model (`docs-md/atl-trust-model-decisions.md`, decision
//! Р1): no TSA root, fingerprint, or operator key lives inside this tool.
//! `atl-cli` is a reference verifier for a public protocol; Evidentum is
//! just one operator among others the protocol does not privilege. Trust
//! material must come from the caller, through an explicit interface, never
//! from anything this binary ships with.
//!
//! This module is that interface for RFC 3161 anchors. Two flags feed it,
//! and their roles are kept strictly apart:
//!
//! - `--tsa-trust-store <path>` (see
//!   [`crate::cli::VerifyArgs::tsa_trust_store`]) names certificates the
//!   caller has decided, through some external trusted channel, to treat as
//!   **trust anchors**: a chain that reaches one of them terminates
//!   successfully.
//! - `--tsa-intermediates <path>` (see
//!   [`crate::cli::VerifyArgs::tsa_intermediates`]) supplies certificates
//!   merely used to **bridge a gap** in a token's own certificate set. They
//!   confer no trust of their own: a chain walking through one still has to
//!   reach an anchor.
//!
//! Keeping them apart matters. Sectigo and DigiCert tokens name a "root"
//! that is itself cross-signed by a legacy root absent from the token; the
//! only way to complete such a chain used to be feeding the missing issuer
//! in as an *anchor*, which silently moves the trust boundary outward.
//! Nothing here decides *which* certificates to trust -- it only parses what
//! the caller already chose, and files each under the role the caller named.

use std::path::{Path, PathBuf};

use atl_core::TrustStore;
use der::Decode;
use x509_cert::Certificate;

use crate::error::{CliError, CliResult};

/// Load RFC 3161 trust **anchors** from `path` into a fresh [`TrustStore`].
///
/// `path` may be:
/// - a single file containing one or more PEM-encoded certificates
///   (concatenated, as in a typical CA bundle), or a single DER-encoded
///   certificate;
/// - a directory, in which every non-hidden regular file is loaded the same
///   way (not recursive -- see [`list_certificate_files`] for how symlinks
///   are treated).
///
/// Every certificate found is registered with
/// [`TrustStore::with_anchor_certificate`]. A trust anchor need not be
/// self-signed -- see [`TrustStore`]'s own docs for why.
///
/// # Errors
///
/// Returns [`CliError::TrustStoreError`] if `path` does not exist, cannot
/// be read, contains no certificates, or contains a file that fails to
/// parse. Malformed trust material is refused rather than silently skipped:
/// a mistyped path or a corrupted file must produce an error, not a trust
/// store quietly missing an anchor the caller meant to configure.
pub fn load_tsa_trust_store(path: &Path) -> CliResult<TrustStore> {
    let certs = load_certificates(path, "trust store")?;
    Ok(certs
        .into_iter()
        .fold(TrustStore::new(), TrustStore::with_anchor_certificate))
}

/// Add **intermediate** certificates from `path` to `store`.
///
/// Same file/directory rules as [`load_tsa_trust_store`], but every
/// certificate is registered with
/// [`TrustStore::with_intermediate_certificate`]: chain construction may
/// walk through them, and they never terminate a chain by themselves. This
/// is what lets a cross-signed Sectigo/DigiCert chain be completed without
/// promoting the missing issuer to a trust anchor.
///
/// # Errors
///
/// As [`load_tsa_trust_store`].
pub fn load_tsa_intermediates(store: TrustStore, path: &Path) -> CliResult<TrustStore> {
    let certs = load_certificates(path, "intermediates")?;
    Ok(certs
        .into_iter()
        .fold(store, TrustStore::with_intermediate_certificate))
}

/// Parse every certificate under `path`, which may be a file or a directory.
///
/// `role` names the flag being loaded, for error messages only.
fn load_certificates(path: &Path, role: &str) -> CliResult<Vec<Certificate>> {
    let files = if path.is_dir() {
        list_certificate_files(path, role)?
    } else {
        vec![path.to_path_buf()]
    };

    let mut certs = Vec::new();
    for file in &files {
        certs.extend(load_certs_from_file(file)?);
    }

    if certs.is_empty() {
        return Err(CliError::TrustStoreError(format!(
            "no certificates found under {role} path: {}",
            path.display()
        )));
    }

    Ok(certs)
}

/// List the certificate files directly inside `dir`, sorted for
/// deterministic loading order.
///
/// # What is included
///
/// Non-hidden entries that resolve to a regular file. `Path::is_file`
/// follows symlinks, and that is deliberate: a symlink placed in the
/// directory pointing at a certificate elsewhere is an explicit instruction
/// from the caller to load that certificate, exactly like a copy of it would
/// be. Symlinks pointing at directories are skipped, as are real
/// subdirectories -- loading is never recursive, so a symlinked directory
/// cannot smuggle in a tree of certificates (or a symlink loop).
///
/// # Errors
///
/// Returns [`CliError::TrustStoreError`] if the directory holds no
/// candidate files, and [`CliError::FileReadError`] if the directory cannot
/// be read **or if any individual entry cannot be read**. A failed
/// `DirEntry` used to be dropped silently here, which could load a trust
/// store missing an anchor without a word of warning; for trust material,
/// partial success is not success.
fn list_certificate_files(dir: &Path, role: &str) -> CliResult<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| CliError::file_read_error(dir, e))? {
        let entry = entry.map_err(|e| CliError::file_read_error(dir, e))?;
        let path = entry.path();

        let hidden = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.'));
        if hidden {
            continue;
        }

        // `is_file` follows symlinks; a broken symlink or a directory both
        // answer `false` and are skipped. See this function's doc comment.
        if !path.is_file() {
            continue;
        }

        entries.push(path);
    }
    entries.sort();

    if entries.is_empty() {
        return Err(CliError::TrustStoreError(format!(
            "no certificate files found in {role} directory: {}",
            dir.display()
        )));
    }

    Ok(entries)
}

/// Parse every certificate in `path`: a PEM chain (one or more concatenated
/// `-----BEGIN CERTIFICATE-----` blocks) if the file looks like PEM,
/// otherwise a single DER certificate.
fn load_certs_from_file(path: &Path) -> CliResult<Vec<Certificate>> {
    let bytes = std::fs::read(path).map_err(|e| CliError::file_read_error(path, e))?;

    if looks_like_pem(&bytes) {
        Certificate::load_pem_chain(&bytes).map_err(|e| {
            CliError::TrustStoreError(format!(
                "failed to parse PEM certificate(s) in '{}': {e}",
                path.display()
            ))
        })
    } else {
        Certificate::from_der(&bytes)
            .map(|cert| vec![cert])
            .map_err(|e| {
                CliError::TrustStoreError(format!(
                    "failed to parse DER certificate in '{}': {e}",
                    path.display()
                ))
            })
    }
}

/// Heuristic: a file is treated as PEM if it contains a `-----` boundary
/// marker anywhere in its first few KB; otherwise it is parsed as raw DER.
fn looks_like_pem(bytes: &[u8]) -> bool {
    const SCAN_LIMIT: usize = 4096;
    let scan = &bytes[..bytes.len().min(SCAN_LIMIT)];
    scan.windows(5).any(|w| w == b"-----")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// A real, freshly-generated, self-signed P-256 test certificate
    /// (`CN=atl-cli-test-anchor`, generated with `openssl req -x509
    /// -newkey ec -pkeyopt ec_paramgen_curve:P-256`), in PEM form. Used
    /// purely as *a* well-formed certificate to exercise the loader --
    /// this module never decides what to trust, and this key/certificate
    /// is not used anywhere outside this test.
    const TEST_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBkjCCATegAwIBAgIUDzKEUAnsig9Zhi5Vl7MfQ+++jlYwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTYXRsLWNsaS10ZXN0LWFuY2hvcjAeFw0yNjA4MjYwNDQyNDha
Fw0zNjA4MjMwNDQyNDhaMB4xHDAaBgNVBAMME2F0bC1jbGktdGVzdC1hbmNob3Iw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQd7xtZtkyF4gyW/VQzdvOVb7cA2arG
eQeDOcI+54UEPFmOxcA9DGYuPS6B6z8FfNjtoZtbUVPv0Lga2iZXQNAyo1MwUTAd
BgNVHQ4EFgQUEmFtD0chtu0rOjkq2f4IZjEdPGswHwYDVR0jBBgwFoAUEmFtD0ch
tu0rOjkq2f4IZjEdPGswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBG
AiEA7/eRyjEOeYOfJoS0QVynPHE4gsXysObm2w2AFWgXxd0CIQD3LdePBRHLpnsd
Z8tQnULzKpK5V3331Z4vAMn1FDvwtg==
-----END CERTIFICATE-----
";

    /// The exact same certificate as [`TEST_CERT_PEM`], as raw DER bytes
    /// (hex-encoded here so the test module needs no extra base64
    /// dependency; `hex` is already a crate dependency).
    const TEST_CERT_DER_HEX: &str = "3082019230820137a00302010202140f32845009ec8a0f59862e5597b31f43efbe8e56300a06082a8648ce3d040302301e311c301a06035504030c1361746c2d636c692d746573742d616e63686f72301e170d3236303832363034343234385a170d3336303832333034343234385a301e311c301a06035504030c1361746c2d636c692d746573742d616e63686f723059301306072a8648ce3d020106082a8648ce3d030107034200041def1b59b64c85e20c96fd543376f3956fb700d9aac679078339c23ee785043c598ec5c03d0c662e3d2e81eb3f057cd8eda19b5b5153efd0b81ada265740d032a3533051301d0603551d0e0416041412616d0f4721b6ed2b3a392ad9fe0866311d3c6b301f0603551d2304183016801412616d0f4721b6ed2b3a392ad9fe0866311d3c6b300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100eff791ca310e79839f2684b4415ca73c713882c5f2b0e6e6db0d80156817c5dd022100f72dd78f0511cba67b1d67cb509d42f32a92b9577df7d59e2f00c9f5143bf0b6";

    fn test_cert_der() -> Vec<u8> {
        hex::decode(TEST_CERT_DER_HEX).expect("fixture hex must decode")
    }

    #[test]
    fn load_single_pem_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("root.pem");
        std::fs::write(&file, TEST_CERT_PEM).unwrap();

        let store = load_tsa_trust_store(&file).expect("valid PEM file must load");
        // We can't inspect TrustStore's private fields directly, but a
        // successful load with no error is the observable contract here;
        // matching behavior is covered end-to-end in
        // `verify::online::tests`.
        let _ = store;
    }

    #[test]
    fn load_single_der_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("root.der");
        std::fs::write(&file, test_cert_der()).unwrap();

        let store = load_tsa_trust_store(&file);
        assert!(store.is_ok(), "valid DER file must load: {store:?}");
    }

    #[test]
    fn load_directory_of_certificates() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.pem"), TEST_CERT_PEM).unwrap();
        std::fs::write(dir.path().join("b.der"), test_cert_der()).unwrap();

        let store = load_tsa_trust_store(dir.path());
        assert!(store.is_ok(), "directory of certs must load: {store:?}");
    }

    #[test]
    fn directory_skips_hidden_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("root.pem"), TEST_CERT_PEM).unwrap();
        // A hidden file that is NOT valid trust material -- if this were
        // loaded, the whole call would fail.
        let mut hidden = std::fs::File::create(dir.path().join(".DS_Store")).unwrap();
        hidden.write_all(b"not a certificate").unwrap();

        let store = load_tsa_trust_store(dir.path());
        assert!(store.is_ok(), "hidden files must be skipped: {store:?}");
    }

    #[test]
    fn missing_path_is_an_error() {
        let result = load_tsa_trust_store(Path::new("/nonexistent/trust-store-path"));
        assert!(result.is_err());
    }

    #[test]
    fn empty_directory_is_an_error() {
        let dir = TempDir::new().unwrap();
        let result = load_tsa_trust_store(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn garbage_file_is_an_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("not-a-cert.txt");
        std::fs::write(&file, b"this is not a certificate at all").unwrap();

        let result = load_tsa_trust_store(&file);
        assert!(result.is_err());
    }

    #[test]
    fn directory_with_one_bad_file_fails_loudly() {
        // A directory with one good and one bad file must fail entirely,
        // not silently drop the bad one -- see the module doc comment on
        // why malformed trust material is refused rather than skipped.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("good.pem"), TEST_CERT_PEM).unwrap();
        std::fs::write(dir.path().join("bad.pem"), b"garbage").unwrap();

        let result = load_tsa_trust_store(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn looks_like_pem_detects_boundary_marker() {
        assert!(looks_like_pem(b"-----BEGIN CERTIFICATE-----\nabc\n"));
        assert!(!looks_like_pem(&[0x30, 0x82, 0x01, 0x0a]));
    }

    #[test]
    fn intermediates_load_from_file_and_directory() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("inter.pem");
        std::fs::write(&file, TEST_CERT_PEM).unwrap();

        let store =
            load_tsa_intermediates(TrustStore::new(), &file).expect("intermediates file must load");
        // Intermediates compose with anchors rather than replacing them.
        let combined = load_tsa_intermediates(store, dir.path());
        assert!(
            combined.is_ok(),
            "directory of intermediates must load: {combined:?}"
        );
    }

    #[test]
    fn intermediates_reject_bad_material_loudly() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("not-a-cert.txt");
        std::fs::write(&file, b"garbage").unwrap();

        assert!(load_tsa_intermediates(TrustStore::new(), &file).is_err());
        assert!(load_tsa_intermediates(TrustStore::new(), Path::new("/nonexistent/x")).is_err());
    }

    /// A symlink pointing at a certificate outside the directory IS loaded:
    /// placing it there is an explicit instruction from the caller. See
    /// `list_certificate_files`.
    #[test]
    #[cfg(unix)]
    fn directory_follows_symlinks_to_files() {
        let outside = TempDir::new().unwrap();
        let real_cert = outside.path().join("real-root.pem");
        std::fs::write(&real_cert, TEST_CERT_PEM).unwrap();

        let dir = TempDir::new().unwrap();
        std::os::unix::fs::symlink(&real_cert, dir.path().join("link.pem")).unwrap();

        let store = load_tsa_trust_store(dir.path());
        assert!(
            store.is_ok(),
            "symlink to a certificate must be loaded: {store:?}"
        );
    }

    /// A symlink pointing at a directory is skipped, exactly like a real
    /// subdirectory: loading is never recursive.
    #[test]
    #[cfg(unix)]
    fn directory_skips_symlinks_to_directories() {
        let nested = TempDir::new().unwrap();
        // Contents that would fail to parse if they were ever loaded.
        std::fs::write(nested.path().join("junk.pem"), b"not a certificate").unwrap();

        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("root.pem"), TEST_CERT_PEM).unwrap();
        std::os::unix::fs::symlink(nested.path(), dir.path().join("nested")).unwrap();
        std::fs::create_dir(dir.path().join("real-subdir")).unwrap();

        let store = load_tsa_trust_store(dir.path());
        assert!(
            store.is_ok(),
            "directory symlinks must be skipped, not descended into: {store:?}"
        );
    }

    /// A broken symlink resolves to neither file nor directory and is
    /// skipped rather than aborting the load.
    #[test]
    #[cfg(unix)]
    fn directory_skips_broken_symlinks() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("root.pem"), TEST_CERT_PEM).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist.pem"),
            dir.path().join("dangling.pem"),
        )
        .unwrap();

        let store = load_tsa_trust_store(dir.path());
        assert!(store.is_ok(), "broken symlink must be skipped: {store:?}");
    }
}
