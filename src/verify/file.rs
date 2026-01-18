//! File hashing and loading

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::{CliError, CliResult};

/// Maximum source file size (1 GB)
pub const MAX_SOURCE_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum receipt file size (10 MB)
pub const MAX_RECEIPT_SIZE: u64 = 10 * 1024 * 1024;

/// Buffer size for streaming hash (64 KB)
const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Hash a file using SHA-256 with streaming
///
/// This function streams the file in chunks to avoid loading large files
/// entirely into memory. It enforces a 1 GB file size limit.
///
/// # Arguments
///
/// * `path` - Path to the file to hash
///
/// # Errors
///
/// Returns error if:
/// - File does not exist
/// - File exceeds size limit
/// - File cannot be read
pub fn hash_file(path: &Path) -> CliResult<[u8; 32]> {
    // Check file exists
    if !path.exists() {
        return Err(CliError::SourceNotFound(path.to_path_buf()));
    }

    // Check file size
    let metadata =
        std::fs::metadata(path).map_err(|e| CliError::file_read_error(path, e))?;

    if metadata.len() > MAX_SOURCE_FILE_SIZE {
        return Err(CliError::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
            max_bytes: MAX_SOURCE_FILE_SIZE,
        });
    }

    // Stream-hash the file
    let file = File::open(path).map_err(|e| CliError::file_read_error(path, e))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| CliError::file_read_error(path, e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

/// Format hash as "sha256:{hex}"
///
/// # Arguments
///
/// * `hash` - 32-byte SHA-256 hash
///
/// # Returns
///
/// String in format "sha256:hexvalue"
#[must_use]
pub fn format_hash(hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash))
}

/// Compare computed hash with expected hash string
///
/// # Arguments
///
/// * `computed` - Computed hash bytes
/// * `expected` - Expected hash string in "sha256:hex" format
///
/// # Returns
///
/// `true` if hashes match, `false` otherwise
#[must_use]
pub fn compare_hash(computed: &[u8; 32], expected: &str) -> bool {
    let computed_str = format_hash(computed);
    computed_str == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();

        let hash = hash_file(file.path()).unwrap();
        // SHA-256 of "test content"
        assert_eq!(
            hex::encode(hash),
            "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
        );
    }

    #[test]
    fn test_hash_file_not_found() {
        let result = hash_file(Path::new("/nonexistent/file"));
        assert!(matches!(result, Err(CliError::SourceNotFound(_))));
    }

    #[test]
    fn test_format_hash() {
        let hash = [0xab; 32];
        let formatted = format_hash(&hash);
        assert_eq!(
            formatted,
            "sha256:abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn test_compare_hash_match() {
        let hash = [0xab; 32];
        let expected = format!("sha256:{}", hex::encode(hash));
        assert!(compare_hash(&hash, &expected));
    }

    #[test]
    fn test_compare_hash_mismatch() {
        let hash = [0xab; 32];
        let expected =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!compare_hash(&hash, expected));
    }

    #[test]
    fn test_hash_empty_file() {
        let file = NamedTempFile::new().unwrap();
        // Empty file
        let hash = hash_file(file.path()).unwrap();
        // SHA-256 of empty string
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
