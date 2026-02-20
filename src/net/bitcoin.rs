//! Bitcoin API client for block timestamp lookup

use crate::error::{CliError, CliResult};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

/// Bitcoin API provider configuration
struct ApiProvider {
    name: &'static str,
    base_url: &'static str,
    two_step: bool,
    timestamp_field: &'static str,
}

const PROVIDERS: &[ApiProvider] = &[
    ApiProvider {
        name: "blockstream.info",
        base_url: "https://blockstream.info/api",
        two_step: true,
        timestamp_field: "timestamp",
    },
    ApiProvider {
        name: "mempool.space",
        base_url: "https://mempool.space/api",
        two_step: true,
        timestamp_field: "timestamp",
    },
    ApiProvider {
        name: "blockchain.info",
        base_url: "https://blockchain.info",
        two_step: false,
        timestamp_field: "time",
    },
];

/// Global cache for block information
static BLOCK_INFO_CACHE: once_cell::sync::Lazy<RwLock<HashMap<u64, BitcoinBlockInfo>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// Bitcoin block information with header data
#[derive(Debug, Clone)]
pub struct BitcoinBlockInfo {
    pub height: u64,
    pub timestamp_secs: u64,
    /// Block hash (hex string, 64 chars)
    #[allow(dead_code)]
    pub block_hash: String,
    /// Merkle root from block header (hex string, 64 chars)
    pub merkle_root: String,
}

/// Get Bitcoin block info including merkle_root
pub async fn get_block_info(height: u64, timeout: Duration) -> CliResult<BitcoinBlockInfo> {
    // Check cache first; if the lock is poisoned, treat as cache miss
    if let Some(info) = BLOCK_INFO_CACHE
        .read()
        .ok()
        .and_then(|c| c.get(&height).cloned())
    {
        return Ok(info);
    }

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| CliError::NetworkError(format!("HTTP client error: {e}")))?;

    let mut errors = Vec::new();

    for provider in PROVIDERS {
        match fetch_block_info_from_provider(&client, provider, height).await {
            Ok(info) => {
                // Write to cache; if the lock is poisoned, skip caching (non-critical)
                if let Ok(mut cache) = BLOCK_INFO_CACHE.write() {
                    cache.insert(height, info.clone());
                }
                return Ok(info);
            }
            Err(e) => {
                errors.push(format!("{}: {}", provider.name, e));
            }
        }
    }

    Err(CliError::OtsVerificationFailed(format!(
        "Failed to fetch block {} from all APIs: {}",
        height,
        errors.join("; ")
    )))
}

/// Get Bitcoin block timestamp from blockchain APIs (round-robin)
/// Deprecated: Use get_block_info() instead
#[allow(dead_code)]
pub async fn get_block_timestamp(height: u64, timeout: Duration) -> CliResult<BitcoinBlockInfo> {
    get_block_info(height, timeout).await
}

async fn fetch_block_info_from_provider(
    client: &reqwest::Client,
    provider: &ApiProvider,
    height: u64,
) -> Result<BitcoinBlockInfo, String> {
    if provider.two_step {
        fetch_block_info_two_step(client, provider.base_url, height).await
    } else {
        fetch_block_info_single_step(client, provider.base_url, height).await
    }
}

#[allow(dead_code)]
async fn fetch_from_provider(
    client: &reqwest::Client,
    provider: &ApiProvider,
    height: u64,
) -> Result<u64, String> {
    if provider.two_step {
        fetch_two_step(client, provider.base_url, height, provider.timestamp_field).await
    } else {
        fetch_single_step(client, provider.base_url, height, provider.timestamp_field).await
    }
}

async fn fetch_block_info_two_step(
    client: &reqwest::Client,
    base_url: &str,
    height: u64,
) -> Result<BitcoinBlockInfo, String> {
    // Step 1: Get block hash by height
    let hash_url = format!("{base_url}/block-height/{height}");
    let block_hash = client
        .get(&hash_url)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP status error: {e}"))?
        .text()
        .await
        .map_err(|e| format!("Read error: {e}"))?
        .trim()
        .to_string();

    // Validate block hash format (64 hex chars)
    if block_hash.len() != 64 || !block_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid block hash format: {block_hash}"));
    }

    // Step 2: Get block details
    let block_url = format!("{base_url}/block/{block_hash}");
    let response = client
        .get(&block_url)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP status error: {e}"))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON error: {e}"))?;

    let timestamp = response["timestamp"]
        .as_u64()
        .ok_or("Missing 'timestamp' field")?;

    let merkle_root = response["merkle_root"]
        .as_str()
        .ok_or("Missing 'merkle_root' field")?
        .to_string();

    // Validate merkle_root format (64 hex chars)
    if merkle_root.len() != 64 || !merkle_root.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid merkle_root format: {merkle_root}"));
    }

    Ok(BitcoinBlockInfo {
        height,
        timestamp_secs: timestamp,
        block_hash,
        merkle_root,
    })
}

#[allow(dead_code)]
async fn fetch_two_step(
    client: &reqwest::Client,
    base_url: &str,
    height: u64,
    timestamp_field: &str,
) -> Result<u64, String> {
    let hash_url = format!("{base_url}/block-height/{height}");
    let hash = client
        .get(&hash_url)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP status error: {e}"))?
        .text()
        .await
        .map_err(|e| format!("Read error: {e}"))?;

    let block_url = format!("{base_url}/block/{}", hash.trim());
    let response = client
        .get(&block_url)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP status error: {e}"))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON error: {e}"))?;

    response[timestamp_field]
        .as_u64()
        .ok_or_else(|| format!("Missing '{timestamp_field}' field"))
}

async fn fetch_block_info_single_step(
    client: &reqwest::Client,
    base_url: &str,
    height: u64,
) -> Result<BitcoinBlockInfo, String> {
    let url = format!("{base_url}/block-height/{height}?format=json");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP status error: {e}"))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON error: {e}"))?;

    let block = response["blocks"].get(0).ok_or("Missing 'blocks[0]'")?;

    let timestamp = block["time"].as_u64().ok_or("Missing 'blocks[0].time'")?;

    let block_hash = block["hash"]
        .as_str()
        .ok_or("Missing 'blocks[0].hash'")?
        .to_string();

    let merkle_root = block["mrkl_root"]
        .as_str()
        .ok_or("Missing 'blocks[0].mrkl_root'")?
        .to_string();

    // Validate formats
    if block_hash.len() != 64 || !block_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid block hash format: {block_hash}"));
    }

    if merkle_root.len() != 64 || !merkle_root.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid merkle_root format: {merkle_root}"));
    }

    Ok(BitcoinBlockInfo {
        height,
        timestamp_secs: timestamp,
        block_hash,
        merkle_root,
    })
}

#[allow(dead_code)]
async fn fetch_single_step(
    client: &reqwest::Client,
    base_url: &str,
    height: u64,
    timestamp_field: &str,
) -> Result<u64, String> {
    let url = format!("{base_url}/block-height/{height}?format=json");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP status error: {e}"))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON error: {e}"))?;

    response["blocks"]
        .get(0)
        .and_then(|block| block[timestamp_field].as_u64())
        .ok_or_else(|| format!("Missing 'blocks[0].{timestamp_field}' field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_block_info_creation() {
        let info = BitcoinBlockInfo {
            height: 800000,
            timestamp_secs: 1700000000,
            block_hash: "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"
                .to_string(),
            merkle_root: "91f01a00530c8c83617190048ea8b0814d506cf24dfdbcf8893f8f0cab7f0855"
                .to_string(),
        };
        assert_eq!(info.height, 800000);
        assert_eq!(info.timestamp_secs, 1700000000);
        assert_eq!(info.block_hash.len(), 64);
        assert_eq!(info.merkle_root.len(), 64);
    }

    #[test]
    fn test_bitcoin_block_info_debug() {
        let info = BitcoinBlockInfo {
            height: 1,
            timestamp_secs: 2,
            block_hash: "0".repeat(64),
            merkle_root: "1".repeat(64),
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("height"));
        assert!(debug_str.contains("timestamp_secs"));
        assert!(debug_str.contains("block_hash"));
        assert!(debug_str.contains("merkle_root"));
    }

    #[test]
    fn test_bitcoin_block_info_clone() {
        let info = BitcoinBlockInfo {
            height: 123,
            timestamp_secs: 456,
            block_hash: "abc".repeat(21) + "a",
            merkle_root: "def".repeat(21) + "d",
        };
        let cloned = info.clone();
        assert_eq!(cloned.height, 123);
        assert_eq!(cloned.timestamp_secs, 456);
        assert_eq!(cloned.block_hash, info.block_hash);
        assert_eq!(cloned.merkle_root, info.merkle_root);
    }

    #[test]
    fn test_providers_configured() {
        assert!(!PROVIDERS.is_empty());
        assert_eq!(PROVIDERS.len(), 3);
        for provider in PROVIDERS {
            assert!(!provider.name.is_empty());
            assert!(!provider.base_url.is_empty());
            assert!(!provider.timestamp_field.is_empty());
            assert!(provider.base_url.starts_with("https://"));
        }
    }

    #[test]
    fn test_providers_have_different_names() {
        let names: Vec<_> = PROVIDERS.iter().map(|p| p.name).collect();
        assert!(names.contains(&"blockstream.info"));
        assert!(names.contains(&"mempool.space"));
        assert!(names.contains(&"blockchain.info"));
    }

    #[test]
    fn test_providers_two_step_configuration() {
        let blockstream = &PROVIDERS[0];
        assert_eq!(blockstream.name, "blockstream.info");
        assert!(blockstream.two_step);

        let blockchain_info = &PROVIDERS[2];
        assert_eq!(blockchain_info.name, "blockchain.info");
        assert!(!blockchain_info.two_step);
    }

    #[tokio::test]
    async fn test_get_block_info_caching() {
        // Pre-populate cache with test data
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                123456,
                BitcoinBlockInfo {
                    height: 123456,
                    timestamp_secs: 9999999,
                    block_hash: "a".repeat(64),
                    merkle_root: "b".repeat(64),
                },
            );
        }

        // Second call should hit cache
        let result = get_block_info(123456, Duration::from_secs(1)).await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.height, 123456);
        assert_eq!(info.timestamp_secs, 9999999);
        assert_eq!(info.block_hash.len(), 64);
        assert_eq!(info.merkle_root.len(), 64);
    }

    #[tokio::test]
    async fn test_get_block_info_cache_multiple_entries() {
        // Add multiple entries to cache
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                100000,
                BitcoinBlockInfo {
                    height: 100000,
                    timestamp_secs: 1000000,
                    block_hash: "c".repeat(64),
                    merkle_root: "d".repeat(64),
                },
            );
            cache.insert(
                200000,
                BitcoinBlockInfo {
                    height: 200000,
                    timestamp_secs: 2000000,
                    block_hash: "e".repeat(64),
                    merkle_root: "f".repeat(64),
                },
            );
        }

        // Verify both can be retrieved
        let r1 = get_block_info(100000, Duration::from_secs(1)).await;
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().timestamp_secs, 1000000);

        let r2 = get_block_info(200000, Duration::from_secs(1)).await;
        assert!(r2.is_ok());
        assert_eq!(r2.unwrap().timestamp_secs, 2000000);
    }

    #[tokio::test]
    async fn test_get_block_timestamp_invalid_height() {
        // Very high block height that doesn't exist yet
        let result = get_block_timestamp(99999999, Duration::from_millis(500)).await;
        // Should fail (either timeout or 404)
        assert!(result.is_err());
        if let Err(e) = result {
            let err_str = format!("{}", e);
            assert!(err_str.contains("Failed to fetch block") || err_str.contains("99999999"));
        }
    }

    #[tokio::test]
    async fn test_get_block_timestamp_very_short_timeout() {
        // Use extremely short timeout to force timeout error
        let result = get_block_timestamp(88888888, Duration::from_millis(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_from_provider_invalid_height() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();

        let provider = &PROVIDERS[0];
        let result = fetch_from_provider(&client, provider, 99999999).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_from_provider_all_providers() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();

        for provider in PROVIDERS {
            let result = fetch_from_provider(&client, provider, 99999999).await;
            // Should fail for invalid height
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_api_provider_fields() {
        let provider = ApiProvider {
            name: "test",
            base_url: "https://test.com",
            two_step: true,
            timestamp_field: "ts",
        };
        assert_eq!(provider.name, "test");
        assert_eq!(provider.base_url, "https://test.com");
        assert!(provider.two_step);
        assert_eq!(provider.timestamp_field, "ts");
    }

    #[test]
    fn test_cache_initialization() {
        // Just accessing the cache should work
        let _cache = BLOCK_INFO_CACHE.read().unwrap();
        // Cache should be empty or contain entries from previous tests
    }

    #[test]
    fn test_bitcoin_block_info_format() {
        let info = BitcoinBlockInfo {
            height: 700000,
            timestamp_secs: 1638000000,
            block_hash: "0".repeat(64),
            merkle_root: "1".repeat(64),
        };
        let debug = format!("{:?}", info);
        assert!(debug.contains("700000"));
        assert!(debug.contains("1638000000"));
    }

    #[tokio::test]
    async fn test_get_block_info_two_calls_different_heights() {
        // Pre-populate cache
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                111111,
                BitcoinBlockInfo {
                    height: 111111,
                    timestamp_secs: 1111111,
                    block_hash: "1".repeat(64),
                    merkle_root: "2".repeat(64),
                },
            );
            cache.insert(
                222222,
                BitcoinBlockInfo {
                    height: 222222,
                    timestamp_secs: 2222222,
                    block_hash: "3".repeat(64),
                    merkle_root: "4".repeat(64),
                },
            );
        }

        let r1 = get_block_info(111111, Duration::from_secs(1)).await;
        let r2 = get_block_info(222222, Duration::from_secs(1)).await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_ne!(r1.unwrap().timestamp_secs, r2.unwrap().timestamp_secs);
    }

    #[test]
    fn test_providers_timestamp_fields() {
        // Verify all providers have valid timestamp_field settings
        for provider in PROVIDERS {
            assert!(!provider.timestamp_field.is_empty());
            assert!(provider.timestamp_field == "timestamp" || provider.timestamp_field == "time");
        }
    }
}
