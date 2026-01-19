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

/// Global cache for block timestamps
static BLOCK_TIME_CACHE: once_cell::sync::Lazy<RwLock<HashMap<u64, u64>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// Bitcoin block information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BitcoinBlockInfo {
    pub height: u64,
    pub timestamp_secs: u64,
}

/// Get Bitcoin block timestamp from blockchain APIs (round-robin)
#[allow(dead_code)]
pub async fn get_block_timestamp(height: u64, timeout: Duration) -> CliResult<BitcoinBlockInfo> {
    // Check cache first
    if let Some(&ts) = BLOCK_TIME_CACHE.read().unwrap().get(&height) {
        return Ok(BitcoinBlockInfo {
            height,
            timestamp_secs: ts,
        });
    }

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| CliError::NetworkError(format!("HTTP client error: {e}")))?;

    let mut errors = Vec::new();

    for provider in PROVIDERS {
        match fetch_from_provider(&client, provider, height).await {
            Ok(ts) => {
                BLOCK_TIME_CACHE.write().unwrap().insert(height, ts);
                return Ok(BitcoinBlockInfo {
                    height,
                    timestamp_secs: ts,
                });
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
        };
        assert_eq!(info.height, 800000);
        assert_eq!(info.timestamp_secs, 1700000000);
    }

    #[test]
    fn test_bitcoin_block_info_debug() {
        let info = BitcoinBlockInfo {
            height: 1,
            timestamp_secs: 2,
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("height"));
        assert!(debug_str.contains("timestamp_secs"));
    }

    #[test]
    fn test_bitcoin_block_info_clone() {
        let info = BitcoinBlockInfo {
            height: 123,
            timestamp_secs: 456,
        };
        let cloned = info.clone();
        assert_eq!(cloned.height, 123);
        assert_eq!(cloned.timestamp_secs, 456);
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
    async fn test_get_block_timestamp_caching() {
        // Pre-populate cache with test data
        {
            let mut cache = BLOCK_TIME_CACHE.write().unwrap();
            cache.insert(123456, 9999999);
        }

        // Second call should hit cache
        let result = get_block_timestamp(123456, Duration::from_secs(1)).await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.height, 123456);
        assert_eq!(info.timestamp_secs, 9999999);
    }

    #[tokio::test]
    async fn test_get_block_timestamp_cache_multiple_entries() {
        // Add multiple entries to cache
        {
            let mut cache = BLOCK_TIME_CACHE.write().unwrap();
            cache.insert(100000, 1000000);
            cache.insert(200000, 2000000);
        }

        // Verify both can be retrieved
        let r1 = get_block_timestamp(100000, Duration::from_secs(1)).await;
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().timestamp_secs, 1000000);

        let r2 = get_block_timestamp(200000, Duration::from_secs(1)).await;
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
        let _cache = BLOCK_TIME_CACHE.read().unwrap();
        // Cache should be empty or contain entries from previous tests
    }

    #[test]
    fn test_bitcoin_block_info_format() {
        let info = BitcoinBlockInfo {
            height: 700000,
            timestamp_secs: 1638000000,
        };
        let debug = format!("{:?}", info);
        assert!(debug.contains("700000"));
        assert!(debug.contains("1638000000"));
    }

    #[tokio::test]
    async fn test_get_block_timestamp_two_calls_different_heights() {
        // Pre-populate cache
        {
            let mut cache = BLOCK_TIME_CACHE.write().unwrap();
            cache.insert(111111, 1111111);
            cache.insert(222222, 2222222);
        }

        let r1 = get_block_timestamp(111111, Duration::from_secs(1)).await;
        let r2 = get_block_timestamp(222222, Duration::from_secs(1)).await;

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
