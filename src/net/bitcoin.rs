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
pub async fn get_block_timestamp(
    height: u64,
    timeout: Duration,
) -> CliResult<BitcoinBlockInfo> {
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
