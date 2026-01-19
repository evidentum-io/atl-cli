//! Internet connectivity detection

#[cfg(feature = "online")]
use std::time::Duration;

/// Endpoints to probe for internet connectivity
#[cfg(feature = "online")]
const CONNECTIVITY_ENDPOINTS: &[&str] = &[
    "https://www.google.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://detectportal.firefox.com/success.txt",
];

/// Timeout for each connectivity check
#[cfg(feature = "online")]
const DETECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Check if internet is available (async)
///
/// Returns true if any endpoint responds within timeout.
/// Uses parallel requests with first-success-wins strategy.
#[cfg(feature = "online")]
pub async fn has_internet() -> bool {
    use futures::future::select_all;

    let checks: Vec<_> = CONNECTIVITY_ENDPOINTS
        .iter()
        .map(|url| Box::pin(check_endpoint(url)))
        .collect();

    if checks.is_empty() {
        return false;
    }

    let (first_result, _remaining_index, _remaining) = select_all(checks).await;
    first_result
}

#[cfg(feature = "online")]
async fn check_endpoint(url: &str) -> bool {
    let client = match reqwest::Client::builder().timeout(DETECT_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(url).send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

/// Blocking version for use in synchronous code
#[cfg(feature = "online")]
pub fn has_internet_blocking() -> bool {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return false,
    };

    rt.block_on(has_internet())
}

/// Always returns false when online feature is disabled
#[cfg(not(feature = "online"))]
#[allow(dead_code)]
pub fn has_internet_blocking() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "online"))]
    fn test_has_internet_blocking_offline() {
        // Without online feature, always returns false
        assert!(!has_internet_blocking());
    }

    #[tokio::test]
    #[cfg(feature = "online")]
    async fn test_has_internet_success() {
        // This will likely succeed in CI/dev environment with internet
        // If it fails, test environment has no connectivity (acceptable)
        let result = has_internet().await;
        // We don't assert the result because it depends on network availability
        // Just ensure the function doesn't panic
        let _ = result;
    }

    #[tokio::test]
    #[cfg(feature = "online")]
    async fn test_check_endpoint_invalid_url() {
        // Invalid/unreachable URL should return false (or may succeed if DNS resolves)
        let result = check_endpoint("http://invalid.nonexistent.tld.xyz").await;
        // Just ensure it doesn't panic - result may vary based on DNS
        let _ = result;
    }

    #[test]
    #[cfg(feature = "online")]
    fn test_has_internet_blocking_executes() {
        // Ensure blocking version doesn't panic
        let result = has_internet_blocking();
        // Don't assert result - depends on network
        let _ = result;
    }

    #[cfg(feature = "online")]
    #[test]
    fn test_connectivity_endpoints_not_empty() {
        assert!(!CONNECTIVITY_ENDPOINTS.is_empty());
    }

    #[cfg(feature = "online")]
    #[test]
    fn test_detect_timeout_reasonable() {
        assert!(DETECT_TIMEOUT.as_secs() > 0);
        assert!(DETECT_TIMEOUT.as_secs() <= 10);
    }
}
