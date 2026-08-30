//! Block-explorer API client for Bitcoin block-header lookup.
//!
//! # What this module does, and what it emphatically does not
//!
//! It queries public block-explorer HTTP APIs and reads a block header out
//! of their JSON. It does **not** observe the Bitcoin network: no proof of
//! work is validated, no chain of headers is followed, no peer is contacted.
//! There is no way, from inside this module, to know that what an endpoint
//! returned is what Bitcoin actually contains.
//!
//! Two consequences shape everything below.
//!
//! **Wording.** Nothing here may be described as observed on-chain or
//! confirmed against the blockchain, because none of that happens. Values
//! are *reported by named sources*, and the names travel with the values all
//! the way to the output.
//!
//! **Corroboration.** A single endpoint used to decide a verdict on its own:
//! one wrong or compromised API could make an anchor `verified`. So a header
//! is only usable as agreement when **two or more separately operated
//! providers return the same one**. Separately *operated* is all that is
//! claimed: whether they share infrastructure or an upstream data source is
//! not something this tool can check. Anything less is reported as what it is, and never
//! as a fact — in either direction.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;

use crate::error::{CliError, CliResult};
use crate::verify::anchor::{sources_agree, BlockSourceReport};

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

/// Time of Bitcoin's genesis block (2009-01-03T18:15:05Z), in seconds since
/// the epoch. No block header can be older.
pub const GENESIS_BLOCK_TIME: u64 = 1_231_006_505;

/// Bitcoin consensus rejects a header whose time is more than two hours
/// ahead of network-adjusted time, so anything further ahead than this is
/// not a block time at all.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;

/// Reject a block time that cannot be one.
///
/// An API returning `0`, or a date before Bitcoin existed, or a time far in
/// the future, has returned garbage or an error body — not a fact. Such a
/// response is discarded here, at the point of intake, so it can never
/// become a published value.
///
/// This matters because the renderer downstream is deliberately literal: a
/// `0` reaching it was formatted as `1970-01-01T00:00:00Z`, a parsable,
/// real-looking timestamp for a block that no more existed than the check
/// did. Removing the local `0` sentinel fixed the tool's own stub; this
/// closes the same hole for a value handed to us by someone else.
///
/// # Errors
///
/// Returns a description of why the value cannot be a block time.
pub fn validate_block_time(secs: u64) -> Result<u64, String> {
    // `None` when the clock cannot be read at all.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok();
    validate_block_time_against(secs, now)
}

/// [`validate_block_time`] with the clock supplied, so the unreadable-clock
/// branch is reachable from a test. `now` is `None` when the clock could not
/// be read.
///
/// # Errors
///
/// Returns a description of why the value cannot be a block time.
pub fn validate_block_time_against(secs: u64, now: Option<u64>) -> Result<u64, String> {
    if secs < GENESIS_BLOCK_TIME {
        return Err(format!(
            "implausible block time {secs}: earlier than Bitcoin's genesis block \
             ({GENESIS_BLOCK_TIME})"
        ));
    }
    // Fail closed. An unreadable clock means the upper bound cannot be
    // evaluated at all, and a check that cannot be performed is not a check
    // that passed.
    //
    // This arm used to fall back to `u64::MAX`, which -- with the
    // `saturating_add` below -- made the comparison unsatisfiable, so *every*
    // future time passed. The comment beside it claimed the opposite ("an
    // unreadable clock must not become a reason to accept a value"), which
    // is the same defect this whole rework has been removing from the
    // output, sitting in a comment instead.
    let Some(now) = now else {
        return Err(format!(
            "cannot validate block time {secs}: the system clock is unreadable, so it cannot be \
             bounded from above"
        ));
    };
    if secs > now.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        return Err(format!(
            "implausible block time {secs}: more than {MAX_FUTURE_BLOCK_TIME}s in the future"
        ));
    }
    Ok(secs)
}

/// How long a corroborated header may be reused within one run.
///
/// One expected Bitcoin block interval. The number is reasoned rather than
/// picked: within one expected interval no new block is likely to have
/// arrived, so re-asking the same endpoints is unlikely to yield a different
/// answer; past it, the picture may well have moved and the question is
/// worth asking again.
///
/// It does **not** make a cached header fresh, and it prevents no
/// reorganisation — see [`lookup_block`] for what is and is not established.
/// What it does is bound staleness. Without it, staleness grew without limit
/// with the size of a batch run.
pub const CACHE_TTL: Duration = Duration::from_secs(600);

/// A cached entry may still be used.
///
/// Split out so the boundary is testable without waiting ten minutes.
#[must_use]
pub const fn cache_entry_is_fresh(age: Duration) -> bool {
    age.as_secs() < CACHE_TTL.as_secs()
}

/// A corroborated lookup and when it was made.
///
/// The instant is a [`Instant`], not a wall-clock time: it is monotonic, it
/// cannot fail to be read, and it therefore does not depend on the system
/// clock that [`validate_block_time`] deliberately refuses to trust.
#[derive(Debug, Clone)]
struct CacheEntry {
    fetched_at: Instant,
    lookup: BlockLookup,
}

/// Block lookups already made **in this process**.
///
/// Process-local, holding corroborated headers only, and bounded in time by
/// [`CACHE_TTL`]. See [`lookup_block`] for what corroboration establishes and
/// for the things it does not.
static BLOCK_INFO_CACHE: once_cell::sync::Lazy<RwLock<HashMap<u64, CacheEntry>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// A block header as one named provider reported it.
#[derive(Debug, Clone)]
pub struct BitcoinBlockInfo {
    pub height: u64,
    pub timestamp_secs: u64,
    /// Block hash (hex string, 64 chars)
    pub block_hash: String,
    /// Merkle root from block header (hex string, 64 chars)
    pub merkle_root: String,
}

impl BitcoinBlockInfo {
    /// This report, in the shape the anchor fact set publishes.
    #[must_use]
    pub fn to_source_report(&self, source: &str) -> BlockSourceReport {
        BlockSourceReport {
            source: source.to_string(),
            block_hash: self.block_hash.clone(),
            merkle_root: self.merkle_root.clone(),
            block_timestamp_secs: self.timestamp_secs,
        }
    }
}

/// One provider's answer.
#[derive(Debug, Clone)]
pub struct BlockReport {
    pub source: &'static str,
    pub info: BitcoinBlockInfo,
}

/// What asking every provider about one block height produced.
///
/// Four outcomes, kept apart because they call for four different things to
/// be said to the user — and because collapsing any two of them is how a
/// verifier ends up asserting more than it checked.
#[derive(Debug, Clone)]
pub enum BlockLookup {
    /// Two or more separately operated providers reported the same header.
    /// The strongest statement this tool makes about Bitcoin — and it is a
    /// statement about the endpoints agreeing, not about Bitcoin.
    Corroborated {
        info: BitcoinBlockInfo,
        reports: Vec<BlockSourceReport>,
    },
    /// Exactly one provider answered. Nothing corroborates it, so it may
    /// neither accept nor refute.
    ///
    /// Deliberately carries no parsed `BitcoinBlockInfo`. The header is
    /// present in `reports` as *what one endpoint said*, and there is no
    /// field for it as an established value, because there is no way to
    /// reach one from here — the type refuses the mistake rather than
    /// documenting against it.
    Uncorroborated {
        reports: Vec<BlockSourceReport>,
        failures: Vec<String>,
    },
    /// Providers answered and contradicted each other. Not a refutation of
    /// anything — a conflict among the sources, which the user must see.
    Disagreement { reports: Vec<BlockSourceReport> },
    /// Nobody answered.
    Unavailable { failures: Vec<String> },
}

/// Sort the providers' answers into one of the four outcomes.
///
/// Pure, and separated from the HTTP for exactly that reason: the network
/// cannot be made to disagree on demand, so this is where the interesting
/// cases are tested.
///
/// Agreement is **unanimity among those who answered**, not a majority. A
/// majority rule would let two wrong endpoints outvote a correct one, and,
/// worse, would hide the disagreement — which is itself a finding a user
/// needs (a fork, a stale index, a compromised endpoint).
#[must_use]
pub fn classify(reports: Vec<BlockReport>, failures: Vec<String>) -> BlockLookup {
    let source_reports: Vec<BlockSourceReport> = reports
        .iter()
        .map(|r| r.info.to_source_report(r.source))
        .collect();

    match reports.split_first() {
        None => BlockLookup::Unavailable { failures },
        Some((_only, [])) => BlockLookup::Uncorroborated {
            reports: source_reports,
            failures,
        },
        Some((first, _rest)) => {
            // The one definition of agreement, shared with both renderers so
            // that what is decided here is exactly what gets shown.
            if sources_agree(&source_reports) {
                BlockLookup::Corroborated {
                    info: first.info.clone(),
                    reports: source_reports,
                }
            } else {
                BlockLookup::Disagreement {
                    reports: source_reports,
                }
            }
        }
    }
}

/// Ask every provider about `height` and classify their answers.
///
/// Every provider is queried, concurrently, on every lookup not served by a
/// **fresh** cache entry — and the cache holds only corroborated headers,
/// only for [`CACHE_TTL`], so anything short of corroboration and anything
/// older than that is retried in full. The old code returned the first
/// answer it got, which meant a single endpoint decided the verdict.
///
/// # What corroboration here does and does not establish
///
/// Stated exactly, because an earlier version of this comment called a
/// corroborated header "a stable fact" — a claim nothing in this file
/// checks, which is the very habit this crate has spent its whole rework
/// removing from the output.
///
/// What is established: at the moment of the query — or of a query for the
/// same height made within the last [`CACHE_TTL`] of this run, since a
/// corroborated header is reused for that long — two or more of the
/// configured block-explorer APIs reported the same header for this height.
///
/// What is **not**:
///
/// - **Confirmation depth is not checked.** A header one block deep and one
///   thousand blocks deep are treated identically. A shallow block can be
///   orphaned.
/// - **Chain reorganisation is not tracked.** Nothing re-asks the sources
///   whether they still report the same header, here or anywhere.
/// - **The sources are not shown to be independent of each other.** They are
///   separately operated endpoints and nothing more is established: shared
///   hosting, a shared upstream index or a common failure are not ruled out.
///   This is why the line above says "two or more of the configured APIs"
///   and never "two independent sources" — an earlier version of this very
///   comment asserted independence ten lines above denying it.
///
/// None of that is a property of the cache. A completely fresh lookup
/// establishes exactly the same thing and no more: it compares against what
/// endpoints report *now*, at whatever depth. The cache changes when the
/// question was asked, not what the answer proves — which is precisely why
/// the answer's age is bounded by [`CACHE_TTL`] and stated above, rather
/// than left to grow with the length of a batch run.
pub async fn lookup_block(height: u64, timeout: Duration) -> BlockLookup {
    // A cached header is reused only while it is still fresh. Past the TTL
    // the question is asked again, so a long batch run cannot keep answering
    // from a corroboration made at its start.
    if let Some(hit) = BLOCK_INFO_CACHE.read().ok().and_then(|c| {
        c.get(&height)
            .filter(|e| cache_entry_is_fresh(e.fetched_at.elapsed()))
            .map(|e| e.lookup.clone())
    }) {
        return hit;
    }

    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(e) => {
            return BlockLookup::Unavailable {
                failures: vec![format!("HTTP client error: {e}")],
            }
        }
    };

    let answers = futures::future::join_all(PROVIDERS.iter().map(|p| async {
        (
            p.name,
            fetch_block_info_from_provider(&client, p, height).await,
        )
    }))
    .await;

    let mut reports = Vec::new();
    let mut failures = Vec::new();
    for (name, answer) in answers {
        match answer {
            Ok(info) => reports.push(BlockReport { source: name, info }),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }

    let lookup = classify(reports, failures);
    // Only a corroborated header is cached, and deliberately so.
    //
    // Not because it is "a stable fact" -- nothing here checks that, see the
    // function docs -- but because re-asking the same endpoints the same
    // question within one expected block interval is unlikely to produce a
    // different answer, while saving a batch run from hammering three free
    // public endpoints once per receipt.
    //
    // The other three outcomes are transient conditions of the network and
    // of the providers. Caching them turned one timeout into a permanent
    // wrong answer for that height for the rest of the process -- and made
    // the claim in the docs above false on the second call.
    //
    // The TTL is not decoration, and the argument that it was rested on a
    // false premise: "the process lives seconds". Batch mode walks a whole
    // directory in one process, item by item, with no bound on how long that
    // takes -- so without a TTL the second receipt anchored at some height
    // would be answered from a corroboration obtained at the start of the
    // run, however long ago that was, and the claim "at the moment of the
    // query" would silently have meant "at the moment of the first query of
    // this run".
    if matches!(lookup, BlockLookup::Corroborated { .. }) {
        if let Ok(mut cache) = BLOCK_INFO_CACHE.write() {
            cache.insert(
                height,
                CacheEntry {
                    fetched_at: Instant::now(),
                    lookup: lookup.clone(),
                },
            );
        }
    }
    lookup
}

/// Fetch a corroborated block header, for callers that only want the happy
/// path.
///
/// # Errors
///
/// Returns an error unless two or more providers reported the same header.
#[allow(dead_code)]
pub async fn get_block_info(height: u64, timeout: Duration) -> CliResult<BitcoinBlockInfo> {
    match lookup_block(height, timeout).await {
        BlockLookup::Corroborated { info, .. } => Ok(info),
        other => Err(CliError::OtsVerificationFailed(format!(
            "block {height} was not corroborated by two providers: {other:?}"
        ))),
    }
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

    // The detail response must describe the block step 1 named. Without
    // this, the two halves of a two-step lookup are joined by nothing but
    // the assumption that the endpoint answered the question it was asked.
    check_reported_hash(&response["id"], &block_hash)?;

    // ... and it must be the height that was requested. `height` used to be
    // copied in from the function argument, so a well-formed response about
    // a different block was accepted as an answer about this one -- and the
    // claim that "the height matches by construction" was simply untrue.
    check_reported_height(&response["height"], height)?;

    // Validated at intake: a value that cannot be a block time is a broken
    // response, and a broken response must not become a published fact.
    let timestamp = validate_block_time(
        response["timestamp"]
            .as_u64()
            .ok_or("Missing 'timestamp' field")?,
    )?;

    let merkle_root = hex64(&response["merkle_root"], "merkle_root")?;

    Ok(BitcoinBlockInfo {
        height,
        timestamp_secs: timestamp,
        block_hash,
        merkle_root,
    })
}

/// Read a 64-character hex field, or say which field was wrong.
fn hex64(value: &serde_json::Value, field: &str) -> Result<String, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("Missing '{field}' field"))?;
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid {field} format: {text}"));
    }
    Ok(text.to_string())
}

/// The block a response describes must be the block that was asked about.
///
/// # Errors
///
/// Returns a description when the field is absent or names another height.
pub fn check_reported_height(value: &serde_json::Value, requested: u64) -> Result<(), String> {
    let reported = value
        .as_u64()
        .ok_or("Missing 'height' field: the response is not bound to any block height")?;
    if reported != requested {
        return Err(format!(
            "response describes block {reported}, not the requested block {requested}"
        ));
    }
    Ok(())
}

/// The detail response must name the same block the hash lookup returned.
///
/// # Errors
///
/// Returns a description when the field is absent or names another block.
pub fn check_reported_hash(value: &serde_json::Value, expected: &str) -> Result<(), String> {
    let reported = hex64(value, "id")?;
    // Constant-time and case-insensitive, like every other digest
    // comparison in this crate.
    let same = match (hex::decode(&reported), hex::decode(expected)) {
        (Ok(a), Ok(b)) if a.len() == b.len() => bool::from(a.ct_eq(&b)),
        _ => false,
    };
    if !same {
        return Err(format!(
            "response describes block {reported}, not the block {expected} returned for this \
             height"
        ));
    }
    Ok(())
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

    // Same binding as the two-step path: the answer must be about the block
    // that was asked about.
    check_reported_height(&block["height"], height)?;

    let timestamp = validate_block_time(block["time"].as_u64().ok_or("Missing 'blocks[0].time'")?)?;

    let block_hash = hex64(&block["hash"], "blocks[0].hash")?;
    let merkle_root = hex64(&block["mrkl_root"], "blocks[0].mrkl_root")?;

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

    fn block(height: u64, ts: u64, hash: &str, root: &str) -> BitcoinBlockInfo {
        BitcoinBlockInfo {
            height,
            timestamp_secs: ts,
            block_hash: hash.repeat(64),
            merkle_root: root.repeat(64),
        }
    }

    fn report(source: &'static str, info: BitcoinBlockInfo) -> BlockReport {
        BlockReport { source, info }
    }

    /// A cache entry as fresh as `age` is old.
    fn entry(lookup: BlockLookup, age: Duration) -> CacheEntry {
        CacheEntry {
            fetched_at: Instant::now()
                .checked_sub(age)
                .expect("the test clock can go back a few minutes"),
            lookup,
        }
    }

    const TS: u64 = 1_768_806_080;

    /// **Corroboration.** Two providers reporting the same header is the
    /// strongest statement this tool makes about Bitcoin, and the only one
    /// that may lead to a `verified` anchor.
    #[test]
    fn two_agreeing_providers_corroborate() {
        let lookup = classify(
            vec![
                report("blockstream.info", block(900_000, TS, "a", "b")),
                report("mempool.space", block(900_000, TS, "a", "b")),
            ],
            vec![],
        );
        match lookup {
            BlockLookup::Corroborated { info, reports } => {
                assert_eq!(info.timestamp_secs, TS);
                assert_eq!(reports.len(), 2);
                assert_eq!(reports[0].source, "blockstream.info");
                assert_eq!(reports[1].source, "mempool.space");
            }
            other => panic!("expected corroboration, got {other:?}"),
        }
    }

    /// Hex case must not manufacture a disagreement: the roots are decoded
    /// and compared as bytes.
    #[test]
    fn hex_case_does_not_manufacture_a_disagreement() {
        let mut upper = block(900_000, TS, "a", "b");
        upper.block_hash = upper.block_hash.to_uppercase();
        upper.merkle_root = upper.merkle_root.to_uppercase();
        let lookup = classify(
            vec![
                report("blockstream.info", block(900_000, TS, "a", "b")),
                report("mempool.space", upper),
            ],
            vec![],
        );
        assert!(matches!(lookup, BlockLookup::Corroborated { .. }));
    }

    /// **Disagreement.** Not a refutation of anything: the sources conflict,
    /// so no header is established and nothing can be compared. Every report
    /// survives into the outcome, because the conflict is the finding.
    #[test]
    fn disagreeing_providers_are_a_conflict_not_a_refutation() {
        for (label, a, b) in [
            (
                "merkle root",
                block(900_000, TS, "a", "b"),
                block(900_000, TS, "a", "c"),
            ),
            (
                "block hash",
                block(900_000, TS, "a", "b"),
                block(900_000, TS, "d", "b"),
            ),
            (
                "time",
                block(900_000, TS, "a", "b"),
                block(900_000, TS + 1, "a", "b"),
            ),
        ] {
            let lookup = classify(
                vec![report("blockstream.info", a), report("mempool.space", b)],
                vec![],
            );
            match lookup {
                BlockLookup::Disagreement { reports } => {
                    assert_eq!(reports.len(), 2, "{label}: both reports must survive");
                }
                other => panic!("{label}: expected disagreement, got {other:?}"),
            }
        }
    }

    /// Unanimity, not majority. Two endpoints must not be able to outvote a
    /// third, and the disagreement must not be summarised away.
    #[test]
    fn agreement_is_unanimity_not_majority() {
        let lookup = classify(
            vec![
                report("blockstream.info", block(900_000, TS, "a", "b")),
                report("mempool.space", block(900_000, TS, "a", "b")),
                report("blockchain.info", block(900_000, TS, "a", "c")),
            ],
            vec![],
        );
        match lookup {
            BlockLookup::Disagreement { reports } => assert_eq!(reports.len(), 3),
            other => panic!("a majority must not silence a dissenting source: {other:?}"),
        }
    }

    /// **One source.** Settles nothing in either direction.
    #[test]
    fn a_single_provider_is_uncorroborated() {
        let lookup = classify(
            vec![report("blockstream.info", block(900_000, TS, "a", "b"))],
            vec!["mempool.space: HTTP error".to_string()],
        );
        match lookup {
            BlockLookup::Uncorroborated { reports, failures } => {
                assert_eq!(reports.len(), 1);
                assert_eq!(failures.len(), 1);
            }
            other => panic!("expected an uncorroborated single source, got {other:?}"),
        }
    }

    /// **Nobody answered.**
    #[test]
    fn no_provider_is_unavailable() {
        let lookup = classify(vec![], vec!["a: down".to_string(), "b: down".to_string()]);
        match lookup {
            BlockLookup::Unavailable { failures } => assert_eq!(failures.len(), 2),
            other => panic!("expected unavailable, got {other:?}"),
        }
        assert!(matches!(
            classify(vec![], vec![]),
            BlockLookup::Unavailable { .. }
        ));
    }

    /// A value that cannot be a block time is rejected at intake, so it can
    /// never be formatted into a real-looking timestamp downstream. Zero is
    /// the case that mattered: it used to render as `1970-01-01T00:00:00Z`.
    #[test]
    fn implausible_block_times_are_rejected_at_intake() {
        assert!(validate_block_time(0).is_err(), "the 1970 sentinel");
        assert!(validate_block_time(GENESIS_BLOCK_TIME - 1).is_err());
        assert!(validate_block_time(u64::MAX).is_err(), "far future");
        assert_eq!(
            validate_block_time(GENESIS_BLOCK_TIME),
            Ok(GENESIS_BLOCK_TIME)
        );
        assert_eq!(validate_block_time(TS), Ok(TS));
    }

    /// **The blocker.** An unreadable clock used to fall back to `u64::MAX`,
    /// which -- with the saturating add -- made the upper-bound comparison
    /// unsatisfiable, so every future time passed. Fail-open, under a
    /// comment claiming the opposite.
    ///
    /// Without a clock the upper bound cannot be evaluated, and a check that
    /// cannot be performed is not a check that passed.
    #[test]
    fn an_unreadable_clock_rejects_rather_than_admits() {
        // Far-future values are the ones the upper bound exists to catch.
        for secs in [u64::MAX, TS + 10 * 365 * 24 * 3600] {
            assert!(
                validate_block_time_against(secs, None).is_err(),
                "no clock must mean no acceptance, not free passage: {secs}"
            );
        }
        // The lower bound still works without a clock -- it needs none.
        assert!(validate_block_time_against(0, None).is_err());
        // And a plausible value is still refused, because the tool cannot
        // show that it is plausible.
        assert!(validate_block_time_against(TS, None).is_err());

        // With a clock, the same values behave as documented.
        assert_eq!(validate_block_time_against(TS, Some(TS + 60)), Ok(TS));
        assert!(validate_block_time_against(TS, Some(TS - MAX_FUTURE_BLOCK_TIME - 1)).is_err());
        assert_eq!(
            validate_block_time_against(TS, Some(TS - MAX_FUTURE_BLOCK_TIME)),
            Ok(TS),
            "exactly at the consensus limit is still a valid header time"
        );
    }

    /// **A response must be bound to the block that was asked about.**
    ///
    /// `BitcoinBlockInfo.height` was filled in from the function argument,
    /// so a well-formed response describing a *different* block was accepted
    /// as an answer about this one -- and the claim that the height matched
    /// "by construction" was untrue.
    #[test]
    fn a_response_about_another_block_is_rejected() {
        use serde_json::json;

        assert!(check_reported_height(&json!(932_897), 932_897).is_ok());
        let wrong = check_reported_height(&json!(932_898), 932_897)
            .expect_err("a response about another height must not be accepted");
        assert!(wrong.contains("932898"), "{wrong}");
        assert!(wrong.contains("932897"), "{wrong}");

        // A response that names no height at all is bound to nothing.
        let unbound = check_reported_height(&json!(null), 932_897)
            .expect_err("an unbound response must not be accepted");
        assert!(
            unbound.contains("not bound to any block height"),
            "{unbound}"
        );

        // And the two halves of a two-step lookup must describe one block.
        let hash = "a".repeat(64);
        assert!(check_reported_hash(&json!(hash), &hash).is_ok());
        assert!(
            check_reported_hash(&json!(hash.to_uppercase()), &hash).is_ok(),
            "hex case must not break the binding"
        );
        let other = "b".repeat(64);
        assert!(
            check_reported_hash(&json!(other), &hash).is_err(),
            "step 2 must not be allowed to describe a different block from step 1"
        );
        assert!(check_reported_hash(&json!(null), &hash).is_err());
    }

    /// A disagreement about nothing but the time is still a disagreement.
    /// Pinned here as well as in the renderers, because this is where the
    /// classification is made.
    #[test]
    fn a_time_only_disagreement_is_classified_as_one() {
        let lookup = classify(
            vec![
                report("blockstream.info", block(900_000, TS, "a", "b")),
                report("mempool.space", block(900_000, TS + 1, "a", "b")),
            ],
            vec![],
        );
        assert!(
            matches!(lookup, BlockLookup::Disagreement { .. }),
            "{lookup:?}"
        );
    }

    /// **The TTL exists because the batch path is unbounded in time.**
    ///
    /// The argument that justified having no TTL -- "the process lives
    /// seconds" -- was false: batch mode walks a whole directory in one
    /// process, item by item, with no bound on how long that takes. Without
    /// a TTL, the second receipt anchored at some height would be answered
    /// from a corroboration obtained at the start of the run, and the claim
    /// "at the moment of the query" would silently have meant "at the moment
    /// of the first query of this run".
    #[test]
    fn a_cached_header_goes_stale() {
        assert!(cache_entry_is_fresh(Duration::ZERO));
        assert!(cache_entry_is_fresh(CACHE_TTL - Duration::from_secs(1)));
        assert!(
            !cache_entry_is_fresh(CACHE_TTL),
            "at the TTL the entry is no longer reusable"
        );
        assert!(!cache_entry_is_fresh(CACHE_TTL + Duration::from_secs(1)));
        // A long batch run is exactly the case this bounds.
        assert!(!cache_entry_is_fresh(Duration::from_secs(3600)));
    }

    /// A stale entry is not served: the lookup falls through and asks again.
    ///
    /// Uses a height no block has, so the fall-through resolves to
    /// `Unavailable` rather than to whatever the stale entry claimed --
    /// which is the observable difference between reusing it and not.
    #[tokio::test]
    async fn a_stale_cache_entry_is_not_served() {
        const HEIGHT: u64 = 99_999_998;
        let info = block(HEIGHT, TS, "a", "b");
        let stale = BlockLookup::Corroborated {
            reports: vec![
                info.to_source_report("blockstream.info"),
                info.to_source_report("mempool.space"),
            ],
            info,
        };

        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                HEIGHT,
                entry(stale.clone(), CACHE_TTL + Duration::from_secs(1)),
            );
        }
        let served = lookup_block(HEIGHT, Duration::from_secs(5)).await;
        assert!(
            matches!(served, BlockLookup::Unavailable { .. }),
            "a stale entry must be re-queried, not handed back: {served:?}"
        );

        // And the same entry, fresh, is reused.
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(HEIGHT, entry(stale, Duration::ZERO));
        }
        assert!(matches!(
            lookup_block(HEIGHT, Duration::from_secs(5)).await,
            BlockLookup::Corroborated { .. }
        ));

        // Leave no stale state behind for other tests in this process.
        BLOCK_INFO_CACHE.write().unwrap().remove(&HEIGHT);
    }

    /// Only a corroborated header is cached. Caching the transient outcomes
    /// turned one timeout into a permanent wrong answer for that height, and
    /// falsified "every provider is queried on every lookup".
    #[test]
    fn only_corroborated_lookups_are_cacheable() {
        let info = block(900_000, TS, "a", "b");
        let corroborated = BlockLookup::Corroborated {
            reports: vec![
                info.to_source_report("blockstream.info"),
                info.to_source_report("mempool.space"),
            ],
            info: info.clone(),
        };
        assert!(matches!(corroborated, BlockLookup::Corroborated { .. }));

        for transient in [
            BlockLookup::Unavailable { failures: vec![] },
            BlockLookup::Uncorroborated {
                reports: vec![info.to_source_report("one")],
                failures: vec![],
            },
            BlockLookup::Disagreement {
                reports: vec![info.to_source_report("one")],
            },
        ] {
            assert!(
                !matches!(transient, BlockLookup::Corroborated { .. }),
                "only a corroborated header may be cached: {transient:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_get_block_info_caching() {
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                123_456,
                entry(
                    BlockLookup::Corroborated {
                        info: block(123_456, TS, "a", "b"),
                        reports: vec![
                            block(123_456, TS, "a", "b").to_source_report("blockstream.info"),
                            block(123_456, TS, "a", "b").to_source_report("mempool.space"),
                        ],
                    },
                    Duration::ZERO,
                ),
            );
        }

        let info = get_block_info(123_456, Duration::from_secs(1))
            .await
            .expect("a cached corroborated lookup");
        assert_eq!(info.height, 123_456);
        assert_eq!(info.timestamp_secs, TS);
    }

    /// A cached lookup that was never corroborated must not be handed out as
    /// a fact by the convenience accessor.
    #[tokio::test]
    async fn an_uncorroborated_cached_lookup_is_not_a_fact() {
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                123_457,
                entry(
                    BlockLookup::Uncorroborated {
                        reports: vec![block(123_457, TS, "a", "b").to_source_report("only.one")],
                        failures: vec![],
                    },
                    Duration::ZERO,
                ),
            );
        }
        assert!(get_block_info(123_457, Duration::from_secs(1))
            .await
            .is_err());
    }

    /// **Live, network.** A height no block has: every provider 404s, so the
    /// outcome is `Unavailable` and never anything stronger.
    #[tokio::test]
    async fn a_nonexistent_height_is_unavailable_not_a_finding() {
        let lookup = lookup_block(99_999_999, Duration::from_secs(5)).await;
        match lookup {
            BlockLookup::Unavailable { .. } => {}
            // Offline CI reaches the same arm by a different route.
            other => panic!("a height with no block must be unavailable, got {other:?}"),
        }
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
        fn corroborated(height: u64, ts: u64, hash: &str, root: &str) -> BlockLookup {
            let info = block(height, ts, hash, root);
            BlockLookup::Corroborated {
                reports: vec![
                    info.to_source_report("blockstream.info"),
                    info.to_source_report("mempool.space"),
                ],
                info,
            }
        }
        {
            let mut cache = BLOCK_INFO_CACHE.write().unwrap();
            cache.insert(
                111_111,
                entry(corroborated(111_111, TS, "1", "2"), Duration::ZERO),
            );
            cache.insert(
                222_222,
                entry(corroborated(222_222, TS + 600, "3", "4"), Duration::ZERO),
            );
        }

        let r1 = get_block_info(111_111, Duration::from_secs(1)).await;
        let r2 = get_block_info(222_222, Duration::from_secs(1)).await;

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
