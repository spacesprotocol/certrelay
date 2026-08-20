//! HTTP routes for the relay server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use governor::RateLimiter;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use libveritas::msg::Message;
use tokio::sync::Mutex;

pub use governor::Quota;
pub use resolver::{Announcement, EpochHint, PeerInfo, Query, QueryRequest};
use spaces_nums::ChainProofRequest;

use crate::handler::Handler;
use crate::peer::{PeerConfig, PeerTable};
use crate::spaced::SpacedClient;

/// Per-IP rate limiter type alias.
pub type IpRateLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

/// Configuration for rate limits.
///
/// Buckets follow the cheap/expensive split: `read` covers indexed lookups,
/// `proof` covers endpoints that trigger proof generation.
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Quota for /message (client publish intake)
    pub message: Quota,
    /// Quota for /query and /chain-proof (both trigger proof generation)
    pub proof: Quota,
    /// Quota for cheap reads: /hints, /reverse, /addrs, /anchors, /peers
    pub read: Quota,
    /// Quota for /announce
    pub announce: Quota,
    /// Quota for /sync and /sync/summary (pages are the unit)
    pub sync: Quota,
    /// Quota for /poke
    pub poke: Quota,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            message: Quota::per_minute(NonZeroU32::new(60).unwrap()),
            proof: Quota::per_minute(NonZeroU32::new(30).unwrap()),
            read: Quota::per_minute(NonZeroU32::new(120).unwrap()),
            announce: Quota::per_minute(NonZeroU32::new(5).unwrap()),
            sync: Quota::per_minute(NonZeroU32::new(60).unwrap()),
            poke: Quota::per_minute(NonZeroU32::new(30).unwrap()),
        }
    }
}

/// Rate limiters for each endpoint type.
pub struct RateLimiters {
    pub message: Arc<IpRateLimiter>,
    pub proof: Arc<IpRateLimiter>,
    pub read: Arc<IpRateLimiter>,
    pub announce: Arc<IpRateLimiter>,
    pub sync: Arc<IpRateLimiter>,
    pub poke: Arc<IpRateLimiter>,
}

impl RateLimiters {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            message: Arc::new(RateLimiter::dashmap(config.message)),
            proof: Arc::new(RateLimiter::dashmap(config.proof)),
            read: Arc::new(RateLimiter::dashmap(config.read)),
            announce: Arc::new(RateLimiter::dashmap(config.announce)),
            sync: Arc::new(RateLimiter::dashmap(config.sync)),
            poke: Arc::new(RateLimiter::dashmap(config.poke)),
        }
    }

    /// Evict stale per-IP entries; call periodically or the maps grow forever.
    pub fn cleanup(&self) {
        for limiter in [
            &self.message,
            &self.proof,
            &self.read,
            &self.announce,
            &self.sync,
            &self.poke,
        ] {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }
}

/// Default max message size (512 KB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 512 * 1024;

/// Connect timeout for outbound requests to peers.
pub const OUTBOUND_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Total timeout for outbound requests to peers.
pub const OUTBOUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Max bytes accepted when reading a peer's /peers response.
pub const MAX_PEERS_RESPONSE_SIZE: usize = 64 * 1024;
/// Max peer entries processed from a single /peers response.
pub const MAX_PEERS_PER_RESPONSE: usize = 256;

/// Max rows in one /sync page.
pub const MAX_SYNC_PAGE_ROWS: usize = 1000;
/// Soft byte cap for one /sync page (stops adding rows once exceeded).
pub const MAX_SYNC_PAGE_BYTES: usize = 2 * 1024 * 1024;

/// Concurrent chain-proof generations (global, identity-independent cap).
pub const PROOF_CONCURRENCY: usize = 6;
/// Concurrent message verifications (global, identity-independent cap).
pub const VERIFY_CONCURRENCY: usize = 4;

/// Default bootstrap relay URLs.
pub const BOOTSTRAP_RELAYS: &[&str] = &[
    "https://relay-cosmos.spacesprotocol.org",
    "https://relay-atlas.spacesprotocol.org",
    "http://70.251.209.207:47778",
];

/// Shared application state.
pub struct AppState {
    pub handler: Handler,
    pub chain: SpacedClient,
    pub peers: Mutex<PeerTable>,
    pub limiters: RateLimiters,
    pub max_message_size: usize,
    pub http_client: reqwest::Client,
    /// Our own URL for announcements (if set)
    pub self_url: Option<String>,
    /// Our capabilities
    pub capabilities: u32,
    /// If true, we are a bootstrap node and skip bootstrapping from others
    pub is_bootstrap: bool,
    /// HTTP header to read the client IP from (e.g. "x-forwarded-for", "cf-connecting-ip").
    /// If None, uses the socket address directly.
    pub remote_ip_header: Option<String>,
    /// Accept peers with private/loopback addresses (local development and tests).
    pub allow_private_peers: bool,
    /// Signal that new data was stored — wakes the poke-send loop, which
    /// coalesces bursts into one poke per peer per debounce window.
    pub poke_dirty: tokio::sync::Notify,
    /// Queue of peer URLs to sync with soon (fed by validated /poke requests,
    /// drained by the poke-sync loop with per-peer cooldowns).
    pub poke_sync_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Receiver half, taken once by the poke-sync loop.
    pub poke_sync_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    /// Global cap on concurrent proof generation. HTTP handlers try-acquire
    /// and return 503 when saturated; background sync waits its turn.
    pub proof_sem: Arc<tokio::sync::Semaphore>,
    /// Global cap on concurrent message verification (CPU-bound).
    pub verify_sem: Arc<tokio::sync::Semaphore>,
    /// Observability counters served by GET /stats.
    pub stats: crate::stats::Stats,
    /// Retention policy (storage budget + entitlement) for the admission
    /// gate and eviction sweep.
    pub retention: crate::retention::RetentionConfig,
    /// Approximate recently-queried handles, spared during eviction.
    pub query_heat: std::sync::Mutex<crate::retention::QueryHeat>,
    /// Long-lived signing key used to sign the anchor root we serve. `None`
    /// when no key has been provisioned (e.g. in tests); then `X-Anchor-Sig`
    /// is simply omitted.
    pub identity: Option<crate::identity::RelayIdentity>,
    /// Cached signature over the current `(anchor root, height)`. Recomputed by
    /// the anchor refresh only when the pair changes, so steady-state requests
    /// never re-sign.
    pub anchor_sig: std::sync::Mutex<Option<crate::identity::AnchorSig>>,
}

impl AppState {
    pub fn new(handler: Handler, chain: SpacedClient, peer_config: PeerConfig) -> Self {
        Self::with_rate_limits(handler, chain, peer_config, RateLimitConfig::default())
    }

    pub fn with_rate_limits(
        handler: Handler,
        chain: SpacedClient,
        peer_config: PeerConfig,
        rate_config: RateLimitConfig,
    ) -> Self {
        let (poke_sync_tx, poke_sync_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            handler,
            chain,
            peers: Mutex::new(PeerTable::new(peer_config)),
            limiters: RateLimiters::new(&rate_config),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            http_client: outbound_client_builder()
                .build()
                .expect("failed to build http client"),
            self_url: None,
            capabilities: 0,
            is_bootstrap: false,
            remote_ip_header: None,
            allow_private_peers: false,
            poke_dirty: tokio::sync::Notify::new(),
            poke_sync_tx,
            poke_sync_rx: Mutex::new(Some(poke_sync_rx)),
            proof_sem: Arc::new(tokio::sync::Semaphore::new(PROOF_CONCURRENCY)),
            verify_sem: Arc::new(tokio::sync::Semaphore::new(VERIFY_CONCURRENCY)),
            stats: crate::stats::Stats::default(),
            retention: crate::retention::RetentionConfig::default(),
            query_heat: std::sync::Mutex::new(crate::retention::QueryHeat::default()),
            identity: None,
            anchor_sig: std::sync::Mutex::new(None),
        }
    }

    pub fn with_self_url(mut self, url: String) -> Self {
        self.peers.get_mut().set_self_url(&url);
        self.self_url = Some(url);
        self
    }

    /// Client for contacting a peer URL with the address policy enforced at
    /// connection time. For DNS-named peers the host is resolved, every
    /// address checked against the IP policy, and the vetted addresses pinned
    /// into the client — closing the resolve-then-fetch TOCTOU (DNS
    /// rebinding). IP-literal peers already passed the syntactic policy, so
    /// the shared client is used. Errors mean the peer's address is not
    /// allowed (or unresolvable) and it should not be contacted.
    pub async fn peer_client(&self, url: &str) -> anyhow::Result<reqwest::Client> {
        if self.allow_private_peers {
            return Ok(self.http_client.clone());
        }
        crate::peer::validate_peer_url(url, false).map_err(|e| anyhow::anyhow!(e))?;
        let parsed = url::Url::parse(url)?;
        match parsed.host() {
            Some(url::Host::Domain(domain)) => {
                let port = parsed.port_or_known_default().unwrap_or(443);
                let addrs: Vec<SocketAddr> =
                    tokio::net::lookup_host((domain, port)).await?.collect();
                if addrs.is_empty() {
                    anyhow::bail!("peer host did not resolve: {}", url);
                }
                if !addrs.iter().all(|a| crate::peer::ip_is_public(&a.ip())) {
                    anyhow::bail!("peer resolves to a disallowed address: {}", url);
                }
                Ok(outbound_client_builder()
                    .resolve_to_addrs(domain, &addrs)
                    .build()?)
            }
            Some(_) => Ok(self.http_client.clone()),
            None => anyhow::bail!("peer url has no host: {}", url),
        }
    }
}

/// Base builder for all peer-facing clients: bounded timeouts and **no
/// redirect following** — a 302 from a peer must never steer a request at
/// internal services (spaced/yuki RPC, cloud metadata).
fn outbound_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(OUTBOUND_CONNECT_TIMEOUT)
        .timeout(OUTBOUND_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
}

/// Build the router with all routes.
pub fn router(state: Arc<AppState>) -> Router {
    let cors = tower_http::cors::CorsLayer::permissive();

    Router::new()
        .route("/message", post(handle_message))
        .route("/announce", post(handle_announce))
        .route("/peers", get(handle_peers))
        .route("/query", get(handle_query))
        .route("/anchors", get(handle_anchors))
        .route("/hints", get(handle_hints))
        .route("/chain-proof", post(handle_chain_proof))
        .route("/reverse", get(handle_reverse))
        .route("/addrs", get(handle_addrs))
        .route("/sync", get(handle_sync))
        .route("/sync/summary", get(handle_sync_summary))
        .route("/poke", post(handle_poke))
        .route("/health", get(handle_health))
        .route("/stats", get(handle_stats))
        .layer(axum::middleware::from_fn(version_header))
        .layer(cors)
        .with_state(state)
}

/// Stamp `X-Certrelay-Version` on every response. The value is `CARGO_PKG_VERSION`
/// at compile time — i.e. whatever release-plz bumped the crate to — so it needs
/// no manual upkeep and lets clients see which build a relay is running.
async fn version_header(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "x-certrelay-version",
        axum::http::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    resp
}

/// Extract the client IP from the configured header, falling back to socket address.
///
/// If `remote_ip_header` is set, reads that header and parses the **last** IP.
/// For append-style headers (X-Forwarded-For) the rightmost entry is the one
/// written by our own trusted proxy — leftmost entries are client-controlled
/// and would let anyone rotate fake IPs past the per-IP limits. Single-value
/// overwrite headers (CF-Connecting-IP) are unaffected.
fn client_ip(addr: &SocketAddr, headers: &HeaderMap, header_name: &Option<String>) -> IpAddr {
    if let Some(name) = header_name
        && let Some(value) = headers.get(name.as_str()).and_then(|v| v.to_str().ok())
    {
        let last = value.rsplit(',').next().unwrap_or("").trim();
        if let Ok(ip) = last.parse::<IpAddr>() {
            return ip;
        }
    }
    addr.ip()
}

/// POST /message - Receive and process a certificate message.
///
/// Body: borsh-encoded Message
/// On success: verifies and stores. Never forwards to peers — propagation is
/// pull-based (peers sync from us).
async fn handle_message(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    crate::stats::bump(&state.stats.messages_received);
    if state.limiters.message.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_message);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited".to_string());
    }

    if body.len() > state.max_message_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "message too large".to_string(),
        );
    }

    // Deserialize the message
    let msg: Message = match Message::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("failed to deserialize message: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                "invalid message format".to_string(),
            );
        }
    };

    // Global verify cap: shed load instead of queueing unbounded CPU work
    let Ok(_permit) = Arc::clone(&state.verify_sem).try_acquire_owned() else {
        crate::stats::bump(&state.stats.busy_rejections);
        return (StatusCode::SERVICE_UNAVAILABLE, "busy".to_string());
    };

    // Retention admission gate: under storage pressure, spaces over their
    // entitlement accept no new handles (updates still pass).
    let mut gated_spaces = std::collections::HashSet::new();
    for bundle in &msg.spaces {
        let space = bundle.subject.to_string();
        if !gated_spaces.contains(&space)
            && crate::retention::first_insert_gated(&state, &state.retention, &space)
                .unwrap_or(false)
        {
            gated_spaces.insert(space);
        }
    }

    // Verify and store on the blocking pool: ZK receipt verification is
    // CPU-bound and must not stall the async runtime.
    let blocking_state = Arc::clone(&state);
    let result = tokio::task::spawn_blocking(move || {
        blocking_state
            .handler
            .handle_message_gated(msg, &gated_spaces)
    })
    .await;
    match result {
        Ok(Ok(result)) => {
            crate::stats::bump_by(&state.stats.admission_gated, result.gated as u64);
            if result.stored > 0 {
                crate::stats::bump(&state.stats.messages_accepted);
                state.poke_dirty.notify_one();
            } else {
                crate::stats::bump(&state.stats.messages_deduped);
            }
        }
        Ok(Err(e)) => {
            crate::stats::bump(&state.stats.messages_rejected);
            tracing::warn!("failed to handle message: {}", e);
            return (StatusCode::BAD_REQUEST, format!("rejected: {}", e));
        }
        Err(e) => {
            tracing::error!("message verification task failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            );
        }
    }

    (StatusCode::OK, "ok".to_string())
}

/// GET/HEAD /health - Unmetered liveness check (peer health checks and load
/// balancers target this so they never contend with rate-limited endpoints).
async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// GET /stats - Observability counters (JSON), plus live peer/semaphore state.
async fn handle_stats(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let mut snapshot = state.stats.snapshot();
    let (verified, unverified) = {
        let peers = state.peers.lock().await;
        (peers.verified_count(), peers.unverified_count())
    };
    snapshot["peers"] = serde_json::json!({
        "verified": verified,
        "unverified": unverified,
    });
    if let Ok((rows, bytes)) = state.handler.store.storage_totals() {
        snapshot["storage"] = serde_json::json!({
            "rows": rows,
            "bytes": bytes,
            "budget_bytes": state.retention.max_storage_bytes,
        });
    }
    snapshot["concurrency"] = serde_json::json!({
        "proof_permits_available": state.proof_sem.available_permits(),
        "verify_permits_available": state.verify_sem.available_permits(),
    });
    // Report the running version (whatever release-plz stamped into the crate)
    // and the anchor-signing pubkey, so operators/clients can read both here.
    snapshot["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    if let Some(identity) = &state.identity {
        snapshot["anchor_pubkey"] = serde_json::json!(identity.public_key_hex());
    }
    axum::Json(snapshot).into_response()
}

/// POST /poke - A peer signals it has new data; schedule a pull from it.
///
/// Body: JSON [`resolver::Poke`]. Content-free fast propagation: the poke
/// carries no records, only "pull me." Only verified peers are acted on, a
/// cursor at or behind our watermark is dropped, and the actual pull runs
/// through the same rate-paced sync path as the interval loop — so a poke
/// flood cannot make us do more work than the steady-state maximum.
async fn handle_poke(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.poke.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_poke);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }

    crate::stats::bump(&state.stats.pokes_received);
    let poke: resolver::Poke = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid poke format"),
    };
    if poke.url.len() > 256 {
        return (StatusCode::BAD_REQUEST, "invalid url");
    }
    // Normalize before ANY keyed use: https://x, https://x/, https://x// all
    // pass verification but would otherwise be distinct watermark/cooldown
    // keys, bypassing the cursor dedup and per-peer cooldown.
    let poke_url = crate::peer::normalize_url(&poke.url);
    let Ok(cursor) = poke.cursor.parse::<resolver::SyncCursor>() else {
        return (StatusCode::BAD_REQUEST, "invalid cursor");
    };

    // Poke is not discovery: act only on peers we already verified.
    // Respond "ok" either way so the response doesn't leak table membership.
    if !state.peers.lock().await.is_verified(&poke_url) {
        return (StatusCode::OK, "ok");
    }

    // Claimed-cursor dedup: at or behind our watermark means nothing new.
    // (Watermarks only ever advance from real sync pages, never from here.)
    let watermark = state
        .handler
        .store
        .get_watermark(&poke_url)
        .ok()
        .flatten()
        .and_then(|c| c.parse::<resolver::SyncCursor>().ok());
    if watermark.is_some_and(|w| cursor <= w) {
        return (StatusCode::OK, "ok");
    }

    crate::stats::bump(&state.stats.pokes_accepted);
    let _ = state.poke_sync_tx.send(poke_url);
    (StatusCode::OK, "ok")
}

/// POST /announce - Announce a peer URL with capabilities.
///
/// Body: JSON Announcement { url, capabilities }
async fn handle_announce(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.announce.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_announce);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }

    let announcement: Announcement = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("failed to deserialize announcement: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid announcement format");
        }
    };

    if announcement.url.is_empty() || announcement.url.len() > 256 {
        return (StatusCode::BAD_REQUEST, "invalid url");
    }
    if let Err(reason) =
        crate::peer::validate_peer_url(&announcement.url, state.allow_private_peers)
    {
        tracing::debug!("rejected announce {}: {}", announcement.url, reason);
        return (StatusCode::BAD_REQUEST, reason);
    }

    let peer = PeerInfo {
        source_ip: ip,
        url: announcement.url.clone(),
        capabilities: announcement.capabilities,
    };
    let mut peers = state.peers.lock().await;
    let result = peers.announce(&peer);
    tracing::debug!(
        "announce from {}: {} (caps: {}) -> {:?}",
        peer.source_ip,
        peer.url,
        peer.capabilities,
        result
    );

    (StatusCode::OK, "ok")
}

/// GET /peers - Get list of verified peers with their info.
///
/// Returns: JSON array of PeerInfo
async fn handle_peers(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let peers = state.peers.lock().await;
    let peer_list = peers.peers_info();
    drop(peers);

    axum::Json(peer_list).into_response()
}

/// POST /query - Query for certificates.
///
/// Query params:
///   `q` — comma-separated handles (e.g. `alice@bitcoin,bob@bitcoin,@bitcoin`)
///   `hints` — optional comma-separated epoch hints (e.g. `@bitcoin:abcdef:870000`)
/// Returns: binary borsh-encoded Message with certificates and proofs
/// Whether an `If-None-Match` header matches our ETag (handles lists, `*`, and
/// weak `W/` prefixes).
fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    if_none_match == "*"
        || if_none_match.split(',').any(|t| {
            let t = t.trim();
            t == etag
                || t.strip_prefix("W/")
                    .map(|w| w.trim() == etag)
                    .unwrap_or(false)
        })
}

/// Cheap content version for a `/query` response: hashes each covered handle's
/// stored `zone_hash` (parent spaces + requested sub-handles). It changes on
/// create / delete / record / commitment updates but NOT merely because a new
/// block re-anchored the proof — so an unchanged query can answer `304` and skip
/// proof generation, while the client's older-but-still-valid proof stays usable
/// (anchors are cumulative). Returns `None` if the version lookup fails.
fn query_etag(store: &crate::store::SqliteStore, sorted_handles: &[String]) -> Option<String> {
    use sha2::Digest;
    let refs: Vec<&str> = sorted_handles.iter().map(|s| s.as_str()).collect();
    let rows = store.get_handle_hints(&refs).ok()?;
    let present: HashMap<&str, &[u8]> = rows
        .iter()
        .map(|r| (r.handle.as_str(), r.zone_hash.as_slice()))
        .collect();
    let mut h = sha2::Sha256::new();
    for handle in sorted_handles {
        h.update(handle.as_bytes());
        h.update([0u8]);
        match present.get(handle.as_str()) {
            Some(zh) => h.update(zh),
            None => h.update(b"absent"),
        }
        h.update([0xffu8]);
    }
    Some(format!("\"{}\"", hex::encode(h.finalize())))
}

async fn handle_query(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    // Cheap read gate covers every /query — including conditional 304s and the
    // zone-hash lookup below. Proof generation has its own stricter gate,
    // charged only on a cache miss just before the proof is built.
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, vec![]).into_response();
    }

    let q = match params.get("q") {
        Some(q) if !q.is_empty() => q,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "missing q parameter".as_bytes().to_vec(),
            )
                .into_response();
        }
    };

    let handles: Vec<&str> = q
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    // Requested handles are "hot": spared during retention eviction.
    {
        let mut heat = state.query_heat.lock().unwrap();
        for h in &handles {
            heat.touch(h);
        }
    }

    const MAX_HANDLES: usize = 6;
    if handles.len() > MAX_HANDLES {
        return (
            StatusCode::BAD_REQUEST,
            "too many handles (max 6)".as_bytes().to_vec(),
        )
            .into_response();
    }

    // Parse epoch hints: "space:root_hex:height,space:root_hex:height"
    let mut hint_map: HashMap<String, EpochHint> = HashMap::new();
    if let Some(hints_str) = params.get("hints") {
        for part in hints_str.split(',') {
            let segments: Vec<&str> = part.splitn(3, ':').collect();
            if segments.len() == 3
                && let Ok(height) = segments[2].parse::<u32>()
            {
                hint_map.insert(
                    segments[0].to_string(),
                    EpochHint {
                        root: segments[1].to_string(),
                        height,
                    },
                );
            }
        }
    }

    // Group handles by space
    let mut by_space: HashMap<String, Vec<String>> = HashMap::new();
    for handle in &handles {
        let sep = handle.find(['@', '#']);
        let (space, label) = match sep {
            Some(0) => (handle.to_string(), String::new()),
            Some(i) => (handle[i..].to_string(), handle[..i].to_string()),
            None => continue,
        };
        by_space.entry(space).or_default().push(label);
    }

    // Content version (parent spaces + requested sub-handles) for conditional
    // requests. Computed from cheap zone_hash lookups, before proof generation.
    let mut version_handles: Vec<String> = Vec::new();
    for (space, labels) in &by_space {
        version_handles.push(space.clone());
        for l in labels {
            if !l.is_empty() {
                version_handles.push(format!("{l}{space}"));
            }
        }
    }
    version_handles.sort();
    version_handles.dedup();
    let etag = query_etag(&state.handler.store, &version_handles);

    let queries: Vec<Query> = by_space
        .into_iter()
        .map(|(space, labels)| {
            let filtered: Vec<String> = labels.into_iter().filter(|l| !l.is_empty()).collect();
            let mut q = Query::new(space.clone(), filtered);
            if let Some(hint) = hint_map.remove(&space) {
                q = q.with_epoch_hint(hint);
            }
            q
        })
        .collect();

    let mut resp_headers = HeaderMap::new();
    // Short TTL: an unchanged repeat within the window is served from the
    // client's cache with no request; after it lapses the ETag makes
    // revalidation cheap — a 304 skips proof generation entirely.
    resp_headers.insert("cache-control", "public, max-age=5".parse().unwrap());
    if let Some(ref etag) = etag {
        if let Ok(v) = etag.parse() {
            resp_headers.insert("etag", v);
        }
        // If the covered zones are unchanged, don't regenerate the proof.
        if headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|inm| etag_matches(inm, etag))
        {
            return (StatusCode::NOT_MODIFIED, resp_headers).into_response();
        }
    }

    // Cache miss: this request will generate a proof, so charge the stricter
    // proof budget now (304s and cache hits above never reach here).
    if state.limiters.proof.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_proof);
        return (StatusCode::TOO_MANY_REQUESTS, vec![]).into_response();
    }

    // Global proof cap: shed load instead of queueing proof generation
    let Ok(_permit) = state.proof_sem.try_acquire() else {
        crate::stats::bump(&state.stats.busy_rejections);
        return (StatusCode::SERVICE_UNAVAILABLE, vec![]).into_response();
    };

    match state.handler.resolve(&state.chain, queries).await {
        Ok(msg) => {
            crate::stats::bump(&state.stats.proofs_served);
            (resp_headers, msg.to_bytes()).into_response()
        }
        Err(e) => {
            tracing::warn!("failed to resolve query: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, vec![]).into_response()
        }
    }
}

/// GET /anchors - Get anchor set as JSON.
///
/// Without query params, returns the most up-to-date anchor set.
/// With `?root=<hex>`, returns the anchor set matching that root hash.
///
/// Response includes `X-Anchor-Root` and `X-Anchor-Height` headers for the latest
/// anchor set. Clients can use HEAD to cheaply compare across peers.
async fn handle_anchors(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let store = state.handler.anchor_store.lock().unwrap();

    let mut headers = HeaderMap::new();
    if let Some(latest) = store.latest() {
        // Anchors are canonically newest-first, so the tip is the first entry.
        // `.last()` here reported the oldest anchor in the window as the height.
        let height = latest.tip_height();
        let trust_set = libveritas::compute_trust_set(&latest.entries);
        if let Ok(v) = hex::encode(trust_set.id).parse() {
            headers.insert("x-anchor-root", v);
        }
        if let Ok(v) = height.to_string().parse() {
            headers.insert("x-anchor-height", v);
        }
        // End-to-end signature over the root so a client that pins this relay's
        // key can trust the root even when TLS terminates at a proxy. The
        // public key is advertised for discovery, but clients MUST pin it
        // out-of-band rather than trust whatever the header claims. Attach the
        // signature only when the cache matches the root/height we're reporting
        // — a refresh in flight can briefly lag, and no sig beats a stale one.
        if let Some(identity) = &state.identity {
            if let Ok(v) = identity.public_key_hex().parse() {
                headers.insert("x-anchor-pubkey", v);
            }
            if let Some(sig) = state.anchor_sig.lock().unwrap().as_ref()
                && sig.trust_id == trust_set.id
                && sig.height == height
                && let Ok(v) = hex::encode(sig.sig).parse()
            {
                headers.insert("x-anchor-sig", v);
            }
        }
    }

    let set = match params.get("root") {
        Some(hex_root) => {
            let bytes: Vec<u8> = match hex::decode(hex_root) {
                Ok(b) => b,
                Err(_) => return (StatusCode::BAD_REQUEST, headers, "invalid hex").into_response(),
            };
            let root: [u8; 32] = match bytes.try_into() {
                Ok(r) => r,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, headers, "root must be 32 bytes")
                        .into_response();
                }
            };
            store.get(resolver::TrustId::from(root)).cloned()
        }
        None => store.latest().cloned(),
    };

    match set {
        Some(resp) => {
            headers.insert("cache-control", "public, max-age=300".parse().unwrap());
            (headers, axum::Json(resp)).into_response()
        }
        None => (StatusCode::NOT_FOUND, headers, "anchor set not found").into_response(),
    }
}

/// GET /hints?q=alice@bitcoin,bob@bitcoin,@bitcoin - Lightweight freshness hints.
///
/// Returns epoch heights and offchain seq numbers without blob deserialization.
async fn handle_hints(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let q = match params.get("q") {
        Some(q) if !q.is_empty() => q,
        _ => return (StatusCode::BAD_REQUEST, "missing q parameter").into_response(),
    };

    let mut handles: Vec<&str> = q
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if handles.len() > 6 {
        return (StatusCode::BAD_REQUEST, "too many handles (max 6)").into_response();
    }

    match state.handler.hints(&mut handles) {
        Ok(res) => {
            let mut headers = HeaderMap::new();
            // The freshness oracle. A short 5s TTL matches /query and sheds
            // repeat load, while keeping staleness small enough that a hint
            // won't mask a change for long (was 300s, which defeated ranking
            // and /query's ETag revalidation).
            headers.insert("cache-control", "public, max-age=5".parse().unwrap());
            (headers, axum::Json(res)).into_response()
        }
        Err(e) => {
            tracing::warn!("hints failed: {}", e);
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
    }
}

/// GET /reverse?ids=num1,num2,... - Look up reverse records for numeric identities.
///
/// Returns: JSON array of { id, name } objects.
async fn handle_reverse(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let ids = match params.get("ids") {
        Some(ids) if !ids.is_empty() => ids,
        _ => return (StatusCode::BAD_REQUEST, "missing ids parameter").into_response(),
    };

    let id_list: Vec<&str> = ids
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if id_list.len() > 20 {
        return (StatusCode::BAD_REQUEST, "too many ids (max 20)").into_response();
    }

    match state.handler.store.get_revs(&id_list) {
        Ok(records) => {
            let mut headers = HeaderMap::new();
            headers.insert("cache-control", "public, max-age=300".parse().unwrap());
            (headers, axum::Json(records)).into_response()
        }
        Err(e) => {
            tracing::warn!("reverse lookup failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response()
        }
    }
}

/// GET /addrs?name=btc&addr=bc1q... - Look up handles by address.
///
/// Returns: JSON { address, handles } object.
async fn handle_addrs(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.read.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_read);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let name = match params.get("name") {
        Some(n) if !n.is_empty() => n,
        _ => return (StatusCode::BAD_REQUEST, "missing name parameter").into_response(),
    };
    let address = match params.get("addr") {
        Some(a) if !a.is_empty() => a,
        _ => return (StatusCode::BAD_REQUEST, "missing addr parameter").into_response(),
    };

    match state.handler.store.get_addrs(name, address) {
        Ok(pairs) => {
            let handles = pairs
                .into_iter()
                .map(|(handle, rev)| resolver::AddrEntry { handle, rev })
                .collect();
            let mut headers = HeaderMap::new();
            headers.insert("cache-control", "public, max-age=300".parse().unwrap());
            (
                headers,
                axum::Json(resolver::AddrMatch {
                    address: address.clone(),
                    handles,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("addr lookup failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response()
        }
    }
}

/// GET /sync?cursor=<opaque>&limit=<n> - Page of stored handle rows.
///
/// Returns a borsh-encoded [`resolver::SyncPage`] ordered by
/// `(updated_at, handle)`. Serving is one indexed SELECT streaming blobs
/// exactly as stored — no proof generation. The cursor is peer-local: echo it
/// back to this relay only.
async fn handle_sync(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.sync.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_sync);
        return (StatusCode::TOO_MANY_REQUESTS, vec![]).into_response();
    }

    let cursor = match params.get("cursor").filter(|c| !c.is_empty()) {
        Some(raw) => match raw.parse::<resolver::SyncCursor>() {
            Ok(c) => Some(c),
            Err(e) => return (StatusCode::BAD_REQUEST, e.as_bytes().to_vec()).into_response(),
        },
        None => None,
    };
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(MAX_SYNC_PAGE_ROWS)
        .clamp(1, MAX_SYNC_PAGE_ROWS);

    // Page reads copy up to several MB of blobs under the connection mutex —
    // keep that off the async runtime.
    let blocking_state = Arc::clone(&state);
    let page = tokio::task::spawn_blocking(move || {
        blocking_state
            .handler
            .store
            .sync_page(cursor, limit, MAX_SYNC_PAGE_BYTES)
    })
    .await
    .unwrap_or_else(|e| Err(anyhow::anyhow!("sync page task failed: {e}")));
    match page {
        Ok(page) => match borsh::to_vec(&page) {
            Ok(bytes) => (StatusCode::OK, bytes).into_response(),
            Err(e) => {
                tracing::warn!("failed to serialize sync page: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, vec![]).into_response()
            }
        },
        Err(e) => {
            tracing::warn!("sync page failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, vec![]).into_response()
        }
    }
}

/// GET /sync/summary - Row count and newest cursor (JSON, curl-friendly).
async fn handle_sync_summary(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.sync.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_sync);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    match state.handler.store.sync_summary() {
        Ok(summary) => axum::Json(summary).into_response(),
        Err(e) => {
            tracing::warn!("sync summary failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "summary failed").into_response()
        }
    }
}

/// POST /chain-proof - Build a chain proof from a ChainProofRequest.
///
/// Body: JSON ChainProofRequest
/// Returns: binary borsh-encoded ChainProof
async fn handle_chain_proof(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.proof.check_key(&ip).is_err() {
        crate::stats::bump(&state.stats.rl_proof);
        return (StatusCode::TOO_MANY_REQUESTS, vec![]).into_response();
    }

    let request: ChainProofRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("failed to deserialize chain proof request: {}", e);
            return (StatusCode::BAD_REQUEST, vec![]).into_response();
        }
    };

    if request.spaces.len() > 6 {
        return (
            StatusCode::BAD_REQUEST,
            "too many spaces (max 6)".as_bytes().to_vec(),
        )
            .into_response();
    }
    if request.nums.len() > 20 {
        return (
            StatusCode::BAD_REQUEST,
            "too many nums (max 20)".as_bytes().to_vec(),
        )
            .into_response();
    }

    // Global proof cap: shed load instead of queueing proof generation
    let Ok(_permit) = state.proof_sem.try_acquire() else {
        crate::stats::bump(&state.stats.busy_rejections);
        return (StatusCode::SERVICE_UNAVAILABLE, vec![]).into_response();
    };

    match state.chain.prove(&request).await {
        Ok(proof) => {
            crate::stats::bump(&state.stats.proofs_served);
            (StatusCode::OK, proof.to_bytes()).into_response()
        }
        Err(e) => {
            tracing::warn!("failed to build chain proof: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, vec![]).into_response()
        }
    }
}

/// Bootstrap from the given seed relays (empty is a no-op, e.g. a non-mainnet
/// relay with no custom `--seed`). Does nothing if this node is a bootstrap
/// node itself.
pub async fn bootstrap(state: &Arc<AppState>, seeds: &[String]) {
    if state.is_bootstrap {
        tracing::info!("running as bootstrap node, skipping bootstrap");
        return;
    }

    for url in seeds {
        match bootstrap_from(state, url).await {
            Ok(peers) => {
                tracing::info!("bootstrapped from {}: {} peers", url, peers.len());
            }
            Err(e) => {
                tracing::warn!("failed to bootstrap from {}: {}", url, e);
            }
        }
    }
}

/// Announce ourselves to a peer and fetch their peer list.
/// Returns the list of peers we learned about.
pub async fn bootstrap_from(
    state: &Arc<AppState>,
    bootstrap_url: &str,
) -> anyhow::Result<Vec<PeerInfo>> {
    let client = state.peer_client(bootstrap_url).await?;

    // Announce ourselves if we have a self URL
    if let Some(ref self_url) = state.self_url {
        let announcement = Announcement {
            url: self_url.clone(),
            capabilities: state.capabilities,
        };
        let url = format!("{}/announce", bootstrap_url);
        let _ = client.post(&url).json(&announcement).send().await;
    }

    // Fetch their peer list, bounding how much we read from an untrusted body
    let url = format!("{}/peers", bootstrap_url);
    let resp = client.get(&url).send().await?;
    if let Some(len) = resp.content_length()
        && len > MAX_PEERS_RESPONSE_SIZE as u64
    {
        anyhow::bail!("peers response too large: {} bytes", len);
    }
    let body = resp.bytes().await?;
    if body.len() > MAX_PEERS_RESPONSE_SIZE {
        anyhow::bail!("peers response too large: {} bytes", body.len());
    }
    let mut peers: Vec<PeerInfo> = serde_json::from_slice(&body)?;
    peers.truncate(MAX_PEERS_PER_RESPONSE);
    peers.retain(|p| {
        p.url.len() <= 256
            && crate::peer::validate_peer_url(&p.url, state.allow_private_peers).is_ok()
    });
    // The claimed source_ip in a peers list is remote-controlled and
    // unverifiable — coerce it to the unspecified address before ANY use
    // (including the returned vec) so it can never claim an IP slot or
    // displace entries attributed to real client IPs (see
    // PeerTable::announce).
    for peer in &mut peers {
        peer.source_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    }

    // Add discovered peers to our table
    {
        let mut peer_table = state.peers.lock().await;
        for peer in &peers {
            peer_table.announce(peer);
        }
    }

    Ok(peers)
}

#[cfg(test)]
mod etag_tests {
    use super::{etag_matches, query_etag};
    use crate::store::SqliteStore;

    #[test]
    fn etag_matches_handles_lists_star_and_weak() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(etag_matches("\"x\", \"abc\"", "\"abc\""));
        assert!(!etag_matches("\"xyz\"", "\"abc\""));
        assert!(!etag_matches("", "\"abc\""));
    }

    // The version must change on create/update/delete of a covered zone, and be
    // stable when nothing changed — that's what makes 304s both safe and useful.
    #[test]
    fn etag_busts_on_create_update_delete() {
        let store = SqliteStore::in_memory().unwrap();
        let covered = vec!["@t".to_string(), "a@t".to_string()];

        store.test_insert("@t", "@t", 100, b"parent-v1");
        let absent = query_etag(&store, &covered).unwrap();

        // create the sub-handle
        store.test_insert("a@t", "@t", 100, b"a-v1");
        let present = query_etag(&store, &covered).unwrap();
        assert_ne!(absent, present, "create must bust the ETag");

        // update its zone (e.g. new records) -> different zone_hash
        store.test_insert("a@t", "@t", 100, b"a-v2");
        let updated = query_etag(&store, &covered).unwrap();
        assert_ne!(present, updated, "update must bust the ETag");

        // nothing changed -> stable (this is where the 304 win comes from)
        assert_eq!(updated, query_etag(&store, &covered).unwrap());

        // delete -> back to the absent version
        store.delete_handles(&["a@t".to_string()]).unwrap();
        assert_eq!(absent, query_etag(&store, &covered).unwrap());
    }
}
