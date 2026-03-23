//! HTTP routes for the relay server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::RateLimiter;
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
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Quota for /message endpoint
    pub message: Quota,
    /// Quota for /query endpoint
    pub query: Quota,
    /// Quota for /announce endpoint
    pub announce: Quota,
    /// Quota for /peers endpoint
    pub peers: Quota,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            message: Quota::per_minute(NonZeroU32::new(10).unwrap()),
            query: Quota::per_minute(NonZeroU32::new(15).unwrap()),
            announce: Quota::per_minute(NonZeroU32::new(5).unwrap()),
            peers: Quota::per_minute(NonZeroU32::new(10).unwrap()),
        }
    }
}

/// Rate limiters for each endpoint type.
pub struct RateLimiters {
    pub message: Arc<IpRateLimiter>,
    pub query: Arc<IpRateLimiter>,
    pub announce: Arc<IpRateLimiter>,
    pub peers: Arc<IpRateLimiter>,
}

impl RateLimiters {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            message: Arc::new(RateLimiter::dashmap(config.message)),
            query: Arc::new(RateLimiter::dashmap(config.query)),
            announce: Arc::new(RateLimiter::dashmap(config.announce)),
            peers: Arc::new(RateLimiter::dashmap(config.peers)),
        }
    }
}

/// Default max message size (512 KB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 512 * 1024;

/// Default bootstrap relay URLs.
pub const BOOTSTRAP_RELAYS: &[&str] = &[
    // TODO: Add production bootstrap relay URLs
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
        Self {
            handler,
            chain,
            peers: Mutex::new(PeerTable::new(peer_config)),
            limiters: RateLimiters::new(&rate_config),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            http_client: reqwest::Client::new(),
            self_url: None,
            capabilities: 0,
            is_bootstrap: false,
            remote_ip_header: None,
        }
    }

    pub fn with_self_url(mut self, url: String) -> Self {
        self.peers.get_mut().set_self_url(&url);
        self.self_url = Some(url);
        self
    }
}

/// Build the router with all routes.
pub fn router(state: Arc<AppState>) -> Router {
    let cors = tower_http::cors::CorsLayer::permissive();

    Router::new()
        .route("/message", post(handle_message))
        .route("/announce", post(handle_announce))
        .route("/peers", get(handle_peers))
        .route("/query", post(handle_query))
        .route("/anchors", get(handle_anchors))
        .route("/hints", get(handle_hints))
        .route("/chain-proof", post(handle_chain_proof))
        .layer(cors)
        .with_state(state)
}

/// Extract the client IP from the configured header, falling back to socket address.
///
/// If `remote_ip_header` is set, reads that header and parses the first IP
/// (handles comma-separated lists like X-Forwarded-For).
fn client_ip(addr: &SocketAddr, headers: &HeaderMap, header_name: &Option<String>) -> IpAddr {
    if let Some(name) = header_name {
        if let Some(value) = headers.get(name.as_str()).and_then(|v| v.to_str().ok()) {
            // Take the first entry (leftmost = original client for XFF-style headers,
            // and the only value for single-value headers like CF-Connecting-IP)
            let first = value.split(',').next().unwrap_or("").trim();
            if let Ok(ip) = first.parse::<IpAddr>() {
                return ip;
            }
        }
    }
    addr.ip()
}

/// POST /message - Receive and process a certificate message.
///
/// Body: borsh-encoded Message
/// On success: verifies, stores, and gossips to peers.
async fn handle_message(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.message.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited".to_string());
    }

    if body.len() > state.max_message_size {
        return (StatusCode::PAYLOAD_TOO_LARGE, "message too large".to_string());
    }

    // Deserialize the message
    let msg: Message = match Message::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("failed to deserialize message: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid message format".to_string());
        }
    };

    // Verify and store
    if let Err(e) = state.handler.handle_message(msg) {
        tracing::warn!("failed to handle message: {}", e);
        return (StatusCode::BAD_REQUEST,  format!("rejected: {}", e));
    }

    gossip_message(state, body).await;

    (StatusCode::OK, "ok".to_string())
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
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }

    let announcement: Announcement = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("failed to deserialize announcement: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid announcement format");
        }
    };

    if announcement.url.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty url");
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
    if state.limiters.peers.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let peers = state.peers.lock().await;
    let peer_list = peers.peers_info();
    drop(peers);

    axum::Json(peer_list).into_response()
}

/// POST /query - Query for certificates.
///
/// Body: JSON QueryRequest
/// Returns: binary borsh-encoded Message with certificates and proofs
async fn handle_query(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&addr, &headers, &state.remote_ip_header);
    if state.limiters.query.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, vec![]).into_response();
    }

    // Deserialize the JSON request
    let request: QueryRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("failed to deserialize query request: {}", e);
            return (StatusCode::BAD_REQUEST, vec![]).into_response();
        }
    };

    // Resolve the queries - response is binary (borsh-encoded Message)
    match state.handler.resolve(&state.chain, request.queries).await {
        Ok(msg) => (StatusCode::OK, msg.to_bytes()).into_response(),
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
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let store = state.handler.anchor_store.lock().unwrap();

    let mut headers = HeaderMap::new();
    if let Some(latest) = store.latest() {
        let height = latest.entries.last().map(|a| a.block.height).unwrap_or(0);
        if let Ok(v) = hex::encode(latest.root).parse() {
            headers.insert("x-anchor-root", v);
        }
        if let Ok(v) = height.to_string().parse() {
            headers.insert("x-anchor-height", v);
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
                Err(_) => return (StatusCode::BAD_REQUEST, headers, "root must be 32 bytes").into_response(),
            };
            store.get(root).cloned()
        }
        None => store.latest().cloned(),
    };

    match set {
        Some(resp) => (headers, axum::Json(resp)).into_response(),
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
    if state.limiters.query.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let q = match params.get("q") {
        Some(q) if !q.is_empty() => q,
        _ => return (StatusCode::BAD_REQUEST, "missing q parameter").into_response(),
    };

    let mut handles: Vec<&str> = q.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

    match state.handler.hints(&mut handles) {
        Ok(res) => axum::Json(res).into_response(),
        Err(e) => {
            tracing::warn!("hints failed: {}", e);
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
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
    if state.limiters.query.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, vec![]).into_response();
    }

    let request: ChainProofRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("failed to deserialize chain proof request: {}", e);
            return (StatusCode::BAD_REQUEST, vec![]).into_response();
        }
    };

    match state.chain.prove(&request).await {
        Ok(proof) => (StatusCode::OK, proof.to_bytes()).into_response(),
        Err(e) => {
            tracing::warn!("failed to build chain proof: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, vec![]).into_response()
        }
    }
}

/// Gossip a message to up to 4 random verified peers.
async fn gossip_message(
    state: Arc<AppState>,
    msg_bytes: Bytes,
) {
    use rand::seq::IndexedRandom;

    let peer_list: Vec<PeerInfo> = {
        let peers = state.peers.lock().await;
        peers.peers_info()
    };

    let targets: Vec<_> = peer_list
        .choose_multiple(&mut rand::rng(), 4)
        .cloned()
        .collect();

    for peer in targets {
        let state = Arc::clone(&state);
        let msg_bytes = msg_bytes.clone();

        tokio::spawn(async move {
            let url = format!("{}/message", peer.url);
            let result = state
                .http_client
                .post(&url)
                .body(msg_bytes.to_vec())
                .header("Content-Type", "application/octet-stream")
                .send()
                .await;

            let mut peers = state.peers.lock().await;
            match result {
                Ok(resp) if resp.status().is_success() => {
                    peers.mark_alive(&peer.url);
                    tracing::trace!("gossip to {} succeeded", peer.url);
                }
                Ok(resp) => {
                    peers.deprioritize(&peer.url);
                    tracing::debug!("gossip to {} failed: {}", peer.url, resp.status());
                }
                Err(e) => {
                    peers.deprioritize(&peer.url);
                    tracing::debug!("gossip to {} failed: {}", peer.url, e);
                }
            }
        });
    }
}

/// Bootstrap from the default bootstrap relays.
/// Does nothing if this node is a bootstrap node itself.
pub async fn bootstrap(state: &Arc<AppState>) {
    if state.is_bootstrap {
        tracing::info!("running as bootstrap node, skipping bootstrap");
        return;
    }

    for &url in BOOTSTRAP_RELAYS {
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
    // Announce ourselves if we have a self URL
    if let Some(ref self_url) = state.self_url {
        let announcement = Announcement {
            url: self_url.clone(),
            capabilities: state.capabilities,
        };
        let url = format!("{}/announce", bootstrap_url);
        let _ = state
            .http_client
            .post(&url)
            .json(&announcement)
            .send()
            .await;
    }

    // Fetch their peer list
    let url = format!("{}/peers", bootstrap_url);
    let resp = state.http_client.get(&url).send().await?;
    let peers: Vec<PeerInfo> = resp.json().await?;

    // Add discovered peers to our table
    {
        let mut peer_table = state.peers.lock().await;
        for peer in &peers {
            peer_table.announce(peer);
        }
    }

    Ok(peers)
}

