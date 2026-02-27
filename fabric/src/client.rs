use libveritas::msg::QueryContext;
use libveritas::sname::{NameLike, SName};
use libveritas::{MessageError, ProvableOption, VerifiedMessage, Veritas, Zone};
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{AnchorResponse, EpochHint, HintsResponse, Message, POW_HEADER, PeerInfo, Query, QueryRequest, pow};
use crate::seeds::SEEDS;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Fabric {
    http: reqwest::Client,
    pool: RelayPool,
    veritas: Mutex<Veritas>,
    pow_difficulty: u32,
    root_cache: dashmap::DashMap<String, Zone>,
    seeds: Vec<String>,
    anchor_set_hash: Mutex<Option<String>>,
    prefer_latest: AtomicBool,
}

pub struct RelayPool {
    inner: Mutex<Vec<RelayEntry>>,
}

pub struct RelayEntry {
    pub url: String,
    pub failures: u32,
}

impl Fabric {
    /// Create a new client with the default seeds.
    pub fn new() -> Self {
        Self::with_seeds(SEEDS)
    }

    /// Create a new client with custom seed URLs.
    pub fn with_seeds(seeds: &[&str]) -> Self {
        Self {
            http: reqwest::Client::new(),
            pool: RelayPool::new(std::iter::empty::<String>()),
            veritas: Mutex::new(Veritas::new()),
            pow_difficulty: crate::DEFAULT_DIFFICULTY,
            root_cache: Default::default(),
            seeds: seeds.iter().map(|s| s.to_string()).collect(),
            anchor_set_hash: Mutex::new(None),
            prefer_latest: AtomicBool::new(true),
        }
    }

    /// Specify a 32-byte anchor set hash to be loaded from peers
    pub fn with_anchor_set(mut self, hash: &str) -> Self {
        self.anchor_set_hash = Mutex::new(Some(hash.to_string()));
        self
    }

    /// Get the current anchor set hash, if any.
    pub fn anchor_set_hash(&self) -> Option<String> {
        self.anchor_set_hash.lock().unwrap().clone()
    }

    /// Set whether to query multiple relays for freshness hints before resolving.
    pub fn set_prefer_latest(&self, latest: bool) {
        self.prefer_latest.store(latest, Ordering::Relaxed);
    }

    pub async fn update_anchors(&self, anchor_set_hash: Option<&str>) -> Result<()> {
        let (anchor_set_hash, peers) = if let Some(hash) = anchor_set_hash {
            let peers =  self.pool.shuffled_urls_n(4);
            (hash.to_string(), peers)
        } else {
           fetch_latest_anchor_set_hash(
                &self.http,
                &self.seeds
            ).await?
        };

        let anchors = fetch_anchor_set(
            &self.http, &anchor_set_hash, &peers).await?;

        if let Ok(v) = Veritas::new().with_anchors(anchors) {
            *self.veritas.lock().unwrap() = v;
            *self.anchor_set_hash.lock().unwrap() = Some(anchor_set_hash);
        }
        Ok(())
    }

    /// Whether the client has no relays in its pool.
    pub fn needs_peers(&self) -> bool {
        self.pool.is_empty()
    }

    /// Whether the client has no anchors loaded for verification.
    pub fn needs_anchors(&self) -> bool {
        self.veritas.lock().unwrap().newest_anchor() == 0
    }

    /// Bootstrap the client: discover peers from seeds and fetch anchors.
    pub async fn bootstrap(&self) -> Result<()> {
        if self.needs_peers() {
            self.bootstrap_peers().await?;
        }
        if self.needs_anchors() {
            let hash = self.anchor_set_hash.lock().unwrap().clone();
            self.update_anchors(hash.as_deref()).await?;
        }
        Ok(())
    }

    /// Discover peers from seed URLs and populate the relay pool.
    async fn bootstrap_peers(&self) -> Result<()> {
        let mut urls: HashSet<String> = self.seeds.iter().cloned().collect();

        for seed in &self.seeds {
            if let Ok(peers) = fetch_peers(&self.http, seed).await {
                for peer in peers {
                    urls.insert(peer.url);
                }
            }
        }

        if urls.is_empty() {
            return Err(Error::NoPeers);
        }

        self.pool.refresh(urls);
        Ok(())
    }


    /// Resolve a single handle (e.g. "alice@bitcoin") and return its verified Zone.
    pub async fn resolve(&self, handle: &str) -> Result<Zone> {
        let zones = self.resolve_all(&[handle]).await?;
        zones.into_values().next().ok_or_else(|| {
            Error::Decode(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{handle} not found"),
            ))
        })
    }

    /// Resolve multiple handles (e.g. ["alice@bitcoin", "damus@nostr"]).
    /// Returns a map from handle string to verified Zone.
    pub async fn resolve_all(&self, handles: &[&str]) -> Result<HashMap<String, Zone>> {
        // Parse handles into SNames, group by space
        let mut by_space: HashMap<String, Vec<String>> = HashMap::new();
        for &h in handles {
            let sname = SName::try_from(h)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
            let space = sname.space()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{h}: no space")))?
                .to_string();
            let subspace = sname.subspace()
                .map(|l| l.to_string())
                .unwrap_or_default();
            by_space.entry(space).or_default().push(subspace);
        }

        let queries = by_space
            .into_iter()
            .map(|(space, handles)| {
                let mut q = Query::new(space.clone(), handles);
                if let Some(zone) = self.root_cache.get(&space) {
                    if let Some(hint) = epoch_hint_from_zone(&zone) {
                        q = q.with_epoch_hint(hint);
                    }
                }
                q
            })
            .collect();
        let request = QueryRequest::new(queries);
        let verified = self.query(&request).await?;

        let mut result = HashMap::new();
        for zone in verified.zones {
            result.insert(zone.handle.to_string(), zone);
        }
        Ok(result)
    }

    async fn query(&self, request: &QueryRequest) -> Result<VerifiedMessage> {
        self.bootstrap().await?;
        let mut ctx = QueryContext::new();
        request
            .queries
            .iter()
            .filter_map(|q| self.root_cache.get(&q.space))
            .map(|z| z.clone())
            .for_each(|z| {
                ctx.add_zone(z);
            });

        let relays = if self.prefer_latest.load(Ordering::Relaxed) {
            self.pick_relays(request, 4).await
        } else {
            self.pool.shuffled_urls_n(4)
        };

        let res = self.send_query(&ctx, request, &relays).await?;
        res.zones
            .iter()
            .filter(|z| z.handle.is_single_label())
            .for_each(|z| {
                self.root_cache.insert(z.handle.to_string(), z.clone());
            });
        Ok(res)
    }

    /// Send query to relays in order, verifying the response. Falls back on failure.
    async fn send_query(
        &self,
        ctx: &QueryContext,
        request: &QueryRequest,
        relays: &[String],
    ) -> Result<VerifiedMessage> {
        let body = serde_json::to_vec(request)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut last_err = Error::NoPeers;
        for url in relays {
            match self.post_binary(&format!("{url}/query"), &body).await {
                Ok(bytes) => {
                    let msg = Message::from_slice(&bytes).map_err(Error::Decode)?;
                    match self.veritas.lock().unwrap().verify_message(ctx, msg) {
                        Ok(res) => {
                            self.pool.mark_alive(url);
                            return Ok(res);
                        }
                        Err(e) => {
                            self.pool.mark_failed(url);
                            last_err = Error::Verify(e);
                        }
                    }
                }
                Err(e) => {
                    self.pool.mark_failed(url);
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    /// Pick up to `count` relays sorted by freshest zone data for the specified query request.
    async fn pick_relays(&self, request: &QueryRequest, count: usize) -> Vec<String> {
        let hints_query = hints_query_string(request);
        let shuffled = self.pool.shuffled_urls();

        let mut ranked: Vec<(String, HintsResponse)> = Vec::new();

        for batch in shuffled.chunks(count) {
            if ranked.len() >= count {
                break;
            }

            let mut tasks: Vec<(String, tokio::task::JoinHandle<Option<HintsResponse>>)> =
                Vec::with_capacity(batch.len());
            for url in batch {
                let http = self.http.clone();
                let hints_url = format!("{url}/hints");
                let q = hints_query.clone();
                tasks.push((url.clone(), tokio::spawn(async move {
                    let resp = http.get(&hints_url).query(&[("q", &q)]).send().await.ok()?;
                    if !resp.status().is_success() {
                        return None;
                    }
                    resp.json::<HintsResponse>().await.ok()
                })));
            }

            for (url, task) in tasks {
                match task.await {
                    Ok(Some(hints)) => ranked.push((url, hints)),
                    _ => {
                        self.pool.mark_failed(&url);
                    }
                }
            }
        }

        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.into_iter().map(|(url, _)| url).collect()
    }

    /// Broadcast a message to up to 4 random relays for gossip propagation.
    /// Mines proof-of-work automatically. Returns Ok if at least one relay accepted.
    pub async fn broadcast(&self, msg_bytes: &[u8]) -> Result<()> {
        self.bootstrap().await?;
        let body_owned = msg_bytes.to_vec();
        let difficulty = self.pow_difficulty;
        let nonce = tokio::task::spawn_blocking(move || pow::mine(&body_owned, difficulty))
            .await
            .expect("pow mining task panicked");

        self.broadcast_with_pow(msg_bytes, &nonce).await
    }

    /// Broadcast a message with a pre-computed proof-of-work nonce.
    /// Use this when the PoW is computed externally.
    pub async fn broadcast_with_pow(&self, msg_bytes: &[u8], pow_nonce: &str) -> Result<()> {
        self.bootstrap().await?;
        let urls = self.pool.shuffled_urls_n(4);
        if urls.is_empty() {
            return Err(Error::NoPeers);
        }

        let mut any_ok = false;
        let mut last_err = None;
        for url in &urls {
            let result = self
                .http
                .post(format!("{url}/message"))
                .body(msg_bytes.to_vec())
                .header("content-type", "application/octet-stream")
                .header(POW_HEADER, pow_nonce)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => any_ok = true,
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    last_err = Some(Error::Relay { status, body });
                }
                Err(e) => last_err = Some(Error::Http(e)),
            }
        }

        if any_ok {
            Ok(())
        } else {
            Err(last_err.unwrap())
        }
    }

    /// Fetch the peer list from a random relay.
    pub async fn peers(&self) -> Result<Vec<PeerInfo>> {
        let urls = self.pool.shuffled_urls_n(1);
        let url = urls.first().ok_or(Error::NoPeers)?;
        fetch_peers(&self.http, url).await
    }

    /// Re-fetch peers from all known relays and update the relay pool.
    pub async fn refresh_peers(&self) -> Result<()> {
        let current = self.pool.urls();
        let mut new_urls: HashSet<String> = HashSet::new();

        for url in &current {
            if let Ok(peers) = fetch_peers(&self.http, url).await {
                for peer in peers {
                    new_urls.insert(peer.url);
                }
            }
        }

        self.pool.refresh(new_urls);
        if self.pool.is_empty() {
            return Err(Error::NoPeers);
        }
        Ok(())
    }

    /// Get the current list of known relay URLs.
    pub fn relays(&self) -> Vec<String> {
        self.pool.urls()
    }

    async fn post_binary(&self, url: &str, body: &[u8]) -> Result<Vec<u8>> {
        let resp = self
            .http
            .post(url)
            .body(body.to_vec())
            .header("content-type", "application/octet-stream")
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Relay { status, body });
        }

        Ok(resp.bytes().await?.to_vec())
    }
}

/// Build the hints query string from a QueryRequest.
/// e.g. "@bitcoin,alice@bitcoin,bob@bitcoin"
fn hints_query_string(request: &QueryRequest) -> String {
    let mut parts = Vec::new();
    for query in &request.queries {
        parts.push(query.space.clone());
        for handle in &query.handles {
            parts.push(format!("{}{}", handle, query.space));
        }
    }
    parts.join(",")
}

fn epoch_hint_from_zone(zone: &Zone) -> Option<EpochHint> {
    if let ProvableOption::Exists { value: c } = &zone.commitment {
        Some(EpochHint {
            root: hex::encode(c.onchain.state_root),
            height: c.onchain.block_height,
        })
    } else {
        None
    }
}

async fn fetch_peers(http: &reqwest::Client, relay_url: &str) -> Result<Vec<PeerInfo>> {
    let resp = http.get(format!("{relay_url}/peers")).send().await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Relay { status, body });
    }
    Ok(resp.json().await?)
}


impl RelayPool {
    fn new(urls: impl IntoIterator<Item = String>) -> Self {
        let entries = urls
            .into_iter()
            .map(|url| RelayEntry {
                url,
                failures: 0,
            })
            .collect();
        Self {
            inner: Mutex::new(entries),
        }
    }

    /// Shuffle in place, sort failed to back, return all URLs.
    pub fn shuffled_urls(&self) -> Vec<String> {
        self.shuffled_urls_n(usize::MAX)
    }

    /// Shuffle in place, sort failed to back, return up to `n` URLs.
    pub fn shuffled_urls_n(&self, n: usize) -> Vec<String> {
        let mut entries = self.inner.lock().unwrap();
        entries.shuffle(&mut rand::rng());
        entries.sort_by_key(|e| e.failures);
        entries.iter().take(n).map(|e| e.url.clone()).collect()
    }

    pub fn mark_failed(&self, url: &str) {
        let mut entries = self.inner.lock().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.url == url) {
            e.failures = e.failures.saturating_add(1);
        }
    }

    pub fn mark_alive(&self, url: &str) {
        let mut entries = self.inner.lock().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.url == url) {
            e.failures = 0;
        }
    }

    /// Add new URLs to the pool.
    pub fn refresh(&self, new_urls: impl IntoIterator<Item = String>) {
        let mut entries = self.inner.lock().unwrap();
        let existing: HashSet<String> = entries.iter().map(|e| e.url.clone()).collect();
        for url in new_urls {
            if !existing.contains(url.as_str()) {
                entries.push(RelayEntry {
                    url,
                    failures: 0,
                });
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    pub fn urls(&self) -> Vec<String> {
        self.inner.lock().unwrap().iter().map(|e| e.url.clone()).collect()
    }
}

#[derive(Debug)]
pub enum Error {
    Http(reqwest::Error),
    Decode(std::io::Error),
    Verify(MessageError),
    Relay { status: u16, body: String },
    NoPeers,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Http(e) => write!(f, "http error: {e}"),
            Error::Decode(e) => write!(f, "decode error: {e}"),
            Error::Verify(e) => write!(f, "verification error: {e}"),
            Error::Relay { status, body } => write!(f, "relay error ({status}): {body}"),
            Error::NoPeers => write!(f, "no peers available"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Decode(e)
    }
}

impl From<MessageError> for Error {
    fn from(e: MessageError) -> Self {
        Error::Verify(e)
    }
}

/// Fetch latest anchor set hash from the specified set of peers
/// this is only used if Fabric isn't initialized with an anchor set
/// from a trusted source.
///
/// Returns: (<root-hash>, <peers...>)
async fn fetch_latest_anchor_set_hash(http: &reqwest::Client, peers: &[String]) -> Result<(String, Vec<String>)> {
    let mut votes: HashMap<(String, u32), Vec<String>> = HashMap::new();

    for url in peers {
        let Ok(resp) = http.head(format!("{url}/anchors")).send().await else {
            continue;
        };

        let root = resp
            .headers()
            .get("x-anchor-root")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let height: u32 = resp
            .headers()
            .get("x-anchor-height")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        if let Some(root) = root {
            votes.entry((root, height)).or_default().push(url.to_string());
        }
    }

    votes
        .into_iter()
        .max_by_key(|((_, height), peers)| (peers.len(), *height))
        .map(|((root, _), peers)| (root, peers))
        .ok_or_else(|| Error::NoPeers)
}

async fn fetch_anchor_set(
    http: &reqwest::Client,
    hash: &str,
    peers: &[String],
) -> Result<Vec<spaces_ptr::RootAnchor>> {
    let mut last_err: Option<Error> = None;
    for url in peers {
        let resp = match http
            .get(format!("{url}/anchors?root={hash}"))
            .send()
            .await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            last_err = Some(Error::Relay { status, body });
            continue;
        }

        let anchor_set: AnchorResponse = match resp.json().await {
            Ok(a) => a,
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        };

        if !anchor_set.root_matches() {
            continue;
        }

        return Ok(anchor_set.entries);
    }

    Err(last_err.unwrap_or(Error::NoPeers))
}
