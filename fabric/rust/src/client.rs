use crate::seeds::SEEDS;
pub use crate::{
    AnchorSet, EpochHint, HintsResponse, Message, PeerInfo, Query, QueryRequest, TrustId,
};
use libveritas::cert::CertificateChain;
use libveritas::msg::QueryContext;
use libveritas::spaces_protocol::sname::{NameLike, SName};
use libveritas::{
    MessageError, ProvableOption, SovereigntyState, TrustSet, VerifiedMessage, Veritas, Zone,
    compute_trust_set,
};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "signing")]
use libveritas::{
    builder::MessageBuilder,
    msg::ChainProof,
    sip7::{RecordSet, SIG_PRIMARY_ZONE},
};

pub type Result<T> = std::result::Result<T, Error>;

pub struct AnchorBundle {
    pub trust_set: TrustSet,
    pub anchors: Vec<spaces_nums::RootAnchor>,
}

/// Parsed parameters from a `veritas://scan?id=...` QR code.
pub struct ScanParams {
    pub id: TrustId,
}

impl ScanParams {
    /// Parse a `veritas://scan?id={hex}` URI.
    pub fn parse(uri: &str) -> Result<Self> {
        let uri = uri.trim();
        let query = uri.strip_prefix("veritas://scan?").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected veritas://scan?... URI",
            )
        })?;

        let mut id = None;
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "id" {
                    id = Some(TrustId::from_str(value)?);
                }
            }
        }

        Ok(Self {
            id: id.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing id parameter")
            })?,
        })
    }
}

pub struct Fabric {
    http: reqwest::Client,
    pool: RelayPool,
    veritas: Mutex<Veritas>,
    dev_mode: bool,
    root_cache: dashmap::DashMap<String, Zone>,
    seeds: Vec<String>,
    /// The currently pinned trust id, if any.
    trusted: Mutex<Option<TrustSet>>,
    /// The latest trust id observed from peers, if any.
    observed: Mutex<Option<TrustSet>>,
    /// Trust anchor from a semi-trusted source (e.g. public explorer over HTTPS).
    /// Removes the "unverified" badge but never shows the orange checkmark.
    semi_trusted: Mutex<Option<TrustSet>>,
    /// Raw anchors per source, merged into a single Veritas.
    anchor_pool: Mutex<AnchorPool>,
    /// Whether to look for the latest zone from multiple peers
    prefer_latest: AtomicBool,
}

/// Keeps raw anchors from each trust source so they can be merged into one Veritas.
#[derive(Default)]
struct AnchorPool {
    trusted: Vec<spaces_nums::RootAnchor>,
    semi_trusted: Vec<spaces_nums::RootAnchor>,
    observed: Vec<spaces_nums::RootAnchor>,
}

impl AnchorPool {
    fn merged(&self) -> Vec<spaces_nums::RootAnchor> {
        let mut all = Vec::new();
        all.extend_from_slice(&self.trusted);
        all.extend_from_slice(&self.semi_trusted);
        all.extend_from_slice(&self.observed);
        all.sort_by_key(|a| std::cmp::Reverse(a.block.height));
        all.dedup_by_key(|a| a.block.height);
        all
    }
}

/// Serializable snapshot of Fabric state for persistence.
#[derive(Serialize, Deserialize)]
pub struct FabricState {
    pub version: u32,
    pub relays: Vec<String>,
    pub anchors: AnchorPoolState,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub zone_cache: HashMap<String, Zone>,
}

/// Anchor entries per trust source.
#[derive(Serialize, Deserialize, Default)]
pub struct AnchorPoolState {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted: Vec<spaces_nums::RootAnchor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub semi_trusted: Vec<spaces_nums::RootAnchor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed: Vec<spaces_nums::RootAnchor>,
}

pub struct RelayPool {
    inner: Mutex<Vec<RelayEntry>>,
}

pub struct RelayEntry {
    pub url: String,
    pub failures: u32,
}

enum TrustKind {
    /// Fully trusted — user pinned explicitly.
    Trusted(TrustId),
    /// Semi-trusted — from an external source (e.g. public explorer).
    SemiTrusted(TrustId),
    /// Observed — latest from peers, no explicit trust.
    Observed,
}

/// UI badge status derived from trust + sovereignty.
pub enum Badge {
    /// Sovereign handle verified against a trusted root. Show orange checkmark.
    Orange,
    /// Resolved against an observed root that differs from the trusted set.
    /// Handle is in a newer state than what the user has pinned.
    Unverified,
    /// No badge. Pending, dependent, or no trust state applies.
    None,
}

impl fmt::Display for Badge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Badge::Orange => write!(f, "orange"),
            Badge::Unverified => write!(f, "unverified"),
            Badge::None => write!(f, "none"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedBatch {
    pub zones: Vec<Zone>,
    pub roots: Vec<TrustId>,
    pub relays: Vec<String>,
}

impl ResolvedBatch {
    /// Look up a specific handle from the batch.
    pub fn get(&self, handle: &str) -> Option<Resolved> {
        self.zones
            .iter()
            .find(|z| z.handle.to_string() == handle)
            .map(|z| Resolved {
                zone: z.clone(),
                roots: self.roots.clone(),
                relays: self.relays.clone(),
            })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Resolved {
    pub zone: Zone,
    pub roots: Vec<TrustId>,
    pub relays: Vec<String>,
}

impl Default for Fabric {
    fn default() -> Self {
        Self::new()
    }
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
            dev_mode: false,
            root_cache: Default::default(),
            seeds: seeds.iter().map(|s| s.to_string()).collect(),
            observed: Mutex::new(None),
            trusted: Mutex::new(None),
            semi_trusted: Mutex::new(None),
            anchor_pool: Mutex::new(AnchorPool::default()),
            prefer_latest: AtomicBool::new(true),
        }
    }

    pub fn with_dev_mode(mut self) -> Self {
        self.dev_mode = true;
        self
    }

    /// Export the current state for persistence.
    pub fn save_state(&self) -> FabricState {
        let pool = self.anchor_pool.lock().unwrap();
        let zone_cache: HashMap<String, Zone> = self
            .root_cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        FabricState {
            version: 1,
            relays: self.pool.urls(),
            anchors: AnchorPoolState {
                trusted: pool.trusted.clone(),
                semi_trusted: pool.semi_trusted.clone(),
                observed: pool.observed.clone(),
            },
            zone_cache,
        }
    }

    /// Create a Fabric instance from previously saved state.
    /// Rebuilds trust sets and Veritas from the persisted anchors.
    pub fn from_state(state: FabricState) -> Result<Self> {
        let fabric = Self::new();

        if !state.relays.is_empty() {
            fabric.pool.refresh(state.relays);
        }

        {
            let mut pool = fabric.anchor_pool.lock().unwrap();
            pool.trusted = state.anchors.trusted;
            pool.semi_trusted = state.anchors.semi_trusted;
            pool.observed = state.anchors.observed;

            if !pool.trusted.is_empty() {
                *fabric.trusted.lock().unwrap() = Some(compute_trust_set(&pool.trusted));
            }
            if !pool.semi_trusted.is_empty() {
                *fabric.semi_trusted.lock().unwrap() = Some(compute_trust_set(&pool.semi_trusted));
            }
            if !pool.observed.is_empty() {
                *fabric.observed.lock().unwrap() = Some(compute_trust_set(&pool.observed));
            }

            let merged = pool.merged();
            if !merged.is_empty() {
                let v = Veritas::new().with_anchors(merged).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}"))
                })?;
                *fabric.veritas.lock().unwrap() = v;
            }
        }

        for (key, zone) in state.zone_cache {
            fabric.root_cache.insert(key, zone);
        }

        Ok(fabric)
    }

    fn are_roots_trusted(&self, roots: &[TrustId]) -> bool {
        let set = self.trusted.lock().unwrap();
        let Some(trusted_set) = set.as_ref() else {
            return false;
        };
        for root in roots {
            if !trusted_set.roots.contains(&root.to_bytes()) {
                return false;
            }
        }
        true
    }

    fn are_roots_observed(&self, roots: &[TrustId]) -> bool {
        let set = self.observed.lock().unwrap();
        let Some(trusted_set) = set.as_ref() else {
            return false;
        };
        for root in roots {
            if !trusted_set.roots.contains(&root.to_bytes()) {
                return false;
            }
        }
        true
    }

    fn are_roots_semi_trusted(&self, roots: &[TrustId]) -> bool {
        let set = self.semi_trusted.lock().unwrap();
        let Some(semi_set) = set.as_ref() else {
            return false;
        };
        for root in roots {
            if !semi_set.roots.contains(&root.to_bytes()) {
                return false;
            }
        }
        true
    }

    pub fn badge(&self, resolved: &Resolved) -> Badge {
        self.badge_for(resolved.zone.sovereignty, resolved.roots.as_slice())
    }

    pub fn badge_for(&self, sov: SovereigntyState, roots: &[TrustId]) -> Badge {
        let has_any_pool = self.trusted.lock().unwrap().is_some()
            || self.observed.lock().unwrap().is_some()
            || self.semi_trusted.lock().unwrap().is_some();
        if !has_any_pool {
            return Badge::Unverified;
        }

        let is_trusted = self.are_roots_trusted(roots);
        let is_observed = is_trusted || self.are_roots_observed(roots);
        let is_semi_trusted = is_trusted || self.are_roots_semi_trusted(roots);

        if is_trusted && matches!(sov, SovereigntyState::Sovereign) {
            Badge::Orange
        } else if is_observed && !is_trusted && !is_semi_trusted {
            Badge::Unverified
        } else {
            Badge::None
        }
    }

    /// Pin a specific trust id to be loaded from peers.
    pub async fn trust(&self, trust_id: TrustId) -> Result<()> {
        if self.needs_peers() {
            self.bootstrap_peers().await?;
        }
        self.update_anchors(TrustKind::Trusted(trust_id)).await
    }

    /// Update observed trust id from peers
    pub async fn observe(&self) -> Result<()> {
        if self.needs_peers() {
            self.bootstrap_peers().await?;
        }
        self.update_anchors(TrustKind::Observed).await
    }

    /// Set a semi-trusted anchor from an external source (e.g. public explorer).
    pub async fn semi_trust(&self, trust_id: TrustId) -> Result<()> {
        if self.needs_peers() {
            self.bootstrap_peers().await?;
        }
        self.update_anchors(TrustKind::SemiTrusted(trust_id)).await
    }

    /// The trusted trust id, pinned explicitly with trust()
    pub fn trusted(&self) -> Option<TrustId> {
        self.trusted
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| TrustId::from(t.id))
    }

    /// The latest trust id observed from peers, if any.
    pub fn observed(&self) -> Option<TrustId> {
        self.observed
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| TrustId::from(t.id))
    }

    /// The semi-trusted trust id, if any.
    pub fn semi_trusted(&self) -> Option<TrustId> {
        self.semi_trusted
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| TrustId::from(t.id))
    }

    /// Pin trust directly from an AnchorSet. No network requests.
    /// Returns the computed TrustId.
    pub fn trust_from_set(&self, set: &crate::AnchorSet) -> Result<TrustId> {
        let trust_set = compute_trust_set(&set.entries);
        let id = TrustId::from(trust_set.id);
        let mut pool = self.anchor_pool.lock().unwrap();
        pool.trusted = set.entries.clone();
        let v = Veritas::new()
            .with_anchors(pool.merged())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))?;
        *self.veritas.lock().unwrap() = v;
        *self.trusted.lock().unwrap() = Some(trust_set);
        Ok(id)
    }

    /// Parse a `veritas://scan?id=...` QR payload and pin as trusted.
    pub async fn trust_from_qr(&self, payload: &str) -> Result<()> {
        let params = ScanParams::parse(payload)?;
        self.trust(params.id).await
    }

    /// Parse a `veritas://scan?id=...` QR payload and pin as semi-trusted.
    pub async fn semi_trust_from_qr(&self, payload: &str) -> Result<()> {
        let params = ScanParams::parse(payload)?;
        self.semi_trust(params.id).await
    }

    /// Clear the trusted state. Badge will never return Orange until trust is pinned again.
    pub fn clear_trusted(&self) {
        *self.trusted.lock().unwrap() = None;
    }

    /// Clear the semi trusted state.
    pub fn clear_semi_trusted(&self) {
        *self.semi_trusted.lock().unwrap() = None;
    }

    /// Set whether to query multiple relays for freshness hints before resolving.
    pub fn set_prefer_latest(&self, latest: bool) {
        self.prefer_latest.store(latest, Ordering::Relaxed);
    }

    async fn update_anchors(&self, kind: TrustKind) -> Result<()> {
        let (id, peers) = match &kind {
            TrustKind::Trusted(id) | TrustKind::SemiTrusted(id) => {
                let peers = self.pool.shuffled_urls_n(4);
                (*id, peers)
            }
            TrustKind::Observed => fetch_latest_trust_id(&self.http, &self.seeds).await?,
        };

        let ab = fetch_anchor_set(&self.http, id, &peers).await?;

        let mut pool = self.anchor_pool.lock().unwrap();
        match &kind {
            TrustKind::Trusted(_) => pool.trusted = ab.anchors,
            TrustKind::SemiTrusted(_) => pool.semi_trusted = ab.anchors,
            TrustKind::Observed => pool.observed = ab.anchors,
        }
        if let Ok(v) = Veritas::new().with_anchors(pool.merged()) {
            *self.veritas.lock().unwrap() = v;
        }
        drop(pool);

        match kind {
            TrustKind::Trusted(_) => *self.trusted.lock().unwrap() = Some(ab.trust_set),
            TrustKind::SemiTrusted(_) => *self.semi_trusted.lock().unwrap() = Some(ab.trust_set),
            TrustKind::Observed => *self.observed.lock().unwrap() = Some(ab.trust_set),
        }
        Ok(())
    }

    /// Whether the client has no relays in its pool.
    fn needs_peers(&self) -> bool {
        self.pool.is_empty()
    }

    /// Whether the client has no anchors loaded for verification.
    fn needs_anchors(&self) -> bool {
        self.veritas.lock().unwrap().newest_anchor() == 0
    }

    /// Bootstrap the client: discover peers from seeds and fetch anchors.
    pub async fn bootstrap(&self) -> Result<()> {
        if self.needs_peers() {
            self.bootstrap_peers().await?;
        }
        if self.needs_anchors() {
            self.update_anchors(TrustKind::Observed).await?;
        }
        Ok(())
    }

    /// Discover peers from seed URLs and populate the relay pool.
    async fn bootstrap_peers(&self) -> Result<()> {
        let mut urls: HashSet<String> = self.seeds.iter().cloned().collect();
        let mut last_err: Option<Error> = None;

        for seed in &self.seeds {
            match fetch_peers(&self.http, seed).await {
                Ok(peers) => {
                    for peer in peers {
                        urls.insert(peer.url);
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if urls.is_empty() {
            if last_err.is_none() {
                self.pool.refresh(self.seeds.clone());
                return Ok(());
            }
            return Err(last_err.unwrap_or(Error::NoPeers));
        }

        self.pool.refresh(urls);
        Ok(())
    }

    /// Resolve a single handle and return its verified Zone.
    /// Supports dotted names like `hello.alice@bitcoin`.
    pub async fn resolve(&self, handle: &str) -> Result<Option<Resolved>> {
        let rb = self.resolve_all(&[handle]).await?;
        let zone = rb
            .zones
            .into_iter()
            .find(|z| z.handle.to_string() == handle);
        Ok(zone.map(|z| Resolved {
            zone: z,
            roots: rb.roots,
            relays: rb.relays,
        }))
    }

    /// Reverse-resolve by a num id to retrieve its human-readable name.
    ///
    /// Queries relays for the reverse mapping, resolves the forward name,
    /// and verifies the zone's num_id matches.
    pub async fn resolve_by_id(&self, num_id: &str) -> Result<Option<Resolved>> {
        self.bootstrap().await?;
        let relays = self.pool.shuffled_urls_n(4);
        let mut last_err: Option<Error> = None;
        let mut any_responded = false;

        for url in &relays {
            // 1. Fetch reverse mapping
            let reverse_url = format!("{url}/reverse?ids={num_id}");
            let records: Vec<crate::ReverseRecord> = match self.http.get(&reverse_url).send().await
            {
                Ok(resp) if resp.status().is_success() => match resp.json().await {
                    Ok(r) => r,
                    Err(_) => continue,
                },
                _ => continue,
            };

            any_responded = true;

            let Some(entry) = records.iter().find(|r| r.id == num_id) else {
                continue;
            };

            // 2. Resolve forward
            let resolved = match self.resolve(&entry.name).await {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            // 3. Verify num_id matches
            let zone_num_id = resolved.zone.num_id.as_ref().map(|id| id.to_string());
            if zone_num_id.as_deref() != Some(num_id) {
                last_err = Some(Error::Decode(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("reverse mismatch: expected {num_id}, got {:?}", zone_num_id),
                )));
                continue;
            }

            return Ok(Some(resolved));
        }

        // If relays responded but had no mapping, assume not found
        if any_responded && last_err.is_none() {
            return Ok(None);
        }

        Err(last_err.unwrap_or(Error::NoPeers))
    }

    /// Search for handles by address record.
    ///
    /// Queries relays for handles claiming the address, resolves them forward,
    /// and filters to zones that actually contain the matching addr record.
    pub async fn search_addr(&self, name: &str, addr: &str) -> Result<ResolvedBatch> {
        self.bootstrap().await?;
        let relays = self.pool.shuffled_urls_n(4);
        let mut last_err = Error::NoPeers;

        for url in &relays {
            // 1. Fetch addr index
            let addr_url = format!("{url}/addrs?name={name}&addr={addr}");
            let addr_match: crate::AddrMatch = match self.http.get(&addr_url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.json().await {
                    Ok(r) => r,
                    Err(_) => continue,
                },
                _ => continue,
            };

            if addr_match.handles.is_empty() {
                continue;
            }

            // 2. Resolve forward using the rev names
            let rev_names: Vec<String> = addr_match.handles.iter().map(|e| e.rev.clone()).collect();
            let refs: Vec<&str> = rev_names.iter().map(|s| s.as_str()).collect();
            let batch = match self.resolve_all(&refs).await {
                Ok(b) => b,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };

            // 3. Filter to zones that actually have the matching addr record
            let matching_zones: Vec<Zone> = batch
                .zones
                .into_iter()
                .filter(|zone| {
                    zone.records
                        .iter()
                        .map(|mut rrs| {
                            rrs.any(|r| {
                                matches!(r, libveritas::sip7::ParsedRecord::Addr { key, value }
                                if key == name && value.iter().next() == Some(addr))
                            })
                        })
                        .unwrap_or(false)
                })
                .collect();

            if matching_zones.is_empty() {
                last_err = Error::Decode(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no verified matches",
                ));
                continue;
            }

            return Ok(ResolvedBatch {
                zones: matching_zones,
                roots: batch.roots,
                relays: batch.relays,
            });
        }

        Err(last_err)
    }

    /// Resolve multiple handles, including nested names like `hello.alice@bitcoin`.
    pub async fn resolve_all(&self, handles: &[&str]) -> Result<ResolvedBatch> {
        let snames: Vec<SName> = handles
            .iter()
            .filter_map(|h| SName::try_from(*h).ok())
            .collect();

        let lookup = libveritas::names::Lookup::new(snames);
        let mut all_zones: Vec<Zone> = Vec::new();
        let mut roots: Vec<TrustId> = Vec::new();
        let mut relays: Vec<String> = Vec::new();

        let mut prev_batch: Vec<SName> = Vec::new();
        let mut batch: Vec<SName> = lookup.start();
        while !batch.is_empty() {
            // If advance returned the same batch, no progress — break
            if batch == prev_batch {
                break;
            }
            let strs: Vec<String> = batch.iter().map(|s| s.to_string()).collect();
            let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
            let (verified, relay_url) = self.resolve_flat(&refs, true).await?;
            prev_batch = batch;
            batch = lookup.advance(&verified.zones);
            all_zones.extend(verified.zones);
            roots.push(TrustId::from(verified.root_id));
            if !relays.contains(&relay_url) {
                relays.push(relay_url);
            }
        }

        lookup.expand_zones(&mut all_zones);

        Ok(ResolvedBatch {
            zones: all_zones,
            roots,
            relays,
        })
    }

    /// Export a certificate chain for a handle in `.spacecert` format.
    pub async fn export(&self, handle: &str) -> Result<Vec<u8>> {
        let sname = SName::try_from(handle)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

        let lookup = libveritas::names::Lookup::new(vec![sname.clone()]);
        let mut all_verified: Vec<VerifiedMessage> = Vec::new();

        let mut prev_batch: Vec<SName> = Vec::new();
        let mut batch: Vec<SName> = lookup.start();
        while !batch.is_empty() {
            if batch == prev_batch {
                break;
            }
            let strs: Vec<String> = batch.iter().map(|s| s.to_string()).collect();
            let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
            let (verified, _relay_url) = self.resolve_flat(&refs, false).await?;
            prev_batch = batch;
            batch = lookup.advance(&verified.zones);
            all_verified.push(verified);
        }

        let mut certs = Vec::new();
        for msg in &all_verified {
            certs.extend(msg.certificates());
        }

        let chain = CertificateChain::new(sname, certs);
        Ok(chain.to_bytes())
    }

    /// Resolve a flat list of non-dotted handles in a single relay query.
    async fn resolve_flat(
        &self,
        handles: &[&str],
        hints: bool,
    ) -> Result<(VerifiedMessage, String)> {
        let mut by_space: HashMap<String, Vec<String>> = HashMap::new();
        for &h in handles {
            let sname = SName::try_from(h).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
            let space = sname
                .space()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{h}: no space"))
                })?
                .to_string();
            let subspace = sname.subspace().map(|l| l.to_string()).unwrap_or_default();
            by_space.entry(space).or_default().push(subspace);
        }

        let queries = by_space
            .into_iter()
            .map(|(space, handles)| {
                let mut q = Query::new(space.clone(), handles);
                if hints {
                    if let Some(zone) = self.root_cache.get(&space) {
                        if let Some(hint) = epoch_hint_from_zone(&zone) {
                            q = q.with_epoch_hint(hint);
                        }
                    }
                }
                q
            })
            .collect();
        let request = QueryRequest::new(queries);
        self.query(&request).await
    }

    async fn query(&self, request: &QueryRequest) -> Result<(VerifiedMessage, String)> {
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

        let (res, relay_url) = self.send_query(&ctx, request, &relays).await?;
        res.zones
            .iter()
            .filter(|z| z.handle.is_single_label())
            .for_each(|z| {
                self.root_cache.insert(z.handle.to_string(), z.clone());
            });
        Ok((res, relay_url))
    }

    /// Send query to relays in order, verifying the response. Falls back on failure.
    /// Returns the verified message and the URL of the relay that served it.
    async fn send_query(
        &self,
        ctx: &QueryContext,
        request: &QueryRequest,
        relays: &[String],
    ) -> Result<(VerifiedMessage, String)> {
        // Build GET query params
        let mut q_parts: Vec<String> = Vec::new();
        let mut hint_parts: Vec<String> = Vec::new();
        for q in &request.queries {
            q_parts.push(q.space.clone());
            for h in &q.handles {
                if !h.is_empty() {
                    q_parts.push(format!("{}{}", h, q.space));
                }
            }
            if let Some(ref hint) = q.epoch_hint {
                hint_parts.push(format!("{}:{}:{}", q.space, hint.root, hint.height));
            }
        }
        let q_param = q_parts.join(",");
        let hints_param = hint_parts.join(",");

        let mut last_err = Error::NoPeers;
        for url in relays {
            let mut req = self
                .http
                .get(format!("{url}/query"))
                .query(&[("q", &q_param)]);
            if !hints_param.is_empty() {
                req = req.query(&[("hints", &hints_param)]);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    self.pool.mark_failed(url);
                    last_err = Error::Decode(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("GET {url}/query: {e}"),
                    ));
                    continue;
                }
            };
            if !resp.status().is_success() {
                self.pool.mark_failed(url);
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                last_err = Error::Relay { status, body };
                continue;
            }
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    self.pool.mark_failed(url);
                    last_err = Error::Decode(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("GET {url}/query: reading response: {e}"),
                    ));
                    continue;
                }
            };
            let msg = Message::from_slice(&bytes).map_err(|e| {
                Error::Decode(std::io::Error::new(
                    e.kind(),
                    format!("{url}/query: decoding message: {e}"),
                ))
            })?;
            let options = if self.dev_mode {
                libveritas::VERIFY_DEV_MODE
            } else {
                0
            };
            match self
                .veritas
                .lock()
                .unwrap()
                .verify_with_options(ctx, msg, options)
            {
                Ok(res) => {
                    self.pool.mark_alive(url);
                    return Ok((res, url.clone()));
                }
                Err(e) => {
                    self.pool.mark_failed(url);
                    last_err = Error::Verify(e);
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
                tasks.push((
                    url.clone(),
                    tokio::spawn(async move {
                        let resp = http.get(&hints_url).query(&[("q", &q)]).send().await.ok()?;
                        if !resp.status().is_success() {
                            return None;
                        }
                        resp.json::<HintsResponse>().await.ok()
                    }),
                ));
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

    /// Request a chain proof from a relay.
    /// Sends a `ChainProofRequest` and returns the borsh-encoded `ChainProof` bytes.
    pub async fn prove(&self, request: &spaces_nums::ChainProofRequest) -> Result<Vec<u8>> {
        self.bootstrap().await?;
        let body = serde_json::to_vec(request)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let urls = self.pool.shuffled_urls_n(4);
        let mut last_err = Error::NoPeers;

        for url in &urls {
            let prove_url = format!("{url}/chain-proof");
            let result = self
                .http
                .post(&prove_url)
                .body(body.clone())
                .header("content-type", "application/json")
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    self.pool.mark_alive(url);
                    return resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                        Error::Decode(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("POST {prove_url}: reading response: {e}"),
                        ))
                    });
                }
                Ok(resp) => {
                    self.pool.mark_failed(url);
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    last_err = Error::Relay { status, body };
                }
                Err(e) => {
                    self.pool.mark_failed(url);
                    last_err = Error::Decode(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("POST {prove_url}: {e}"),
                    ));
                }
            }
        }

        Err(last_err)
    }

    /// Broadcast a message to up to 4 random relays for gossip propagation.
    /// Returns Ok if at least one relay accepted.
    pub async fn broadcast(&self, msg_bytes: &[u8]) -> Result<()> {
        self.bootstrap().await?;
        let urls = self.pool.shuffled_urls_n(4);
        if urls.is_empty() {
            return Err(Error::NoPeers);
        }

        let mut any_ok = false;
        let mut last_err = None;
        for url in &urls {
            let msg_url = format!("{url}/message");
            let result = self
                .http
                .post(&msg_url)
                .body(msg_bytes.to_vec())
                .header("content-type", "application/octet-stream")
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => any_ok = true,
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    last_err = Some(Error::Relay { status, body });
                }
                Err(e) => {
                    last_err = Some(Error::Decode(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("POST {msg_url}: {e}"),
                    )))
                }
            }
        }

        if any_ok {
            Ok(())
        } else {
            Err(last_err.unwrap())
        }
    }

    /// Build, sign, and broadcast a message.
    ///
    /// * `cert` — `.spacecert` bytes (from `export()`)
    /// * `records` — RecordSet bytes (from `RecordSet::pack().to_bytes()`)
    /// * `secret_key` — 32-byte BIP-340 secret key
    /// * `primary` — set num id to handle reverse mapping.
    #[cfg(feature = "signing")]
    pub async fn publish(
        &self,
        cert: &[u8],
        records: RecordSet,
        secret_key: &[u8; 32],
        primary: bool,
    ) -> Result<()> {
        let msg = self.sign(cert, records, secret_key, primary).await?;
        self.broadcast(&msg).await
    }

    /// Build and sign a message ready for broadcasting.
    ///
    /// Returns the signed message bytes.
    #[cfg(feature = "signing")]
    pub async fn sign(
        &self,
        cert: &[u8],
        records: RecordSet,
        secret_key: &[u8; 32],
        primary: bool,
    ) -> Result<Vec<u8>> {
        let chain = CertificateChain::from_slice(cert)?;
        let mut builder = MessageBuilder::new();
        builder.add_handle(chain, records);
        let proof_bytes = self.prove(&builder.chain_proof_request()).await?;
        let proof = ChainProof::from_slice(&proof_bytes)?;
        let (mut message, mut unsigned) = builder.build(proof)?;

        for u in &mut unsigned {
            if primary {
                u.flags |= SIG_PRIMARY_ZONE;
            }
            let sig = crate::signing::sign_schnorr(&u.signing_id(), secret_key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            let signed = u.pack_sig(sig.to_vec());
            message.set_records(&u.canonical, signed);
        }

        Ok(message.to_bytes())
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

    /// Returns a clone of the internal Veritas instance for offline verification.
    pub fn veritas(&self) -> Veritas {
        self.veritas.lock().unwrap().clone()
    }
}

/// Build the hints query string from a QueryRequest.
/// e.g. "@bitcoin,alice@bitcoin,bob@bitcoin"
fn hints_query_string(request: &QueryRequest) -> String {
    let mut parts = HashSet::new();
    for query in &request.queries {
        parts.insert(query.space.clone());
        for handle in &query.handles {
            parts.insert(format!("{}{}", handle, query.space));
        }
    }
    parts.into_iter().collect::<Vec<_>>().join(",")
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
    let url = format!("{relay_url}/peers");
    let resp = http.get(&url).send().await.map_err(|e| {
        Error::Decode(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("GET {url}: {e}"),
        ))
    })?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Relay { status, body });
    }
    resp.json().await.map_err(|e| {
        Error::Decode(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("GET {url}: {e}"),
        ))
    })
}

impl RelayPool {
    fn new(urls: impl IntoIterator<Item = String>) -> Self {
        let entries = urls
            .into_iter()
            .map(|url| RelayEntry { url, failures: 0 })
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
                entries.push(RelayEntry { url, failures: 0 });
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    pub fn urls(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.url.clone())
            .collect()
    }
}

#[derive(Debug)]
pub enum Error {
    Decode(std::io::Error),
    Verify(MessageError),
    Relay { status: u16, body: String },
    NoPeers,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(e) => write!(f, "decode error: {e}"),
            Error::Verify(e) => write!(f, "verification error: {e}"),
            Error::Relay { status, body } => write!(f, "relay error ({status}): {body}"),
            Error::NoPeers => write!(f, "no peers available"),
        }
    }
}

impl std::error::Error for Error {}

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

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Decode(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    }
}

/// Fetch latest anchor set hash from the specified set of peers
///
/// Returns: (<root-hash>, <peers...>)
async fn fetch_latest_trust_id(
    http: &reqwest::Client,
    peers: &[String],
) -> Result<(TrustId, Vec<String>)> {
    let mut votes: HashMap<(String, u32), Vec<String>> = HashMap::new();
    let mut last_err: Option<Error> = None;

    for url in peers {
        let resp = match http.head(format!("{url}/anchors")).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(Error::Decode(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("HEAD {url}/anchors: {e}"),
                )));
                continue;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            last_err = Some(Error::Relay {
                status,
                body: format!("HEAD {url}/anchors: {status}"),
            });
            continue;
        }

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
            votes
                .entry((root, height))
                .or_default()
                .push(url.to_string());
        }
    }

    let (hash, peers) = votes
        .into_iter()
        .max_by_key(|((_, height), peers)| (peers.len(), *height))
        .map(|((root, _), peers)| (root, peers))
        .ok_or_else(|| last_err.unwrap_or(Error::NoPeers))?;

    Ok((TrustId::from_str(&hash)?, peers))
}

async fn fetch_anchor_set(
    http: &reqwest::Client,
    trust_id: TrustId,
    peers: &[String],
) -> Result<AnchorBundle> {
    let mut last_err: Option<Error> = None;
    for url in peers {
        let anchor_url = format!("{url}/anchors?root={trust_id}");
        let resp = match http.get(&anchor_url).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(Error::Decode(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("GET {anchor_url}: {e}"),
                )));
                continue;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            last_err = Some(Error::Relay { status, body });
            continue;
        }

        let anchor_set: AnchorSet = match resp.json().await {
            Ok(a) => a,
            Err(e) => {
                last_err = Some(Error::Decode(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("GET {anchor_url}: {e}"),
                )));
                continue;
            }
        };

        let ab = AnchorBundle {
            trust_set: compute_trust_set(&anchor_set.entries),
            anchors: anchor_set.entries,
        };

        if TrustId::from(ab.trust_set.id) != trust_id {
            last_err = Some(Error::Decode(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GET {anchor_url}: anchor root mismatch"),
            )));
            continue;
        }

        return Ok(ab);
    }

    Err(last_err.unwrap_or(Error::NoPeers))
}
