use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

pub use resolver::{PeerInfo, capabilities};

pub struct PeerTable {
    /// IP -> announced URL (one slot per IP)
    ip_slots: HashMap<IpAddr, String>,
    /// URL -> unverified peer info
    unverified: HashMap<String, PeerEntry>,
    /// URL -> verified peer info
    verified: HashMap<String, PeerEntry>,
    config: PeerConfig,
    /// Our own URL (never returned in peer lists)
    self_url: Option<String>,
}

pub struct PeerConfig {
    pub max_unverified: usize,
    pub max_verified: usize,
    pub verified_ttl: Duration,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            max_unverified: 1_000,
            max_verified: 1_00,
            verified_ttl: Duration::from_secs(600),
        }
    }
}

struct PeerEntry {
    source_ip: IpAddr,
    capabilities: u32,
    last_seen: Instant,
}

#[derive(Debug, PartialEq)]
pub enum AnnounceResult {
    /// Already verified and still fresh
    AlreadyVerified,
    /// Added or refreshed as unverified
    Unverified,
}

impl PeerTable {
    pub fn new(config: PeerConfig) -> Self {
        Self {
            ip_slots: HashMap::new(),
            unverified: HashMap::new(),
            verified: HashMap::new(),
            config,
            self_url: None,
        }
    }

    /// Set our own URL so we never gossip to ourselves.
    pub fn set_self_url(&mut self, url: &str) {
        self.self_url = Some(normalize_url(url));
    }

    fn is_self(&self, url: &str) -> bool {
        self.self_url.as_ref().is_some_and(|s| s == url)
    }

    /// Announce a peer.
    /// One slot per IP. Deduplicated by URL.
    pub fn announce(&mut self, peer: &PeerInfo) -> AnnounceResult {
        let url = normalize_url(&peer.url);
        let source_ip = peer.source_ip;
        let capabilities = peer.capabilities;

        // Never add ourselves
        if self.is_self(&url) {
            return AnnounceResult::AlreadyVerified;
        }

        let now = Instant::now();

        // Already verified and fresh? Just refresh.
        if let Some(peer) = self.verified.get_mut(&url)
            && now.duration_since(peer.last_seen) < self.config.verified_ttl
        {
            peer.last_seen = now;
            peer.capabilities = capabilities;
            return AnnounceResult::AlreadyVerified;
        }

        // Remove this IP's previous announcement if it was a different URL
        if let Some(old_url) = self.ip_slots.get(&source_ip)
            && *old_url != url
        {
            let old_url = old_url.clone();
            // Remove old URL from unverified if no other IP points to it
            let other_refs = self
                .ip_slots
                .iter()
                .any(|(ip, u)| *ip != source_ip && *u == old_url);
            if !other_refs {
                self.unverified.remove(&old_url);
            }
        }

        // Assign this IP's slot
        self.ip_slots.insert(source_ip, url.clone());

        // Upsert into unverified
        self.unverified
            .entry(url)
            .and_modify(|e| {
                e.last_seen = now;
                e.capabilities = capabilities;
            })
            .or_insert(PeerEntry {
                source_ip,
                capabilities,
                last_seen: now,
            });

        // Evict oldest if over capacity
        while self.unverified.len() > self.config.max_unverified {
            if let Some(oldest) = self
                .unverified
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(url, _)| url.clone())
            {
                self.unverified.remove(&oldest);
                self.ip_slots.retain(|_, u| *u != oldest);
            } else {
                break;
            }
        }

        AnnounceResult::Unverified
    }

    /// Mark a URL as alive (call after successful health check or gossip send).
    /// Moves from unverified to verified, or refreshes if already verified.
    pub fn mark_alive(&mut self, url: &str) {
        let url = normalize_url(url);
        let now = Instant::now();

        // If already verified, just refresh
        if let Some(entry) = self.verified.get_mut(&url) {
            entry.last_seen = now;
            return;
        }

        // Move from unverified to verified
        let Some(entry) = self.unverified.remove(&url) else {
            return; // Unknown peer, ignore
        };

        self.ip_slots.retain(|_, u| *u != url);

        self.verified.insert(
            url,
            PeerEntry {
                source_ip: entry.source_ip,
                capabilities: entry.capabilities,
                last_seen: now,
            },
        );

        // Evict oldest verified if over capacity
        while self.verified.len() > self.config.max_verified {
            if let Some(oldest) = self
                .verified
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(url, _)| url.clone())
            {
                self.verified.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Deprioritize a URL after a failed health check.
    /// Bumps it to the back of the line instead of removing it.
    pub fn deprioritize(&mut self, url: &str) {
        let url = normalize_url(url);
        if let Some(entry) = self.unverified.get_mut(&url) {
            entry.last_seen = Instant::now();
        }
    }

    /// Get list of verified, non-stale peer URLs.
    pub fn peers(&self) -> Vec<&str> {
        let now = Instant::now();
        self.verified
            .iter()
            .filter(|(url, e)| {
                !self.is_self(url) && now.duration_since(e.last_seen) < self.config.verified_ttl
            })
            .map(|(url, _)| url.as_str())
            .collect()
    }

    /// Get list of verified, non-stale peers with full info.
    pub fn peers_info(&self) -> Vec<PeerInfo> {
        let now = Instant::now();
        self.verified
            .iter()
            .filter(|(url, e)| {
                !self.is_self(url) && now.duration_since(e.last_seen) < self.config.verified_ttl
            })
            .map(|(url, e)| PeerInfo {
                source_ip: e.source_ip,
                url: url.clone(),
                capabilities: e.capabilities,
            })
            .collect()
    }

    /// Pick a candidate from unverified to health-check.
    /// Returns the least-recently-seen URL (tried longest ago or never tried).
    pub fn next_candidate(&self) -> Option<&str> {
        self.unverified
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(url, _)| url.as_str())
    }

    /// True if we need more verified peers.
    pub fn needs_peers(&self) -> bool {
        let active = self
            .verified
            .values()
            .filter(|e| Instant::now().duration_since(e.last_seen) < self.config.verified_ttl)
            .count();
        active < self.config.max_verified / 2
    }

    /// Move expired verified peers back to unverified so they can be re-checked.
    pub fn demote_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<(String, PeerEntry)> = self
            .verified
            .extract_if(|_, e| now.duration_since(e.last_seen) >= self.config.verified_ttl)
            .collect();
        for (url, entry) in expired {
            self.unverified.entry(url).or_insert(entry);
        }
    }

    pub fn verified_count(&self) -> usize {
        self.verified.len()
    }

    pub fn unverified_count(&self) -> usize {
        self.unverified.len()
    }
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PeerConfig {
        PeerConfig {
            max_unverified: 3,
            max_verified: 2,
            verified_ttl: Duration::from_secs(600),
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn peer(last: u8, url: &str) -> PeerInfo {
        PeerInfo {
            source_ip: ip(last),
            url: url.to_string(),
            capabilities: 0,
        }
    }

    #[test]
    fn announce_and_list() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));

        assert_eq!(table.unverified_count(), 2);
        assert_eq!(table.peers().len(), 0);

        table.mark_alive("https://relay1.com");
        assert_eq!(table.unverified_count(), 1);
        assert_eq!(table.peers(), vec!["https://relay1.com"]);
    }

    #[test]
    fn one_slot_per_ip() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(1, "https://relay2.com"));

        // relay1 should be gone since ip(1) switched to relay2
        assert_eq!(table.unverified_count(), 1);
        assert!(table.next_candidate().unwrap().contains("relay2"));
    }

    #[test]
    fn dedup_same_url_different_ips() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay1.com"));

        // Same URL, only one unverified entry
        assert_eq!(table.unverified_count(), 1);
    }

    #[test]
    fn shared_url_not_removed_when_one_ip_switches() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay1.com"));

        // ip(1) switches to a new URL
        table.announce(&peer(1, "https://relay2.com"));

        // relay1 still exists because ip(2) still points to it
        assert_eq!(table.unverified_count(), 2);
    }

    #[test]
    fn evicts_oldest_unverified() {
        let mut table = PeerTable::new(config()); // max_unverified = 3
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));
        table.announce(&peer(3, "https://relay3.com"));
        table.announce(&peer(4, "https://relay4.com"));

        assert_eq!(table.unverified_count(), 3);
    }

    #[test]
    fn deprioritize_sends_to_back() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.announce(&peer(2, "https://relay2.com"));

        // relay1 announced first, so it's the next candidate
        assert!(table.next_candidate().unwrap().contains("relay1"));

        // deprioritize bumps it to the back
        table.deprioritize("https://relay1.com");
        assert!(table.next_candidate().unwrap().contains("relay2"));
    }

    #[test]
    fn already_verified_refreshes() {
        let mut table = PeerTable::new(config());
        table.announce(&peer(1, "https://relay1.com"));
        table.mark_alive("https://relay1.com");

        let result = table.announce(&peer(1, "https://relay1.com"));
        assert_eq!(result, AnnounceResult::AlreadyVerified);
    }

    #[test]
    fn peers_info_includes_capabilities() {
        let mut table = PeerTable::new(config());
        let p = PeerInfo {
            source_ip: ip(1),
            url: "https://relay1.com".to_string(),
            capabilities: 0x1,
        };
        table.announce(&p);
        table.mark_alive("https://relay1.com");

        let peers = table.peers_info();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].has_capability(0x1));
        assert_eq!(peers[0].source_ip, ip(1));
    }
}
