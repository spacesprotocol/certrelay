//! Wire format types for relay P2P communication.
//!
//! All protocol types use JSON serialization for cross-language compatibility.
//! Only the `Message` type from libveritas remains binary (borsh).



pub mod anchor;
#[cfg(feature = "client")]
pub mod client;
pub mod seeds;
#[cfg(feature = "signing")]
pub mod signing;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// Re-export the entire libveritas crate
pub extern crate libveritas;
// Also re-export Message directly since it's used in the wire format
pub use libveritas::msg::Message;
use spaces_nums::RootAnchor;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustId([u8; 32]);

impl TrustId {
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for TrustId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for TrustId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl FromStr for TrustId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = hex::decode(s)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;

        Ok(Self(bytes))
    }
}

/// Capability flags for peers.
///
/// Reserved for future use. Capabilities allow peers to advertise
/// what features they support.
pub mod capabilities {
    // No capabilities defined yet
}

/// A query for certificate data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    /// The space to query (e.g., "@bitcoin").
    pub space: String,
    /// Handles within the space to query.
    pub handles: Vec<String>,
    /// Optional epoch hint for optimizing proof size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_hint: Option<EpochHint>,
}

impl Query {
    pub fn new(space: impl Into<String>, handles: Vec<String>) -> Self {
        Self {
            space: space.into(),
            handles,
            epoch_hint: None,
        }
    }

    pub fn with_epoch_hint(mut self, hint: EpochHint) -> Self {
        self.epoch_hint = Some(hint);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintsResponse {
    pub anchor_tip: u32,
    pub hints: Vec<SpaceHint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorSet {
    pub entries: Vec<RootAnchor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpaceHint {
    pub epoch_tip: u32,
    pub name: String,
    pub seq: u64,
    pub delegate_seq: u64,
    pub epochs: Vec<EpochResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochResult {
    pub epoch: u32,
    pub res: Vec<HandleHint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandleHint {
    pub seq: u64,
    pub name: String,
}

impl PartialEq for HintsResponse {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for HintsResponse {}

impl PartialOrd for HintsResponse {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HintsResponse {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut score: i32 = 0;

        for space in &self.hints {
            let Some(other_space) = other.hints.iter().find(|s| s.name == space.name) else {
                score += 1;
                continue;
            };

            score += cmp_score(space.epoch_tip, other_space.epoch_tip);
            score += cmp_score(space.seq, other_space.seq);
            score += cmp_score(space.delegate_seq, other_space.delegate_seq);

            let self_handles = flatten_handles(space);
            let other_handles = flatten_handles(other_space);

            for (name, self_seq) in &self_handles {
                match other_handles.get(*name) {
                    Some(other_seq) => score += cmp_score(*self_seq, *other_seq),
                    None => score += 1,
                }
            }
            for name in other_handles.keys() {
                if !self_handles.contains_key(*name) {
                    score -= 1;
                }
            }
        }

        for other_space in &other.hints {
            if !self.hints.iter().any(|s| s.name == other_space.name) {
                score -= 1;
            }
        }

        if score != 0 {
            score.cmp(&0)
        } else {
            self.anchor_tip.cmp(&other.anchor_tip)
        }
    }
}

fn cmp_score<T: Ord>(a: T, b: T) -> i32 {
    match a.cmp(&b) {
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
    }
}

fn flatten_handles(space: &SpaceHint) -> HashMap<&str, u64> {
    let mut map = HashMap::new();
    for epoch in &space.epochs {
        for handle in &epoch.res {
            let existing = map.get(handle.name.as_str()).copied().unwrap_or(0);
            if handle.seq > existing {
                map.insert(handle.name.as_str(), handle.seq);
            }
        }
    }
    map
}

/// Epoch hint for query optimization.
///
/// If the client has a cached epoch root, providing this hint allows
/// the relay to skip including redundant proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochHint {
    /// The merkle root of the cached epoch (hex-encoded).
    pub root: String,
    /// The block height of the cached epoch.
    pub height: u32,
}

/// Request body for POST /query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    /// The queries to execute.
    pub queries: Vec<Query>,
}

impl QueryRequest {
    pub fn new(queries: Vec<Query>) -> Self {
        Self { queries }
    }

    pub fn single(space: impl Into<String>, handles: Vec<String>) -> Self {
        Self {
            queries: vec![Query::new(space, handles)],
        }
    }
}

/// Announcement payload for POST /announce.
///
/// Sent by a peer to announce itself to another relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    /// The URL where this peer can be reached.
    pub url: String,
    /// Capability flags indicating what this peer supports.
    pub capabilities: u32,
}

impl Announcement {
    pub fn new(url: impl Into<String>, capabilities: u32) -> Self {
        Self {
            url: url.into(),
            capabilities,
        }
    }

    pub fn has_capability(&self, cap: u32) -> bool {
        self.capabilities & cap != 0
    }
}

/// Information about a peer, returned from GET /peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The IP address that announced this peer.
    pub source_ip: IpAddr,
    /// The URL where this peer can be reached.
    pub url: String,
    /// Capability flags indicating what this peer supports.
    pub capabilities: u32,
}

impl PeerInfo {
    pub fn has_capability(&self, cap: u32) -> bool {
        self.capabilities & cap != 0
    }
}

impl AnchorSet {
    pub fn from_anchors(anchors: Vec<RootAnchor>) -> Self {
        Self {
            entries: anchors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_roundtrip() {
        let query = Query::new("@bitcoin", vec!["alice".into()]);
        let req = QueryRequest::new(vec![query]);

        let json = serde_json::to_string(&req).unwrap();
        let decoded: QueryRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].space, "@bitcoin");
        assert_eq!(decoded.queries[0].handles, vec!["alice"]);
    }

    #[test]
    fn test_announcement_roundtrip() {
        let announcement = Announcement::new("https://relay.example.com", 0);
        let json = serde_json::to_string(&announcement).unwrap();
        let decoded: Announcement = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.url, "https://relay.example.com");
        assert_eq!(decoded.capabilities, 0);
    }

    #[test]
    fn test_peer_info_roundtrip() {
        let peer = PeerInfo {
            source_ip: "192.168.1.1".parse().unwrap(),
            url: "https://peer.example.com".to_string(),
            capabilities: 0,
        };
        let json = serde_json::to_string(&peer).unwrap();
        let decoded: PeerInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.url, "https://peer.example.com");
        assert_eq!(decoded.source_ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_epoch_hint_skipped_when_none() {
        let query = Query::new("@bitcoin", vec!["alice".into()]);
        let json = serde_json::to_string(&query).unwrap();
        assert!(!json.contains("epoch_hint"));
    }
}



