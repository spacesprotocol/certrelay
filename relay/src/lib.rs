//! Certificate relay for verifying and storing zones and certificates.

pub mod app;
pub mod handler;
pub mod http;
pub mod peer;
pub mod relay;
pub mod store;
pub mod spaced;

pub use resolver::anchor;

use libveritas::{AnchorError, Veritas};
pub use http::{
    bootstrap, bootstrap_from, router, AppState, Quota, RateLimitConfig, RateLimiters,
    BOOTSTRAP_RELAYS, DEFAULT_MAX_MESSAGE_SIZE,
};
pub use peer::{AnnounceResult, PeerConfig, PeerTable};

// Re-export wire format types from relay-client
pub use resolver::{capabilities, Announcement, EpochHint, PeerInfo, Query, QueryRequest};
pub use handler::{Handler};
pub use relay::{Config, Relay, ServiceRunner};
pub use spaces_client::config::ExtendedNetwork;
use spaces_nums::RootAnchor;
pub use spaced::SpacedClient;
pub use store::SqliteStore;


// Create veritas with disabled name expansion
fn create_relay_veritas(anchors: Vec<RootAnchor>) -> Result<Veritas, AnchorError> {
    Veritas::new()
        .with_anchors(anchors)
}
