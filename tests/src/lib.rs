use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use libveritas::cert::{NumsSubtree, SpacesSubtree};
use libveritas::msg::{ChainProof, QueryContext};
use libveritas::Veritas;
use libveritas_testutil::fixture::ChainState;
use relay::{
    AppState, Handler, PeerConfig, SqliteStore, SpacedClient, router,
};
use fabric::anchor::AnchorSets;
use relay::http::{Quota, RateLimitConfig};
use spaces_protocol::slabel::SLabel;
use spaces_nums::RootAnchor;

/// Build a Veritas that includes the current root anchor so the tip
/// matches the current chain height (important after Finalize steps).
pub fn build_veritas(state: &ChainState) -> Veritas {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    Veritas::new()
        .with_anchors(anchors).unwrap()
}

/// Collect the test anchors from a ChainState.
pub fn test_anchors(state: &ChainState) -> Vec<spaces_nums::RootAnchor> {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    anchors
}

/// Build a mock chain proof from the test chain state.
/// Returns the full spaces and ptrs subtrees so any query can be served.
pub fn mock_chain_proof(state: &ChainState) -> (ChainProof, Vec<RootAnchor>) {
    (ChainProof {
        anchor: state.chain.current_root_anchor().block,
        spaces: SpacesSubtree(state.chain.spaces_tree.clone()),
        nums: NumsSubtree(state.chain.nums_tree.clone()),
    }, test_anchors(state))
}

/// Create a Handler wired to the test chain state with an in-memory store.
pub fn setup_handler(state: &ChainState) -> Handler {
    let veritas = build_veritas(state);
    let store = SqliteStore::in_memory().unwrap();
    let mut handler = Handler::new(veritas, store, AnchorSets::from_anchors(vec![]));
    handler.dev_mode = true;
    handler
}

/// Replace the handler's Veritas with one built from the current chain state.
pub fn sync_veritas(handler: &Handler, state: &ChainState) {
    *handler.veritas.lock().unwrap() = build_veritas(state);
}

/// Build a QueryContext from the handler's store (mirrors what handler does internally).
pub fn build_ctx(handler: &Handler, spaces: &[SLabel]) -> QueryContext {
    let mut ctx = QueryContext::new();
    let space_refs: Vec<&SLabel> = spaces.iter().collect();
    let zones = handler.store.get_zones(&space_refs).unwrap();
    for z in zones {
        ctx.add_zone(z);
    }
    ctx
}

/// Start a relay HTTP server on a random port with a mock SpacedClient.
/// Returns (base_url, Arc<AppState>).
pub async fn start_relay(chain_state: &ChainState) -> (String, Arc<AppState>) {
    let veritas = build_veritas(chain_state);
    let store = SqliteStore::in_memory().unwrap();
    let anchor_store = AnchorSets::from_anchors(test_anchors(chain_state));
    let mut handler = Handler::new(veritas, store, anchor_store);
    handler.dev_mode = true;
    let chain = SpacedClient::mock(mock_chain_proof(chain_state));

    let rate_config = RateLimitConfig {
        message: Quota::per_second(NonZeroU32::new(100).unwrap()),
        query: Quota::per_second(NonZeroU32::new(100).unwrap()),
        announce: Quota::per_second(NonZeroU32::new(100).unwrap()),
        peers: Quota::per_second(NonZeroU32::new(100).unwrap()),
    };
    let state = Arc::new(AppState::with_rate_limits(handler, chain, PeerConfig::default(), rate_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let app_state = state.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (url, app_state)
}
