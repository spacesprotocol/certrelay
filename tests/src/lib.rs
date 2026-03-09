use std::net::SocketAddr;
use std::sync::Arc;

use libveritas::cert::{PtrsSubtree, SpacesSubtree};
use libveritas::msg::{ChainProof, QueryContext};
use libveritas::Veritas;
use libveritas_testutil::fixture::ChainState;
use relay::{
    AppState, Handler, PeerConfig, SqliteStore, SpacedClient, router,
};
use relay::anchor::AnchorStore;
use spaces_protocol::slabel::SLabel;

/// Build a Veritas that includes the current root anchor so the tip
/// matches the current chain height (important after Finalize steps).
pub fn build_veritas(state: &ChainState) -> Veritas {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    Veritas::new()
        .with_anchors(anchors).unwrap()
        .with_dev_mode(true)
}

/// Collect the test anchors from a ChainState.
pub fn test_anchors(state: &ChainState) -> Vec<spaces_ptr::RootAnchor> {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    anchors
}

/// Build a mock chain proof from the test chain state.
/// Returns the full spaces and ptrs subtrees so any query can be served.
pub fn mock_chain_proof(state: &ChainState) -> ChainProof {
    ChainProof {
        anchor: state.chain.current_root_anchor().block,
        spaces: SpacesSubtree(state.chain.spaces_tree.clone()),
        ptrs: PtrsSubtree(state.chain.ptrs_tree.clone()),
    }
}

/// Create a Handler wired to the test chain state with an in-memory store.
pub fn setup_handler(state: &ChainState) -> Handler {
    let veritas = build_veritas(state);
    let store = SqliteStore::in_memory().unwrap();
    Handler::new(veritas, store, AnchorStore::from_anchors(vec![]))
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
    let anchor_store = AnchorStore::from_anchors(test_anchors(chain_state));
    let handler = Handler::new(veritas, store, anchor_store);
    let chain = SpacedClient::mock(mock_chain_proof(chain_state));

    let state = Arc::new(AppState::new(handler, chain, PeerConfig::default()));

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
