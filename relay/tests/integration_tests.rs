use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use libveritas::Veritas;
use libveritas::msg::QueryContext;
use libveritas_testutil::fixture::*;
use relay::anchor::AnchorSets;
use relay::{AppState, Config, ExtendedNetwork, Handler, PeerInfo, Relay, SqliteStore};
use resolver::{AnchorSet, HintsResponse};
use spaces_protocol::slabel::SLabel;

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/// Build a Veritas that includes the current root anchor so the tip
/// matches the current chain height (important after Finalize steps).
fn build_veritas(state: &ChainState) -> Veritas {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    Veritas::new().with_anchors(anchors).unwrap()
}

/// Create a Handler wired to the test chain state with an in-memory store.
fn setup_handler(state: &ChainState) -> Handler {
    let veritas = build_veritas(state);
    let store = SqliteStore::in_memory().unwrap();
    let mut handler = Handler::new(veritas, store, AnchorSets::from_anchors(vec![]));
    handler.dev_mode = true;
    handler
}

/// Replace the handler's Veritas with one built from the current chain state.
fn sync_veritas(handler: &Handler, state: &ChainState) {
    *handler.veritas.lock().unwrap() = build_veritas(state);
}

/// Collect the test anchors from a ChainState.
fn test_anchors(state: &ChainState) -> Vec<spaces_nums::RootAnchor> {
    let mut anchors = state.anchors.clone();
    anchors.push(state.chain.current_root_anchor());
    anchors.sort_by(|a, b| b.block.height.cmp(&a.block.height));
    anchors.dedup_by_key(|a| a.block.height);
    anchors
}

/// Start a relay HTTP server on a random port.
/// Returns (base_url, Arc<AppState>).
async fn start_relay(chain_state: &ChainState) -> (String, Arc<AppState>) {
    let mut config = Config::new(PathBuf::from("/tmp/relay-test"), ExtendedNetwork::Testnet4);
    config.db_path = PathBuf::from(":memory:");
    config.spaced_url = Some("http://127.0.0.1:1".into());
    config.anchors = test_anchors(chain_state);
    config.dev_mode = true;

    let relay = Relay::new(config).unwrap();
    *relay.state().handler.veritas.lock().unwrap() = build_veritas(chain_state);
    *relay.state().handler.anchor_store.lock().unwrap() =
        AnchorSets::from_anchors(test_anchors(chain_state));

    let state = relay.state().clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    tokio::spawn(async move {
        relay.run(listener).await.unwrap();
    });

    (url, state)
}

/// Build a QueryContext from the handler's store (mirrors what handler does internally).
fn build_ctx(handler: &Handler, spaces: &[SLabel]) -> QueryContext {
    let mut ctx = QueryContext::new();
    let space_refs: Vec<&SLabel> = spaces.iter().collect();
    let zones = handler.store.get_zones(&space_refs).unwrap();
    for z in zones {
        ctx.add_zone(z);
    }
    ctx
}

// ─────────────────────────────────────────────────────────────────────────
// Handler-level tests
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn test_single_commit_finalized() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let handler = setup_handler(&state);
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    handler.handle_message(msg).unwrap();

    for name in ["alice", "bob"] {
        let key = format!("{}@sovereign", name);
        assert!(
            handler.store.get_handle(&key).unwrap().is_some(),
            "{} should be stored",
            key
        );
    }

    assert!(
        handler.store.get_handle("@sovereign").unwrap().is_some(),
        "root handle should be stored"
    );
}

#[test]
fn test_kitchen_sink() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, kitchen_sink());
    runner.run(&mut state);

    let handler = setup_handler(&state);
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    handler.handle_message(msg).unwrap();

    for name in ["alice", "bob", "charlie", "dave", "eve", "frank"] {
        let key = format!("{}@kitchensink", name);
        assert!(
            handler.store.get_handle(&key).unwrap().is_some(),
            "{} should be stored",
            key
        );
    }

    for name in ["grace", "heidi"] {
        let key = format!("{}@kitchensink", name);
        assert!(
            handler.store.get_handle(&key).unwrap().is_some(),
            "{} (staged) should be stored",
            key
        );
    }

    assert!(
        handler.store.get_handle("@kitchensink").unwrap().is_some(),
        "root handle should be stored"
    );
}

/// Submit messages incrementally and verify the relay always stores the best
/// zone for each handle.  The relay's update_handles uses is_better_than to
/// keep fresher zones, so a later message with a worse zone (e.g. Dependent
/// replacing Pending) is correctly rejected.  We mirror that logic here.
#[test]
fn test_incremental_zone_replacement() {
    use libveritas::Zone;
    use std::collections::HashMap;

    let mut chain_state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut chain_state, kitchen_sink());
    let handler = setup_handler(&chain_state);

    // Track the best known zone for each handle across steps.
    let mut best_zones: HashMap<String, Vec<u8>> = HashMap::new();

    while let Some(_step) = runner.run_next(&mut chain_state) {
        sync_veritas(&handler, &chain_state);

        let bundle = runner.build_bundle();
        let msg = chain_state.message(vec![bundle]);

        // Build the same context the handler will use
        let spaces: Vec<SLabel> = msg.spaces.iter().map(|s| s.subject.clone()).collect();
        let ctx = build_ctx(&handler, &spaces);

        // Verify manually to get expected zones
        let veritas = build_veritas(&chain_state);
        let verified = veritas
            .verify_with_options(&ctx, msg.clone(), libveritas::VERIFY_DEV_MODE)
            .unwrap();

        // Update best_zones: only replace when the new zone is strictly better
        for zone in &verified.zones {
            let key = zone.canonical.to_string();
            let new_bytes = borsh::to_vec(zone).unwrap();
            let dominated = best_zones.get(&key).map_or(true, |existing_bytes| {
                let existing: Zone = borsh::from_slice(existing_bytes).unwrap();
                zone.is_better_than(&existing).unwrap_or(false)
            });
            if dominated {
                best_zones.insert(key, new_bytes);
            }
        }

        // Submit to handler (uses the same context + is_better_than internally)
        handler.handle_message(msg).unwrap();

        // Query back and compare — store should have the best zone seen so far
        for (handle_key, expected_bytes) in &best_zones {
            let stored = handler
                .store
                .get_handle(handle_key)
                .unwrap()
                .unwrap_or_else(|| panic!("{} should be stored", handle_key));

            let stored_bytes = borsh::to_vec(&stored.zone).unwrap();
            assert_eq!(
                &stored_bytes, expected_bytes,
                "stored zone for {} should match best known zone",
                handle_key
            );
        }
    }
}

#[test]
fn test_all_fixtures() {
    let fixtures: Vec<(&str, Fixture, Vec<&str>)> = vec![
        ("@staged", staged_only(), vec!["alice", "bob"]),
        ("@pending", single_commit_pending(), vec!["alice", "bob"]),
        (
            "@sovereign",
            single_commit_finalized(),
            vec!["alice", "bob"],
        ),
        (
            "@two-pending",
            two_commits_second_pending(),
            vec!["alice", "bob", "charlie"],
        ),
        (
            "@two-finalized",
            two_commits_both_finalized(),
            vec!["alice", "bob", "charlie"],
        ),
        (
            "@finalized-staged",
            finalized_with_staged(),
            vec!["alice", "bob"],
        ),
    ];

    for (space, fixture, expected_handles) in fixtures {
        let mut state = ChainState::new();
        let mut runner = FixtureRunner::new(&mut state, fixture);
        runner.run(&mut state);

        let handler = setup_handler(&state);
        let bundle = runner.build_bundle();
        let msg = state.message(vec![bundle]);
        handler.handle_message(msg).unwrap();

        for name in expected_handles {
            let key = format!("{}{}", name, space);
            assert!(
                handler.store.get_handle(&key).unwrap().is_some(),
                "{} should be stored for fixture {}",
                key,
                space
            );
        }

        assert!(
            handler.store.get_handle(space).unwrap().is_some(),
            "root {} should be stored",
            space
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// HTTP-level tests
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_relay_accepts_message() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url))
        .body(msg_bytes)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "ok");

    let record = app_state
        .handler
        .store
        .get_handle("alice@sovereign")
        .unwrap();
    assert!(
        record.is_some(),
        "alice should be stored after HTTP submission"
    );
}

#[tokio::test]
async fn test_broadcast_invalid_bytes() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let client = reqwest::Client::new();

    // Empty body
    let resp = client
        .post(format!("{}/message", url))
        .body(vec![])
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "invalid message format");

    // Garbage bytes
    let resp = client
        .post(format!("{}/message", url))
        .body(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "invalid message format");
}

#[tokio::test]
async fn test_broadcast_response_readable() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    // Use the same reqwest setup as the Fabric client
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url))
        .body(msg_bytes)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status.is_success(), "expected 2xx, got {}", status);

    // This is the path that would produce "error decoding response body"
    let body_text = resp
        .text()
        .await
        .expect("should be able to read response body as text");
    assert_eq!(body_text, "ok");
}

#[tokio::test]
async fn test_peers_endpoint() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;

    // Add a peer and mark it alive (peers endpoint only returns verified peers)
    {
        let mut peers = app_state.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 2]),
            url: "http://relay2.example.com".to_string(),
            capabilities: 0,
        });
        peers.mark_alive("http://relay2.example.com");
    }

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/peers", url)).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    // Should parse as valid JSON array of PeerInfo
    let peers: Vec<PeerInfo> = resp
        .json()
        .await
        .expect("peers response should be valid JSON");
    assert!(!peers.is_empty(), "should have at least one peer");
}

#[tokio::test]
async fn test_anchors_endpoint() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let client = reqwest::Client::new();

    // HEAD /anchors should return headers
    let resp = client
        .head(format!("{}/anchors", url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let root = resp
        .headers()
        .get("x-anchor-root")
        .expect("should have x-anchor-root header")
        .to_str()
        .unwrap();
    assert!(!root.is_empty(), "anchor root should not be empty");

    let height = resp
        .headers()
        .get("x-anchor-height")
        .expect("should have x-anchor-height header")
        .to_str()
        .unwrap();
    assert!(!height.is_empty(), "anchor height should not be empty");

    // GET /anchors should return valid JSON
    let resp = client.get(format!("{}/anchors", url)).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let anchor_set: AnchorSet = resp
        .json()
        .await
        .expect("anchors response should be valid JSON AnchorSet");
    assert!(!anchor_set.entries.is_empty(), "should have anchor entries");

    // GET /anchors?root=<hex> should return the same set
    let trust_set = libveritas::compute_trust_set(&anchor_set.entries);
    let root_hex = hex::encode(trust_set.id);
    let resp = client
        .get(format!("{}/anchors?root={}", url, root_hex))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let fetched: AnchorSet = resp
        .json()
        .await
        .expect("anchors response with root param should be valid JSON");
    let fetched_trust = libveritas::compute_trust_set(&fetched.entries);
    assert_eq!(
        fetched_trust.id, trust_set.id,
        "fetched anchor root should match"
    );

    // GET /anchors?root=<nonexistent> should return 404
    let fake_root = "cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3";
    let resp = client
        .get(format!("{}/anchors?root={}", url, fake_root))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "anchor set not found");
}

#[tokio::test]
async fn test_hints_endpoint() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    // Submit message first
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url))
        .body(msg.to_bytes())
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Query hints
    let resp = client
        .get(format!(
            "{}/hints?q=alice@sovereign,bob@sovereign,@sovereign",
            url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let hints: HintsResponse = resp
        .json()
        .await
        .expect("hints response should be valid JSON");
    assert!(!hints.hints.is_empty(), "should have space hints");
    assert!(hints.anchor_tip > 0, "anchor_tip should be > 0");
}

#[tokio::test]
async fn test_gossip_propagation() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url_a, state_a) = start_relay(&state).await;
    let (url_b, state_b) = start_relay(&state).await;

    // Add relay B as a verified peer in relay A
    {
        let mut peers = state_a.peers.lock().await;
        peers.announce(&PeerInfo {
            source_ip: IpAddr::from([10, 0, 0, 2]),
            url: url_b.clone(),
            capabilities: 0,
        });
        peers.mark_alive(&url_b);
    }

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/message", url_a))
        .body(msg_bytes)
        .header("content-type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Wait for gossip
    tokio::time::sleep(Duration::from_millis(500)).await;

    let root = state_b.handler.store.get_handle("@sovereign").unwrap();
    assert!(root.is_some(), "relay B should have @sovereign from gossip");

    let alice = state_b.handler.store.get_handle("alice@sovereign").unwrap();
    assert!(
        alice.is_some(),
        "relay B should have alice@sovereign from gossip"
    );
}
