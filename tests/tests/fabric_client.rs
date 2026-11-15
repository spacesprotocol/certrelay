use fabric::client::{Fabric, TrustId};
use integration_tests::start_relay;
use libveritas_testutil::fixture::*;
use std::str::FromStr;

#[tokio::test(flavor = "multi_thread")]
async fn test_bootstrap() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    fabric.bootstrap().await.expect("bootstrap should succeed");
    assert!(
        fabric.observed().is_some(),
        "should have observed trust set after bootstrap"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bootstrap_bad_trust_id() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fake_id =
        TrustId::from_str("cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3")
            .unwrap();
    let fabric = Fabric::with_seeds(&[url.as_str()]);

    let result = fabric.trust(fake_id).await;
    assert!(result.is_err(), "trust with bad id should fail");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("404") || err_msg.contains("not found"),
        "error should indicate anchor set not found, got: {}",
        err_msg
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_broadcast() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    fabric
        .broadcast(&msg_bytes)
        .await
        .expect("broadcast should succeed");

    let record = app_state
        .handler
        .store
        .get_handle("alice@sovereign")
        .unwrap();
    assert!(record.is_some(), "alice should be stored after broadcast");

    let root = app_state.handler.store.get_handle("@sovereign").unwrap();
    assert!(
        root.is_some(),
        "@sovereign should be stored after broadcast"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_broadcast_error_details() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    // Broadcasting invalid bytes should fail
    let result = fabric.broadcast(&[0xDE, 0xAD, 0xBE, 0xEF]).await;
    assert!(result.is_err(), "broadcast with garbage bytes should fail");

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    // Should be a relay error (400), not a decode/http error
    assert!(
        err_msg.contains("relay error") || err_msg.contains("400"),
        "expected relay error, got: {}",
        err_msg
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolve() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    // Submit message directly so there's data to resolve
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

    // Resolve via Fabric client
    let fabric = Fabric::with_seeds(&[url.as_str()]);

    fabric
        .resolve("alice@sovereign")
        .await
        .expect("should resolve alice@sovereign");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolve_all() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    // Submit message
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

    // Resolve multiple handles
    let fabric = Fabric::with_seeds(&[url.as_str()]);

    let zones = fabric
        .resolve_all(&["alice@sovereign", "bob@sovereign"])
        .await
        .expect("should resolve multiple handles");

    assert!(
        zones
            .iter()
            .any(|z| z.handle.to_string() == "alice@sovereign")
            || zones.iter().any(|z| z.handle.to_string() == "@sovereign"),
        "should contain alice or root zone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolve_nonexistent() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    // Resolve a handle that was never broadcast — returns None
    let result = fabric.resolve("nobody@sovereign").await.unwrap();
    assert!(
        result.is_none(),
        "resolving nonexistent handle should return None"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolve_all_partial() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    // Submit message so alice exists
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

    // Resolve one existing and one nonexistent handle
    let fabric = Fabric::with_seeds(&[url.as_str()]);
    fabric.set_prefer_latest(false);
    let zones = fabric
        .resolve_all(&["alice@sovereign", "nobody@sovereign"])
        .await
        .expect("resolve_all should succeed with partial results");

    // Should return the existing handle, not the missing one
    assert!(
        !zones
            .iter()
            .any(|z| z.handle.to_string() == "nobody@sovereign"),
        "nonexistent handle should not be in results"
    );
    assert!(zones.len() >= 1, "should have at least the existing handle");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_broadcast_then_resolve() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    // Broadcast
    fabric
        .broadcast(&msg_bytes)
        .await
        .expect("broadcast should succeed");

    // Resolve the same handles we just broadcast
    fabric
        .resolve("alice@sovereign")
        .await
        .expect("should resolve alice after broadcast");

    let zones = fabric
        .resolve_all(&["alice@sovereign", "bob@sovereign"])
        .await
        .expect("should resolve all after broadcast");
    assert!(zones.len() >= 2, "should have at least 2 zones");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_peek_dumps_stored_zones() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    // Store data.
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

    // Peek the space root — one handle, unverified dump straight from the DB.
    let zones: Vec<serde_json::Value> = client
        .get(format!("{}/peek?q=@sovereign", url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let root = zones
        .iter()
        .find(|z| z["handle"] == "@sovereign")
        .expect("@sovereign should be in the dump");
    // Fields a UI needs, parsed straight from the stored zone (unverified).
    assert_eq!(root["sovereignty"], "sovereign");
    assert!(root["script_pubkey"].as_str().is_some());
    assert!(root["records"].is_array());
    assert!(root.get("commitment").is_some());

    // A first-level sub-handle resolves in one keyed read.
    let zones: Vec<serde_json::Value> = client
        .get(format!("{}/peek?q=alice@sovereign", url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        zones.iter().any(|z| z["handle"] == "alice@sovereign"),
        "alice@sovereign should be in the dump, got {zones:?}"
    );

    // A handle that isn't stored → empty array (not an error).
    let zones: Vec<serde_json::Value> = client
        .get(format!("{}/peek?q=ghost@sovereign", url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        zones.is_empty(),
        "missing handle should return [], got {zones:?}"
    );

    // Guardrails: missing q, more than one handle, and deeper-than-one nesting
    // are all 400s.
    for (path, why) in [
        ("/peek", "missing q"),
        (
            "/peek?q=@sovereign,alice@sovereign",
            "comma / multiple handles",
        ),
        ("/peek?q=a.b.c@sovereign", "two levels of nesting"),
    ] {
        let status = client
            .get(format!("{}{}", url, path))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert_eq!(status, 400, "{why} should be a 400");
    }
}

/// The nested `/peek` path drives libveritas' `Lookup` against the DB and relies
/// on each batch handle's string form being exactly a stored key. Pin that
/// contract: a one-level name's first batch is the flat parent sub-handle
/// (`genesis@key`), which is a keyed read — not the raw dotted name. (The
/// subsequent alias walk is covered by libveritas' own Lookup tests.)
#[test]
fn peek_nested_first_batch_is_a_flat_key() {
    use libveritas::names::Lookup;
    use libveritas::spaces_protocol::sname::SName;

    let sname = SName::try_from("across-remove-super.genesis@key").unwrap();
    let lookup = Lookup::new(vec![sname]);
    let batch: Vec<String> = lookup.start().iter().map(|s| s.to_string()).collect();
    assert_eq!(batch, vec!["genesis@key".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_discover_by_controlling_spk() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app) = start_relay(&state).await;

    // Store @sovereign + alice@sovereign.
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

    // Read alice's controlling spk straight from the stored zone — the exact
    // bytes the index is built from, so the test doesn't depend on any
    // serialization format.
    let recs = app.handler.store.get_handles(&["alice@sovereign"]).unwrap();
    assert!(!recs.is_empty(), "alice@sovereign should be stored");
    let spk_hex = hex::encode(recs[0].zone.script_pubkey.as_bytes());

    // Discover by that controlling key.
    let rows: Vec<serde_json::Value> = client
        .get(format!("{}/discover?spks={}", url, spk_hex))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let found = rows
        .iter()
        .find(|r| r["handle"] == "alice@sovereign")
        .expect("alice@sovereign should be discovered by its controlling spk");
    assert_eq!(found["controlling_spk"], spk_hex);
    assert_eq!(found["space"], "@sovereign");
    assert!(
        found["zone_hash"].as_str().is_some_and(|s| s.len() == 64),
        "zone_hash should be 32-byte hex, got {found:?}"
    );

    // An unknown controlling key discovers nothing (empty, not an error).
    let empty: Vec<serde_json::Value> = client
        .get(format!("{}/discover?spks={}", url, "ab".repeat(34)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        empty.is_empty(),
        "unknown spk should discover nothing, got {empty:?}"
    );

    // Missing spks parameter is a 400.
    let status = client
        .get(format!("{}/discover", url))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 400, "missing spks should be a 400");
}
