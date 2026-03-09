use fabric::client::Fabric;
use libveritas_testutil::fixture::*;
use integration_tests::start_relay;

#[tokio::test]
async fn test_bootstrap() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    fabric.bootstrap().await.expect("bootstrap should succeed");
    assert!(!fabric.needs_peers(), "should have peers after bootstrap");
    assert!(!fabric.needs_anchors(), "should have anchors after bootstrap");
}

#[tokio::test]
async fn test_bootstrap_bad_anchor_set() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fake_hash = "cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3";
    let fabric = Fabric::with_seeds(&[url.as_str()])
        .with_anchor_set(fake_hash);

    let result = fabric.bootstrap().await;
    assert!(result.is_err(), "bootstrap with bad anchor set should fail");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("404") || err_msg.contains("not found"),
        "error should indicate anchor set not found, got: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_broadcast() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, app_state) = start_relay(&state).await;

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let msg_bytes = msg.to_bytes();

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    fabric.broadcast(&msg_bytes).await
        .expect("broadcast should succeed");

    let record = app_state.handler.store.get_handle("alice@sovereign").unwrap();
    assert!(record.is_some(), "alice should be stored after broadcast");

    let root = app_state.handler.store.get_handle("@sovereign").unwrap();
    assert!(root.is_some(), "@sovereign should be stored after broadcast");
}

#[tokio::test]
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

#[tokio::test]
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

    fabric.resolve("alice@sovereign").await
        .expect("should resolve alice@sovereign");
}

#[tokio::test]
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

    let zones = fabric.resolve_all(&["alice@sovereign", "bob@sovereign"]).await
        .expect("should resolve multiple handles");

    assert!(zones.contains_key("alice@sovereign") || zones.contains_key("@sovereign"),
        "should contain alice or root zone");
}

#[tokio::test]
async fn test_resolve_nonexistent() {
    let mut state = ChainState::new();
    let mut runner = FixtureRunner::new(&mut state, single_commit_finalized());
    runner.run(&mut state);

    let (url, _) = start_relay(&state).await;

    let fabric = Fabric::with_seeds(&[url.as_str()]);

    // Resolve a handle that was never broadcast
    let result = fabric.resolve("nobody@sovereign").await;
    assert!(result.is_err(), "resolving nonexistent handle should fail");
}

#[tokio::test]
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
    let zones = fabric.resolve_all(&["alice@sovereign", "nobody@sovereign"]).await
        .expect("resolve_all should succeed with partial results");

    // Should return the existing handle, not the missing one
    assert!(!zones.contains_key("nobody@sovereign"), "nonexistent handle should not be in results");
    assert!(zones.len() >= 1, "should have at least the existing handle");
}

#[tokio::test]
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
    fabric.broadcast(&msg_bytes).await
        .expect("broadcast should succeed");

    // Resolve the same handles we just broadcast
    fabric.resolve("alice@sovereign").await
        .expect("should resolve alice after broadcast");

    let zones = fabric.resolve_all(&["alice@sovereign", "bob@sovereign"]).await
        .expect("should resolve all after broadcast");
    assert!(zones.len() >= 2, "should have at least 2 zones");
}
