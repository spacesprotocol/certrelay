use std::path::PathBuf;

use clap::Parser;
use spacedb::Configuration;
use spaces_client::store::chain::ROOT_ANCHORS_COUNT;
use spaces_checkpoint::{needs_checkpoint, fetch_latest, ensure_checkpoint, integrity, CHECKPOINT_BASE_URL, CHECKPOINT_FILES};
use crate::{bootstrap, bootstrap_from, create_relay_veritas, AppState, Config, ExtendedNetwork, Relay, ServiceRunner, BOOTSTRAP_RELAYS};
use crate::anchor::AnchorSets;

#[derive(Parser)]
#[command(name = "certrelay", about = "Certificate relay for the Spaces protocol")]
struct Args {
    /// Network to use
    #[arg(long, default_value = "mainnet", env = "CERTRELAY_CHAIN")]
    chain: ExtendedNetwork,

    /// Data directory
    #[arg(long, env = "CERTRELAY_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Spaced RPC URL. If omitted, runs an embedded yuki light client and spaced node.
    #[arg(long, env = "CERTRELAY_SPACED_RPC_URL")]
    spaced_rpc_url: Option<String>,

    /// Bind address for the relay HTTP server
    #[arg(long, default_value = "127.0.0.1", env = "CERTRELAY_BIND")]
    bind: String,

    /// Listen port for the relay HTTP server (default: 7778 for mainnet, 7779 otherwise)
    #[arg(long, env = "CERTRELAY_PORT")]
    port: Option<u16>,

    /// Public URL for peer announcements
    #[arg(long, env = "CERTRELAY_SELF_URL")]
    self_url: Option<String>,

    /// Act as a bootstrap relay
    #[arg(long, env = "CERTRELAY_BOOTSTRAP")]
    is_bootstrap: bool,

    /// HTTP header to read client IP from when behind a reverse proxy.
    /// Examples: "x-forwarded-for", "cf-connecting-ip", "x-real-ip"
    #[arg(long, env = "CERTRELAY_REMOTE_IP_HEADER")]
    remote_ip_header: Option<String>,

    /// Anchor refresh interval in seconds (default: 1800 = 30 minutes)
    #[arg(long, default_value = "300", env = "CERTRELAY_ANCHOR_REFRESH")]
    anchor_refresh: u64,

    /// Skip downloading a checkpoint and sync from scratch
    #[arg(long)]
    skip_checkpoint_sync: bool,
}

fn default_data_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".certrelay"))
        .unwrap_or_else(|_| PathBuf::from(".certrelay"))
}

pub async fn run(
    args: Vec<String>,
    shutdown: tokio::sync::broadcast::Sender<()>,
) -> anyhow::Result<()> {
    let args = Args::try_parse_from(args)?;

    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    std::fs::create_dir_all(&data_dir)?;



    // Start embedded yuki + spaced if no external spaced URL was provided
    let mut spaced_url = args.spaced_rpc_url;
    if spaced_url.is_none() {
        let yuki_checkpoint_file = data_dir.join("yuki_checkpoint");
        let mut yuki_checkpoint = None;

        // Reuse the checkpoint from a previous run if it exists
        if let Ok(saved) = std::fs::read_to_string(&yuki_checkpoint_file) {
            let saved = saved.trim().to_string();
            if !saved.is_empty() {
                yuki_checkpoint = Some(saved);
            }
        }

        if yuki_checkpoint.is_none() && args.chain == ExtendedNetwork::Mainnet {
            let a = spaces_protocol::constants::ChainAnchor::MAINNET();
            yuki_checkpoint = Some(format!("{}:{}", a.hash, a.height));
        }

        // Download a checkpoint so spaced can sync quickly (mainnet only)
        if args.chain == ExtendedNetwork::Mainnet && !args.skip_checkpoint_sync {
            let spaced_dir = data_dir.join("spaced").join("mainnet");
            if needs_checkpoint(&spaced_dir) {
                let default = integrity::checkpoint();
                let checkpoint = match fetch_latest(CHECKPOINT_BASE_URL) {
                    Ok(Some(latest)) if latest.height > default.height => latest,
                    Ok(_) => default,
                    Err(e) => {
                        anyhow::bail!(
                            "could not fetch checkpoint info: {e}. \
                            Please try again or use --skip-checkpoint-sync to sync from scratch"
                        );
                    }
                };

                yuki_checkpoint = Some(checkpoint.block_id());

                let digest = checkpoint.digest_bytes()
                    .map_err(|e| anyhow::anyhow!("invalid checkpoint digest: {e}"))?;
                let url = checkpoint.url(CHECKPOINT_BASE_URL);

                match ensure_checkpoint(&spaced_dir, &url, &digest, None) {
                    Ok(true) => {
                        tracing::info!("checkpoint applied");
                        build_hash_indexes_for_checkpoint(spaced_dir)?;
                    }
                    Ok(false) => {
                        anyhow::bail!(
                            "could not download checkpoint. \
                            Please try again or use --skip-checkpoint-sync to sync from scratch"
                        );
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "checkpoint error: {e}. \
                            Please try again or use --skip-checkpoint-sync to sync from scratch"
                        );
                    }
                }
            }
        }

        // Persist the checkpoint for consistent yuki restarts
        if let Some(ref cp) = yuki_checkpoint {
            let _ = std::fs::write(&yuki_checkpoint_file, cp);
        }

        let runner = ServiceRunner::new(data_dir.clone(), args.chain, yuki_checkpoint, shutdown.clone());
        let spaced_auth_url = runner.spaced_url_with_auth();
        tracing::info!(
            "starting embedded services (yuki + spaced) for {}",
            args.chain
        );
        std::thread::Builder::new()
            .name("services".into())
            .spawn({
                let shutdown = shutdown.clone();
                move || {
                    if let Err(e) = runner.run() {
                        tracing::error!("embedded services failed: {e}");
                        let _ = shutdown.send(());
                    }
                }
            })?;

        // Use the authenticated URL for the embedded spaced
        spaced_url = Some(spaced_auth_url);
    }

    let mut config = Config::new(data_dir, args.chain);
    config.spaced_url = spaced_url;
    config.is_bootstrap = args.is_bootstrap;
    config.self_url = args.self_url;
    config.remote_ip_header = args.remote_ip_header;

    let relay = Relay::new(config)?;

    if !relay.state().is_bootstrap {
        bootstrap(relay.state()).await;
    }

    // Refresh anchors from spaced periodically
    tokio::spawn({
        let state = relay.state().clone();
        let refresh_secs = args.anchor_refresh;
        async move {
            // Retry quickly on startup until spaced is ready
            loop {
                match refresh_anchors(&state).await {
                    Ok(()) => {
                        tracing::info!("initial anchor refresh succeeded");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("waiting for spaced: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
            // Then refresh on the regular interval
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
            loop {
                interval.tick().await;
                match refresh_anchors(&state).await {
                    Ok(()) => tracing::debug!("refreshed anchors"),
                    Err(e) => tracing::warn!("failed to refresh anchors: {e}"),
                }
            }
        }
    });

    // Periodically verify unverified peers when we need more verified ones
    tokio::spawn({
        let state = relay.state().clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let candidate = {
                    let mut peers = state.peers.lock().await;
                    peers.demote_expired();
                    if !peers.needs_peers() {
                        continue;
                    }
                    peers.next_candidate().map(|s| s.to_string())
                };
                if let Some(url) = candidate {
                    let check_url = format!("{}/peers", url);
                    match state.http_client.head(&check_url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let mut peers = state.peers.lock().await;
                            peers.mark_alive(&url);
                            tracing::debug!("verified peer: {}", url);
                        }
                        _ => {
                            tracing::debug!("peer health check failed: {}", url);
                        }
                    }
                }
            }
        }
    });

    // Periodically re-announce to verified peers and discover new ones
    tokio::spawn({
        let state = relay.state().clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(20 * 60));
            loop {
                interval.tick().await;
                let mut urls: Vec<String> = {
                    let peers = state.peers.lock().await;
                    peers.peers().iter().map(|s| s.to_string()).collect()
                };
                // Always include seeds so we stay discoverable
                for &seed in BOOTSTRAP_RELAYS {
                    if !urls.iter().any(|u| u == seed) {
                        urls.push(seed.to_string());
                    }
                }
                for url in urls {
                    let _ = bootstrap_from(&state, &url).await;
                }
            }
        }
    });

    let port = args.port.unwrap_or(match args.chain {
        ExtendedNetwork::Mainnet => 7778,
        _ => 7779,
    });
    let bind_addr = format!("{}:{}", args.bind, port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("relay listening on {}", listener.local_addr()?);

    let mut shutdown_rx = shutdown.subscribe();
    tokio::select! {
        result = relay.run(listener) => result,
        _ = shutdown_rx.recv() => {
            tracing::info!("shutdown signal received");
            Ok(())
        }
    }
}

async fn refresh_anchors(state: &AppState) -> anyhow::Result<()> {
    let mut anchors = state.chain.get_root_anchors().await?;
    let anchor_store = AnchorSets::from_anchors(anchors.clone());
    anchors.truncate(ROOT_ANCHORS_COUNT as _);
    let new_veritas = create_relay_veritas(anchors)?;
    *state.handler.veritas.lock().unwrap() = new_veritas;
    *state.handler.anchor_store.lock().unwrap() = anchor_store;
    Ok(())
}

pub fn build_hash_indexes_for_checkpoint(spaces_dir: PathBuf) -> anyhow::Result<()> {
    for file in CHECKPOINT_FILES {
        if !file.ends_with(".sdb") {
            continue;
        }
        let path = spaces_dir.join(file);
        let Some(db_path) = path.to_str() else {
            continue
        };
        build_hash_indexes_for_snapshots(db_path)?;
    }

    Ok(())
}

pub fn build_hash_indexes_for_snapshots(db_path: &str) -> anyhow::Result<()> {
    tracing::info!("building hash indexes for snapshots ....");
    let db = spacedb::db::Database::open_with_config(
        db_path,
        Configuration::standard()
            .with_cache_size(500_000_000 /* 500 MB */)
    )?;

    for (num, snapshot) in db.iter().enumerate() {
        let mut snapshot = snapshot?;
        snapshot.build_hash_index()?;
        if num >= ROOT_ANCHORS_COUNT as _ {
            break;
        }
        tracing::info!("hash index built for snapshot {}", num);
    }

    tracing::info!("hash indexes built successfully");
    Ok(())
}
