use std::path::{Path, PathBuf};

use crate::anchor::AnchorSets;
use crate::{
    AppState, BOOTSTRAP_RELAYS, Config, ExtendedNetwork, Relay, ServiceRunner, bootstrap,
    bootstrap_from, create_relay_veritas,
};
use clap::Parser;
use spacedb::Configuration;
use spaces_checkpoint::{
    CHECKPOINT_BASE_URL, CHECKPOINT_FILES, ensure_checkpoint, fetch_latest, integrity,
    needs_checkpoint,
};
use spaces_client::store::chain::ROOT_ANCHORS_COUNT;

#[derive(Parser)]
#[command(
    name = "certrelay",
    about = "Certificate relay for the Spaces protocol"
)]
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

    /// Override the bootstrap/seed relays used for peer discovery. Repeatable
    /// (`--seed URL --seed URL`) or comma-separated via the env var. When set,
    /// these fully REPLACE the built-in mainnet seeds — this is how you point a
    /// private regtest/testnet network at your own relays. When empty, mainnet
    /// uses the built-in seeds and every other network uses none.
    #[arg(long = "seed", env = "CERTRELAY_SEEDS", value_delimiter = ',')]
    seeds: Vec<String>,

    /// HTTP header to read client IP from when behind a reverse proxy.
    /// Examples: "x-forwarded-for", "cf-connecting-ip", "x-real-ip"
    #[arg(long, env = "CERTRELAY_REMOTE_IP_HEADER")]
    remote_ip_header: Option<String>,

    /// Anchor refresh interval in seconds (default: 300 = 5 minutes)
    #[arg(long, default_value = "300", env = "CERTRELAY_ANCHOR_REFRESH")]
    anchor_refresh: u64,

    /// Skip downloading a checkpoint and sync from scratch
    #[arg(long)]
    skip_checkpoint_sync: bool,

    /// Accept peers with private/loopback addresses (local development only)
    #[arg(long, env = "CERTRELAY_ALLOW_PRIVATE_PEERS")]
    allow_private_peers: bool,

    /// Path to a TOML config file for rate limits, sync tuning, peer table
    /// sizes, and concurrency caps (all fields optional)
    #[arg(long, env = "CERTRELAY_CONFIG")]
    config: Option<PathBuf>,
}

fn default_data_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".certrelay"))
        .unwrap_or_else(|_| PathBuf::from(".certrelay"))
}

/// Mask `user:pass` in URLs of the form `scheme://user:pass@host[...]` so
/// secrets in env-var-sourced configuration are never echoed to the console.
fn redact_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        if let Some(at_rel) = after.find('@') {
            let userinfo = &after[..at_rel];
            if userinfo.contains(':') {
                return format!("{}://***:***{}", &url[..scheme_end], &after[at_rel..]);
            }
        }
    }
    url.to_string()
}

/// Print every `CERTRELAY_*`-backed setting that this process will use,
/// alongside the effective values after defaults have been applied. Written
/// to stderr with `eprintln!` so it's visible regardless of `RUST_LOG` /
/// tracing-subscriber configuration.
fn log_startup_env(args: &Args, data_dir: &Path) {
    let effective_port = args.port.unwrap_or(match args.chain {
        ExtendedNetwork::Mainnet => 7778,
        _ => 7779,
    });
    let spaced_url_display = match args.spaced_rpc_url.as_deref() {
        Some(u) => redact_url(u),
        None => "<embedded yuki + spaced>".to_string(),
    };
    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "<unset>".to_string());

    eprintln!("certrelay: effective configuration");
    eprintln!("  CERTRELAY_CHAIN            = {}", args.chain);
    eprintln!("  CERTRELAY_DATA_DIR         = {}", data_dir.display());
    eprintln!("  CERTRELAY_BIND             = {}", args.bind);
    eprintln!("  CERTRELAY_PORT             = {}", effective_port);
    eprintln!(
        "  CERTRELAY_SELF_URL         = {}",
        args.self_url.as_deref().unwrap_or("<unset>")
    );
    eprintln!("  CERTRELAY_SPACED_RPC_URL   = {}", spaced_url_display);
    eprintln!(
        "  CERTRELAY_REMOTE_IP_HEADER = {}",
        args.remote_ip_header.as_deref().unwrap_or("<unset>")
    );
    eprintln!("  CERTRELAY_BOOTSTRAP        = {}", args.is_bootstrap);
    eprintln!(
        "  CERTRELAY_ANCHOR_REFRESH   = {}s",
        args.anchor_refresh
    );
    eprintln!(
        "  CERTRELAY_SEEDS            = {}",
        if args.seeds.is_empty() {
            "<builtin mainnet / none off-mainnet>".to_string()
        } else {
            args.seeds.join(",")
        }
    );
    eprintln!("  --skip-checkpoint-sync     = {}", args.skip_checkpoint_sync);
    eprintln!(
        "  CERTRELAY_ALLOW_PRIVATE_PEERS = {}",
        args.allow_private_peers
    );
    eprintln!(
        "  CERTRELAY_CONFIG           = {}",
        args.config
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unset>".to_string())
    );
    eprintln!("  RUST_LOG                   = {}", rust_log);
}

pub async fn run(
    args: Vec<String>,
    shutdown: tokio::sync::broadcast::Sender<()>,
) -> anyhow::Result<()> {
    let args = Args::try_parse_from(args)?;

    // Cloning here (rather than `unwrap_or_else` which would move out of
    // `args`) lets log_startup_env borrow the full Args struct below.
    let data_dir = args
        .data_dir
        .as_ref()
        .cloned()
        .unwrap_or_else(default_data_dir);
    std::fs::create_dir_all(&data_dir)?;

    log_startup_env(&args, &data_dir);

    // Captured before fields of `args` get consumed below, so the final
    // "ready" banner can still surface the public URL to operators.
    let self_url_for_banner: Option<String> = args.self_url.clone();

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

                let digest = checkpoint
                    .digest_bytes()
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

        let runner = ServiceRunner::new(
            data_dir.clone(),
            args.chain,
            yuki_checkpoint,
            shutdown.clone(),
        );
        let spaced_auth_url = runner.spaced_url_with_auth();
        tracing::info!(
            "starting embedded services (yuki + spaced) for {}",
            args.chain
        );
        std::thread::Builder::new().name("services".into()).spawn({
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

    let settings = match &args.config {
        Some(path) => {
            let s = crate::settings::FileConfig::load(path)?;
            tracing::info!("loaded config from {}", path.display());
            s
        }
        None => crate::settings::FileConfig::default(),
    };
    let sync_config = settings.sync_config();

    let mut config = Config::new(data_dir, args.chain);
    config.spaced_url = spaced_url;
    config.is_bootstrap = args.is_bootstrap;
    config.self_url = args.self_url;
    config.remote_ip_header = args.remote_ip_header;
    config.allow_private_peers = args.allow_private_peers;
    config.peer_config = settings.peer_config();
    config.settings = settings;

    let relay = Relay::new(config)?;

    // Seeds for peer discovery. A custom --seed/CERTRELAY_SEEDS list fully
    // replaces the defaults (this is how a regtest/testnet network points at
    // its own relays). Otherwise only mainnet gets the built-in seeds: a
    // non-mainnet relay that inherited the mainnet seeds would sync mainnet
    // certificates against a chain that cannot verify them — every space fails,
    // the failed-space circuit breaker trips each round, prove/verify CPU is
    // burned for nothing, and a developer's test rig quietly talks to
    // production relays. Feeds BOTH the startup bootstrap and the maintenance
    // loops so the two can never disagree.
    let seed_urls: Vec<String> = if !args.seeds.is_empty() {
        args.seeds.clone()
    } else if args.chain == ExtendedNetwork::Mainnet {
        BOOTSTRAP_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };

    if !relay.state().is_bootstrap {
        bootstrap(relay.state(), &seed_urls).await;
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

    // Storage retention: entitlement-weighted eviction under the disk budget
    tokio::spawn(crate::retention::run_retention_loop(
        relay.state().clone(),
        relay.state().retention.clone(),
    ));

    // Peer-table maintenance: proactive refresh of verified peers, candidate
    // verification, rate-limiter map cleanup, and standing seed candidates
    // (so a fleet-wide restart can't strand a relay with an empty table)
    tokio::spawn(crate::sync::run_peer_maintenance_loop(
        relay.state().clone(),
        std::time::Duration::from_secs(10),
        3,
        seed_urls.clone(),
    ));

    // Pull-based propagation: periodically sync stored handles from peers,
    // send pokes when we store new data, and pull promptly when poked.
    tokio::spawn(crate::sync::run_sync_loop(
        relay.state().clone(),
        sync_config.clone(),
    ));
    tokio::spawn(crate::sync::run_poke_send_loop(
        relay.state().clone(),
        sync_config.clone(),
    ));
    tokio::spawn(crate::sync::run_poke_sync_loop(
        relay.state().clone(),
        sync_config,
    ));

    // Periodically re-announce to verified peers and discover new ones
    tokio::spawn({
        let state = relay.state().clone();
        let seed_urls = seed_urls.clone();
        async move {
            loop {
                // Jittered so a fleet restarted together doesn't hit the
                // seeds in lockstep every sweep. (Startup discovery is
                // handled by bootstrap() and the maintenance loop's standing
                // seed candidates, so no immediate first sweep is needed.)
                let jitter = std::time::Duration::from_millis(rand::random_range(0..120_000));
                tokio::time::sleep(std::time::Duration::from_secs(20 * 60) + jitter).await;
                let mut urls: Vec<String> = {
                    let peers = state.peers.lock().await;
                    peers.peers().iter().map(|s| s.to_string()).collect()
                };
                // Always include seeds so we stay discoverable (empty off
                // mainnet unless --seed was given).
                for seed in &seed_urls {
                    if !urls.iter().any(|u| u == seed) {
                        urls.push(seed.clone());
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
    let local = listener.local_addr()?;
    tracing::info!("relay listening on {}", local);

    // Guaranteed-visible "ready" banner so operators always see *where*
    // the relay is serving, even if no tracing-subscriber is configured.
    eprintln!();
    eprintln!("certrelay: ready");
    eprintln!("  listening on:  http://{}", local);
    if local.ip().is_unspecified() {
        eprintln!(
            "                 (also reachable as http://127.0.0.1:{} on this host)",
            local.port()
        );
    }
    if let Some(self_url) = self_url_for_banner.as_deref() {
        eprintln!("  public URL:    {}", self_url.trim_end_matches('/'));
    }

    relay
        .run_with_shutdown(listener, shutdown.subscribe())
        .await
}

async fn refresh_anchors(state: &AppState) -> anyhow::Result<()> {
    let mut anchors = state.chain.get_root_anchors().await?;
    let anchor_store = AnchorSets::from_anchors(anchors.clone());
    anchors.truncate(ROOT_ANCHORS_COUNT as _);
    let new_veritas = create_relay_veritas(anchors)?;
    *state.handler.veritas.write().unwrap() = new_veritas;
    *state.handler.anchor_store.lock().unwrap() = anchor_store;
    refresh_anchor_sig(state);
    Ok(())
}

/// Re-sign the anchor root we serve, but only when it actually changed. The
/// Schnorr signature is cached and served verbatim from `/anchors`, so this
/// keeps per-request cost at a header copy instead of a signing operation.
fn refresh_anchor_sig(state: &AppState) {
    let Some(identity) = &state.identity else {
        return;
    };
    // Clone the latest set out before touching the signature cache so we never
    // hold the anchor-store lock across the sign (and so the two locks are
    // always taken store-then-sig, avoiding a cycle with the read path).
    let latest = state.handler.anchor_store.lock().unwrap().latest().cloned();
    let Some(latest) = latest else {
        return;
    };
    let height = latest.tip_height();
    let trust_id = libveritas::compute_trust_set(&latest.entries).id;

    let mut cache = state.anchor_sig.lock().unwrap();
    let unchanged = cache
        .as_ref()
        .is_some_and(|c| c.trust_id == trust_id && c.height == height);
    if unchanged {
        return;
    }
    let sig = identity.sign_anchor(&trust_id, height);
    *cache = Some(crate::identity::AnchorSig {
        trust_id,
        height,
        sig,
    });
}

pub fn build_hash_indexes_for_checkpoint(spaces_dir: PathBuf) -> anyhow::Result<()> {
    for file in CHECKPOINT_FILES {
        if !file.ends_with(".sdb") {
            continue;
        }
        let path = spaces_dir.join(file);
        let Some(db_path) = path.to_str() else {
            continue;
        };
        build_hash_indexes_for_snapshots(db_path)?;
    }

    Ok(())
}

pub fn build_hash_indexes_for_snapshots(db_path: &str) -> anyhow::Result<()> {
    tracing::info!("building hash indexes for snapshots ....");
    let db = spacedb::db::Database::open_with_config(
        db_path,
        Configuration::standard().with_cache_size(500_000_000 /* 500 MB */),
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
