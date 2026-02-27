use std::path::PathBuf;

use clap::Parser;
use relay::{
    bootstrap, Config, ExtendedNetwork, PowGuard, Relay, ServiceRunner,
};
use relay::http::refresh_anchors;

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

    /// Listen port for the relay HTTP server
    #[arg(long, default_value = "7779", env = "CERTRELAY_PORT")]
    port: u16,

    /// Public URL for peer announcements
    #[arg(long, env = "CERTRELAY_SELF_URL")]
    self_url: Option<String>,

    /// Act as a bootstrap relay
    #[arg(long, env = "CERTRELAY_BOOTSTRAP")]
    is_bootstrap: bool,

    /// PoW difficulty (0 to disable)
    #[arg(long, default_value = "20", env = "CERTRELAY_POW_DIFFICULTY")]
    pow_difficulty: u32,

    /// HTTP header to read client IP from when behind a reverse proxy.
    /// Examples: "x-forwarded-for", "cf-connecting-ip", "x-real-ip"
    #[arg(long, env = "CERTRELAY_REMOTE_IP_HEADER")]
    remote_ip_header: Option<String>,
}

fn default_data_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".certrelay"))
        .unwrap_or_else(|_| PathBuf::from(".certrelay"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    std::fs::create_dir_all(&data_dir)?;

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Start embedded yuki + spaced if no external spaced URL was provided
    if args.spaced_rpc_url.is_none() {
        let runner = ServiceRunner::new(data_dir.clone(), args.chain, shutdown_tx.clone());
        tracing::info!(
            "starting embedded services (yuki + spaced) for {}",
            args.chain
        );
        std::thread::Builder::new()
            .name("services".into())
            .spawn({
                let shutdown = shutdown_tx.clone();
                move || {
                    if let Err(e) = runner.run() {
                        tracing::error!("embedded services failed: {e}");
                        let _ = shutdown.send(());
                    }
                }
            })?;
    }

    let mut config = Config::new(data_dir, args.chain);
    config.spaced_url = args.spaced_rpc_url;
    config.pow = PowGuard::new(args.pow_difficulty);
    config.is_bootstrap = args.is_bootstrap;
    config.self_url = args.self_url;
    config.remote_ip_header = args.remote_ip_header;

    let relay = Relay::new(config)?;

    if !relay.state().is_bootstrap {
        bootstrap(relay.state()).await;
    }

    // Refresh anchors from spaced every 30 minutes
    tokio::spawn({
        let state = relay.state().clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                match refresh_anchors(&state).await {
                    Ok(()) => tracing::info!("refreshed anchors"),
                    Err(e) => tracing::warn!("failed to refresh anchors: {e}"),
                }
            }
        }
    });

    let bind_addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("relay listening on {}", listener.local_addr()?);

    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::select! {
        result = relay.run(listener) => result,
        _ = shutdown_rx.recv() => {
            tracing::info!("shutdown signal received");
            Ok(())
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down...");
            let _ = shutdown_tx.send(());
            Ok(())
        }
    }
}
