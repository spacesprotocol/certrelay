use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use spaces_client::config::ExtendedNetwork;
use spaces_client::jsonrpsee::http_client::{HeaderMap, HeaderValue, HttpClientBuilder};
use spaces_client::store::chain::ROOT_ANCHORS_COUNT;
use spaces_protocol::bitcoin::BlockHash;
use spaces_protocol::bitcoin::hashes::Hash as HashUtil;
use spaces_protocol::constants::ChainAnchor;
use spaces_nums::RootAnchor;
use crate::anchor::AnchorSets;
use crate::create_relay_veritas;
use crate::handler::Handler;
use crate::http::{self, AppState, DEFAULT_MAX_MESSAGE_SIZE};
use crate::peer::PeerConfig;
use crate::spaced::SpacedClient;
use crate::store::SqliteStore;

fn zero_anchor() -> RootAnchor {
    RootAnchor {
        spaces_root: [0u8; 32],
        nums_root: None,
        block: ChainAnchor {
            hash: BlockHash::all_zeros(),
            height: 0,
        },
    }
}

pub struct Config {
    pub db_path: PathBuf,
    pub data_dir: PathBuf,
    pub network: ExtendedNetwork,
    /// If provided, connect to this spaced RPC directly.
    /// If None, use the default port for the configured network
    /// (assumes a ServiceRunner is providing spaced).
    pub spaced_url: Option<String>,
    pub anchors: Vec<RootAnchor>,
    pub self_url: Option<String>,
    pub capabilities: u32,
    pub is_bootstrap: bool,
    pub max_message_size: usize,
    pub peer_config: PeerConfig,
    /// HTTP header to read client IP from (e.g. "x-forwarded-for", "cf-connecting-ip").
    pub remote_ip_header: Option<String>,
    /// Accept fake ZK receipts (for testing only).
    pub dev_mode: bool,
}

impl Config {
    pub fn new(data_dir: PathBuf, network: ExtendedNetwork) -> Self {
        Self {
            db_path: data_dir.join("relay.db"),
            data_dir,
            network,
            spaced_url: None,
            anchors: vec![zero_anchor()],
            self_url: None,
            capabilities: 0,
            is_bootstrap: false,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            peer_config: PeerConfig::default(),
            remote_ip_header: None,
            dev_mode: false,
        }
    }
}

/// A runnable relay instance.
pub struct Relay {
    state: Arc<AppState>,
}

impl Relay {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let spaced_url = config.spaced_url.clone()
            .unwrap_or_else(|| ServiceRunner::default_spaced_url(config.network));

        let mut builder = HttpClientBuilder::default();
        let url = if let Ok(parsed) = url::Url::parse(&spaced_url) {
            if !parsed.username().is_empty() {
                let credentials = format!(
                    "{}:{}",
                    parsed.username(),
                    parsed.password().unwrap_or("")
                );
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    credentials,
                );
                let mut headers = HeaderMap::new();
                headers.insert(
                    "authorization",
                    HeaderValue::from_str(&format!("Basic {encoded}"))?,
                );
                builder = builder.set_headers(headers);
                let mut clean = parsed.clone();
                clean.set_username("").ok();
                clean.set_password(None).ok();
                clean.to_string()
            } else {
                spaced_url
            }
        } else {
            spaced_url
        };

        let rpc_client = builder.build(&url)?;
        let veritas = create_relay_veritas(config.anchors.clone())?;
        let anchor_store = AnchorSets::from_anchors(config.anchors);

        let store = SqliteStore::open(&config.db_path)?;
        let chain = SpacedClient::new(rpc_client);
        let mut handler = Handler::new(veritas, store, anchor_store);
        handler.dev_mode = config.dev_mode;

        let mut state = AppState::new(
            handler,
            chain,
            config.peer_config,
        );
        state.max_message_size = config.max_message_size;
        state.capabilities = config.capabilities;
        state.is_bootstrap = config.is_bootstrap;
        state.remote_ip_header = config.remote_ip_header;

        if let Some(url) = config.self_url {
            state = state.with_self_url(url);
        }

        Ok(Self {
            state: Arc::new(state),
        })
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    pub async fn run(self, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
        let router = http::router(self.state);
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

/// Runs yuki (Bitcoin light client) and spaced in dedicated threads,
/// each with its own tokio runtime for full isolation.
pub struct ServiceRunner {
    data_dir: PathBuf,
    network: ExtendedNetwork,
    yuki_checkpoint: Option<String>,
    rpc_password: String,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

impl ServiceRunner {
    pub fn new(
        data_dir: PathBuf,
        network: ExtendedNetwork,
        yuki_checkpoint: Option<String>,
        shutdown: tokio::sync::broadcast::Sender<()>,
    ) -> Self {
        use rand::Rng;
        let rpc_password: String = rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        Self { data_dir, network, yuki_checkpoint, rpc_password, shutdown }
    }

    /// Start yuki and spaced in dedicated threads with their own tokio runtimes.
    /// Blocks the calling thread until either service exits.
    pub fn run(self) -> anyhow::Result<()> {
        let yuki_args = self.yuki_args();
        let spaced_args = self.spaced_args();

        let (done_tx, done_rx) = std::sync::mpsc::channel::<(&str, anyhow::Result<()>)>();

        let done_yuki = done_tx.clone();
        let shutdown_yuki = self.shutdown.clone();
        std::thread::Builder::new()
            .name("yuki".into())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(anyhow::Error::from)
                    .and_then(|rt| rt.block_on(Self::yuki_runner(yuki_args, shutdown_yuki)));
                let _ = done_yuki.send(("yuki", result));
            })?;

        let done_spaced = done_tx;
        let shutdown_spaced = self.shutdown.clone();
        std::thread::Builder::new()
            .name("spaced".into())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(anyhow::Error::from)
                    .and_then(|rt| rt.block_on(Self::spaced_runner(spaced_args, shutdown_spaced)));
                let _ = done_spaced.send(("spaced", result));
            })?;

        // Wait for the first service to exit
        let (name, result) = done_rx.recv()
            .map_err(|_| anyhow::anyhow!("service threads exited without reporting"))?;

        // Signal the remaining service to shut down
        let _ = self.shutdown.send(());

        match result {
            Ok(()) => {
                tracing::info!("{} exited", name);
                Ok(())
            }
            Err(e) => {
                tracing::error!("{} failed: {}", name, e);
                Err(e)
            }
        }
    }

    /// The spaced RPC URL this runner will produce.
    pub fn spaced_url(&self) -> String {
        Self::default_spaced_url(self.network)
    }

    /// Default spaced URL for a given network.
    pub fn default_spaced_url(network: ExtendedNetwork) -> String {
        format!("http://127.0.0.1:{}", Self::spaced_port(network))
    }

    /// Spaced URL with embedded auth credentials.
    pub fn spaced_url_with_auth(&self) -> String {
        format!("http://__cookie__:{}@127.0.0.1:{}", self.rpc_password, Self::spaced_port(self.network))
    }

    /// Path to the cookie file spaced will write for RPC auth.
    pub fn spaced_cookie(&self) -> PathBuf {
        self.spaced_data_dir()
            .join(self.network.to_string())
            .join(".cookie")
    }

    fn yuki_url(&self) -> String {
        format!("http://127.0.0.1:{}", Self::yuki_port(self.network))
    }

    fn spaced_data_dir(&self) -> PathBuf {
        self.data_dir.join("spaced")
    }

    fn yuki_port(network: ExtendedNetwork) -> u16 {
        match network {
            ExtendedNetwork::Mainnet => 12881,
            ExtendedNetwork::Testnet4 => 12771,
            _ => 12117,
        }
    }

    fn spaced_port(network: ExtendedNetwork) -> u16 {
        match network {
            ExtendedNetwork::Mainnet => 12888,
            ExtendedNetwork::Testnet4 => 12777,
            _ => 12111,
        }
    }

    fn yuki_args(&self) -> Vec<String> {
        let mut args = vec![
            "yuki".into(),
            "--chain".into(), self.network.to_string(),
            "--rpc-port".into(), Self::yuki_port(self.network).to_string(),
            "--data-dir".into(), self.data_dir.join("yuki").to_str().unwrap().to_string(),
        ];
        if let Some(cp) = &self.yuki_checkpoint {
            args.push("--checkpoint".into());
            args.push(cp.to_string());
        }
        args
    }

    fn spaced_args(&self) -> Vec<String> {
        vec![
            "spaced".into(),
            "--chain".into(), self.network.to_string(),
            "--rpc-port".into(), Self::spaced_port(self.network).to_string(),
            "--data-dir".into(), self.spaced_data_dir().to_str().unwrap().to_string(),
            "--bitcoin-rpc-url".into(), self.yuki_url(),
            "--bitcoin-rpc-light".into(),
            "--num-anchors".into(), (ROOT_ANCHORS_COUNT * 2).to_string(),
            "--index-node-hashes".into(),
            "--enable-pruning".into(),
            "--rpc-user".into(), "__cookie__".into(),
            "--rpc-password".into(), self.rpc_password.clone(),
        ]
    }

    async fn yuki_runner(
        args: Vec<String>,
        shutdown: tokio::sync::broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        yuki::app::run(args, shutdown).await?;
        Ok(())
    }

    async fn spaced_runner(
        args: Vec<String>,
        shutdown: tokio::sync::broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let mut app = spaces_client::app::App::new(shutdown);
        app.run(args).await
    }
}
