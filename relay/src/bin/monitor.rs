//! Bootstrap relay health monitor.
//!
//! Polls each URL in [`BOOTSTRAP_RELAYS`] with `GET /peers` on a fixed interval.
//! Logs error/recovery transitions and peer counts for healthy relays.

use clap::Parser;
use relay::BOOTSTRAP_RELAYS;
use relay::PeerInfo;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const DEFAULT_CHECK_INTERVAL_MINS: u64 = 30;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;

#[derive(Parser)]
#[command(
    name = "monitor",
    about = "Poll bootstrap certrelay seeds and track /peers health",
    long_about = "Polls each URL listed in BOOTSTRAP_RELAYS with GET /peers on a \
                  fixed interval. Logs when a seed enters or leaves an error state \
                  (unreachable, timeout, empty peer list). Logs peer counts for \
                  seeds that return a non-empty list. With --watch-all, also probes \
                  every peer URL reported by the bootstrap relays (deduplicated)."
)]
struct Args {
    /// Minutes to wait between poll loops.
    #[arg(
        long,
        env = "CHECK_INTERVAL",
        default_value_t = DEFAULT_CHECK_INTERVAL_MINS
    )]
    check_interval: u64,

    /// Per-request HTTP timeout in seconds.
    #[arg(
        long,
        env = "REQUEST_TIMEOUT",
        default_value_t = DEFAULT_REQUEST_TIMEOUT_SECS
    )]
    timeout: u64,

    /// Log filter passed to env_logger (e.g. info, debug, monitor=debug).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    rust_log: String,

    /// Also probe every peer URL returned by bootstrap relays (deduplicated).
    #[arg(long, env = "WATCH_ALL", default_value_t = false)]
    watch_all: bool,
}

struct RelayTracker {
    in_error: bool,
    error_since: Option<Instant>,
}

enum ProbeOutcome {
    Ok { count: usize, peers: Vec<PeerInfo> },
    Err(String),
}

impl ProbeOutcome {
    fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
}

#[derive(Clone, Copy)]
enum NodeKind {
    Bootstrap,
    Discovered,
}

impl NodeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Discovered => "discovered",
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    env_logger::Builder::new()
        .parse_filters(&args.rust_log)
        .init();

    let check_interval = Duration::from_secs(args.check_interval * 60);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()
        .expect("failed to build HTTP client");

    let mut trackers: HashMap<String, RelayTracker> = HashMap::new();

    log::info!(
        "monitor: watching {} bootstrap relay(s), interval={}min, timeout={}s, watch_all={}",
        BOOTSTRAP_RELAYS.len(),
        args.check_interval,
        args.timeout,
        args.watch_all
    );

    let mut cycle_summary: Option<String> = None;

    loop {
        if let Some(ref summary) = cycle_summary {
            log::info!("{summary}");
        }

        let mut discovered_peers: HashSet<String> = HashSet::new();
        let mut bootstrap_active = 0;
        let bootstrap_total = BOOTSTRAP_RELAYS.len();

        for &base in BOOTSTRAP_RELAYS {
            let url = peers_url(base);
            let outcome = probe(&client, &url, args.timeout).await;
            if outcome.is_ok() {
                bootstrap_active += 1;
            }
            if args.watch_all {
                collect_discovered_peers(&outcome, &mut discovered_peers);
            }
            record_outcome(&mut trackers, NodeKind::Bootstrap, base, outcome);
        }

        let mut discovered_active = 0;
        let discovered_total = if args.watch_all {
            discovered_peers.len()
        } else {
            0
        };

        if args.watch_all {
            let mut peer_urls: Vec<String> = discovered_peers.into_iter().collect();
            peer_urls.sort();
            log::debug!("watch-all: probing {} discovered peer(s)", peer_urls.len());
            for base in peer_urls {
                let url = peers_url(&base);
                let outcome = probe(&client, &url, args.timeout).await;
                if outcome.is_ok() {
                    discovered_active += 1;
                }
                record_outcome(&mut trackers, NodeKind::Discovered, &base, outcome);
            }
        }

        cycle_summary = Some(format_loop_summary(
            bootstrap_active,
            bootstrap_total,
            discovered_active,
            discovered_total,
            args.watch_all,
        ));

        tokio::time::sleep(check_interval).await;
    }
}

fn pct(active: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (active as f64 / total as f64) * 100.0
    }
}

fn format_loop_summary(
    bootstrap_active: usize,
    bootstrap_total: usize,
    discovered_active: usize,
    discovered_total: usize,
    watch_all: bool,
) -> String {
    let bootstrap_pct = pct(bootstrap_active, bootstrap_total);
    let mut line = format!(
        "====== {bootstrap_active} of {bootstrap_total} bootstrap nodes active {bootstrap_pct:.1}% ======"
    );
    if watch_all {
        let discovered_pct = pct(discovered_active, discovered_total);
        line.push_str(&format!(
            " {discovered_active} of {discovered_total} discovered nodes active {discovered_pct:.1}% ======"
        ));
    }
    line
}

fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

fn is_bootstrap(url: &str) -> bool {
    let normalized = normalize_url(url);
    BOOTSTRAP_RELAYS
        .iter()
        .any(|seed| normalize_url(seed) == normalized)
}

fn collect_discovered_peers(outcome: &ProbeOutcome, discovered: &mut HashSet<String>) {
    let ProbeOutcome::Ok { peers, .. } = outcome else {
        return;
    };
    for peer in peers {
        if !is_bootstrap(&peer.url) {
            discovered.insert(normalize_url(&peer.url));
        }
    }
}

fn record_outcome(
    trackers: &mut HashMap<String, RelayTracker>,
    kind: NodeKind,
    base: &str,
    outcome: ProbeOutcome,
) {
    let label = kind.as_str();
    let tracker = trackers.entry(base.to_string()).or_insert(RelayTracker {
        in_error: false,
        error_since: None,
    });

    match outcome {
        ProbeOutcome::Ok { count, .. } => {
            if tracker.in_error {
                let down_for = tracker
                    .error_since
                    .map(|t| t.elapsed())
                    .unwrap_or_default();
                log::info!(
                    "[{label}] {base}: resumed from error state (was down for {:.1}s)",
                    down_for.as_secs_f64()
                );
                tracker.in_error = false;
                tracker.error_since = None;
            }
            if count > 0 {
                log::info!("[{label}] {base}/peers : {count} peer(s)");
            }
        }
        ProbeOutcome::Err(reason) => {
            if !tracker.in_error {
                log::error!("[{label}] {base}: entered error state — {reason}");
                tracker.in_error = true;
                tracker.error_since = Some(Instant::now());
            } else {
                log::warn!("[{label}] {base}: still in error state — {reason}");
            }
        }
    }
}

fn peers_url(base: &str) -> String {
    format!("{}/peers", base.trim_end_matches('/'))
}

async fn probe(client: &reqwest::Client, url: &str, timeout_secs: u64) -> ProbeOutcome {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            let reason = if e.is_timeout() {
                format!("connection timed out after {timeout_secs}s")
            } else if e.is_connect() {
                format!("unreachable: {e}")
            } else {
                format!("request failed: {e}")
            };
            return ProbeOutcome::Err(reason);
        }
    };

    if !resp.status().is_success() {
        return ProbeOutcome::Err(format!("HTTP {}", resp.status()));
    }

    let peers: Vec<PeerInfo> = match resp.json().await {
        Ok(p) => p,
        Err(e) => return ProbeOutcome::Err(format!("invalid JSON: {e}")),
    };

    if peers.is_empty() {
        return ProbeOutcome::Err("empty peer list []".into());
    }

    ProbeOutcome::Ok {
        count: peers.len(),
        peers,
    }
}
