//! Minimal resolver example: pass a handle on the command line and
//! optionally one or more relay seeds; print the resulting zone as
//! pretty-printed JSON to stdout.
//!
//! Run from this directory:
//!
//!   cargo run -- --seeds http://127.0.0.1:7778 --dev-mode user@rad
//!
//! Or against the public network with defaults:
//!
//!   cargo run -- user@rad

use fabric::TrustId;
use fabric::client::Fabric;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(argv).await);
}

async fn run(args: Vec<String>) -> i32 {
    let mut handle: Option<String> = None;
    let mut seeds: Vec<String> = Vec::new();
    let mut trust_id: Option<TrustId> = None;
    let mut dev_mode = false;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seeds" => {
                let Some(val) = it.next() else {
                    return usage("--seeds requires a value");
                };
                seeds = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if seeds.is_empty() {
                    return usage("--seeds requires at least one non-empty URL");
                }
            }
            "--trust-id" => {
                let Some(val) = it.next() else {
                    return usage("--trust-id requires a value");
                };
                match TrustId::from_str(&val) {
                    Ok(t) => trust_id = Some(t),
                    Err(e) => {
                        eprintln!("error: invalid trust id: {e}");
                        return 1;
                    }
                }
            }
            "--dev-mode" => dev_mode = true,
            "-h" | "--help" => {
                print_usage();
                return 0;
            }
            other if other.starts_with('-') => {
                return usage(&format!("unknown option: {other}"));
            }
            other => {
                if handle.is_some() {
                    return usage("only one handle is supported");
                }
                handle = Some(other.to_string());
            }
        }
    }

    let Some(handle) = handle else {
        return usage("missing handle");
    };

    let mut fabric = if seeds.is_empty() {
        Fabric::new()
    } else {
        let refs: Vec<&str> = seeds.iter().map(|s| s.as_str()).collect();
        Fabric::with_seeds(&refs)
    };
    if dev_mode {
        fabric = fabric.with_dev_mode();
    }
    if let Some(id) = trust_id
        && let Err(e) = fabric.trust(id).await
    {
        eprintln!("error: failed to pin trust id: {e}");
        return 1;
    }

    match fabric.resolve(&handle).await {
        Ok(Some(zone)) => match serde_json::to_string_pretty(&zone) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("error: serializing zone to JSON: {e}");
                1
            }
        },
        Ok(None) => {
            eprintln!("{handle}: not found");
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn usage(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    print_usage();
    2
}

fn print_usage() {
    eprintln!(
        "Usage: query-local [OPTIONS] <handle>\n\
         \n\
         Resolve a Spaces handle (e.g. user@rad) via the certrelay network\n\
         and print the resulting zone as pretty-printed JSON on stdout.\n\
         \n\
         Options:\n\
         \x20 --seeds <url,url,...>   Comma-separated relay URLs\n\
         \x20                         (default: built-in public seeds)\n\
         \x20 --trust-id <hex>        Pin a trust ID for verified-badge state\n\
         \x20 --dev-mode              Skip finality checks (use against\n\
         \x20                         freshly-synced local relays)\n\
         \x20 -h, --help              Show this help\n\
         \n\
         Examples:\n\
         \x20 # Resolve via your local relay\n\
         \x20 query-local --seeds http://127.0.0.1:7778 --dev-mode user@rad\n\
         \n\
         \x20 # Resolve against multiple seeds; fabric picks the freshest\n\
         \x20 query-local --seeds http://127.0.0.1:7778,https://relay-cosmos.spacesprotocol.org \\\n\
         \x20             user@rad\n\
         \n\
         \x20 # Resolve via the built-in public seeds\n\
         \x20 query-local user@rad"
    );
}
