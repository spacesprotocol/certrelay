use fabric::TrustId;
use fabric::client::Fabric;
use fabric::libveritas::sip7::{Record, RecordSet};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(dispatch(argv).await);
}

/// Subcommand router.
///
/// Backwards-compatible: if the first positional token is `resolve` or
/// `publish`, that's the subcommand. Otherwise (e.g. `fabric --seeds X
/// alice@bitcoin`) the args are forwarded to `resolve`, preserving the
/// previous CLI shape.
async fn dispatch(argv: Vec<String>) -> i32 {
    let mut iter = argv.into_iter();
    match iter.next().as_deref() {
        None => {
            print_top_usage();
            1
        }
        Some("-h") | Some("--help") => {
            print_top_usage();
            0
        }
        Some("resolve") => run_resolve(iter.collect()).await,
        Some("publish") => run_publish(iter.collect()).await,
        Some(first) => {
            let mut args = Vec::with_capacity(1);
            args.push(first.to_string());
            args.extend(iter);
            run_resolve(args).await
        }
    }
}

// ---------------------------------------------------------------------------
// Resolve subcommand (unchanged behaviour from the pre-publish CLI)
// ---------------------------------------------------------------------------

async fn run_resolve(args: Vec<String>) -> i32 {
    let mut handles: Vec<String> = Vec::new();
    let mut seeds: Vec<String> = Vec::new();
    let mut trust_id: Option<TrustId> = None;
    let mut dev_mode = false;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seeds" => {
                let Some(val) = it.next() else {
                    return usage_err("--seeds requires a value", Cmd::Resolve);
                };
                seeds = val.split(',').map(|s| s.to_string()).collect();
            }
            "--trust-id" => {
                let Some(val) = it.next() else {
                    return usage_err("--trust-id requires a value", Cmd::Resolve);
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
                print_resolve_usage();
                return 0;
            }
            other if other.starts_with('-') => {
                return usage_err(&format!("unknown option: {other}"), Cmd::Resolve);
            }
            other => handles.push(other.to_string()),
        }
    }

    if handles.is_empty() {
        return usage_err("no handles specified", Cmd::Resolve);
    }

    let fabric = match build_fabric(&seeds, dev_mode, trust_id).await {
        Ok(f) => f,
        Err(code) => return code,
    };

    let handle_refs: Vec<&str> = handles.iter().map(|s| s.as_ref()).collect();
    match fabric.resolve_all(&handle_refs).await {
        Ok(zones) => {
            for handle in &handles {
                match zones.iter().find(|z| z.handle.to_string() == *handle) {
                    Some(zone) => println!("{}", serde_json::to_string(zone).unwrap()),
                    None => eprintln!("{handle}: not found"),
                }
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// Publish subcommand (new)
// ---------------------------------------------------------------------------

async fn run_publish(args: Vec<String>) -> i32 {
    let mut handle: Option<String> = None;
    let mut seeds: Vec<String> = Vec::new();
    let mut trust_id: Option<TrustId> = None;
    let mut dev_mode = false;

    let mut secret_inline: Option<String> = None;
    let mut secret_env: Option<String> = None;
    let mut secret_file: Option<String> = None;

    let mut explicit_seq: Option<u64> = None;
    let mut primary = true;
    let mut dry_run = false;

    let mut txts: Vec<(String, Vec<String>)> = Vec::new();
    let mut addrs: Vec<(String, Vec<String>)> = Vec::new();

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seeds" => {
                let Some(val) = it.next() else {
                    return usage_err("--seeds requires a value", Cmd::Publish);
                };
                seeds = val.split(',').map(|s| s.to_string()).collect();
            }
            "--trust-id" => {
                let Some(val) = it.next() else {
                    return usage_err("--trust-id requires a value", Cmd::Publish);
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
            "--secret-key" => {
                let Some(val) = it.next() else {
                    return usage_err("--secret-key requires a value", Cmd::Publish);
                };
                secret_inline = Some(val);
            }
            "--secret-key-env" => {
                let Some(val) = it.next() else {
                    return usage_err("--secret-key-env requires a value", Cmd::Publish);
                };
                secret_env = Some(val);
            }
            "--secret-key-file" => {
                let Some(val) = it.next() else {
                    return usage_err("--secret-key-file requires a value", Cmd::Publish);
                };
                secret_file = Some(val);
            }
            "--seq" => {
                let Some(val) = it.next() else {
                    return usage_err("--seq requires a value", Cmd::Publish);
                };
                match val.parse::<u64>() {
                    Ok(n) => explicit_seq = Some(n),
                    Err(_) => {
                        return usage_err(
                            "--seq must be a non-negative integer",
                            Cmd::Publish,
                        );
                    }
                }
            }
            "--txt" => {
                let Some(val) = it.next() else {
                    return usage_err("--txt requires key=value[,value2,...]", Cmd::Publish);
                };
                match parse_record_kv(&val) {
                    Some(kv) => txts.push(kv),
                    None => {
                        return usage_err(
                            "--txt requires key=value[,value2,...]",
                            Cmd::Publish,
                        );
                    }
                }
            }
            "--addr" => {
                let Some(val) = it.next() else {
                    return usage_err("--addr requires key=value[,value2,...]", Cmd::Publish);
                };
                match parse_record_kv(&val) {
                    Some(kv) => addrs.push(kv),
                    None => {
                        return usage_err(
                            "--addr requires key=value[,value2,...]",
                            Cmd::Publish,
                        );
                    }
                }
            }
            "--no-primary" => primary = false,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                print_publish_usage();
                return 0;
            }
            other if other.starts_with('-') => {
                return usage_err(&format!("unknown option: {other}"), Cmd::Publish);
            }
            other => {
                if handle.is_some() {
                    return usage_err(
                        "publish takes exactly one handle",
                        Cmd::Publish,
                    );
                }
                handle = Some(other.to_string());
            }
        }
    }

    let Some(handle) = handle else {
        return usage_err("publish requires a handle", Cmd::Publish);
    };

    if txts.is_empty() && addrs.is_empty() {
        return usage_err("at least one --txt or --addr is required", Cmd::Publish);
    }

    let secret_bytes = match resolve_secret_key(secret_inline, secret_env, secret_file) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let fabric = match build_fabric(&seeds, dev_mode, trust_id).await {
        Ok(f) => f,
        Err(code) => return code,
    };

    // Pick the next seq. Explicit --seq always wins; otherwise resolve the
    // handle once to read the currently-stored seq and bump it.
    let seq = match explicit_seq {
        Some(n) => n,
        None => match fabric.resolve(&handle).await {
            Ok(Some(zone)) => zone.records.seq().unwrap_or(0).saturating_add(1),
            Ok(None) => 1,
            Err(e) => {
                eprintln!("error: looking up current seq for {handle}: {e}");
                eprintln!("(pass --seq <N> to skip the pre-publish resolve)");
                return 1;
            }
        },
    };

    let mut record_list: Vec<Record> = Vec::with_capacity(1 + txts.len() + addrs.len());
    record_list.push(Record::seq(seq));
    for (k, vals) in &txts {
        let refs: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
        record_list.push(Record::txt(k, &refs));
    }
    for (k, vals) in &addrs {
        let refs: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
        record_list.push(Record::addr(k, &refs));
    }
    let records = match RecordSet::pack(record_list) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: packing records: {e}");
            return 1;
        }
    };

    if dry_run {
        let summary = serde_json::json!({
            "handle":  handle,
            "seq":     seq,
            "primary": primary,
            "txts":    txts.iter().map(|(k, v)| serde_json::json!({ "key": k, "values": v })).collect::<Vec<_>>(),
            "addrs":   addrs.iter().map(|(k, v)| serde_json::json!({ "key": k, "values": v })).collect::<Vec<_>>(),
            "dry_run": true,
        });
        println!("{}", summary);
        return 0;
    }

    // Pull the existing cert chain so the relay's `prove` call has the
    // right anchor context. Requires that the handle has been minted and
    // is already known to at least one reachable relay.
    let cert = match fabric.export(&handle).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: exporting cert chain for {handle}: {e}");
            eprintln!("(the handle must already exist on a reachable relay before you can publish records under it)");
            return 1;
        }
    };

    if let Err(e) = fabric.publish(&cert, records, &secret_bytes, primary).await {
        eprintln!("error: publish failed: {e}");
        return 1;
    }

    let summary = serde_json::json!({
        "handle":  handle,
        "seq":     seq,
        "primary": primary,
        "txts":    txts.len(),
        "addrs":   addrs.len(),
    });
    println!("{}", summary);
    0
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
enum Cmd {
    Resolve,
    Publish,
}

async fn build_fabric(
    seeds: &[String],
    dev_mode: bool,
    trust_id: Option<TrustId>,
) -> Result<Fabric, i32> {
    let mut fabric = if seeds.is_empty() {
        Fabric::new()
    } else {
        let refs: Vec<&str> = seeds.iter().map(|s| s.as_str()).collect();
        Fabric::with_seeds(&refs)
    };
    if dev_mode {
        fabric = fabric.with_dev_mode();
    }
    if let Some(id) = trust_id {
        if let Err(e) = fabric.trust(id).await {
            eprintln!("error: failed to pin trust id: {e}");
            return Err(1);
        }
    }
    Ok(fabric)
}

fn resolve_secret_key(
    inline: Option<String>,
    env: Option<String>,
    file: Option<String>,
) -> Result<[u8; 32], i32> {
    let provided = [inline.is_some(), env.is_some(), file.is_some()]
        .iter()
        .filter(|b| **b)
        .count();
    if provided == 0 {
        eprintln!(
            "error: supply exactly one of --secret-key / --secret-key-env / --secret-key-file"
        );
        return Err(2);
    }
    if provided > 1 {
        eprintln!(
            "error: --secret-key, --secret-key-env and --secret-key-file are mutually exclusive"
        );
        return Err(2);
    }

    let raw = if let Some(s) = inline {
        s
    } else if let Some(var) = env {
        match std::env::var(&var) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("error: env var {var} is not set");
                return Err(1);
            }
        }
    } else if let Some(path) = file {
        match std::fs::read_to_string(&path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: reading {path}: {e}");
                return Err(1);
            }
        }
    } else {
        unreachable!("provided count was validated above")
    };

    let trimmed = raw.trim();
    let bytes = match hex::decode(trimmed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: secret key is not valid hex: {e}");
            return Err(1);
        }
    };
    if bytes.len() != 32 {
        eprintln!(
            "error: secret key must decode to exactly 32 bytes (got {})",
            bytes.len()
        );
        return Err(1);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_record_kv(s: &str) -> Option<(String, Vec<String>)> {
    let (k, v) = s.split_once('=')?;
    let key = k.trim();
    if key.is_empty() {
        return None;
    }
    let values: Vec<String> = v.split(',').map(|s| s.to_string()).collect();
    if values.iter().all(|s| s.is_empty()) {
        return None;
    }
    Some((key.to_string(), values))
}

fn usage_err(msg: &str, cmd: Cmd) -> i32 {
    eprintln!("error: {msg}");
    match cmd {
        Cmd::Resolve => print_resolve_usage(),
        Cmd::Publish => print_publish_usage(),
    }
    2
}

fn print_top_usage() {
    println!(
        "Usage: fabric <COMMAND> [OPTIONS] [ARGS]\n\
         \n\
         Commands:\n\
         \x20 resolve <handle> [<handle> ...]   Resolve handles via the relay network\n\
         \x20 publish <handle>                  Sign + broadcast records under a handle\n\
         \n\
         Backwards compatibility: `fabric [options] <handle>...` (no command)\n\
         is equivalent to `fabric resolve [options] <handle>...`.\n\
         \n\
         Run `fabric <command> --help` for command-specific options."
    );
}

fn print_resolve_usage() {
    println!(
        "Usage: fabric resolve [OPTIONS] <handle> [<handle> ...]\n\
         \n\
         Resolve handles via the certrelay network.\n\
         \n\
         Options:\n\
         \x20 --seeds <url,url,...>      Seed relay URLs (comma-separated)\n\
         \x20 --trust-id <hex>           Trust ID for verification\n\
         \x20 --dev-mode                 Enable dev mode (skip finality checks)\n\
         \x20 -h, --help                 Show this help"
    );
}

fn print_publish_usage() {
    println!(
        "Usage: fabric publish [OPTIONS] <handle>\n\
         \n\
         Sign and broadcast records under <handle> to the relay network.\n\
         The handle must already have a certificate chain available on the\n\
         relay (i.e. it was previously minted by the parent space owner).\n\
         \n\
         Connection options:\n\
         \x20 --seeds <url,url,...>      Seed relay URLs (comma-separated)\n\
         \x20 --trust-id <hex>           Trust ID for verification\n\
         \x20 --dev-mode                 Enable dev mode (skip finality checks)\n\
         \n\
         Signing material (exactly one required):\n\
         \x20 --secret-key <hex>         32-byte BIP-340 secret as 64-char hex\n\
         \x20                            (UNSAFE: visible in `ps`/shell history)\n\
         \x20 --secret-key-env <VAR>     Read secret hex from environment variable VAR\n\
         \x20 --secret-key-file <path>   Read secret hex from file (whitespace-trimmed)\n\
         \n\
         Records (at least one --txt or --addr required, all repeatable):\n\
         \x20 --txt  <key>=<v1>[,<v2>,...]   Add a TXT record\n\
         \x20 --addr <key>=<v1>[,<v2>,...]   Add an addr record\n\
         \n\
         Other:\n\
         \x20 --seq <N>                  Explicit seq number (default: <current>+1)\n\
         \x20 --no-primary               Skip SIG_PRIMARY_ZONE flag\n\
         \x20                            (the relay won't write num_id -> handle reverse map)\n\
         \x20 --dry-run                  Print the would-be payload as JSON, don't broadcast\n\
         \x20 -h, --help                 Show this help\n\
         \n\
         Example:\n\
         \x20 SECRET=$(cat ./user-rad-secret.hex) \\\n\
         \x20   fabric publish --seeds http://127.0.0.1:7778 --dev-mode \\\n\
         \x20                  --secret-key-env SECRET \\\n\
         \x20                  --txt website=https://example.com \\\n\
         \x20                  --addr btc=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 \\\n\
         \x20                  user@rad"
    );
}
