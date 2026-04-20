use fabric::TrustId;
use fabric::client::Fabric;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut handles = Vec::new();
    let mut seeds = Vec::new();
    let mut trust_id = None;
    let mut dev_mode = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seeds" => {
                let val = it
                    .next()
                    .unwrap_or_else(|| exit_usage("--seeds requires a value"));
                seeds = val.split(',').map(|s| s.to_string()).collect();
            }
            "--trust-id" => {
                let val = it
                    .next()
                    .unwrap_or_else(|| exit_usage("--trust-id requires a value"));
                trust_id = Some(TrustId::from_str(val).unwrap_or_else(|e| {
                    eprintln!("error: invalid trust id: {e}");
                    std::process::exit(1);
                }));
            }
            "--dev-mode" => dev_mode = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                if other.starts_with('-') {
                    exit_usage(&format!("unknown option: {other}"));
                }
                handles.push(other);
            }
        }
    }

    if handles.is_empty() {
        exit_usage("no handles specified");
    }

    let mut fabric = if seeds.is_empty() {
        Fabric::new()
    } else {
        let refs: Vec<&str> = seeds.iter().map(|s| s.as_ref()).collect();
        Fabric::with_seeds(&refs)
    };
    if dev_mode {
        fabric = fabric.with_dev_mode();
    }
    if let Some(id) = trust_id {
        if let Err(e) = fabric.trust(id).await {
            eprintln!("error: failed to pin trust id: {e}");
            std::process::exit(1);
        }
    }

    let handle_refs: Vec<&str> = handles.iter().map(|s| s.as_ref()).collect();
    match fabric.resolve_all(&handle_refs).await {
        Ok(batch) => {
            for handle in &handles {
                match batch.zones.iter().find(|z| z.handle.to_string() == *handle) {
                    Some(zone) => println!("{}", serde_json::to_string(zone).unwrap()),
                    None => eprintln!("{handle}: not found"),
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!(
        "Usage: fabric [options] <handle> [<handle> ...]\n\
         \n\
         Resolve handles via the certrelay network.\n\
         \n\
         Options:\n\
         \x20 --seeds <url,url,...>      Seed relay URLs (comma-separated)\n\
         \x20 --trust-id <hex>            Trust ID for verification\n\
         \x20 --dev-mode                 Enable dev mode (skip finality checks)\n\
         \x20 -h, --help                 Show this help"
    );
}

fn exit_usage(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_usage();
    std::process::exit(1);
}
