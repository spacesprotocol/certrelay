use fabric::client::Fabric;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut handles = Vec::new();
    let mut seeds = Vec::new();
    let mut anchor_set_hash = None;
    let mut dev_mode = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seeds" => {
                let val = it.next().unwrap_or_else(|| exit_usage("--seeds requires a value"));
                seeds = val.split(',').map(|s| s.to_string()).collect();
            }
            "--anchor-set-hash" => {
                let val = it.next().unwrap_or_else(|| exit_usage("--anchor-set-hash requires a value"));
                anchor_set_hash = Some(val.clone());
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
    if let Some(hash) = &anchor_set_hash {
        fabric = fabric.with_anchor_set(hash);
    }

    let handle_refs: Vec<&str> = handles.iter().map(|s| s.as_ref()).collect();
    match fabric.resolve_all(&handle_refs).await {
        Ok(zones) => {
            for handle in &handles {
                match zones.iter().find(|z| z.handle.to_string() == *handle) {
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
         \x20 --anchor-set-hash <hex>    Anchor set hash for verification\n\
         \x20 --dev-mode                 Enable dev mode (skip finality checks)\n\
         \x20 -h, --help                 Show this help"
    );
}

fn exit_usage(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_usage();
    std::process::exit(1);
}
