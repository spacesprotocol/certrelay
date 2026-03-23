# Fabric — Rust

Rust client for resolving handles and broadcasting updates via the Spaces certrelay network.

## Installation

```toml
[dependencies]
fabric = { git = "https://github.com/spacesprotocol/certrelay.git", features = ["client", "signing"] }
```

Features:
- `client` (default) — async HTTP client for resolving and broadcasting
- `signing` — BIP-340 Schnorr signing via `secp256k1`

## Querying Records

```rust
use fabric::client::Fabric;

#[tokio::main]
async fn main() {
    let fabric = Fabric::new();

    // Resolve a single handle
    let zone = fabric.resolve("alice@bitcoin").await.unwrap();
    println!("handle: {}", zone.handle);

    for record in &zone.records.records {
        println!("  {} = {}", record.tag, record.value);
    }

    // Resolve multiple handles at once
    let zones = fabric.resolve_all(&["alice@bitcoin", "bob@bitcoin"]).await.unwrap();
    for zone in &zones {
        println!("{}: {} records", zone.handle, zone.records.records.len());
    }

    // Export a .spacecert certificate chain
    let cert_bytes = fabric.export("alice@bitcoin").await.unwrap();
}
```

## Updating Records & Broadcasting

```rust
use fabric::client::Fabric;
use fabric::libveritas::{sip7, builder, msg::DataUpdateRequest};

#[tokio::main]
async fn main() {
    let fabric = Fabric::new();

    // 1. Pack records into wire format
    let record_set = sip7::RecordSet::pack(vec![
        sip7::Record::txt("name", "alice"),
        sip7::Record::txt("SIP-7", "v=0;dest=sp1qqx..."),
    ]).unwrap();

    // 2. Sign the record set (requires "signing" feature)
    let signature = fabric::signing::sign_message(
        &record_set.to_bytes(), &secret_key
    )?;

    // 3. Create offchain records (record set + signature)
    let offchain_records = libveritas::create_offchain_records(&record_set, signature)?;

    // 4. Build the message
    let mut builder = builder::MessageBuilder::new();
    builder.add_records("alice@bitcoin", offchain_records);

    // 5. Get a chain proof from a relay
    let chain_proof_req = builder.chain_proof_request();
    let chain_proof = fabric.prove(&chain_proof_req).await?;

    // 6. Finalize the message with the proof
    let msg = builder.build(chain_proof)?;

    // 7. Broadcast to the network
    fabric.broadcast(&msg.to_bytes()).await?;
}
```

## Offline Verification

Access the internal `Veritas` instance for offline proof verification:

```rust
let fabric = Fabric::new();
fabric.bootstrap().await.unwrap();

let veritas = fabric.veritas();
// Use veritas directly for custom verification
```

## Configuration

```rust
let fabric = Fabric::with_seeds(&["https://relay1.example.com", "https://relay2.example.com"])
    .with_dev_mode()              // Skip finality checks (testing only)
    .with_anchor_set("abcdef.."); // Pin to specific anchor set

// Prefer freshest relays (default: true)
fabric.set_prefer_latest(false);
```

## Re-exports

This crate re-exports `libveritas` so you can access all types directly:

```rust
use fabric::libveritas::{Zone, Veritas, Message};
use fabric::libveritas::builder::MessageBuilder;
```
