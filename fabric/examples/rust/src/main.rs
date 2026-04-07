use fabric::client::{Fabric};
use fabric::libveritas::builder::MessageBuilder;
use fabric::libveritas::cert::CertificateChain;
use fabric::libveritas::msg::ChainProof;
use fabric::libveritas::sip7::{ParsedRecord, Record, RecordSet, SIG_PRIMARY_ZONE};
use fabric::signing::sign_schnorr;

/// Resolve a single handle
async fn example_resolve() -> anyhow::Result<()> {
    // <doc:resolve>
    let fabric = Fabric::new();
    let Some(resolved) = fabric.resolve("alice@bitcoin").await? else {
        println!("handle not found");
        return Ok(());
    };

    println!("Handle found: {}", resolved.zone.handle);
    // </doc:resolve>

    Ok(())
}

/// Verification
async fn example_trust_and_verification() -> anyhow::Result<()> {
    let fabric = Fabric::new();

    // <doc:verification>
    // Before pinning a trust id: resolve uses observed (peer) state
    // badge() returns Unverified
    let resolved = fabric.resolve("alice@bitcoin").await?
        .expect("handle exists");
    fabric.badge(&resolved); // Unverified

    // Pin trust from a QR scan
    let qr = "veritas://scan?id=14ef902621df01bdeee0b23fedf67458563a20df600af8979a4748dcd9d1b9f9";

    // For highest level of trust (scan QR code from Veritas desktop)
    fabric.trust_from_qr(qr).await?;

    // Does not require re-resolving, badge now checks
    // whether resolved was against a trusted root
    fabric.badge(&resolved); // Orange if handle is sovereign (final certificate)

    // Or from a semi-trusted source (e.g. an explorer you trust with qr scanned over HTTPS)
    // .badge() will not show Orange for roots in this trust pool,
    // but it will not report it as "Unverified".
    fabric.semi_trust_from_qr(qr).await?;

    // Check current trust ids
    fabric.trusted();  // pinned id from local verification
    fabric.semi_trusted(); // pinned id from semi-trusted source
    fabric.observed(); // latest from peers

    // Clear trusted state
    fabric.clear_trusted();
    fabric.clear_semi_trusted();

    // </doc:verification>

    Ok(())
}

/// Unpack records from a resolved handle
async fn example_unpack_records() -> anyhow::Result<()> {
    let fabric = Fabric::new();
    let resolved = fabric.resolve("alice@bitcoin").await?.expect("handle exists");

    // <doc:unpack-records>
    for record in resolved.zone.records.unpack()? {
        match record {
            ParsedRecord::Txt { key, value } => {
                println!("txt {}={}", key, value.to_vec().join(", "))
            }
            ParsedRecord::Addr { key, value } => {
                println!("addr {}={}", key, value.to_vec().join(", "))
            }
            _ => {}
        }
    }
    // </doc:unpack-records>

    Ok(())
}

/// Resolve multiple handles
async fn example_resolve_all() -> anyhow::Result<()> {
    let fabric = Fabric::new();

    // <doc:resolve-all>
    let batch = fabric
        .resolve_all(&["alice@bitcoin", "bob@bitcoin"])
        .await?;

    for zone in &batch.zones {
        println!("{}: {:?}", zone.handle, zone.sovereignty);
    }
    // </doc:resolve-all>

    Ok(())
}

/// Pack records into a RecordSet
fn example_pack_records() -> anyhow::Result<()> {
    // <doc:pack-records>
    let records = RecordSet::pack(vec![
        Record::seq(1),
        Record::txt("website", &["https://example.com"]),
        Record::addr("btc", &["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
        Record::addr("nostr", &[
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            "wss://relay.example.com",
        ]),
    ])?;
    // </doc:pack-records>

    let _ = records;
    Ok(())
}

/// Publish signed records
async fn example_publish() -> anyhow::Result<()> {
    let fabric = Fabric::new();
    let secret_key: [u8; 32] = hex::decode(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )?
    .try_into()
    .unwrap();

    let records = RecordSet::pack(vec![
        Record::seq(1),
        Record::txt("website", &["https://example.com"]),
        Record::addr("btc", &["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ])?;

    // <doc:publish>
    let cert = fabric.export("alice@bitcoin").await?;
    fabric.publish(&cert, records, &secret_key, true).await?;
    // </doc:publish>

    Ok(())
}

/// Resolve by numeric ID
async fn example_resolve_by_id() -> anyhow::Result<()> {
    let fabric = Fabric::new();

    // <doc:resolve-by-id>
    let Some(resolved) = fabric.resolve_by_id("num1qx8dtlzq...").await? else {
        println!("handle not found");
        return Ok(());
    };

    println!("Handle found: {}", resolved.zone.handle);
    // </doc:resolve-by-id>

    Ok(())
}

/// Search by address
async fn example_search_addr() -> anyhow::Result<()> {
    let fabric = Fabric::new();

    // <doc:search-addr>
    let batch = fabric
        .search_addr("nostr", "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")
        .await?;

    for zone in &batch.zones {
        println!("{}: {:?}", zone.handle, zone.sovereignty);
    }
    // </doc:search-addr>

    Ok(())
}

/// Advanced: Build and broadcast a message manually
async fn example_message_builder() -> anyhow::Result<()> {
    let fabric = Fabric::new();
    let secret_key: [u8; 32] = hex::decode(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )?
    .try_into()
    .unwrap();

    let cert_bytes = fabric.export("alice@bitcoin").await?;
    let records = RecordSet::pack(vec![
        Record::seq(1),
        Record::addr("btc", &["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ])?;

    // <doc:message-builder>
    let cert = CertificateChain::from_slice(&cert_bytes)?;
    let mut builder = MessageBuilder::new();
    builder.add_handle(cert, records);

    let proof = ChainProof::from_slice(
        &fabric.prove(&builder.chain_proof_request()).await?,
    )?;

    let (mut msg, unsigned) = builder.build(proof)?;

    for mut u in unsigned {
        u.flags |= SIG_PRIMARY_ZONE;
        let sig = sign_schnorr(&u.signing_id(), &secret_key)?;
        msg.set_records(&u.canonical, u.pack_sig(sig.to_vec()));
    }

    fabric.broadcast(&msg.to_bytes()).await?;
    // </doc:message-builder>

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    example_resolve().await?;
    let _ = example_trust_and_verification().await;
    example_unpack_records().await?;
    example_resolve_all().await?;
    example_pack_records()?;
    example_publish().await?;
    example_resolve_by_id().await?;
    example_search_addr().await?;
    example_message_builder().await?;

    println!("Done!");
    Ok(())
}