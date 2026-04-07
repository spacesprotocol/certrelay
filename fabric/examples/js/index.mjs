import { Fabric, RecordSet, Record, MessageBuilder } from "@spacesprotocol/fabric-web";
import { signSchnorr } from "@spacesprotocol/fabric-web/signing";

/// Resolve a single handle
async function exampleResolve() {
    // <doc:resolve>
    const fabric = new Fabric();
    const resolved = await fabric.resolve("alice@bitcoin");
    if (!resolved) {
        console.log("handle not found");
        return;
    }

    console.log(`Handle found: ${resolved.zone.handle}`);
    // </doc:resolve>
}

/// Verification
async function exampleTrustAndVerification() {
    const fabric = new Fabric();

    // <doc:verification>
    // Before pinning a trust id: resolve uses observed (peer) state
    // badge() returns "unverified"
    const resolved = await fabric.resolve("alice@bitcoin");

    fabric.badge(resolved); // "unverified"

    // Pin trust from a QR scan
    const qr = "veritas://scan?id=14ef902621df01bdeee0b23fedf67458563a20df600af8979a4748dcd9d1b9f9";

    // For highest level of trust (scan QR code from Veritas desktop)
    await fabric.trustFromQr(qr);

    // Does not require re-resolving, badge now checks
    // whether resolved was against a trusted root
    fabric.badge(resolved); // "orange" if handle is sovereign (final certificate)

    // Or from a semi-trusted source (e.g. an explorer you trust with qr scanned over HTTPS)
    // .badge() will not show "orange" for roots in this trust pool,
    // but it will not report it as "unverified".
    await fabric.semiTrustFromQr(qr);

    // Check current trust ids
    fabric.trusted();      // pinned id from local verification
    fabric.semiTrusted();  // pinned id from semi-trusted source
    fabric.observed();     // latest from peers

    // Clear trusted state
    fabric.clearTrusted();
    // </doc:verification>
}

/// Unpack records from a resolved handle
async function exampleUnpackRecords() {
    const fabric = new Fabric();
    const resolved = await fabric.resolve("alice@bitcoin");

    // <doc:unpack-records>
    const json = resolved.zone.toJson();

    for (const record of json.records) {
        if (record.type === "txt") {
            console.log(`txt ${record.key}=${record.value.join(", ")}`);
        } else if (record.type === "addr") {
            console.log(`addr ${record.key}=${record.value.join(", ")}`);
        }
    }
    // </doc:unpack-records>
}

/// Resolve multiple handles
async function exampleResolveAll() {
    const fabric = new Fabric();

    // <doc:resolve-all>
    const batch = await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"]);

    for (const zone of batch.zones) {
        console.log(`${zone.handle}`);
    }
    // </doc:resolve-all>
}

/// Pack records into a RecordSet
function examplePackRecords() {
    // <doc:pack-records>
    const records = RecordSet.pack([
        Record.seq(1n),
        Record.txt("website", ["https://example.com"]),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
        Record.addr("nostr", [
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            "wss://relay.example.com",
        ]),
    ]);
    // </doc:pack-records>
}

/// Publish signed records
async function examplePublish() {
    const fabric = new Fabric();
    const secretKey = new Uint8Array(Buffer.from(
        "0000000000000000000000000000000000000000000000000000000000000001", "hex"
    ));

    const rs = RecordSet.pack([
        Record.seq(1n),
        Record.txt("website", ["https://example.com"]),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ]);

    // <doc:publish>
    const cert = await fabric.export("alice@bitcoin");
    await fabric.publish({
        cert,
        records: rs.toBytes(),
        sign: (digest) => signSchnorr(digest, secretKey),
        primary: true,
    });
    // </doc:publish>
}

/// Resolve by numeric ID
async function exampleResolveById() {
    const fabric = new Fabric();

    // <doc:resolve-by-id>
    const resolved = await fabric.resolveById("num1qx8dtlzq...");
    if (!resolved) {
        console.log("handle not found");
        return;
    }

    console.log(`Handle found: ${resolved.zone.handle}`);
    // </doc:resolve-by-id>
}

/// Search by address
async function exampleSearchAddr() {
    const fabric = new Fabric();

    // <doc:search-addr>
    const batch = await fabric.searchAddr("nostr", "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6");

    for (const zone of batch.zones) {
        console.log(`${zone.handle}`);
    }
    // </doc:search-addr>
}

/// Advanced: Build and broadcast a message manually
async function exampleMessageBuilder() {
    const fabric = new Fabric();
    const secretKey = new Uint8Array(Buffer.from(
        "0000000000000000000000000000000000000000000000000000000000000001", "hex"
    ));

    const certBytes = await fabric.export("alice@bitcoin");
    const rs = RecordSet.pack([
        Record.seq(1n),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ]);

    // <doc:message-builder>
    const builder = new MessageBuilder();
    builder.addHandle(certBytes, rs.toBytes());

    const chainProofReq = builder.chainProofRequest();
    const chainProof = await fabric.prove(
        typeof chainProofReq === "string" ? chainProofReq : JSON.stringify(chainProofReq)
    );

    const { message, unsigned } = builder.build(chainProof);

    for (const u of unsigned) {
        u.setFlags(u.flags() | 0x01); // SIG_PRIMARY_ZONE
        const sig = signSchnorr(u.signingId(), secretKey);
        message.setRecords(u.canonical(), u.packSig(sig));
    }

    await fabric.broadcast(message.toBytes());
    // </doc:message-builder>
}

async function main() {
    await exampleResolve();

    try {
        await exampleTrustAndVerification();
    } catch (e) {
        // Expected to fail with example QR ID
    }

    await exampleUnpackRecords();
    await exampleResolveAll();
    examplePackRecords();
    await examplePublish();
    await exampleResolveById();
    await exampleSearchAddr();
    await exampleMessageBuilder();

    console.log("Done!");
}

main().catch(console.error);
