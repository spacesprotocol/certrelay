import Fabric

func exampleResolveIntro() async throws {
    // <doc:resolve-intro>
    let fabric = Fabric()
    let resolved = try await fabric.resolve("alice@bitcoin")
    // </doc:resolve-intro>
}

/// Resolve a single handle
func exampleResolve() async throws {
    // <doc:resolve>
    let fabric = Fabric()
    guard let resolved = try await fabric.resolve("alice@bitcoin") else {
        print("handle not found")
        return
    }

    print("Handle found: \(resolved.zone.handle)")
    // </doc:resolve>
}

/// Verification
func exampleTrustAndVerification() async throws {
    let fabric = Fabric()

    // <doc:verification>
    // Before pinning a trust id: resolve uses observed (peer) state
    // badge() returns Unverified
    let resolved = try await fabric.resolve("alice@bitcoin")!

    fabric.badge(resolved) // Unverified

    // Pin trust from a QR scan
    let qr = "veritas://scan?id=14ef902621df01bdeee0b23fedf67458563a20df600af8979a4748dcd9d1b9f9"

    // For highest level of trust (scan QR code from Veritas desktop)
    try await fabric.trustFromQr(qr)

    // Does not require re-resolving, badge now checks
    // whether resolved was against a trusted root
    fabric.badge(resolved) // Orange if handle is sovereign (final certificate)

    // Or from a semi-trusted source (e.g. an explorer you trust with qr scanned over HTTPS)
    // .badge() will not show Orange for roots in this trust pool,
    // but it will not report it as "Unverified".
    try await fabric.semiTrustFromQr(qr)

    // Check current trust ids
    fabric.trusted()      // pinned id from local verification
    fabric.semiTrusted()  // pinned id from semi-trusted source
    fabric.observed()     // latest from peers

    // Clear trusted state
    fabric.clearTrusted()
    fabric.clearSemiTrusted()

    // </doc:verification>
}

/// Unpack records from a resolved handle
func exampleUnpackRecords() async throws {
    let fabric = Fabric()
    let resolved = try await fabric.resolve("alice@bitcoin")!

    // <doc:unpack-records>
    let records = try resolved.zone.records.unpack()

    for record in records {
        switch record {
        case .txt(let key, let value):
            print("txt \(key)=\(value.joined(separator: ", "))")
        case .addr(let key, let value):
            print("addr \(key)=\(value.joined(separator: ", "))")
        default:
            break
        }
    }
    // </doc:unpack-records>
}

/// Resolve multiple handles
func exampleResolveAll() async throws {
    let fabric = Fabric()

    // <doc:resolve-all>
    let batch = try await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"])

    for zone in batch.zones {
        print("\(zone.handle): \(zone.sovereignty)")
    }
    // </doc:resolve-all>
}

/// Pack records into a RecordSet
func examplePackRecords() throws {
    // <doc:pack-records>
    let records = try RecordSet.pack([
        Record.seq(1),
        Record.txt("website", ["https://example.com"]),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
        Record.addr("nostr", [
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            "wss://relay.example.com",
        ]),
    ])
    // </doc:pack-records>

    _ = records
}

/// Publish signed records
func examplePublish() async throws {
    let fabric = Fabric()
    let secretKey = Data(hex:
        "0000000000000000000000000000000000000000000000000000000000000001"
    )

    let rs = try RecordSet.pack([
        Record.seq(1),
        Record.txt("website", ["https://example.com"]),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ])

    // <doc:publish>
    let cert = try await fabric.export("alice@bitcoin")
    try await fabric.publish(cert, rs, secretKey, primary: true)
    // </doc:publish>
}

/// Resolve by numeric ID
func exampleResolveById() async throws {
    let fabric = Fabric()

    // <doc:resolve-by-id>
    guard let resolved = try await fabric.resolveById("num1qx8dtlzq...") else {
        print("handle not found")
        return
    }

    print("Handle found: \(resolved.zone.handle)")
    // </doc:resolve-by-id>
}

/// Search by address
func exampleSearchAddr() async throws {
    let fabric = Fabric()

    // <doc:search-addr>
    let batch = try await fabric.searchAddr("nostr", "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")

    for zone in batch.zones {
        print("\(zone.handle): \(zone.sovereignty)")
    }
    // </doc:search-addr>
}

/// Advanced: Build and broadcast a message manually
func exampleMessageBuilder() async throws {
    let fabric = Fabric()
    let secretKey = Data(hex:
        "0000000000000000000000000000000000000000000000000000000000000001"
    )

    let certBytes = try await fabric.export("alice@bitcoin")
    let records = try RecordSet.pack([
        Record.seq(1),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ])

    // <doc:message-builder>
    let cert = try CertificateChain.fromSlice(certBytes)
    var builder = MessageBuilder()
    builder.addHandle(cert, records)

    let proofBytes = try await fabric.prove(builder.chainProofRequest())
    let proof = try ChainProof.fromSlice(proofBytes)

    var (msg, unsigned) = try builder.build(proof)

    for var u in unsigned {
        u.flags |= SIG_PRIMARY_ZONE
        let sig = try signSchnorr(u.signingId(), secretKey)
        msg.setRecords(u.canonical, u.packSig(sig))
    }

    try await fabric.broadcast(msg.toBytes())
    // </doc:message-builder>
}

@main
struct Example {
    static func main() async {
        do {
            try await exampleResolve()
        } catch {
            print("resolve failed: \(error)")
        }

        do {
            try await exampleTrustAndVerification()
        } catch {
            print("verification example failed (expected): \(error)")
        }

        do {
            try await exampleUnpackRecords()
            try await exampleResolveAll()
            try examplePackRecords()
            try await examplePublish()
            try await exampleResolveById()
            try await exampleSearchAddr()
            try await exampleMessageBuilder()
        } catch {
            print("error: \(error)")
        }

        print("Done!")
    }
}
