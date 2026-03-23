# Fabric — Swift

Swift client for resolving handles and broadcasting updates via the Spaces certrelay network. Supports iOS 15+ and macOS 12+.

## Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/spacesprotocol/fabric-swift.git", from: "0.1.0"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [.product(name: "Fabric", package: "fabric-swift")]
    ),
]
```

## Querying Records

```swift
import Fabric

let fabric = Fabric()

// Resolve a single handle
let zone = try await fabric.resolve("alice@bitcoin")
print("handle: \(zone.handle)")

for record in zone.records.records {
    print("  \(record.tag) = \(record.value)")
}

// Resolve multiple handles at once
let zones = try await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"])
for zone in zones {
    print("\(zone.handle): \(zone.records.records.count) records")
}

// Export a .spacecert certificate chain
let certBytes = try await fabric.export("alice@bitcoin")
```

## Updating Records & Broadcasting

```swift
import Fabric

let fabric = Fabric()

// 1. Pack records into wire format
let recordSet = try RecordSet.pack(records: [
    .txt(key: "name", value: "alice"),
    .txt(key: "SIP-7", value: "v=0;dest=sp1qqx..."),
])

// 2. Sign the record set
let signature = try signMessage(msg: recordSet.toBytes(), secretKey: secretKey)

// 3. Create offchain records (record set + signature)
let offchainRecords = try createOffchainRecords(recordSet: recordSet, signature: signature)

// 4. Build the message
let builder = MessageBuilder()
builder.addRecords(handle: "alice@bitcoin", recordsBytes: offchainRecords)

// 5. Get a chain proof from a relay
let chainProofReq = builder.chainProofRequest()
let chainProof = try await fabric.prove(chainProofReq)

// 6. Finalize the message with the proof
let msg = try builder.build(chainProof: chainProof)

// 7. Broadcast to the network
try await fabric.broadcast(msg.toBytes())
```

## Offline Verification

Access the internal `Veritas` instance for offline proof verification:

```swift
let fabric = Fabric()
try await fabric.bootstrap()

if let veritas = fabric.veritas {
    // Use veritas directly for custom verification
}
```

## Configuration

```swift
let fabric = Fabric(
    seeds: ["https://relay1.example.com", "https://relay2.example.com"],
    devMode: true,              // Skip finality checks (testing only)
    anchorSetHash: "abcdef.."   // Pin to specific anchor set
)
fabric.preferLatest = false     // Disable freshest-relay preference
```

## Re-exports

This package re-exports all `Libveritas` types via `@_exported import`:

```swift
import Fabric

let zone: Zone = ...
let msg: Message = ...
let builder = MessageBuilder()
```
