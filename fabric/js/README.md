# Fabric — JavaScript / TypeScript

JavaScript/TypeScript client for resolving handles and broadcasting updates via the Spaces certrelay network. Available in two variants:

| Package | Runtime | Backend |
|---------|---------|---------|
| `@spacesprotocol/fabric-web` | Browsers & Node.js | WASM |
| `@spacesprotocol/fabric-react-native` | React Native | Native (UniFFI) |

Both packages share the same API surface via `@spacesprotocol/fabric-core`.

## Installation

### Web / Node.js

```bash
npm install @spacesprotocol/fabric-web

# With signing support (BIP-340 Schnorr via @noble/curves):
npm install @spacesprotocol/fabric-web @noble/curves
```

### React Native

```bash
npm install @spacesprotocol/fabric-react-native

# With signing support:
npm install @spacesprotocol/fabric-react-native @noble/curves
```

## Querying Records

```typescript
import { Fabric, zoneToJson } from "@spacesprotocol/fabric-web";
// or: import { Fabric, zoneToJson } from "@spacesprotocol/fabric-react-native";

const fabric = new Fabric();

// Resolve a single handle
const zone = await fabric.resolve("alice@bitcoin");
console.log(zoneToJson(zone));

// Resolve multiple handles at once
const zones = await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"]);
for (const zone of zones) {
  console.log(`${zone.handle}: ${zone.toJson().records.length} records`);
}

// Export a .spacecert certificate chain
const certBytes = await fabric.export("alice@bitcoin");
```

## Updating Records & Broadcasting

```typescript
import { Fabric, MessageBuilder, RecordSet, createOffchainRecords } from "@spacesprotocol/fabric-web";
import { signMessage } from "@spacesprotocol/fabric-web/signing";

const fabric = new Fabric();

// 1. Pack records into wire format
const recordSet = RecordSet.pack([
  { type: "txt", key: "name", value: "alice" },
  { type: "txt", key: "SIP-7", value: "v=0;dest=sp1qqx..." },
]);

// 2. Sign the record set (requires: npm install @noble/curves)
const signature = signMessage(recordSet.toBytes(), secretKey);

// 3. Create offchain records (record set + signature)
const offchainRecords = createOffchainRecords(recordSet, signature);

// 4. Build the message
const builder = new MessageBuilder();
builder.addRecords("alice@bitcoin", offchainRecords);

// 5. Get a chain proof from a relay
const chainProofReq = builder.chainProofRequest();
const chainProof = await fabric.prove(chainProofReq);

// 6. Finalize the message with the proof
const msg = builder.build(chainProof);

// 7. Broadcast to the network
await fabric.broadcast(msg.toBytes());
```

## Offline Verification

Access the internal `Veritas` instance for offline proof verification:

```typescript
const fabric = new Fabric();
await fabric.bootstrap();

const veritas = fabric.getVeritas();
// Use veritas directly for custom verification
```

## Configuration

```typescript
const fabric = new Fabric({
  seeds: ["https://relay1.example.com", "https://relay2.example.com"],
  devMode: true,              // Skip finality checks (testing only)
  anchorSetHash: "abcdef..",  // Pin to specific anchor set
  preferLatest: false,        // Disable freshest-relay preference
});
```

## Re-exports

Both packages re-export all `libveritas` types and functions:

```typescript
import {
  Zone,
  Message,
  MessageBuilder,
  Veritas,
  Lookup,
  zoneToJson,
  zoneToBytes,
  decodeZone,
  decodeCertificate,
} from "@spacesprotocol/fabric-web";
```
