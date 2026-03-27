# Certrelay

Certrelay is a certificate relay network for the [Spaces protocol](https://spacesprotocol.org). It stores and serves cryptographic proofs that bind human-readable names (handles) to owner keys anchored to Bitcoin.

The entire protocol is plain HTTP, so relays are directly queryable from browsers, mobile apps, and any language with an HTTP client.

A client can query any relay to resolve a handle like `alice@bitcoin` into its current owner key, sovereignty state, and optional owner-signed data. All verifiable against Bitcoin's chain state.


## Fabric client

Fabric is the high-level client for certrelay. It handles peer discovery, anchor verification, relay selection so you just call `resolve`.


### JavaScript / TypeScript

Install the package for your platform:

```bash
# Browser or Node.js
npm install @spacesprotocol/fabric-web

# React Native
npm install @spacesprotocol/fabric-react-native
```

Resolve a handle:

```ts
import { Fabric } from '@spacesprotocol/fabric-web';
// or: import { Fabric } from '@spacesprotocol/fabric-react-native';

const fabric = new Fabric();
const zone = await fabric.resolve("alice@bitcoin");

console.log(zone.handle());       // "alice@bitcoin"
console.log(zone.toJson());       // full zone data as JSON
```

Resolve multiple handles:

```ts
const zones = await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"]);
for (const zone of zones) {
  console.log(zone.handle, zone.toJson());
}
```

Export a `.spacecert` certificate chain:

```ts
const certBytes = await fabric.export("alice@bitcoin");
```

Broadcast a signed message:

```ts
await fabric.broadcast(messageBytes);
```

By default, Fabric discovers anchors from seed relays. If you have a trusted anchor set hash (e.g. from your own Bitcoin node), pass it for **trustless** verification:

```ts
const fabric = new Fabric({ anchorSetHash: "ab3f...c7d2" });
```

### Rust

```rust
use fabric::client::Fabric;

let fabric = Fabric::new();
let zone = fabric.resolve("alice@bitcoin").await?;

println!("{}: {:?}", zone.handle, zone.sovereignty);

// With a trusted anchor set hash
let fabric = Fabric::new().with_anchor_set("ab3f...c7d2");
```

### Packages

| Package | Description |
|---------|-------------|
| `@spacesprotocol/fabric-core` | Provider-agnostic core (advanced use) |
| `@spacesprotocol/fabric-web` | Browser & Node.js (WASM backend) |
| `@spacesprotocol/fabric-react-native` | React Native (native backend) |
| `fabric` (Rust crate) | Rust client |

The web and React Native packages re-export everything from core, so most consumers only need one dependency. If you need custom provider wiring, use `fabric-core` directly.

## Protocol

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/query` | Resolve handles (JSON request, binary response) |
| POST | `/message` | Submit a certificate message (binary) |
| POST | `/announce` | Announce a peer relay (JSON) |
| GET | `/peers` | List known peers (JSON) |
| GET | `/hints` | Lightweight freshness check (JSON) |
| POST | `/chain-proof` | Build a chain proof (JSON request, binary response) |
| GET | `/anchors` | Get trust anchor set (JSON) |

### Resolving handles

Send a `POST /query` with a JSON body:

```json
{
  "queries": [
    {
      "space": "@bitcoin",
      "handles": ["alice", "bob"]
    }
  ]
}
```

Each query targets a **space** (e.g. `@bitcoin`) and lists the **handles** within it to resolve. You can query multiple spaces in a single request.

The response is a binary-encoded `Message` containing the chain proofs and certificates needed to verify each handle.

### Epoch hints

If the client has previously resolved a space and cached its epoch root, it can include an epoch hint to skip redundant proofs:

```json
{
  "queries": [
    {
      "space": "@bitcoin",
      "handles": ["alice"],
      "epoch_hint": {
        "root": "abcdef...",
        "height": 870000
      }
    }
  ]
}
```

The relay will omit the receipt proof if the client's cached epoch is still current, reducing response size.

### Freshness hints

`GET /hints?q=alice@bitcoin,bob@bitcoin,@bitcoin` returns lightweight freshness data without fetching full certificates:

```json
{
  "anchor_tip": 870100,
  "hints": [
    {
      "epoch_tip": 870000,
      "name": "@bitcoin",
      "seq": 5,
      "delegate_seq": 3,
      "epochs": [
        {
          "epoch": 870000,
          "res": [
            { "seq": 2, "name": "alice@bitcoin" }
          ]
        }
      ]
    }
  ]
}
```

Fabric uses this to compare freshness across multiple relays and pick the most up-to-date one before querying.

### Trust anchors

`GET /anchors` returns the relay's current anchor set. An optional `?root=<hex>` parameter fetches a specific set by hash.

Response headers include `X-Anchor-Root` and `X-Anchor-Height`, which allows cheap freshness comparison via `HEAD /anchors` without downloading the full set.

## Verification

Clients verify relay responses locally using [libveritas](https://github.com/spacesprotocol/libveritas). No trust is placed in the relay itself. All data is proven against Bitcoin's chain state via merkle proofs and ZK receipts.

### Trust anchor bootstrapping

A client needs one or more **root anchors** to verify messages. A root anchor is a snapshot of Bitcoin's chain state at a specific block height, containing:

- Block hash and height
- Spaces tree merkle root
- Ptrs tree merkle root (commitments, delegations, key rotations)

Anchors can be obtained from a trusted source (hardcoded in the client, fetched from a known relay, or derived from a Bitcoin node). Fabric handles this automatically by fetching from seed relays and verifying the anchor set hash.

### Verification flow

```
Client                          Relay
  |                               |
  |  POST /query (JSON)           |
  |------------------------------>|
  |                               |
  |  binary Message               |
  |<------------------------------|
  |                               |
  |  verify_message(msg)          |
  |  -> Vec<Zone>                 |
```

1. Client sends a query
2. Relay responds with a `Message` containing proofs
3. Client calls `verify_message` which checks all merkle proofs, ZK receipts, and signatures
4. If verification succeeds, the client gets a list of `Zone` objects, one per handle

### What a Zone contains

Each verified `Zone` represents the current state of a handle:

| Field | Type | Description |
|-------|------|-------------|
| `handle` | SName | The resolved handle (e.g. `alice@bitcoin`) |
| `sovereignty` | SovereigntyState | Commitment finality status |
| `script_pubkey` | ScriptBuf | Current Bitcoin script controlling the handle |
| `offchain_data` | Option\<OffchainData\> | Owner-signed arbitrary data |
| `commitment` | ProvableOption\<CommitmentInfo\> | On-chain state commitment |
| `delegate` | ProvableOption\<Delegate\> | Delegation info |
| `anchor` | u32 | Block height of the proof snapshot |

### Sovereignty states

| State | Meaning |
|-------|---------|
| **Sovereign** | Commitment is finalized, the handle is fully self-governing |
| **Pending** | Commitment exists but hasn't reached finality yet |
| **Dependent** | No commitment, handle operates under parent space authority |

### Offchain data

Handle owners can attach arbitrary signed data without making on-chain transactions. The `OffchainData` contains:

- `seq` - sequence number for versioning (higher = newer)
- `data` - arbitrary byte payload
- `signature` - Schnorr signature from the handle's current owner

The signature is verified during `verify_message`. Applications can use this to store TLS certificates, service endpoints, payment addresses, or any other metadata.

## Client implementation

Fabric is the recommended way to interact with the relay network. Under the hood it:

1. **Discovers peers** by fetching `GET /peers` from seed relays and collecting URLs
2. **Fetches trust anchors** by polling `HEAD /anchors` across seeds, voting on the freshest anchor set hash, then downloading and verifying the full set via `GET /anchors?root=<hash>`
3. **Selects relays** by querying `GET /hints` on multiple relays in parallel and ranking them by freshness
4. **Resolves handles** by posting to `POST /query` on the freshest relay, verifying the binary response with libveritas, and falling through to the next relay on failure
5. **Caches root zones** so subsequent queries for handles in the same space can include epoch hints and skip redundant proofs

For broadcasting, Fabric submits the message to multiple relays via `POST /message` for gossip propagation.


## Peer discovery

Relays form a gossip network. New relays announce themselves via `POST /announce` and can be discovered by any client via `GET /peers`:

```json
[
  {
    "source_ip": "203.0.113.1",
    "url": "https://relay2.example.com",
    "capabilities": 0
  }
]
```

This allows clients to fall back to alternative relays if one is unavailable.

## Running a relay

```bash
cargo install --git https://github.com/spacesprotocol/certrelay.git --bin certrelay
certrelay
```

That's it. On first run, certrelay will:
1. Download a checkpoint so it can sync quickly (~8MB)
2. Build hash indexes (~2 min)
3. Start an embedded Bitcoin light client ([yuki](https://github.com/imperviousinc/yuki)) and [spaced](https://github.com/spacesprotocol/spaces) node
4. Sync to the chain tip and start serving

No external Bitcoin node or Spaces node required. Data is stored in `~/.certrelay` by default.

### Configuration

All options can be set via CLI flags or environment variables:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--chain` | `CERTRELAY_CHAIN` | `mainnet` | Network (`mainnet`, `testnet4`) |
| `--data-dir` | `CERTRELAY_DATA_DIR` | `~/.certrelay` | Data directory |
| `--bind` | `CERTRELAY_BIND` | `127.0.0.1` | Bind address |
| `--port` | `CERTRELAY_PORT` | `7778` (mainnet) / `7779` (other) | Listen port |
| `--self-url` | `CERTRELAY_SELF_URL` | - | Public URL for peer announcements |
| `--spaced-rpc-url` | `CERTRELAY_SPACED_RPC_URL` | - | External spaced RPC (skips embedded node) |
| `--remote-ip-header` | `CERTRELAY_REMOTE_IP_HEADER` | - | Header for client IP behind reverse proxy |
| `--is-bootstrap` | `CERTRELAY_BOOTSTRAP` | `false` | Run as a bootstrap node |
| `--skip-checkpoint-sync` | - | `false` | Skip checkpoint download, sync from scratch |
| `--anchor-refresh` | `CERTRELAY_ANCHOR_REFRESH` | `300` | Anchor refresh interval in seconds |

### Public relay behind a reverse proxy

```bash
certrelay \
  --bind 0.0.0.0 \
  --self-url https://relay.example.com \
  --remote-ip-header x-forwarded-for
```

### Using an external spaced node

If you already run a spaced node, point certrelay at it to skip the embedded light client:

```bash
certrelay --spaced-rpc-url http://user:password@127.0.0.1:12888
```
