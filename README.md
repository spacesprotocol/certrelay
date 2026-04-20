# Certrelay

Certificate relay network for the [Spaces protocol](https://spacesprotocol.org). Stores and serves cryptographic proofs that bind human-readable names to owner keys anchored to Bitcoin.

## Overview

Certrelay consists of two components:

- **relay** — HTTP server that verifies certificates, stores them in SQLite, and gossips with peers
- **fabric** — Client library available in Rust, JavaScript, Go, Python, Kotlin, and Swift

The protocol is plain HTTP — relays are queryable from browsers, mobile apps, and any language with an HTTP client. All verification is done client-side against Bitcoin's chain state.

## Fabric Client

For documentation on using Fabric to resolve handles, publish records, and verify identities, see:

**[spacesprotocol.org/docs](https://spacesprotocol.org/docs)**

### Quick Start

```bash
# Rust
cargo add fabric-rs

# JavaScript / TypeScript
npm install @spacesprotocol/fabric-web

# Go
go get github.com/spacesprotocol/fabric-go

# Python
pip install fabric-resolver

# Kotlin
implementation("org.spacesprotocol:fabric:0.1.0")

# Swift
.package(url: "https://github.com/spacesprotocol/fabric-swift.git", from: "0.1.0")
```

## Running a Relay

```bash
cargo install --git https://github.com/spacesprotocol/certrelay.git --bin certrelay
certrelay
```

On first run, certrelay will:
1. Download a checkpoint (~8MB)
2. Build hash indexes (~2 min)
3. Start an embedded Bitcoin light client ([yuki](https://github.com/imperviousinc/yuki)) and [spaced](https://github.com/spacesprotocol/spaces) node
4. Sync to the chain tip and start serving

No external Bitcoin node required. Data is stored in `~/.certrelay` by default.

### Configuration

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

### Public relay behind a reverse proxy

```bash
certrelay \
  --bind 0.0.0.0 \
  --self-url https://relay.example.com \
  --remote-ip-header x-forwarded-for
```

### Using an external spaced node

```bash
certrelay --spaced-rpc-url http://user:password@127.0.0.1:12888
```

## License

MIT