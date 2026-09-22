# Certrelay

Certificate relay network for the [Spaces protocol](https://spacesprotocol.org). Stores and serves cryptographic proofs that bind human-readable names to owner keys anchored to Bitcoin.

## Overview

Certrelay consists of two components:

- **relay** — HTTP server that verifies certificates, stores them in SQLite, and syncs with peers (pull-based replication with poke notifications)
- **fabric** — Client library available in Rust, JavaScript, Go, Python, Kotlin, and Swift

The protocol is plain HTTP — relays are queryable from browsers, mobile apps, and any language with an HTTP client. All verification is done client-side against Bitcoin's chain state.

## Fabric Client

For full reference docs (resolve, publish, sign, verify, badge / trust-pinning), see **[spacesprotocol.org/docs](https://spacesprotocol.org/docs)**.

The [Querying with the Fabric client](#querying-with-the-fabric-client) section below shows how to point every binding at a relay you're running yourself.

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
| `--self-url` | `CERTRELAY_SELF_URL` | - | Public URL for peer announcements (also enables poke sending) |
| `--config` | `CERTRELAY_CONFIG` | - | Path to a TOML config file (see below) |
| `--spaced-rpc-url` | `CERTRELAY_SPACED_RPC_URL` | - | External spaced RPC (skips embedded node) |
| `--remote-ip-header` | `CERTRELAY_REMOTE_IP_HEADER` | - | Header for client IP behind reverse proxy (rightmost entry is used) |
| `--is-bootstrap` | `CERTRELAY_BOOTSTRAP` | `false` | Run as a bootstrap node |
| `--seed` | `CERTRELAY_SEEDS` | mainnet builtins / none off-mainnet | Override bootstrap seeds (repeatable or comma-separated; replaces builtins) |
| `--anchor-refresh` | `CERTRELAY_ANCHOR_REFRESH` | `300` | Anchor refresh interval in seconds |
| `--allow-private-peers` | `CERTRELAY_ALLOW_PRIVATE_PEERS` | `false` | Accept peers on private/loopback addresses (local development only) |
| `--skip-checkpoint-sync` | - | `false` | Skip checkpoint download, sync from scratch |

### Configuration file

Rate limits, sync tuning, peer table sizes, concurrency caps, and storage
retention live in an optional TOML file passed via `--config` (or
`CERTRELAY_CONFIG`). Every field is optional and defaults to the values shown —
a config file only needs the settings being changed. Unknown keys are rejected
to catch typos.

```toml
[rate_limits]
message_per_min = 60       # /message (client publishes)
proof_per_min = 30         # /query, /chain-proof (trigger proof generation)
read_per_min = 120         # /hints, /reverse, /addrs, /anchors, /peers, /stats
announce_per_min = 5       # /announce
sync_per_min = 60          # /sync, /sync/summary (pages are the unit)
poke_per_min = 30          # /poke
space_per_min = 100        # per-space content updates (replacements only)
handle_period_secs = 300   # per-handle content cap period (replacements only)
handle_burst = 3           # per-handle burst within the period

[sync]
interval_secs = 45         # pull round cadence (plus jitter)
jitter_secs = 15
page_limit = 1000          # rows requested per /sync page (max 1000)
peers_per_round = 2        # peers pulled from per round
max_pages_per_peer = 200   # page budget per peer per round
poke_debounce_ms = 2000    # coalescing window for outgoing pokes
poke_cooldown_ms = 5000    # min gap between poke-triggered pulls per peer

[peers]
max_unverified = 1000      # announced-but-unverified peer slots
max_verified = 100         # verified peer slots
verified_ttl_secs = 600    # verified peers expire without a liveness refresh

[limits]
max_message_size = 524288  # /message body cap in bytes (512 KB)
proof_concurrency = 6      # concurrent chain-proof generations (503 beyond)
verify_concurrency = 4     # concurrent message verifications (503 beyond)

[retention]
max_storage_bytes = 10737418240  # handle payload budget (10 GB); 0 = unlimited
entitlement_per_epoch = 10000    # handles per (space, epoch) counted as paid-for
evict_low_water_pct = 90         # evict down to this % of the budget
sweep_interval_secs = 30         # pressure check cadence
eviction_batch = 1000            # rows deleted per transaction
```

Notes on the less obvious knobs:

- **Content limits are churn-only.** `space_per_min` and the `handle_*` caps
  charge only when an existing record is *replaced*; the first insert of a
  handle is always free so relays can bootstrap-sync a whole network's data.
- **Retention never rejects data under budget.** A space's *entitlement* is
  `entitlement_per_epoch × epochs it committed on-chain` — commitments cost
  Bitcoin transactions, so storage beyond entitlement is storage nobody paid
  for. Only when `max_storage_bytes` is exceeded does the relay evict, most
  over-entitled space first (oldest and least-queried rows first), and stop
  admitting *new* handles for over-entitled spaces until pressure clears.
  Size the budget to your disk; a small relay stays functional by shedding
  the heaviest spaces, a big relay can hold everything.

### Monitoring

- `GET /health` — unmetered liveness check for load balancers and peers.
- `GET /stats` — JSON counters: message intake, sync progress (including last
  successful sync per peer — the key signal that replication is healthy),
  pokes, rate-limit rejections, storage totals versus budget, and evictions.

Mesh replication and client query practices: **[MESH.md](MESH.md)**. API
reference: [`CERTRELAY_API.md`](CERTRELAY_API.md). Resolve walkthrough:
[`RESOLVE.md`](RESOLVE.md). Minting vs relay: [`MINTING.md`](MINTING.md).

### Querying with the Fabric client

Once `certrelay` has reached the chain tip it serves the Fabric HTTP API on `http://127.0.0.1:7778`. Every Fabric binding can be pointed at that URL by passing it as a *seed*. Two notes that apply to all the examples below:

- `devMode` / `dev_mode` / `--dev-mode` skips finality (work-depth) checks during verification. **You usually want this when querying your own relay**, because a freshly-synced local node may briefly produce zones whose anchors haven't yet accumulated enough confirmations for the strict default policy.
- Without `--trust-id` (or `Fabric::trust(...)`), zones come back with a `badge` of `unverified`. That's expected — pin a trust id from a QR / Veritas desktop scan when you want the orange-checkmark badge.

#### Verify the relay is responding (no client library)

```bash
# Liveness + peer / anchor snapshots are JSON and curl-friendly.
curl -s  http://127.0.0.1:7778/peers      | head -c 200; echo
curl -s  http://127.0.0.1:7778/anchors    | head -c 200; echo
curl -s 'http://127.0.0.1:7778/hints?q=@rad'

# /query is GET with ?q=<handle@space>[,<handle@space>...] (max 6).
# The response body is a borsh-encoded `Message` (binary), so curl can
# only confirm HTTP status + size; use one of the Fabric clients below
# to actually decode and verify the zone.
curl -sS -o /tmp/zone.msg \
     -w 'http=%{http_code} size=%{size_download}B\n' \
     'http://127.0.0.1:7778/query?q=user@rad'
# expected:  http=200 size=<a few KB>     (subname found, with proof)
# vs.        http=200 size=<small bytes>   (subname not present)
```

#### JavaScript / TypeScript

```bash
npm install @spacesprotocol/fabric-web
```

```javascript
import { Fabric } from "@spacesprotocol/fabric-web";

const fabric = new Fabric({
  seeds:   ["http://127.0.0.1:7778"],
  devMode: true,
});

const { zone } = await fabric.resolve("user@rad");
console.log(JSON.stringify(zone.toJson(), null, 2));
```

A runnable copy lives at [`fabric/js/examples/query-local.mjs`](fabric/js/examples/query-local.mjs):

```bash
cd fabric/js
node examples/query-local.mjs
```

CLI form (handy for shell scripts):

```bash
node fabric-web/dist/cli.js --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

#### Rust

```bash
cargo add fabric-resolver
```

```rust
use fabric::client::Fabric;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fabric = Fabric::with_seeds(&["http://127.0.0.1:7778"])
        .with_dev_mode();

    if let Some(zone) = fabric.resolve("user@rad").await? {
        println!("{}: {:?}", zone.handle, zone.sovereignty);
    } else {
        println!("handle not found");
    }
    Ok(())
}
```

CLI form (installs a `fabric` binary alongside `certrelay`):

```bash
cargo install --git https://github.com/spacesprotocol/certrelay.git --bin fabric
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

#### Python

```bash
pip install fabric-resolver
```

```python
import asyncio
from fabric import Fabric

async def main():
    fabric = Fabric(seeds=["http://127.0.0.1:7778"], dev_mode=True)
    zone = await fabric.resolve("user@rad")
    if zone is None:
        print("handle not found")
    else:
        print(f"{zone.handle}: {zone.sovereignty}")

asyncio.run(main())
```

CLI form:

```bash
python -m fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

#### Go

```bash
go get github.com/spacesprotocol/fabric-go
```

```go
package main

import (
    "fmt"
    "log"

    fabric "github.com/spacesprotocol/fabric-go"
)

func main() {
    f := fabric.New()
    f.SetSeeds([]string{"http://127.0.0.1:7778"})
    f.SetDevMode(true)

    zone, err := f.Resolve("user@rad")
    if err != nil {
        log.Fatal(err)
    }
    if zone == nil {
        fmt.Println("handle not found")
        return
    }
    fmt.Printf("%s: %s\n", zone.Handle, zone.Sovereignty)
}
```

#### Publishing to a local relay

The handle must already exist on a reachable relay (i.e. its certificate
chain was previously minted by the parent space owner via `spaces-cli` or
the Veritas desktop). Publishing then signs a new `RecordSet` under that
existing handle and broadcasts it.

The fastest path is the `fabric publish` CLI shipped alongside `certrelay`
in this repo (and in the Docker image):

```bash
SECRET=$(cat ./user-rad-secret.hex)   # 64-char hex BIP-340 secret key

fabric publish \
    --seeds http://127.0.0.1:7778 \
    --dev-mode \
    --secret-key-env SECRET \
    --txt  website=https://example.com \
    --addr btc=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 \
    --addr nostr=npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 \
    user@rad
# stdout: {"handle":"user@rad","seq":2,"primary":true,"txts":1,"addrs":2}
```

`fabric publish` automatically resolves the handle first to pick the next
`seq` number, exports the existing certificate chain, signs each block
with the supplied key, sets `SIG_PRIMARY_ZONE` (override with
`--no-primary`) and broadcasts to the relay's `/message` endpoint. Use
`--seq <N>` to override the auto-bump and `--dry-run` to print the
would-be payload as JSON without broadcasting. See
`fabric publish --help` for the full list of flags.

The same flow is available programmatically in every binding (the CLI
is a thin wrapper over `fabric.publish(cert, records, secretKey, primary)`):

1. Construct `Fabric` pointing at your local relay.
2. `cert = await fabric.export("user@rad")` — pull the existing certificate chain.
3. Build a `RecordSet` of the records you want to publish (include `Record::seq(N)` strictly greater than the currently-stored seq).
4. `await fabric.publish({ cert, records, secretKey, primary: true })`.

End-to-end library examples that pack records, sign, and broadcast in
every binding live under [`fabric/examples/`](fabric/examples/) — they
default to public seeds, so swap in `seeds: ["http://127.0.0.1:7778"]`
(and enable `devMode` if your local relay isn't yet caught up to a
finalized epoch) to target a relay you're running yourself.

### Docker

A multi-stage Alpine `Dockerfile` is included in the repo. It produces a
~30 MB image whose runtime layer contains only `ca-certificates`, `tini`,
`tzdata`, the statically-linked `certrelay` binary and the `fabric`
client binary used by the built-in healthcheck.

```bash
docker build -t certrelay:latest .

# Run with a named volume for persistence + a healthcheck-driven
# subname probe (any handle that should resolve via this relay):
docker run -d --name certrelay \
    -p 7778:7778 \
    -v certrelay-data:/data \
    -e CERTRELAY_CHAIN=mainnet \
    -e CERTRELAY_BIND=0.0.0.0 \
    -e CERTRELAY_SELF_URL=https://relay.example.com \
    -e CERTRELAY_HEALTHCHECK_HANDLE=user@rad \
    certrelay:latest

docker ps  # STATUS column should flip to "(healthy)" after start-up
```

`CERTRELAY_HEALTHCHECK_HANDLE` is optional. When set, the container
HEALTHCHECK runs `fabric --seeds http://127.0.0.1:$PORT --dev-mode <handle>`
every 30s (after a 2-minute startup grace) and marks the container
`unhealthy` after 3 consecutive failures — i.e. you get *automatic*
"is the relay still resolving subnames?" monitoring straight from
`docker ps` / your orchestrator.

When the variable is unset, the healthcheck still verifies that
`GET /health` answers, so a crashed or wedged relay is still surfaced.

See `NOTES.md` for additional bind-mount / `--env-file` recipes.

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
