# Resolving Handles with `fabric`

`fabric` is the client side of the certrelay protocol. It turns a handle like
`user@rad` into the owner-signed `RecordSet` published under it, plus the
cryptographic proofs (chain commitment, Merkle path) needed to verify the
result against Bitcoin's chain state.

This document covers querying only. For publishing, see the `Publishing to a
local relay` section in [`README.md`](README.md). For minting (how a handle
gets created in the first place), see [`MINTING.md`](MINTING.md).

## 1. The CLI (the quick path)

The Docker image ships a `fabric` binary used by the built-in healthcheck.
From inside the container:

```bash
docker exec -i certrelay fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

From the host, after `cargo install --git https://github.com/spacesprotocol/certrelay.git --bin fabric`:

```bash
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

Output is one JSON object per resolved handle on stdout (one line per handle).
Anything that didn't resolve goes to stderr as `<handle>: not found`.

```json
{
  "handle":      "user@rad",
  "sovereignty": "Sovereign",
  "records": {
    "seq": 2,
    "txt":  { "website": ["https://example.com"] },
    "addr": { "btc":     ["bc1q..."] }
  },
  "badge":       "unverified",
  "commitment":  { ... }
}
```

### Flags

```
Usage: fabric resolve [OPTIONS] <handle> [<handle> ...]

Options:
  --seeds <url,url,...>   Seed relay URLs (comma-separated)
  --trust-id <hex>        Trust ID for verification
  --dev-mode              Enable dev mode (skip finality checks)
  -h, --help              Show this help
```

| Flag | When you need it |
|---|---|
| `--seeds` | Always, unless you want the built-in public seeds (`relay-cosmos`, `relay-atlas`). Use `http://127.0.0.1:7778` for a local relay. |
| `--dev-mode` | **Almost always set against your local relay.** A freshly-synced node may produce zones whose anchors haven't yet accumulated enough work-depth for the strict default policy. Without `--dev-mode` you'll see verification failures even though the data is correct. |
| `--trust-id` | Set when you want the verified-badge state. Without it, every zone comes back with `"badge": "unverified"`. |
| (positional) | One or more handles. Up to 6 per request — the relay's `/query` enforces `MAX_HANDLES = 6`. |

### Backwards-compat shortcut

The dispatcher in `fabric/rust/src/main.rs` treats the no-subcommand form as
an implicit `resolve`, so these two are equivalent:

```bash
fabric resolve --seeds http://127.0.0.1:7778 --dev-mode user@rad
fabric         --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

### Multiple handles in one call

Just list them. They batch into a single `GET /query` call per relay:

```bash
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad other@rad @rad
```

`@rad` (no label) is valid and resolves the **root zone** of the space —
useful for inspecting the space's chain commitment without resolving a
specific subname.

### Filter for what you actually want

`fabric` always emits the full zone JSON; pair it with `jq` for surgical
extraction:

```bash
# Just the records the handle is publishing
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad | jq '.records'

# Just one address (e.g. btc)
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad \
  | jq -r '.records.addr.btc[0]'

# Current seq (useful before a manual republish)
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad | jq '.records.seq'

# Sovereignty state
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad | jq '.sovereignty'
```

### Multiple seeds for resilience

```bash
fabric --seeds http://127.0.0.1:7778,https://relay-cosmos.spacesprotocol.org \
       --dev-mode user@rad
```

Fabric picks among them based on freshness (it calls `/hints` first to see
who has the newest data). Useful when you don't fully trust your local
relay's view yet but want it tried first.

## 2. The library form

The CLI is a thin wrapper around `fabric.resolve()`. All bindings share the
same shape:

1. Construct `Fabric` with seeds + (optional) dev-mode.
2. `await fabric.resolve(handle)` — returns `null` / `None` / `nil` if not
   found, or a `Zone`-shaped object.
3. Inspect `.records`, `.sovereignty`, `.commitment`, etc.

### Rust

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

### JavaScript / TypeScript

A runnable copy lives at `fabric/js/examples/query-local.mjs`:

```javascript
import { Fabric } from "@spacesprotocol/fabric-web";

const RELAY  = "http://127.0.0.1:7778";
const HANDLE = "user@rad";

const fabric = new Fabric({
  seeds:   [RELAY],
  devMode: true,
});

try {
  const { zone } = await fabric.resolve(HANDLE);
  console.log(JSON.stringify(zone.toJson(), null, 2));
} catch (e) {
  console.error(`Failed to resolve ${HANDLE}:`, e.message ?? e);
  process.exit(1);
}
```

Run it directly:

```bash
cd fabric/js
node examples/query-local.mjs
```

### Python

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

### Go

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

Kotlin and Swift bindings follow the same pattern — see their READMEs under
[`fabric/`](fabric/).

## 3. What you get back

A `Zone` object (or null/None/nil if not found). The key fields:

| Field | What it tells you |
|---|---|
| `handle` | The canonical name, e.g. `user@rad` |
| `sovereignty` | `Sovereign` if the handle's certificate is final / irrevocable; `Subspace` if it's still in a mutable Merkle tree under its parent space; sometimes `Unknown` |
| `records` | The owner-signed `RecordSet` — what `fabric publish` writes. `records.seq`, `records.txt`, `records.addr`, etc. |
| `commitment` | The on-chain commitment that anchors this zone (block height, state root). Useful for proving freshness. |
| `num_id` | The numeric identity, used for `GET /reverse` lookups (only present if `SIG_PRIMARY_ZONE` was set when publishing) |
| `delegate` | Optional delegation target — present if the handle delegated its records to another zone |
| `badge` | `verified` if you pinned a `--trust-id` that matches; `unverified` otherwise |

## 4. Verifying without any client library

To bypass the libraries entirely while debugging, the HTTP API is
curl-friendly:

```bash
# Liveness — JSON
curl -s http://127.0.0.1:7778/peers   | head -c 200; echo
curl -s http://127.0.0.1:7778/anchors | head -c 200; echo

# Lightweight existence check — JSON, no proof
curl -s 'http://127.0.0.1:7778/hints?q=user@rad'

# Full resolve — binary borsh-encoded Message
curl -sS -o /tmp/zone.msg \
     -w 'http=%{http_code} size=%{size_download}B\n' \
     'http://127.0.0.1:7778/query?q=user@rad'
# expected:  http=200 size=<a few KB>     → resolved, with proof
# vs.        http=200 size=<small bytes>  → handle not present
```

`/query` returns a binary `borsh`-encoded `Message`. curl can only confirm
transport (status code + body size). To actually decode and verify the
payload you need one of the libraries — that's the point of having clients in
five languages.

## 5. Common gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `<handle>: not found` but you just published | Handle was never minted, OR the relay you're querying isn't peered with one that has the cert | Verify with `curl http://127.0.0.1:7778/hints?q=user@rad`; if empty, give peers time to gossip or query a seed directly |
| Returns but `badge: "unverified"` | Expected default — no trust ID pinned | Pass `--trust-id <hex>` if you want verified-badge state |
| "verification failed" with no `--dev-mode` | Local relay isn't yet at chain tip; anchors lack work-depth | Add `--dev-mode` against local relays |
| Stale `records.seq` after a publish | New `seq` wasn't strictly greater, or gossip hasn't propagated yet | Re-publish with explicit `--seq <higher_N>`; or wait ~30s and re-query |
| Multiple handles partially fail | Hit `MAX_HANDLES = 6` per request, or some weren't found | Split into smaller batches; check stderr for which ones failed |

## TL;DR — single-command recipe

For a local Docker relay with a minted handle:

```bash
docker exec -i certrelay fabric \
    --seeds http://127.0.0.1:7778 \
    --dev-mode \
    user@rad
```

Output is one JSON line per resolved handle. Pipe through `jq '.records'` to
see exactly what records are published, or `jq '.sovereignty'` to check
whether the cert is final. This is the same call the container's
`HEALTHCHECK` makes every 30 seconds against `CERTRELAY_HEALTHCHECK_HANDLE`,
so if `docker ps` shows `(healthy)`, this command is already working.
