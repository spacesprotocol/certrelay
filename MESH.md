# Certrelay Mesh — Best Practice Notes

Operational and client-side observations about how certrelay peers replicate
data, how long certs live, and how applications should query the mesh.
Complements [`CERTRELAY_API.md`](CERTRELAY_API.md), [`RESOLVE.md`](RESOLVE.md),
and [`MINTING.md`](MINTING.md).

Upstream **v0.2.4+** replaced push gossip with **pull-based sync** (`GET /sync`)
plus **`POST /poke`** notifications. This doc reflects that model.

---

## 1. Mental model

Certrelay is an **eventually consistent, pull-replicated mesh** — not a
replicated database with a full snapshot protocol.

| Mechanism | What it moves |
|-----------|---------------|
| Bootstrap / re-announce | Peer URLs only (`POST /announce`, `GET /peers`) |
| Health checks | Promote peers to verified (`GET /health`, unmetered) |
| **Sync** | Stored handle rows via paginated `GET /sync` (borsh pages) |
| **Poke** | Content-free “pull me” signal via `POST /poke` |
| **Publish** | Client `POST /message` (verified locally; pokes peers to pull) |
| Anchors / chain tip | From spaced (or embedded node), not from peer gossip |

There is **no** push gossip fan-out anymore. Relays page each other's stored
rows, re-verify everything locally, and track per-peer watermarks so downtime
resumes as a delta pull. A fresh relay with an empty DB bootstraps through the
same sync path (watermark starts at zero).

---

## 2. Joining the mesh (new relay)

When a relay starts with `CERTRELAY_SELF_URL` and `CERTRELAY_BOOTSTRAP=false`:

1. It announces itself to bootstrap seeds and fetches their peer lists.
2. Discovered URLs start **unverified**; successful health checks make them
   **verified** (only verified peers are synced from and appear in
   `GET /peers`).
3. The sync loop periodically pulls `/sync` pages from verified peers.
4. When this relay stores new data (from `/message` or sync), it **pokes**
   verified peers so they pull soon after.
5. Every ~20 minutes it re-announces to known peers + seeds.

**What the new node receives:** historical handle rows from verified peers via
**pull sync**, not a one-shot dump. Convergence depends on peer reachability,
sync cadence, and retention/eviction policy on peers.

**Practical implications**

- A fresh relay still starts empty but **will backfill** from peers it can
  sync with (unlike the old push-gossip model).
- Backfill speed depends on `sync` tuning (`--config` / `CERTRELAY_CONFIG`),
  peer count, and whether peers poke this node when they learn about it.
- Clients can always query other relays directly while your node catches up.

**Self-URL notes**

- IP-only `http://` URLs are accepted (an IP seed is built into
  `BOOTSTRAP_RELAYS`). Hostname vs IP is not enforced by code.
- What matters is **inbound reachability**: peers must reach your announced
  URL for `/health`, `/sync`, `/poke`, and `/message`.
- `CERTRELAY_REMOTE_IP_HEADER` uses the **rightmost** XFF entry when set.
  Misconfiguration can mis-bucket rate limits.

---

## 3. What gets replicated

| Event | Propagation path |
|-------|------------------|
| `fabric publish` → `POST /message` | Stored locally; verified peers **poked** to pull |
| Peer sync round | `GET /sync?cursor=…` pages ingested + re-verified |
| Incoming poke | Schedules a pull from that peer (debounced / rate-paced) |

`/message` no longer forwards bytes to random peers. Replication is always
**pull + local verify**, same admission path as client publishes.

Monitor sync health via `GET /stats` — **last successful sync per peer** is
the key signal that replication is healthy.

---

## 4. Certificate persistence and overwrite

| Question | Answer |
|----------|--------|
| Do stored certs expire by TTL? | **No** time-based expiry on handles. |
| Storage limits? | Optional **retention** budget (`max_storage_bytes` in config); evicts under pressure. |
| Peer TTL? | Verified peers go stale after ~600s without refresh — peer membership, not cert expiry. |
| Overwrite policy? | Incoming zones replace stored ones only when `zone.is_better_than(existing)`. |
| Offchain `seq` | Publish expects strictly greater seq; relay rejects seq >6h in the future. |

`updated_at` is stored but not used for cert eviction (retention uses its
own policy).

---

## 5. Watching replication logs

Default `info` shows bootstrap and sync at a high level. For detail:

```bash
RUST_LOG=relay::http=debug,relay::app=debug,relay::sync=debug certrelay
```

Useful greps:

```bash
grep -E 'sync|poke|announce|verified peer|bootstrapped|failed to handle message'
```

For seed health from outside the process, use the `monitor` binary:

```bash
cargo run -p relay --bin monitor -- --watch-all
```

There is no Prometheus endpoint; use `GET /stats`, `RUST_LOG`, and grep.

---

## 6. Diagnosing mesh participation

Having peers in local `GET /peers` means outbound health checks work. Full
participation also requires:

| Direction | Requirement |
|-----------|-------------|
| Inbound | Peers can reach your URL (`/health`, `/sync`, `/poke`, `/message`) |
| Outbound | Sync rounds successfully pull from verified peers |
| Visibility | You appear on seed `/peers` after they verify you |

Checklist:

1. Externally: `curl -sI http://YOU/health` and `curl -s http://YOU/stats`
2. Seeds list you: `curl -s https://relay-cosmos.spacesprotocol.org/peers | jq …`
3. Stats show `last_sync` advancing for peers
4. Publish to your relay with `--seeds http://YOU`; check stats / resolve

---

## 7. Fabric CLI: `--seeds` and `--trust-id`

### `--seeds`

Omitting `--seeds` uses built-in public seeds (cosmos/atlas). Your private
relay only receives publishes/sync traffic if peers know and reach your URL.

Use `--seeds http://YOUR-RELAY` to test your node in isolation.

### `--trust-id`

Pins a specific anchor set as **Trusted** for verification/badge state.
Separate from `--dev-mode` (finality relaxation). Does not change which
relays fabric talks to.

---

## 8. Client application best practices

Relays are uneven caches; clients should:

1. Discover peers from seeds (`GET /peers`).
2. Probe several relays with `GET /hints?q=…`.
3. Prefer relays with **higher handle `seq` / space epoch**, not larger bodies.
4. `GET /query` the best candidate; **verify client-side**.
5. Fall back on verify/network failure.

**Don't** pick the largest `/query` body or merge unverified records from
many relays.

---

## 9. Quick reference

```
Join mesh   → peers + health checks
Backfill    → GET /sync pages (watermarked), not push gossip
Publish     → POST /message → poke peers → they pull
Fresh relay → sync from watermark 0 through same path
Clients     → hints (seq/epoch) → query → verify
Health      → GET /health (unmetered), GET /stats (replication)
```

Related docs:

- HTTP surface: [`CERTRELAY_API.md`](CERTRELAY_API.md) (may predate `/sync`; see upstream README for config)
- Resolve / badge: [`RESOLVE.md`](RESOLVE.md)
- Mint vs relay: [`MINTING.md`](MINTING.md)
