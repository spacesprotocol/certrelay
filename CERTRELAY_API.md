# Certrelay HTTP API

Certrelay exposes a plain HTTP API for the Spaces certificate relay network.
All routes are defined in `relay/src/http.rs` and served on the listen address
configured by `CERTRELAY_BIND` / `CERTRELAY_PORT` (default `127.0.0.1:7778` on
mainnet).

There are **9 endpoints**: two write paths (`POST /message`, `POST /announce`)
and seven read paths. Every route is public, CORS-open, and per-IP
rate-limited. There is no authentication.

For client-side usage, see [`RESOLVE.md`](RESOLVE.md) (querying) and the
`Publishing to a local relay` section in [`README.md`](README.md).

## Common behavior

### CORS

All routes are wrapped in a permissive CORS layer, so browser clients can call
the API from any origin.

### Client IP and rate limiting

Each request is keyed to a client IP for rate limiting. By default the IP comes
from the TCP peer address. When `CERTRELAY_REMOTE_IP_HEADER` is set (e.g.
`x-forwarded-for`), the relay reads that header instead and uses the leftmost
IP in comma-separated lists.

### Default rate limits

| Bucket   | Endpoints                                      | Limit        |
|----------|------------------------------------------------|--------------|
| `message`  | `POST /message`                              | 10 / min / IP |
| `announce` | `POST /announce`                             | 5 / min / IP  |
| `peers`    | `GET /peers`, `GET /anchors`                 | 10 / min / IP |
| `query`    | `GET /query`, `GET /hints`, `POST /chain-proof`, `GET /reverse`, `GET /addrs` | 15 / min / IP |

Exceeded limits return `429 Too Many Requests`.

### Message size

`POST /message` bodies are capped at `DEFAULT_MAX_MESSAGE_SIZE` (512 KB).

---

## Endpoint summary

| Method | Path           | Purpose                                      | Request                         | Response                          |
|--------|----------------|----------------------------------------------|---------------------------------|-----------------------------------|
| `POST` | `/message`     | Submit a signed certificate message          | Binary borsh `Message`          | `200` + `"ok"` or error           |
| `POST` | `/announce`    | Announce a peer relay URL                    | JSON `Announcement`             | `200` + `"ok"` or error           |
| `GET`  | `/peers`       | List verified peers                          | —                               | JSON `[PeerInfo]`                 |
| `GET`  | `/query`       | Resolve handles                              | `?q=...` (+ optional `?hints=`) | Binary borsh `Message`            |
| `GET`  | `/anchors`     | Get anchor set                               | — or `?root=<hex>`              | JSON `AnchorSet` + headers        |
| `GET`  | `/hints`       | Lightweight freshness check                  | `?q=...`                        | JSON `HintsResponse`              |
| `POST` | `/chain-proof` | Build a chain proof                          | JSON `ChainProofRequest`        | Binary borsh `ChainProof`         |
| `GET`  | `/reverse`     | Numeric id → handle name                     | `?ids=...`                      | JSON `[{id, name}]`               |
| `GET`  | `/addrs`       | Address → handles                            | `?name=...&addr=...`            | JSON `{address, handles}`         |

---

## `POST /message`

Submit a signed certificate message. This is the **write path** for the relay
network.

**Request**

- Content-Type: typically `application/octet-stream`
- Body: borsh-encoded `Message` containing one or more handle updates (cert +
  signed `RecordSet`)

**Behavior**

1. Deserialize and verify the message against the relay's anchor set and
   on-chain state.
2. On success, store zones and handle records in SQLite.
3. Asynchronously gossip the raw message bytes to up to 4 random verified
   peers.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | Accepted, stored, gossip initiated |
| `400`  | Invalid borsh or verification rejected (`rejected: <reason>`) |
| `413`  | Body exceeds max message size |
| `429`  | Rate limited |

**Example**

Used by `fabric publish` and by peer relays forwarding gossip. Not practical to
construct by hand; use the Fabric client.

---

## `POST /announce`

Register a peer relay URL with this node. Other relays call this during
bootstrap and periodic re-announce.

**Request**

```json
{
  "url": "https://relay.example.com",
  "capabilities": 0
}
```

| Field          | Type   | Required | Notes |
|----------------|--------|----------|-------|
| `url`          | string | yes      | Public HTTPS URL; max 256 bytes |
| `capabilities` | u32    | yes      | Capability flags (currently unused; send `0`) |

The receiver fills in `source_ip` from the TCP connection (or proxy header); the
client does not send it.

**Behavior**

- URL is stored in the **unverified** peer table.
- A background task health-checks unverified peers (`HEAD /peers`) every 10s
  and promotes successful ones to **verified**.
- Only verified peers appear in `GET /peers` and receive gossip.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | `"ok"` |
| `400`  | Invalid JSON, empty URL, or URL too long |
| `429`  | Rate limited |

**Example**

```bash
curl -sS -X POST https://relay.example.com/announce \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://my-relay.example.com","capabilities":0}'
```

---

## `GET /peers`

Return the list of **verified, non-stale** peer relays known to this node.

**Response**

JSON array of `PeerInfo` objects:

```json
[
  {
    "source_ip": "203.0.113.42",
    "url": "https://relay-cosmos.spacesprotocol.org",
    "capabilities": 0
  }
]
```

| Field          | Type   | Description |
|----------------|--------|-------------|
| `source_ip`    | string | IP observed when the peer announced (receiver-attested) |
| `url`          | string | Reachable relay URL |
| `capabilities` | u32    | Capability flags |

Peers whose `last_seen` is older than `verified_ttl` (default 600s) are
omitted. The relay's own `--self-url` is never included.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | JSON array (may be empty) |
| `429`  | Rate limited |

**Example**

```bash
curl -s https://relay.example.com/peers | jq .
curl -sI https://relay.example.com/peers   # HEAD also works (health checks)
```

---

## `GET /query`

Resolve one or more handles and return the certificates and chain proof needed
to verify them locally.

**Query parameters**

| Param   | Required | Description |
|---------|----------|-------------|
| `q`     | yes      | Comma-separated handles (max 6). Examples: `alice@bitcoin`, `bob@bitcoin`, `@bitcoin` (root zone of a space) |
| `hints` | no       | Comma-separated epoch hints: `space:root_hex:height,...`. Lets the relay omit a ZK receipt when the client already has a verifiable epoch cached |

**Response**

- `200 OK` with body = **binary borsh-encoded `Message`**
- Header: `cache-control: public, max-age=300`

The message contains certificates and proofs for each requested handle. Decode
and verify with a Fabric client (`fabric resolve`, or library bindings).

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | Binary `Message` (may be small/empty if handles not found) |
| `400`  | Missing `q`, or more than 6 handles |
| `429`  | Rate limited |
| `500`  | Internal resolve error |

**Example**

```bash
# Confirm transport only (body is binary)
curl -sS -o /tmp/zone.msg \
     -w 'http=%{http_code} size=%{size_download}B\n' \
     'http://127.0.0.1:7778/query?q=user@rad'

# Full resolve via Fabric CLI
fabric --seeds http://127.0.0.1:7778 --dev-mode user@rad
```

---

## `GET /anchors`

Return a trust anchor set used for certificate verification.

**Query parameters**

| Param  | Required | Description |
|--------|----------|-------------|
| `root` | no       | 64-char hex trust id (32 bytes). Return the anchor set matching this root, or `404` if not stored |

Without `root`, returns the latest anchor set held by this relay.

**Response headers** (always present when a latest set exists)

| Header             | Description |
|--------------------|-------------|
| `x-anchor-root`    | Hex-encoded trust id of the latest anchor set |
| `x-anchor-height`  | Block height of the latest receipted anchor |

**Response body**

JSON `AnchorSet` with `entries` (array of root anchors). Header
`cache-control: public, max-age=300` on success.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | JSON anchor set |
| `400`  | Invalid `root` hex or wrong length |
| `404`  | Anchor set not found |
| `429`  | Rate limited |

**Example**

```bash
# Cheap comparison across relays (no body download)
curl -sI https://relay.example.com/anchors | grep -i '^x-anchor-'

# Full anchor set
curl -s https://relay.example.com/anchors | jq .

# Specific trust id
curl -s 'https://relay.example.com/anchors?root=54f37f3308acdb0b2887fef6fde0247a184e33ee14aa6fb34d5f968d81b09205'
```

Fabric clients use `HEAD /anchors` to vote on the freshest trust id across
seeds, then `GET /anchors?root=<hash>` to download the winning set.

---

## `GET /hints`

Lightweight freshness check without returning certificates or proofs.

**Query parameters**

| Param | Required | Description |
|-------|----------|-------------|
| `q`   | yes      | Comma-separated handles (max 6), same format as `/query` |

**Response**

JSON `HintsResponse`:

```json
{
  "anchor_tip": 951192,
  "hints": [
    {
      "epoch_tip": 950988,
      "name": "@swifty",
      "seq": 0,
      "delegate_seq": 0,
      "epochs": [
        {
          "epoch": 950988,
          "res": [{ "seq": 2, "name": "taylor@swifty" }]
        }
      ]
    }
  ]
}
```

| Field        | Description |
|--------------|-------------|
| `anchor_tip` | Current Bitcoin tip height (per relay's spaced) |
| `hints`      | Per-space epoch heights and per-handle seq numbers |

Header: `cache-control: public, max-age=300`.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | JSON hints |
| `400`  | Missing `q`, duplicate handles, or more than 6 handles |
| `429`  | Rate limited |

**Example**

```bash
curl -s 'https://relay.example.com/hints?q=taylor@swifty,@swifty' | jq .
```

Fabric uses `/hints` to rank relays by freshness before sending a full
`/query`.

---

## `POST /chain-proof`

Build a chain proof for a set of spaces and numeric identities. Forwards the
request to the local `spaced` node.

**Request**

JSON `ChainProofRequest`:

| Field    | Type     | Limit |
|----------|----------|-------|
| `spaces` | string[] | max 6 |
| `nums`   | string[] | max 20 |

**Response**

- `200 OK` with body = **binary borsh-encoded `ChainProof`**

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | Binary proof |
| `400`  | Invalid JSON or too many spaces/nums |
| `429`  | Rate limited |
| `500`  | Spaced failed to build proof |

**Example**

Used internally by `fabric publish` when signing a message. Typically not called
directly by operators.

---

## `GET /reverse`

Look up human-readable handle names from numeric identities (`num_id`).

**Query parameters**

| Param | Required | Description |
|-------|----------|-------------|
| `ids` | yes      | Comma-separated numeric ids (max 20) |

**Response**

JSON array:

```json
[
  { "id": "num1qx8dtlzq...", "name": "taylor@swifty" }
]
```

Reverse mappings exist only for handles that published with the
`SIG_PRIMARY_ZONE` flag (the default for `fabric publish`).

Header: `cache-control: public, max-age=300`.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | JSON array (may be partial if some ids unknown) |
| `400`  | Missing `ids` or more than 20 ids |
| `429`  | Rate limited |
| `500`  | Lookup failed |

**Example**

```bash
curl -s 'https://relay.example.com/reverse?ids=num1qx8dtlzq...' | jq .
```

---

## `GET /addrs`

Find handles that published a given address record.

**Query parameters**

| Param  | Required | Description |
|--------|----------|-------------|
| `name` | yes      | Addr-record protocol key (e.g. `btc`, `eth`, `nostr`) |
| `addr` | yes      | Address value to search for |

**Response**

```json
{
  "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  "handles": [
    { "handle": "alice@bitcoin", "rev": "alice@bitcoin" }
  ]
}
```

Header: `cache-control: public, max-age=300`.

**Responses**

| Status | Meaning |
|--------|---------|
| `200`  | JSON match (handles may be empty) |
| `400`  | Missing `name` or `addr` |
| `429`  | Rate limited |
| `500`  | Lookup failed |

**Example**

```bash
curl -s 'https://relay.example.com/addrs?name=btc&addr=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4' | jq .
```

---

## What is not exposed

| Missing endpoint | Notes |
|------------------|-------|
| `/health`        | Docker HEALTHCHECK uses `GET /peers` (+ optional `fabric resolve`); see `docker-healthcheck.sh` |
| Admin / config   | No shutdown, reload, or stats routes |
| Authentication   | All endpoints are public |
| Metrics          | No Prometheus scrape endpoint; use `RUST_LOG` and log grep |

---

## Quick smoke test

```bash
RELAY=http://127.0.0.1:7778

curl -s  "$RELAY/peers"   | head -c 200; echo
curl -s  "$RELAY/anchors" | head -c 200; echo
curl -s  "$RELAY/hints?q=@rad"
curl -sS -o /dev/null -w 'query http=%{http_code} size=%{size_download}B\n' \
         "$RELAY/query?q=user@rad"
```

For decoded handle resolution, use the Fabric client — see [`RESOLVE.md`](RESOLVE.md).
