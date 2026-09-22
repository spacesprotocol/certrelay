# How a Handle Gets Minted

Minting (creating a new subname like `user@rad`) happens **outside `certrelay`**
entirely. `certrelay` only stores and serves the artifacts of a mint that has
already occurred upstream in the Spaces tooling
([`spacesprotocol/spaces`](https://github.com/spacesprotocol/spaces) — the
`space-cli` + `subs` binaries). This is why the README keeps saying *"the
handle must already exist on a reachable relay before you can publish records
under it."*

This document traces where each piece in a `.spacecert` file (e.g.
`data/certs/user@rad.cert.json`) comes from.

## The two-party model

Minting `user@rad` involves two distinct actors with distinct keys:

| Party | Owns | What they do |
|---|---|---|
| **Parent-space operator** for `@rad` | The on-chain `@rad` space (a Bitcoin UTXO) | Issues batches of subnames by signing a Merkle root and anchoring it to Bitcoin |
| **End user** wanting `user@rad` | A fresh BIP-340 keypair they generate themselves | Submits a request to the operator, then later uses the secret to sign records via `fabric publish` |

The protocol's "trustless" property comes from the fact that the operator can
never forge a handle to a key the end user didn't generate — the user's pubkey
is part of what gets hashed into the Merkle leaf, and the user keeps the
secret.

## The minting flow, step by step

This is the `space-cli` / `subs` pipeline documented in
[`SUBSPACES.md`](https://github.com/spacesprotocol/spaces/blob/main/SUBSPACES.md)
in the upstream `spaces` repo. `certrelay` participates only in the very last
step.

### 1. Operator brings `@rad` online

The operator first registers and "operates" the parent space on Bitcoin:

```bash
space-cli operate @rad
```

This sets up `@rad`'s on-chain state so the operator can anchor subspace tree
roots into it. Done once, lives on Bitcoin forever.

### 2. End user generates a keypair and a request

The end user runs `subs` locally:

```bash
subs request user@rad
```

This produces a `user@rad.req.json` containing the user's freshly-generated
x-only public key plus the desired handle. **The user's 32-byte secret never
leaves their machine.** That secret is exactly the same hex blob you'll
eventually feed to `fabric publish --secret-key-file`.

### 3. Operator accepts the request

The operator collects requests (typically many at once — that's the "batch
issuance" advantage Spaces emphasizes) and folds them into their subspace
tree:

```bash
subs add user@rad.req.json
subs add bob@rad.req.json
subs add carol@rad.req.json
...
```

Each `add` inserts a leaf in the operator's local Merkle tree. The leaf hashes
`(handle_label, user_pubkey, ...)` together. Millions of subnames collapse
into a single 32-byte root.

### 4. Operator commits the tree root on Bitcoin

Periodically the operator pushes the new tree root to chain. Mechanically this
is a Bitcoin transaction signed by the `@rad` space UTXO that publishes the
new 32-byte root as the "current state" of the `@rad` subspace tree. After
confirmation, that root is anchored to a specific Bitcoin block height — this
is the "anchor" that `certrelay` (via `spaced`) refreshes every
`CERTRELAY_ANCHOR_REFRESH` seconds and exposes on `GET /anchors`.

After this confirms, `user@rad` is officially minted: a Merkle inclusion proof
exists that links `(user, user_pubkey)` to a root that's permanently anchored
to Bitcoin proof-of-work.

### 5. Operator hands the end user a `.spacecert`

The operator exports the two-piece certificate proving that minting happened
and gives it to the user. The file is a small JSON envelope with two base64
fields:

```json
{
  "root_cert":   "AANyYWQA…",
  "handle_cert": "AAVvdGhlcgNyYWQA…"
}
```

That's literally the format of `data/certs/user@rad.cert.json` and
`data/certs/other@rad.cert.json` in this repo. Decoded:

| Field | What it contains |
|---|---|
| `root_cert` | Proof that `@rad` exists as a registered space (root-level certificate, label = `rad`) |
| `handle_cert` | Proof that `user@rad` is bound to a specific x-only pubkey, plus a Merkle path from that leaf up to the tree root that was anchored in step 4 |

You can see this is exactly what `fabric.export()` reconstructs by walking the
resolution upward from leaf to root:

```rust
// fabric/rust/src/client.rs
pub async fn export(&self, handle: &str) -> Result<Vec<u8>> {
    let sname = SName::try_from(handle)?;
    let lookup = libveritas::names::Lookup::new(vec![sname.clone()]);
    let mut all_verified: Vec<VerifiedMessage> = Vec::new();

    let mut prev_batch: Vec<SName> = Vec::new();
    let mut batch: Vec<SName> = lookup.start();
    while !batch.is_empty() {
        if batch == prev_batch { break; }
        let strs: Vec<String> = batch.iter().map(|s| s.to_string()).collect();
        let refs:  Vec<&str>  = strs.iter().map(|s| s.as_str()).collect();
        let (verified, _) = self.resolve_flat(&refs, false).await?;
        prev_batch = batch;
        batch = lookup.advance(&verified.zones);
        all_verified.push(verified);
    }

    let mut certs = Vec::new();
    for msg in &all_verified {
        certs.extend(msg.certificates());
    }
    let chain = CertificateChain::new(sname, certs);
    Ok(chain.to_bytes())
}
```

So the cert file is just a portable snapshot of "the certificates a relay
would hand you if you resolved `user@rad` right now."

### 6. End user publishes records via `certrelay`

Now — and only now — `certrelay` enters the picture. The user uses their
stashed secret + the `.spacecert` to sign a `RecordSet` and POST it to a
relay's `/message`, exactly as documented for `fabric publish`. The relay
verifies that:

- the handle cert chains back to the root cert,
- the root cert chains back to a Bitcoin-anchored state root the relay knows
  about (via its `/anchors` set, refreshed from `spaced`),
- the new records' Schnorr signature validates against the pubkey embedded in
  the handle cert,
- the `seq` is strictly greater than what's currently stored.

If all four pass, the relay stores and gossips. If any fail, `/message`
returns 4xx and nothing propagates. See the `Handler::handle_message` /
`gossip_message` path in `relay/src/handler.rs` and `relay/src/http.rs`.

## Optional step 7 — bind the handle to a Bitcoin UTXO (`space pointer`)

For handles that need on-chain interactivity (e.g. being sold, transferred via
Bitcoin transactions, or used as an L1 identity), the user can additionally
mint a **space pointer (sptr)** linking their off-chain handle to an on-chain
UTXO with the same script pubkey, as shown in [`SUBSPACES.md`](https://github.com/spacesprotocol/spaces/blob/main/SUBSPACES.md):

```bash
space-cli createptr 5120d3c3196cb3ed7fa79c882ed62f8e5942e546130d5ae5983da67dbb6c9bdd2e79
# → sptr13thcluavwywaktvv466wr6hykf7x5avg49hgdh7w8hh8chsqvwcskmtxpd
```

This is *purely optional*. Plain off-chain handles (the common case) skip it
and live entirely as Merkle leaves under the operator's tree root, with no
per-handle on-chain footprint. Every `user@rad`-style mint by default takes
**zero extra block space** beyond the operator's periodic batched root
commitment — that's the scalability story.

## Why `certrelay` doesn't mint

Minting requires:

- Signing transactions with the `@rad` space's UTXO key (operator-only).
- Submitting those transactions to Bitcoin and waiting for confirmations.
- Maintaining the local subspace Merkle tree across batches.

None of that is in `certrelay`'s scope. `certrelay` is intentionally a
**post-mint relay**: its only chain interaction is *reading* anchor roots from
`spaced` (via `CERTRELAY_SPACED_RPC_URL`) so it can verify that the certs
people publish chain back to real Bitcoin-anchored roots. The relay does
space-level rate limits (100 handle updates/min per space — see
`relay/src/handler.rs`) but never *creates* a handle, only validates incoming
messages against existing chain anchors.

This separation is also why the cert files in `data/certs/` had to be given
to you (or pulled out of an operator's tooling) ahead of time — neither
`certrelay` nor `fabric` can produce them. They are the operator's signed
attestation of the mint, exported once and reused for every subsequent
`fabric publish`.

## End-to-end: who runs what

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PARENT SPACE OPERATOR (owns @rad UTXO)                                 │
│                                                                         │
│   space-cli operate @rad           ← one-time, on Bitcoin               │
│   subs add user@rad.req.json       ← inserts user into Merkle tree      │
│   space-cli commit ...             ← anchors tree root to Bitcoin       │
│   exports user@rad.cert.json       ← gives the .spacecert to user       │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ (out-of-band: email, QR, etc.)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  END USER                                                               │
│                                                                         │
│   subs request user@rad            ← generated keypair earlier          │
│   ./user-rad-secret.hex            ← the 32-byte secret                 │
│   ./user@rad.cert.json             ← received from operator             │
│                                                                         │
│   fabric publish --secret-key-file ./user-rad-secret.hex \              │
│                  --txt website=https://example.com \                    │
│                  --seeds http://127.0.0.1:7778 user@rad                 │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │  POST /message  (binary)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  CERTRELAY (this repo)                                                  │
│                                                                         │
│   - Verifies handle_cert → root_cert → anchored Bitcoin state root      │
│   - Verifies Schnorr sig on records against handle's pubkey             │
│   - Stores in SQLite                                                    │
│   - Gossips to up to 4 random verified peers                            │
└─────────────────────────────────────────────────────────────────────────┘
```

## TL;DR

- **Minting = the parent-space operator (`@rad`) adding your `user@rad`
  request to their off-chain Merkle tree and committing the new root on
  Bitcoin via `space-cli` / `subs`.** Done outside this repo, in the
  [`spacesprotocol/spaces`](https://github.com/spacesprotocol/spaces) tooling.
- The operator hands you a `.spacecert` file (`root_cert` + `handle_cert`).
  The files in `data/certs/` are exactly that artifact, base64-wrapped.
- You generated the 32-byte secret yourself before submitting the request;
  the operator never sees or signs anything with it.
- `certrelay` enters only after minting: it verifies the cert chain back to
  the on-chain anchor, then serves and gossips whatever records you sign with
  your secret via `fabric publish`.
- Optional `space-cli createptr` gives the handle an on-chain UTXO if you
  need transferability; most off-chain handles skip it.

For the canonical step-by-step commands and the exact wire format of the
request and the tree commitment, the upstream reference is
[`SUBSPACES.md`](https://github.com/spacesprotocol/spaces/blob/main/SUBSPACES.md)
in the `spaces` repo — that's the source of truth for the minting half, just
as this repo is the source of truth for the relay half.
