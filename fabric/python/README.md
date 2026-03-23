# Fabric — Python

Python client for resolving handles and broadcasting updates via the Spaces certrelay network.

## Installation

```bash
pip install fabric-resolver

# With signing support (BIP-340 Schnorr via coincurve):
pip install fabric-resolver[signing]
```

## Querying Records

```python
from fabric import Fabric
import libveritas

# Resolve a single handle
f = Fabric()
zone = f.resolve("alice@bitcoin")
print(libveritas.zone_to_json(zone))

# Resolve multiple handles at once
zones = f.resolve_all(["alice@bitcoin", "bob@bitcoin"])
for zone in zones:
    print(f"{zone.handle}: {len(zone.records.records)} records")

# Export a .spacecert certificate chain
cert_bytes = f.export("alice@bitcoin")
```

## Updating Records & Broadcasting

```python
from fabric import Fabric
import libveritas

f = Fabric()

# 1. Pack records into wire format
record_set = libveritas.RecordSet.pack([
    libveritas.Record.txt("name", "alice"),
    libveritas.Record.txt("SIP-7", "v=0;dest=sp1qqx..."),
])

# 2. Sign the record set (requires: pip install fabric-resolver[signing])
from fabric.signing import sign_message
signature = sign_message(record_set.to_bytes(), secret_key)

# 3. Create offchain records (record set + signature)
offchain_records = libveritas.create_offchain_records(record_set, signature)

# 4. Build the message
builder = libveritas.MessageBuilder()
builder.add_records("alice@bitcoin", offchain_records)

# 5. Get a chain proof from a relay
chain_proof_req = builder.chain_proof_request()
chain_proof = f.prove(chain_proof_req.encode())

# 6. Finalize the message with the proof
msg = builder.build(chain_proof)

# 7. Broadcast to the network
f.broadcast(msg.to_bytes())
```

## Offline Verification

Access the internal `Veritas` instance for offline proof verification:

```python
f = Fabric()
f.bootstrap()

veritas = f.veritas
# Use veritas directly for custom verification
```

## Configuration

```python
f = Fabric(
    seeds=["https://relay1.example.com", "https://relay2.example.com"],
    dev_mode=True,                   # Skip finality checks (testing only)
    anchor_set_hash="abcdef..",      # Pin to specific anchor set
    prefer_latest=False,             # Disable freshest-relay preference
)
```

## Re-exports

The `libveritas` module is available alongside `fabric`:

```python
from fabric import Fabric
import libveritas

zone: libveritas.Zone
msg = libveritas.Message(data)
builder = libveritas.MessageBuilder()
```

## CLI

```bash
# Resolve handles from the command line
python -m fabric alice@bitcoin bob@bitcoin

# With options
python -m fabric --seeds https://relay.example.com --dev-mode alice@bitcoin
```
