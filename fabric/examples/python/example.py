# <doc:install>
# pip install fabric-resolver
# </doc:install>

import asyncio

from fabric import Fabric, RecordSet, Record, sign_schnorr
from fabric import CertificateChain, MessageBuilder, ChainProof, SIG_PRIMARY_ZONE


async def example_resolve_intro():
    # <doc:resolve-intro>
    fabric = Fabric()
    resolved = await fabric.resolve("alice@bitcoin")
    # </doc:resolve-intro>


async def example_resolve():
    """Resolve a single handle"""
    # <doc:resolve>
    fabric = Fabric()
    resolved = await fabric.resolve("alice@bitcoin")
    if resolved is None:
        print("handle not found")
        return

    print(f"Handle found: {resolved.zone.handle}")
    # </doc:resolve>


async def example_trust_and_verification():
    """Verification"""
    fabric = Fabric()

    # <doc:verification>
    # Before pinning a trust id: resolve uses observed (peer) state
    # badge() returns Unverified
    resolved = await fabric.resolve("alice@bitcoin")

    fabric.badge(resolved)  # Unverified

    # Pin trust from a QR scan
    qr = "veritas://scan?id=14ef902621df01bdeee0b23fedf67458563a20df600af8979a4748dcd9d1b9f9"

    # For highest level of trust (scan QR code from Veritas desktop)
    await fabric.trust_from_qr(qr)

    # Does not require re-resolving, badge now checks
    # whether resolved was against a trusted root
    fabric.badge(resolved)  # Orange if handle is sovereign (final certificate)

    # Or from a semi-trusted source (e.g. an explorer you trust with qr scanned over HTTPS)
    # .badge() will not show Orange for roots in this trust pool,
    # but it will not report it as "Unverified".
    await fabric.semi_trust_from_qr(qr)

    # Check current trust ids
    fabric.trusted()       # pinned id from local verification
    fabric.semi_trusted()  # pinned id from semi-trusted source
    fabric.observed()      # latest from peers

    # Clear trusted state
    fabric.clear_trusted()
    fabric.clear_semi_trusted()

    # </doc:verification>


async def example_unpack_records():
    """Unpack records from a resolved handle"""
    fabric = Fabric()
    resolved = await fabric.resolve("alice@bitcoin")

    # <doc:unpack-records>
    records = resolved.zone.records.unpack()

    for record in records:
        if record.type == "txt":
            print(f"txt {record.key}={', '.join(record.value)}")
        elif record.type == "addr":
            print(f"addr {record.key}={', '.join(record.value)}")
    # </doc:unpack-records>


async def example_resolve_all():
    """Resolve multiple handles"""
    fabric = Fabric()

    # <doc:resolve-all>
    batch = await fabric.resolve_all(["alice@bitcoin", "bob@bitcoin"])

    for zone in batch.zones:
        print(f"{zone.handle}: {zone.sovereignty}")
    # </doc:resolve-all>


def example_pack_records():
    """Pack records into a RecordSet"""
    # <doc:pack-records>
    records = RecordSet.pack([
        Record.seq(1),
        Record.txt("website", ["https://example.com"]),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
        Record.addr("nostr", [
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            "wss://relay.example.com",
        ]),
    ])
    # </doc:pack-records>


async def example_publish():
    """Publish signed records"""
    fabric = Fabric()
    secret_key = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )

    rs = RecordSet.pack([
        Record.seq(1),
        Record.txt("website", ["https://example.com"]),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ])

    # <doc:publish>
    cert = await fabric.export("alice@bitcoin")
    await fabric.publish(cert, rs, secret_key, primary=True)
    # </doc:publish>


async def example_resolve_by_id():
    """Resolve by numeric ID"""
    fabric = Fabric()

    # <doc:resolve-by-id>
    resolved = await fabric.resolve_by_id("num1qx8dtlzq...")
    if resolved is None:
        print("handle not found")
        return

    print(f"Handle found: {resolved.zone.handle}")
    # </doc:resolve-by-id>


async def example_search_addr():
    """Search by address"""
    fabric = Fabric()

    # <doc:search-addr>
    batch = await fabric.search_addr("nostr", "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")

    for zone in batch.zones:
        print(f"{zone.handle}: {zone.sovereignty}")
    # </doc:search-addr>


async def example_message_builder():
    """Advanced: Build and broadcast a message manually"""
    fabric = Fabric()
    secret_key = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )

    cert_bytes = await fabric.export("alice@bitcoin")
    records = RecordSet.pack([
        Record.seq(1),
        Record.addr("btc", ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]),
    ])

    # <doc:message-builder>
    cert = CertificateChain.from_slice(cert_bytes)
    builder = MessageBuilder()
    builder.add_handle(cert, records)

    proof_bytes = await fabric.prove(builder.chain_proof_request())
    proof = ChainProof.from_slice(proof_bytes)

    msg, unsigned = builder.build(proof)

    for u in unsigned:
        u.flags |= SIG_PRIMARY_ZONE
        sig = sign_schnorr(u.signing_id(), secret_key)
        msg.set_records(u.canonical, u.pack_sig(sig))

    await fabric.broadcast(msg.to_bytes())
    # </doc:message-builder>


async def main():
    await example_resolve()

    try:
        await example_trust_and_verification()
    except Exception as e:
        print(f"verification example failed (expected): {e}")

    await example_unpack_records()
    await example_resolve_all()
    example_pack_records()
    await example_publish()
    await example_resolve_by_id()
    await example_search_addr()
    await example_message_builder()

    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
