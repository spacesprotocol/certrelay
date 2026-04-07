import org.spacesprotocol.fabric.Fabric
import org.spacesprotocol.fabric.RecordSet
import org.spacesprotocol.fabric.Record
import org.spacesprotocol.fabric.SignSchnorr
import org.spacesprotocol.fabric.CertificateChain
import org.spacesprotocol.fabric.MessageBuilder
import org.spacesprotocol.fabric.ChainProof
import org.spacesprotocol.fabric.SIG_PRIMARY_ZONE

/// Resolve a single handle
suspend fun exampleResolve() {
    // <doc:resolve>
    val fabric = Fabric()
    val resolved = fabric.resolve("alice@bitcoin")
    if (resolved == null) {
        println("handle not found")
        return
    }

    println("Handle found: ${resolved.zone.handle}")
    // </doc:resolve>
}

/// Verification
suspend fun exampleTrustAndVerification() {
    val fabric = Fabric()

    // <doc:verification>
    // Before pinning a trust id: resolve uses observed (peer) state
    // badge() returns Unverified
    val resolved = fabric.resolve("alice@bitcoin")
        ?: throw IllegalStateException("handle exists")

    fabric.badge(resolved) // Unverified

    // Pin trust from a QR scan
    val qr = "veritas://scan?id=14ef902621df01bdeee0b23fedf67458563a20df600af8979a4748dcd9d1b9f9"

    // For highest level of trust (scan QR code from Veritas desktop)
    fabric.trustFromQr(qr)

    // Does not require re-resolving, badge now checks
    // whether resolved was against a trusted root
    fabric.badge(resolved) // Orange if handle is sovereign (final certificate)

    // Or from a semi-trusted source (e.g. an explorer you trust with qr scanned over HTTPS)
    // .badge() will not show Orange for roots in this trust pool,
    // but it will not report it as "Unverified".
    fabric.semiTrustFromQr(qr)

    // Check current trust ids
    fabric.trusted()      // pinned id from local verification
    fabric.semiTrusted()  // pinned id from semi-trusted source
    fabric.observed()     // latest from peers

    // Clear trusted state
    fabric.clearTrusted()
    fabric.clearSemiTrusted()

    // </doc:verification>
}

/// Unpack records from a resolved handle
suspend fun exampleUnpackRecords() {
    val fabric = Fabric()
    val resolved = fabric.resolve("alice@bitcoin")
        ?: throw IllegalStateException("handle exists")

    // <doc:unpack-records>
    val records = resolved.zone.records.unpack()

    for (record in records) {
        when (record) {
            is Record.Txt -> println("txt ${record.key}=${record.value.joinToString(", ")}")
            is Record.Addr -> println("addr ${record.key}=${record.value.joinToString(", ")}")
            else -> {}
        }
    }
    // </doc:unpack-records>
}

/// Resolve multiple handles
suspend fun exampleResolveAll() {
    val fabric = Fabric()

    // <doc:resolve-all>
    val batch = fabric.resolveAll(listOf("alice@bitcoin", "bob@bitcoin"))

    for (zone in batch.zones) {
        println("${zone.handle}: ${zone.sovereignty}")
    }
    // </doc:resolve-all>
}

/// Pack records into a RecordSet
fun examplePackRecords() {
    // <doc:pack-records>
    val records = RecordSet.pack(listOf(
        Record.seq(1),
        Record.txt("website", listOf("https://example.com")),
        Record.addr("btc", listOf("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")),
        Record.addr("nostr", listOf(
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            "wss://relay.example.com",
        )),
    ))
    // </doc:pack-records>
}

/// Publish signed records
suspend fun examplePublish() {
    val fabric = Fabric()
    val secretKey = "0000000000000000000000000000000000000000000000000000000000000001"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val rs = RecordSet.pack(listOf(
        Record.seq(1),
        Record.txt("website", listOf("https://example.com")),
        Record.addr("btc", listOf("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")),
    ))

    // <doc:publish>
    val cert = fabric.export("alice@bitcoin")
    fabric.publish(cert, rs, secretKey, primary = true)
    // </doc:publish>
}

/// Resolve by numeric ID
suspend fun exampleResolveById() {
    val fabric = Fabric()

    // <doc:resolve-by-id>
    val resolved = fabric.resolveById("num1qx8dtlzq...")
    if (resolved == null) {
        println("handle not found")
        return
    }

    println("Handle found: ${resolved.zone.handle}")
    // </doc:resolve-by-id>
}

/// Search by address
suspend fun exampleSearchAddr() {
    val fabric = Fabric()

    // <doc:search-addr>
    val batch = fabric.searchAddr("nostr", "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")

    for (zone in batch.zones) {
        println("${zone.handle}: ${zone.sovereignty}")
    }
    // </doc:search-addr>
}

/// Advanced: Build and broadcast a message manually
suspend fun exampleMessageBuilder() {
    val fabric = Fabric()
    val secretKey = "0000000000000000000000000000000000000000000000000000000000000001"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val certBytes = fabric.export("alice@bitcoin")
    val records = RecordSet.pack(listOf(
        Record.seq(1),
        Record.addr("btc", listOf("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")),
    ))

    // <doc:message-builder>
    val cert = CertificateChain.fromSlice(certBytes)
    val builder = MessageBuilder()
    builder.addHandle(cert, records)

    val proofBytes = fabric.prove(builder.chainProofRequest())
    val proof = ChainProof.fromSlice(proofBytes)

    val (msg, unsigned) = builder.build(proof)

    for (u in unsigned) {
        u.flags = u.flags or SIG_PRIMARY_ZONE
        val sig = SignSchnorr(u.signingId(), secretKey)
        msg.setRecords(u.canonical, u.packSig(sig))
    }

    fabric.broadcast(msg.toBytes())
    // </doc:message-builder>
}

suspend fun main() {
    exampleResolve()

    try {
        exampleTrustAndVerification()
    } catch (e: Exception) {
        println("verification example failed (expected): ${e.message}")
    }

    exampleUnpackRecords()
    exampleResolveAll()
    examplePackRecords()
    examplePublish()
    exampleResolveById()
    exampleSearchAddr()
    exampleMessageBuilder()

    println("Done!")
}
