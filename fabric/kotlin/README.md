# Fabric — Kotlin

Kotlin/JVM client for resolving handles and broadcasting updates via the Spaces certrelay network. Works on both JVM and Android.

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("org.spacesprotocol:fabric:0.1.0")

    // Pick the right libveritas variant:
    implementation("org.spacesprotocol:libveritas-jvm:0.1.0")   // JVM
    // or: implementation("org.spacesprotocol:libveritas:0.1.0") // Android (AAR)

    // For signing support (BIP-340 Schnorr via ACINQ secp256k1-kmp):
    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.17.3")
    runtimeOnly("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.17.3")   // JVM
    // or: runtimeOnly("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.17.3") // Android
}
```

### Gradle (Groovy)

```groovy
dependencies {
    implementation 'org.spacesprotocol:fabric:0.1.0'
    implementation 'org.spacesprotocol:libveritas-jvm:0.1.0'
}
```

## Querying Records

```kotlin
import org.spacesprotocol.fabric.Fabric
import org.spacesprotocol.libveritas.zoneToJson

fun main() {
    val fabric = Fabric()

    // Resolve a single handle
    val zone = fabric.resolve("alice@bitcoin")
    println(zoneToJson(zone))

    // Resolve multiple handles at once
    val zones = fabric.resolveAll(listOf("alice@bitcoin", "bob@bitcoin"))
    for (zone in zones) {
        println("${zone.handle}: ${zone.records.records.size} records")
    }

    // Export a .spacecert certificate chain
    val certBytes = fabric.export("alice@bitcoin")
}
```

## Updating Records & Broadcasting

```kotlin
import org.spacesprotocol.fabric.Fabric
import org.spacesprotocol.libveritas.*

fun main() {
    val fabric = Fabric()

    // 1. Pack records into wire format
    val recordSet = RecordSet.pack(listOf(
        Record.Txt("name", "alice"),
        Record.Txt("SIP-7", "v=0;dest=sp1qqx..."),
    ))

    // 2. Sign the record set
    val signature = org.spacesprotocol.fabric.signMessage(recordSet.toBytes(), secretKey)

    // 3. Create offchain records (record set + signature)
    val offchainRecords = createOffchainRecords(recordSet, signature)

    // 4. Build the message
    val builder = MessageBuilder()
    builder.addRecords("alice@bitcoin", offchainRecords)

    // 5. Get a chain proof from a relay
    val chainProofReq = builder.chainProofRequest()
    val chainProof = fabric.prove(chainProofReq.toByteArray())

    // 6. Finalize the message with the proof
    val msg = builder.build(chainProof)

    // 7. Broadcast to the network
    fabric.broadcast(msg.toBytes())
}
```

## Offline Verification

Access the internal `Veritas` instance for offline proof verification:

```kotlin
val fabric = Fabric()
fabric.bootstrap()

val veritas = fabric.getVeritas()
// Use veritas directly for custom verification
```

## Configuration

```kotlin
val fabric = Fabric(
    seeds = listOf("https://relay1.example.com", "https://relay2.example.com"),
    devMode = true,              // Skip finality checks (testing only)
    anchorSetHash = "abcdef.."   // Pin to specific anchor set
)
fabric.preferLatest = false      // Disable freshest-relay preference
```

## Re-exports

This package re-exports all `libveritas` types as typealiases so you can use them directly from the `org.spacesprotocol.fabric` package:

```kotlin
import org.spacesprotocol.fabric.Zone
import org.spacesprotocol.fabric.Message
import org.spacesprotocol.fabric.MessageBuilder
```
