package org.spacesprotocol.fabric

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.spacesprotocol.libveritas.*
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.util.concurrent.Callable
import java.util.concurrent.Executors

@Serializable
private data class EpochHint(
    val root: String,
    val height: UInt,
)

@Serializable
private data class Query(
    val space: String,
    val handles: List<String>,
    @SerialName("epoch_hint") val epochHint: EpochHint? = null,
)

@Serializable
private data class QueryRequest(
    val queries: List<Query>,
)

@Serializable
data class PeerInfo(
    @SerialName("source_ip") val sourceIp: String = "",
    val url: String,
    val capabilities: Int = 0,
)

enum class VerificationBadge { Orange, Unverified, None }

data class Resolved(val zone: Zone, val roots: List<String>)
data class ResolvedBatch(val zones: List<Zone>, val roots: List<String>)

private val json = Json { ignoreUnknownKeys = true }

private enum class TrustKind { Trusted, SemiTrusted, Observed }

@Serializable
private data class ReverseEntry(val id: String, val name: String)

@Serializable
private data class AddrMatchResponse(val address: String, val handles: List<AddrEntryResponse>)

@Serializable
private data class AddrEntryResponse(val handle: String, val rev: String)

private class AnchorPool {
    var trusted: String = ""      // raw entries JSON array string
    var semiTrusted: String = ""  // raw entries JSON array string
    var observed: String = ""     // raw entries JSON array string

    fun merged(): String {
        val parts = mutableListOf<String>()
        for (src in listOf(trusted, semiTrusted, observed)) {
            if (src.isNotEmpty()) {
                // Strip outer brackets and add contents
                val inner = src.trim().removePrefix("[").removeSuffix("]").trim()
                if (inner.isNotEmpty()) parts.add(inner)
            }
        }
        return "[${parts.joinToString(",")}]"
    }
}

data class ScanParams(val id: String)

class Fabric(
    private val seeds: List<String> = DEFAULT_SEEDS,
    var devMode: Boolean = false,
    var preferLatest: Boolean = true,
) {
    private val pool = RelayPool()
    private var veritas: Veritas? = null
    private val zoneCache = mutableMapOf<String, Zone>()
    private val lock = Any()
    private val anchorPool = AnchorPool()

    @Volatile private var trusted: TrustSet? = null
    @Volatile private var semiTrusted: TrustSet? = null
    @Volatile private var observed: TrustSet? = null

    val relays: List<String> get() = pool.urls()

    /** The internal Veritas instance for offline verification. Null until bootstrap() is called. */
    fun getVeritas(): org.spacesprotocol.libveritas.Veritas? = synchronized(lock) { veritas }

    // -- Trust --

    fun trust(trustId: String) {
        if (pool.isEmpty) bootstrapPeers()
        updateAnchors(trustId, TrustKind.Trusted)
    }

    fun trustFromQr(payload: String) {
        val params = parseScanUri(payload)
        trust(params.id)
    }

    fun semiTrustFromQr(payload: String) {
        val params = parseScanUri(payload)
        semiTrust(params.id)
    }

    fun trusted(): String? = trusted?.id?.toHexString()
    fun observed(): String? = observed?.id?.toHexString()

    fun semiTrust(trustId: String) {
        if (pool.isEmpty) bootstrapPeers()
        updateAnchors(trustId, TrustKind.SemiTrusted)
    }

    fun semiTrusted(): String? = semiTrusted?.id?.toHexString()

    fun clearTrusted() { trusted = null }

    fun badge(resolved: Resolved): VerificationBadge =
        badgeFor(resolved.zone.sovereignty, resolved.roots)

    fun badgeFor(sovereignty: String, roots: List<String>): VerificationBadge {
        val isTrusted = areRootsTrusted(roots)
        val isObserved = isTrusted || areRootsObserved(roots)
        val isSemiTrusted = isTrusted || areRootsSemiTrusted(roots)
        return when {
            isTrusted && sovereignty == "sovereign" -> VerificationBadge.Orange
            isObserved && !isTrusted && !isSemiTrusted -> VerificationBadge.Unverified
            else -> VerificationBadge.None
        }
    }

    // -- Bootstrap --

    fun bootstrap() {
        if (pool.isEmpty) bootstrapPeers()
        if (veritas == null || veritas!!.newestAnchor() == 0u) {
            updateAnchors("", TrustKind.Observed)
        }
    }

    private fun bootstrapPeers() {
        val urls = mutableSetOf<String>()
        for (seed in seeds) {
            urls.add(seed)
            try {
                for (p in fetchPeers(seed)) urls.add(p.url)
            } catch (_: Exception) {}
        }
        if (urls.isEmpty()) throw FabricError("no_peers", "no peers available")
        pool.refresh(urls.toList())
    }

    private fun updateAnchors(trustId: String = "", kind: TrustKind = if (trustId.isNotEmpty()) TrustKind.Trusted else TrustKind.Observed) {
        val hash: String
        val peers: List<String>

        if (kind == TrustKind.Trusted || kind == TrustKind.SemiTrusted) {
            hash = trustId
            peers = pool.shuffledUrls(4)
        } else {
            val result = fetchLatestTrustId()
            hash = result.first
            peers = result.second
        }

        val (anchors, entriesJson) = fetchAnchors(hash, peers)
        val v = Veritas(anchors)

        synchronized(lock) {
            when (kind) {
                TrustKind.Trusted -> anchorPool.trusted = entriesJson
                TrustKind.SemiTrusted -> anchorPool.semiTrusted = entriesJson
                TrustKind.Observed -> anchorPool.observed = entriesJson
            }

            // Rebuild veritas from merged anchors
            val mergedJson = anchorPool.merged()
            val mergedAnchors = Anchors.fromJson(mergedJson)
            veritas = Veritas(mergedAnchors)

            val ts = anchors.computeTrustSet()
            when (kind) {
                TrustKind.Trusted -> trusted = ts
                TrustKind.SemiTrusted -> semiTrusted = ts
                TrustKind.Observed -> observed = ts
            }
        }
    }

    // -- Resolution --

    fun resolve(handle: String): Resolved? {
        val batch = resolveAll(listOf(handle))
        val zone = batch.zones.find { it.handle == handle } ?: return null
        return Resolved(zone, batch.roots)
    }

    fun resolveById(numId: String): Resolved? {
        bootstrap()
        val urls = pool.shuffledUrls(4)
        var lastErr: Exception = FabricError("no_peers", "reverse resolution failed")

        for (url in urls) {
            val entries = try {
                val conn = java.net.URI("$url/reverse?ids=$numId").toURL().openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                if (conn.responseCode >= 300) {
                    pool.markFailed(url)
                    continue
                }
                val body = java.io.InputStreamReader(conn.inputStream).readText()
                conn.disconnect()
                json.decodeFromString<List<ReverseEntry>>(body)
            } catch (e: Exception) {
                pool.markFailed(url)
                lastErr = FabricError("http", e.message ?: e.toString())
                continue
            }

            val entry = entries.find { it.id == numId } ?: continue

            val resolved = resolve(entry.name) ?: continue

            if (resolved.zone.numId != numId) {
                lastErr = FabricError("verify", "reverse mismatch: expected $numId, got ${resolved.zone.numId}")
                continue
            }

            return resolved
        }

        return null
    }

    fun searchAddr(name: String, addr: String): ResolvedBatch {
        bootstrap()
        val urls = pool.shuffledUrls(4)
        var lastErr: Exception = FabricError("no_peers", "address search failed")

        for (url in urls) {
            val result = try {
                val conn = java.net.URI("$url/addrs?name=$name&addr=$addr").toURL().openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                if (conn.responseCode >= 300) { pool.markFailed(url); continue }
                val body = java.io.InputStreamReader(conn.inputStream).readText()
                conn.disconnect()
                json.decodeFromString<AddrMatchResponse>(body)
            } catch (e: Exception) {
                pool.markFailed(url)
                lastErr = FabricError("http", e.message ?: e.toString())
                continue
            }

            if (result.handles.isEmpty()) continue

            val revNames = result.handles.map { it.rev }
            val batch = try {
                resolveAll(revNames)
            } catch (e: Exception) {
                lastErr = e
                continue
            }

            // Filter to zones that actually contain the matching addr record
            val matching = batch.zones.filter { z ->
                z.records?.let { bytes ->
                    try {
                        val rs = RecordSet(bytes)
                        rs.unpack().any { r ->
                            r is ParsedRecord.Addr && r.key == name && r.value.isNotEmpty() && r.value[0] == addr
                        }
                    } catch (_: Exception) { false }
                } ?: false
            }
            if (matching.isEmpty()) continue
            return ResolvedBatch(matching, batch.roots)
        }

        throw lastErr
    }

    fun resolveAll(handles: List<String>): ResolvedBatch {
        val lookup = Lookup(handles)
        val allZones = mutableListOf<Zone>()
        val roots = mutableListOf<String>()

        var prevBatch = emptyList<String>()
        var batch = lookup.start()
        while (batch.isNotEmpty()) {
            if (batch == prevBatch) break
            val verified = resolveFlat(batch)
            val zones = verified.zones()
            prevBatch = batch
            batch = lookup.advance(zones)
            allZones.addAll(zones)
            roots.add(verified.rootId().toHexString())
        }

        return ResolvedBatch(lookup.expandZones(allZones), roots)
    }

    fun export(handle: String): ByteArray {
        val lookup = Lookup(listOf(handle))
        val allCertBytes = mutableListOf<ByteArray>()

        var prevBatch = emptyList<String>()
        var batch = lookup.start()
        while (batch.isNotEmpty()) {
            if (batch == prevBatch) break
            val verified = resolveFlat(batch)
            allCertBytes.addAll(verified.certificates())
            val zones = verified.zones()
            prevBatch = batch
            batch = lookup.advance(zones)
        }

        return createCertificateChain(handle, allCertBytes)
    }

    private fun resolveFlat(handles: List<String>): VerifiedMessage {
        val bySpace = mutableMapOf<String, MutableList<String>>()
        for (h in handles) {
            val (space, label) = parseHandle(h)
            bySpace.getOrPut(space) { mutableListOf() }.add(label)
        }

        val queries = mutableListOf<Query>()
        for ((space, labels) in bySpace) {
            var epochHint: EpochHint? = null
            synchronized(lock) {
                zoneCache[space]?.let { cached ->
                    epochHintFromZone(cached)?.let { epochHint = it }
                }
            }
            queries.add(Query(space = space, handles = labels, epochHint = epochHint))
        }

        return query(QueryRequest(queries = queries))
    }

    private fun query(request: QueryRequest): VerifiedMessage {
        bootstrap()

        val ctx = QueryContext()
        synchronized(lock) {
            for (q in request.queries) {
                zoneCache[q.space]?.let { cached ->
                    try { ctx.addZone(zoneToBytes(cached)) } catch (_: Exception) {}
                }
            }
        }

        val relays = if (preferLatest) {
            pickRelays(request, 4)
        } else {
            pool.shuffledUrls(4)
        }

        val verified = sendQuery(ctx, request, relays)
        val zones = verified.zones()

        synchronized(lock) {
            for (z in zones) {
                if (z.handle.startsWith("@") || z.handle.startsWith("#")) {
                    zoneCache[z.handle] = z
                }
            }
        }

        return verified
    }

    private fun sendQuery(ctx: QueryContext, request: QueryRequest, relays: List<String>): VerifiedMessage {
        val qParts = mutableListOf<String>()
        val hintParts = mutableListOf<String>()
        for (q in request.queries) {
            ctx.addRequest(q.space)
            qParts.add(q.space)
            for (h in q.handles) {
                if (h.isNotEmpty()) {
                    ctx.addRequest(h + q.space)
                    qParts.add(h + q.space)
                }
            }
            if (q.epochHint != null) {
                hintParts.add("${q.space}:${q.epochHint.root}:${q.epochHint.height}")
            }
        }

        var lastErr: Exception = FabricError("no_peers", "no peers available")

        for (url in relays) {
            val respBytes = try {
                val qParam = URLEncoder.encode(qParts.joinToString(","), "UTF-8")
                var queryUrl = "$url/query?q=$qParam"
                if (hintParts.isNotEmpty()) {
                    val hintsParam = URLEncoder.encode(hintParts.joinToString(","), "UTF-8")
                    queryUrl += "&hints=$hintsParam"
                }
                val conn = URI(queryUrl).toURL().openConnection() as HttpURLConnection
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                if (conn.responseCode >= 300) {
                    val errorBody = conn.errorStream?.readBytes() ?: byteArrayOf()
                    conn.disconnect()
                    throw FabricError("relay", String(errorBody), conn.responseCode)
                }
                val data = conn.inputStream.readBytes()
                conn.disconnect()
                data
            } catch (e: Exception) {
                pool.markFailed(url)
                lastErr = e
                continue
            }

            val msg = try {
                Message(respBytes)
            } catch (e: Exception) {
                pool.markFailed(url)
                lastErr = FabricError("decode", "$url/query: $e")
                continue
            }

            val v = synchronized(lock) { veritas }
                ?: throw FabricError("no_peers", "no veritas instance")

            val verified = try {
                val options: UInt = if (devMode) org.spacesprotocol.libveritas.verifyDevMode() else 0u
                v.verifyWithOptions(ctx, msg, options)
            } catch (e: Exception) {
                pool.markFailed(url)
                lastErr = FabricError("verify", e.message ?: e.toString())
                continue
            }

            pool.markAlive(url)
            return verified
        }

        throw lastErr
    }

    private fun pickRelays(request: QueryRequest, count: Int): List<String> {
        val hintsQuery = hintsQueryString(request)
        val shuffled = pool.shuffledUrls(0)

        data class Ranked(val url: String, val hints: HintsResponse)
        val results = mutableListOf<Ranked>()

        var i = 0
        while (i < shuffled.size && results.size < count) {
            val batch = shuffled.subList(i, minOf(i + count, shuffled.size))
            i += count

            val executor = Executors.newFixedThreadPool(batch.size)
            val futures = batch.map { url ->
                executor.submit(Callable {
                    try {
                        Ranked(url, fetchHints(url, hintsQuery))
                    } catch (_: Exception) {
                        pool.markFailed(url)
                        null
                    }
                })
            }
            for (f in futures) {
                f.get()?.let { results.add(it) }
            }
            executor.shutdown()
        }

        results.sortWith(Comparator { a, b -> compareHints(b.hints, a.hints) })
        return results.map { it.url }
    }

    // -- Prove & Broadcast & Publish --

    /** Requests a chain proof from a relay. */
    fun prove(request: ByteArray): ByteArray {
        bootstrap()
        val urls = pool.shuffledUrls(4)
        var lastErr: Exception = FabricError("no_peers", "no peers available")

        for (url in urls) {
            val resp = try {
                postJson("$url/chain-proof", request)
            } catch (e: Exception) {
                pool.markFailed(url)
                lastErr = e
                continue
            }
            pool.markAlive(url)
            return resp
        }

        throw lastErr
    }

    /** Sends a message to up to 4 random relays for gossip propagation. Succeeds if at least one relay accepts. */
    fun broadcast(msgBytes: ByteArray) {
        bootstrap()
        val urls = pool.shuffledUrls(4)
        if (urls.isEmpty()) throw FabricError("no_peers", "no peers available")

        var anyOk = false
        var lastErr: Exception? = null
        for (url in urls) {
            try {
                postBinary("$url/message", msgBytes)
                anyOk = true
            } catch (e: Exception) {
                lastErr = e
            }
        }
        if (!anyOk) throw (lastErr ?: FabricError("no_peers", "no peers available"))
    }

    /**
     * Builds and signs a message from a certificate chain and unsigned records.
     * Returns the serialized message bytes ready for broadcast.
     *
     * @param cert .spacecert bytes from export()
     * @param records unsigned records bytes
     * @param secretKey 32-byte secret key for signing
     * @param rev whether this is a revocation
     */
    fun sign(cert: ByteArray, records: ByteArray, secretKey: ByteArray, primary: Boolean = true): ByteArray {
        bootstrap()
        val builder = MessageBuilder()
        builder.addHandle(cert, records)
        val proofReqJson = builder.chainProofRequest()
        val proofBytes = prove(proofReqJson.toByteArray())
        val result = builder.build(proofBytes)

        for (u in result.unsigned) {
            if (primary) {
                u.setFlags((u.flags().toInt() or 0x01).toUByte())
            }
            val auxRand = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            val sig = fr.acinq.secp256k1.Secp256k1.signSchnorr(u.signingId(), secretKey, auxRand)
            val signed = u.packSig(sig)
            result.message.setRecords(u.canonical(), signed)
        }

        return result.message.toBytes()
    }

    fun publish(cert: ByteArray, records: ByteArray, secretKey: ByteArray, primary: Boolean = true) {
        val msg = sign(cert, records, secretKey, primary)
        broadcast(msg)
    }

    // -- Peers --

    fun peers(): List<PeerInfo> {
        val urls = pool.shuffledUrls(1)
        if (urls.isEmpty()) throw FabricError("no_peers", "no peers available")
        return fetchPeers(urls[0])
    }

    fun refreshPeers() {
        val current = pool.urls()
        val newUrls = mutableListOf<String>()
        for (url in current) {
            try {
                for (p in fetchPeers(url)) newUrls.add(p.url)
            } catch (_: Exception) {}
        }
        pool.refresh(newUrls)
        if (pool.isEmpty) throw FabricError("no_peers", "no peers available")
    }

    // -- Internal fetch helpers --

    private fun fetchLatestTrustId(): Pair<String, List<String>> {
        data class Vote(val height: Int, val peers: MutableList<String>)
        val votes = mutableMapOf<String, Vote>()

        for (seed in seeds) {
            try {
                val conn = URI("$seed/anchors").toURL().openConnection() as HttpURLConnection
                conn.requestMethod = "HEAD"
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                conn.connect()

                val root = conn.getHeaderField("X-Anchor-Root") ?: continue
                val height = conn.getHeaderField("X-Anchor-Height")?.toIntOrNull() ?: 0
                conn.disconnect()

                if (root.isNotEmpty()) {
                    val key = "$root:$height"
                    votes.getOrPut(key) { Vote(height, mutableListOf()) }.peers.add(seed)
                }
            } catch (_: Exception) {}
        }

        var bestKey = ""
        var bestScore = -1
        for ((key, vote) in votes) {
            val score = vote.peers.size * 1_000_000 + vote.height
            if (score > bestScore) {
                bestScore = score
                bestKey = key
            }
        }

        if (bestKey.isEmpty()) throw FabricError("no_peers", "no peers available")

        val parts = bestKey.split(":", limit = 2)
        return Pair(parts[0], votes[bestKey]!!.peers)
    }

    private fun fetchAnchors(hash: String, peers: List<String>): Pair<Anchors, String> {
        var lastErr: Exception = FabricError("no_peers", "no peers available")

        for (url in peers) {
            try {
                val conn = URI("$url/anchors?root=$hash").toURL().openConnection() as HttpURLConnection
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000

                if (conn.responseCode >= 300) {
                    val body = conn.errorStream?.let { InputStreamReader(it).readText() } ?: ""
                    conn.disconnect()
                    lastErr = FabricError("relay", body, conn.responseCode)
                    continue
                }

                val body = InputStreamReader(conn.inputStream).readText()
                conn.disconnect()

                val obj = json.parseToJsonElement(body).jsonObject
                val entriesJson = obj["entries"]?.toString()
                if (entriesJson == null) {
                    lastErr = FabricError("decode", "missing entries in anchor response")
                    continue
                }

                val anchors = Anchors.fromJson(entriesJson)
                val ts = anchors.computeTrustSet()

                if (ts.id.toHexString() != hash) {
                    lastErr = FabricError("decode", "anchor root mismatch")
                    continue
                }

                return Pair(anchors, entriesJson)
            } catch (e: FabricError) {
                throw e
            } catch (e: Exception) {
                lastErr = FabricError("http", e.message ?: e.toString())
            }
        }

        throw lastErr
    }

    // -- Private trust helpers --

    private fun areRootsTrusted(roots: List<String>): Boolean {
        val ts = trusted ?: return false
        return roots.all { root ->
            val rootBytes = root.hexToByteArray()
            ts.roots.any { it.contentEquals(rootBytes) }
        }
    }

    private fun areRootsObserved(roots: List<String>): Boolean {
        val ts = observed ?: return false
        return roots.all { root ->
            val rootBytes = root.hexToByteArray()
            ts.roots.any { it.contentEquals(rootBytes) }
        }
    }

    private fun areRootsSemiTrusted(roots: List<String>): Boolean {
        val ts = semiTrusted ?: return false
        return roots.all { root ->
            val rootBytes = root.hexToByteArray()
            ts.roots.any { it.contentEquals(rootBytes) }
        }
    }
}

fun parseScanUri(uri: String): ScanParams {
    val trimmed = uri.trim()
    val prefix = "veritas://scan?"
    if (!trimmed.startsWith(prefix)) {
        throw FabricError("decode", "expected veritas://scan?... URI")
    }
    val query = trimmed.removePrefix(prefix)
    val params = query.split("&").associate {
        val (k, v) = it.split("=", limit = 2)
        k to v
    }
    val id = params["id"] ?: throw FabricError("decode", "missing id parameter")
    return ScanParams(id)
}

// -- Utility functions --

private fun fetchPeers(relayUrl: String): List<PeerInfo> {
    val conn = URI("$relayUrl/peers").toURL().openConnection() as HttpURLConnection
    conn.connectTimeout = 10_000
    conn.readTimeout = 10_000

    if (conn.responseCode >= 300) {
        val body = conn.errorStream?.let { InputStreamReader(it).readText() } ?: ""
        conn.disconnect()
        throw FabricError("relay", body, conn.responseCode)
    }

    val body = InputStreamReader(conn.inputStream).readText()
    conn.disconnect()
    return json.decodeFromString<List<PeerInfo>>(body)
}

private fun fetchHints(relayUrl: String, query: String): HintsResponse {
    val encoded = URLEncoder.encode(query, "UTF-8")
    val conn = URI("$relayUrl/hints?q=$encoded").toURL().openConnection() as HttpURLConnection
    conn.connectTimeout = 10_000
    conn.readTimeout = 10_000

    if (conn.responseCode >= 300) {
        conn.disconnect()
        throw FabricError("relay", "hints: status ${conn.responseCode}")
    }

    val body = InputStreamReader(conn.inputStream).readText()
    conn.disconnect()
    return json.decodeFromString<HintsResponse>(body)
}

private fun postJson(url: String, body: ByteArray): ByteArray {
    val conn = URI(url).toURL().openConnection() as HttpURLConnection
    conn.requestMethod = "POST"
    conn.doOutput = true
    conn.setRequestProperty("Content-Type", "application/json")
    conn.connectTimeout = 10_000
    conn.readTimeout = 10_000
    conn.outputStream.use { it.write(body) }

    val data = if (conn.responseCode < 300) {
        conn.inputStream.readBytes()
    } else {
        val errorBody = conn.errorStream?.readBytes() ?: byteArrayOf()
        conn.disconnect()
        throw FabricError("relay", String(errorBody), conn.responseCode)
    }
    conn.disconnect()
    return data
}

private fun postBinary(url: String, body: ByteArray): ByteArray {
    val conn = URI(url).toURL().openConnection() as HttpURLConnection
    conn.requestMethod = "POST"
    conn.doOutput = true
    conn.setRequestProperty("Content-Type", "application/octet-stream")
    conn.connectTimeout = 10_000
    conn.readTimeout = 10_000
    conn.outputStream.use { it.write(body) }

    val data = if (conn.responseCode < 300) {
        conn.inputStream.readBytes()
    } else {
        val errorBody = conn.errorStream?.readBytes() ?: byteArrayOf()
        conn.disconnect()
        throw FabricError("relay", String(errorBody), conn.responseCode)
    }
    conn.disconnect()
    return data
}

private fun parseHandle(handle: String): Pair<String, String> {
    val sep = handle.indexOfFirst { it == '@' || it == '#' }
    if (sep < 0) return Pair(handle, "")
    if (sep == 0) return Pair(handle, "")
    return Pair(handle.substring(sep), handle.substring(0, sep))
}

private fun hintsQueryString(request: QueryRequest): String {
    val parts = mutableSetOf<String>()
    for (q in request.queries) {
        parts.add(q.space)
        for (h in q.handles) {
            parts.add(h + q.space)
        }
    }
    return parts.joinToString(",")
}

private fun epochHintFromZone(zone: Zone): EpochHint? {
    val commitment = zone.commitment
    if (commitment is CommitmentState.Exists) {
        return EpochHint(
            root = commitment.stateRoot.joinToString("") { "%02x".format(it) },
            height = commitment.blockHeight,
        )
    }
    return null
}

private fun hexDecode(hex: String): ByteArray {
    return ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

private fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0)
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
