import Foundation
@_exported import Libveritas

// MARK: - Wire format types (internal)

struct EpochHint: Encodable {
    let root: String
    let height: UInt32
}

struct Query: Encodable {
    let space: String
    let handles: [String]
    var epoch_hint: EpochHint?
}

struct QueryRequest: Encodable {
    let queries: [Query]
}

public struct PeerInfo: Decodable {
    public let source_ip: String
    public let url: String
    public let capabilities: Int
}

// MARK: - Error

public enum FabricError: Error, LocalizedError {
    case http(String)
    case decode(String)
    case verify(String)
    case relay(status: Int, body: String)
    case noPeers

    public var errorDescription: String? {
        switch self {
        case .http(let msg): return "http error: \(msg)"
        case .decode(let msg): return "decode error: \(msg)"
        case .verify(let msg): return "verification error: \(msg)"
        case .relay(let status, let body): return "relay error (\(status)): \(body)"
        case .noPeers: return "no peers available"
        }
    }
}

// MARK: - Verification badge

/// Verification badge for a resolved handle.
public enum VerificationBadge {
    case orange
    case unverified
    case none
}

// MARK: - Resolved types

/// A resolved handle with its zone and verification roots.
public struct Resolved {
    public let zone: Zone
    public let roots: [String]  // hex-encoded root IDs
}

/// A batch of resolved handles with shared verification roots.
public struct ResolvedBatch {
    public let zones: [Zone]
    public let roots: [String]  // hex-encoded root IDs

    /// Look up a specific handle from the batch.
    public func get(_ handle: String) -> Resolved? {
        guard let zone = zones.first(where: { $0.handle == handle }) else { return nil }
        return Resolved(zone: zone, roots: roots)
    }
}

// MARK: - Trust kind

private enum TrustKind {
    case trusted(String)
    case semiTrusted(String)
    case observed
}

// MARK: - Anchor pool

private struct ReverseEntry: Decodable {
    let id: String
    let name: String
}

private struct AddrMatchResponse: Decodable {
    let address: String
    let handles: [AddrEntryResponse]
}

private struct AddrEntryResponse: Decodable {
    let handle: String
    let rev: String
}

private struct AnchorPool {
    var trusted: String = ""      // raw entries JSON array string
    var semiTrusted: String = ""  // raw entries JSON array string
    var observed: String = ""     // raw entries JSON array string

    func merged() -> String? {
        var parts = [String]()
        for src in [trusted, semiTrusted, observed] {
            if src.isEmpty { continue }
            let inner = src.trimmingCharacters(in: .whitespaces)
                .dropFirst() // remove [
                .dropLast()  // remove ]
                .trimmingCharacters(in: .whitespaces)
            if !inner.isEmpty {
                parts.append(String(inner))
            }
        }
        if parts.isEmpty { return nil }
        return "[\(parts.joined(separator: ","))]"
    }
}

// MARK: - Scan params

/// Parsed parameters from a veritas://scan?... URI.
public struct ScanParams {
    public let id: String  // hex-encoded trust ID

    public static func parse(_ uri: String) throws -> ScanParams {
        let trimmed = uri.trimmingCharacters(in: .whitespaces)
        let prefix = "veritas://scan?"
        guard trimmed.hasPrefix(prefix) else {
            throw FabricError.decode("expected veritas://scan?... URI")
        }
        let query = String(trimmed.dropFirst(prefix.count))
        var id: String?
        for pair in query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            if parts.count == 2 && parts[0] == "id" {
                id = String(parts[1])
            }
        }
        guard let id else {
            throw FabricError.decode("missing id parameter")
        }
        return ScanParams(id: id)
    }
}

// MARK: - Fabric client

public final class Fabric: @unchecked Sendable {
    private let session: URLSession
    private let pool = RelayPool()
    private var _veritas: Veritas?
    private var zoneCache: [String: Zone] = [:]
    private let seeds: [String]
    private var trusted: TrustSet?
    private var semiTrusted: TrustSet?
    private var observed: TrustSet?
    private var anchorPool = AnchorPool()
    public var preferLatest: Bool
    private let devMode: Bool
    private let lock = NSLock()

    public var relays: [String] { pool.urls }

    /// The internal Veritas instance for offline verification.
    /// Returns nil if `bootstrap()` has not been called yet.
    public var veritas: Veritas? {
        lock.lock()
        defer { lock.unlock() }
        return _veritas
    }

    /// The pinned trusted trust ID, or nil.
    public var trustedID: String? {
        lock.lock()
        defer { lock.unlock() }
        return trusted.map { Data($0.id).hexString }
    }

    /// The semi-trusted trust ID, or nil.
    public var semiTrustedID: String? {
        lock.lock()
        defer { lock.unlock() }
        return semiTrusted.map { Data($0.id).hexString }
    }

    /// The latest observed trust ID, or nil.
    public var observedID: String? {
        lock.lock()
        defer { lock.unlock() }
        return observed.map { Data($0.id).hexString }
    }

    public init(
        seeds: [String] = defaultSeeds,
        preferLatest: Bool = true,
        devMode: Bool = false
    ) {
        self.seeds = seeds
        self.preferLatest = preferLatest
        self.devMode = devMode
        self.session = URLSession(configuration: .default)
    }

    // MARK: - Bootstrap

    public func bootstrap() async throws {
        if pool.isEmpty {
            try await bootstrapPeers()
        }
        if _veritas == nil || _veritas!.newestAnchor() == 0 {
            try await updateAnchors(kind: .observed)
        }
    }

    private func bootstrapPeers() async throws {
        var urls = Set(seeds)
        for seed in seeds {
            if let peers = try? await fetchPeers(from: seed) {
                for peer in peers {
                    urls.insert(peer.url)
                }
            }
        }
        if urls.isEmpty {
            throw FabricError.noPeers
        }
        pool.refresh(urls)
    }

    // MARK: - Trust

    /// Pin a specific trust ID.
    public func trust(_ trustID: String) async throws {
        if pool.isEmpty { try await bootstrapPeers() }
        try await updateAnchors(kind: .trusted(trustID))
    }

    /// Set a semi-trusted anchor from an external source (e.g. public explorer).
    public func semiTrust(_ trustID: String) async throws {
        if pool.isEmpty { try await bootstrapPeers() }
        try await updateAnchors(kind: .semiTrusted(trustID))
    }

    /// Parse a veritas://scan?id=... QR payload and pin as trusted.
    public func trustFromQr(_ payload: String) async throws {
        let params = try ScanParams.parse(payload)
        try await trust(params.id)
    }

    /// Parse a veritas://scan?id=... QR payload and pin as semi-trusted.
    public func semiTrustFromQr(_ payload: String) async throws {
        let params = try ScanParams.parse(payload)
        try await semiTrust(params.id)
    }

    /// Clear the trusted state.
    public func clearTrusted() {
        lock.lock(); trusted = nil; lock.unlock()
    }

    /// Badge for a Resolved handle.
    public func badge(_ resolved: Resolved) -> VerificationBadge {
        badgeFor(sovereignty: resolved.zone.sovereignty, roots: resolved.roots)
    }

    /// Badge given sovereignty and roots.
    public func badgeFor(sovereignty: String, roots: [String]) -> VerificationBadge {
        lock.lock()
        let hasAny = trusted != nil || observed != nil || semiTrusted != nil
        lock.unlock()
        if !hasAny { return .unverified }

        let isTrusted = areRootsTrusted(roots)
        let isObserved = isTrusted || areRootsObserved(roots)
        let isSemiTrusted = isTrusted || areRootsSemiTrusted(roots)
        if isTrusted && sovereignty == "sovereign" { return .orange }
        if isObserved && !isTrusted && !isSemiTrusted { return .unverified }
        return .none
    }

    // MARK: - Anchors

    private func updateAnchors(kind: TrustKind = .observed) async throws {
        let hash: String
        var peers: [String]

        switch kind {
        case .trusted(let id), .semiTrusted(let id):
            hash = id
            peers = pool.shuffledUrls(4)
        case .observed:
            let result = try await fetchLatestTrustID()
            hash = result.hash
            peers = result.peers
        }

        let (anchors, entriesJson) = try await fetchAnchors(hash: hash, peers: peers)
        let ts = anchors.computeTrustSet()
        if Data(ts.id).hexString != hash {
            throw FabricError.decode("anchor root mismatch")
        }

        lock.lock()
        switch kind {
        case .trusted:
            anchorPool.trusted = entriesJson
        case .semiTrusted:
            anchorPool.semiTrusted = entriesJson
        case .observed:
            anchorPool.observed = entriesJson
        }

        // Rebuild veritas from merged anchors
        if let mergedJson = anchorPool.merged() {
            let mergedAnchors = try Anchors.fromJson(json: mergedJson)
            _veritas = try Veritas(anchors: mergedAnchors)
        }

        switch kind {
        case .trusted:
            trusted = ts
        case .semiTrusted:
            semiTrusted = ts
        case .observed:
            observed = ts
        }
        lock.unlock()
    }

    // MARK: - Resolution

    /// Resolve a single handle. Returns nil if not found. Supports dotted names like `hello.alice@bitcoin`.
    public func resolve(_ handle: String) async throws -> Resolved? {
        let batch = try await resolveAll([handle])
        guard let zone = batch.zones.first(where: { $0.handle == handle }) else {
            return nil
        }
        return Resolved(zone: zone, roots: batch.roots)
    }

    /// Resolve a numeric ID to a verified handle. Returns nil if not found.
    public func resolveById(_ numId: String) async throws -> Resolved? {
        try await bootstrap()
        let relays = pool.shuffledUrls(4)

        for url in relays {
            guard let requestUrl = URL(string: "\(url)/reverse?ids=\(numId)") else { continue }
            let entries: [ReverseEntry]
            do {
                let (data, resp) = try await session.data(from: requestUrl)
                guard let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 else { continue }
                entries = try JSONDecoder().decode([ReverseEntry].self, from: data)
            } catch { continue }

            guard let entry = entries.first(where: { $0.id == numId }) else { continue }

            guard let resolved = try await resolve(entry.name) else { continue }

            guard resolved.zone.numId == numId else { continue }
            return resolved
        }

        return nil
    }

    /// Search for handles by address record, verify via forward resolution.
    public func searchAddr(_ name: String, addr: String) async throws -> ResolvedBatch {
        try await bootstrap()
        let relays = pool.shuffledUrls(4)

        for url in relays {
            guard let requestUrl = URL(string: "\(url)/addrs?name=\(name)&addr=\(addr)") else { continue }
            let result: AddrMatchResponse
            do {
                let (data, resp) = try await session.data(from: requestUrl)
                guard let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 else { continue }
                result = try JSONDecoder().decode(AddrMatchResponse.self, from: data)
            } catch { continue }

            if result.handles.isEmpty { continue }

            let revNames = result.handles.map(\.rev)
            let batch: ResolvedBatch
            do {
                batch = try await resolveAll(revNames)
            } catch { continue }

            // Filter to zones that actually contain the matching addr record
            let matching = batch.zones.filter { z in
                do {
                    let rs = RecordSet(data: z.records)
                    let records = try rs.unpack()
                    return records.contains { r in
                        if case .addr(let k, let v) = r, k == name, let first = v.first, first == addr {
                            return true
                        }
                        return false
                    }
                } catch { return false }
            }
            if matching.isEmpty { continue }
            return ResolvedBatch(zones: matching, roots: batch.roots)
        }

        throw FabricError.noPeers
    }

    /// Resolve multiple handles, including dotted names like `hello.alice@bitcoin`.
    ///
    /// Returns expanded zones for all requested handles.
    /// Uses the Lookup type from libveritas for dotted-name resolution.
    public func resolveAll(_ handles: [String]) async throws -> ResolvedBatch {
        let lookup = try Lookup(names: handles)
        var allZones = [Zone]()
        var roots = [String]()

        var prevBatch = [String]()
        var batch = lookup.start()
        while !batch.isEmpty {
            if batch == prevBatch { break }
            let verified = try await resolveFlat(batch, hints: true)
            let zones = verified.zones()
            prevBatch = batch
            batch = try lookup.advance(zones: zones)
            allZones.append(contentsOf: zones)
            roots.append(Data(verified.rootId()).hexString)
        }

        let expanded = try lookup.expandZones(zones: allZones)
        return ResolvedBatch(zones: expanded, roots: roots)
    }

    /// Export a certificate chain for a handle in `.spacecert` format.
    public func export(_ handle: String) async throws -> Data {
        let lookup = try Lookup(names: [handle])
        var allCertBytes = [Data]()

        var prevBatch = [String]()
        var batch = lookup.start()
        while !batch.isEmpty {
            if batch == prevBatch { break }
            let verified = try await resolveFlat(batch, hints: false)
            allCertBytes.append(contentsOf: verified.certificates())
            let zones = verified.zones()
            prevBatch = batch
            batch = try lookup.advance(zones: zones)
        }

        return try createCertificateChain(subject: handle, certBytesList: allCertBytes)
    }

    // MARK: - Publish

    /// Build a message from a certificate and unsigned records, sign all unsigned entries, and return the message bytes.
    public func sign(cert: Data, records: Data, secretKey: Data, primary: Bool = true) async throws -> Data {
        try await bootstrap()
        let builder = MessageBuilder()
        try builder.addHandle(chainBytes: cert, recordsBytes: records)
        let proofReqJSON = try builder.chainProofRequest()
        let proofBytes = try await prove(Data(proofReqJSON.utf8))
        let result = try builder.build(chainProof: proofBytes)

        for u in result.unsigned {
            if primary {
                u.setFlags(flags: u.flags() | 0x01)
            }
            let sig = try signSchnorr(digest: Data(u.signingId()), secretKey: secretKey)
            let signed = try u.packSig(signature: sig)
            try result.message.setRecords(canonical: u.canonical(), recordsBytes: signed)
        }

        return try result.message.toBytes()
    }

    /// Build, sign, and broadcast a message.
    public func publish(cert: Data, records: Data, secretKey: Data, primary: Bool = true) async throws {
        let msg = try await sign(cert: cert, records: records, secretKey: secretKey, primary: primary)
        try await broadcast(msg)
    }

    /// Resolve a flat list of non-dotted handles in a single relay query.
    private func resolveFlat(_ handles: [String], hints: Bool) async throws -> VerifiedMessage {
        var bySpace = [String: [String]]()
        for h in handles {
            let parsed = parseHandle(h)
            bySpace[parsed.space, default: []].append(parsed.label)
        }

        var queries = [Query]()
        for (space, labels) in bySpace {
            var q = Query(space: space, handles: labels)
            if hints {
                lock.lock()
                let cached = zoneCache[space]
                lock.unlock()
                if let cached, case .exists(let stateRoot, _, _, let blockHeight, _) = cached.commitment {
                    q.epoch_hint = EpochHint(
                        root: stateRoot.map { String(format: "%02x", $0) }.joined(),
                        height: blockHeight
                    )
                }
            }
            queries.append(q)
        }

        let request = QueryRequest(queries: queries)
        return try await query(request)
    }

    private func query(_ request: QueryRequest) async throws -> VerifiedMessage {
        try await bootstrap()

        let ctx = QueryContext()
        lock.lock()
        for q in request.queries {
            if let cached = zoneCache[q.space] {
                try? ctx.addZone(zoneBytes: zoneToBytes(zone: cached))
            }
        }
        lock.unlock()

        let relays: [String]
        if preferLatest {
            relays = await pickRelays(request: request, count: 4)
        } else {
            relays = pool.shuffledUrls(4)
        }

        let verified = try await sendQuery(ctx: ctx, request: request, relays: relays)
        let zones = verified.zones()

        lock.lock()
        for zone in zones {
            if zone.handle.hasPrefix("@") || zone.handle.hasPrefix("#") {
                zoneCache[zone.handle] = zone
            }
        }
        lock.unlock()

        return verified
    }

    private func sendQuery(
        ctx: QueryContext,
        request: QueryRequest,
        relays: [String]
    ) async throws -> VerifiedMessage {
        var qParts = [String]()
        var hintParts = [String]()
        for q in request.queries {
            try ctx.addRequest(handle: q.space)
            qParts.append(q.space)
            for handle in q.handles where !handle.isEmpty {
                try ctx.addRequest(handle: "\(handle)\(q.space)")
                qParts.append("\(handle)\(q.space)")
            }
            if let hint = q.epoch_hint {
                hintParts.append("\(q.space):\(hint.root):\(hint.height)")
            }
        }

        var lastError: FabricError = .noPeers

        for url in relays {
            do {
                var components = URLComponents(string: "\(url)/query")!
                var queryItems = [URLQueryItem(name: "q", value: qParts.joined(separator: ","))]
                if !hintParts.isEmpty {
                    queryItems.append(URLQueryItem(name: "hints", value: hintParts.joined(separator: ",")))
                }
                components.queryItems = queryItems
                let (responseData, resp) = try await session.data(from: components.url!)
                guard let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 else {
                    let httpResp = resp as? HTTPURLResponse
                    pool.markFailed(url)
                    lastError = .relay(
                        status: httpResp?.statusCode ?? 0,
                        body: String(data: responseData, encoding: .utf8) ?? ""
                    )
                    continue
                }
                do {
                    lock.lock()
                    let v = _veritas
                    lock.unlock()
                    guard let v else { throw FabricError.noPeers }
                    let msg = try Message(bytes: responseData)
                    let options: UInt32 = self.devMode ? verifyDevMode() : 0
                    let verified = try v.verifyWithOptions(ctx: ctx, msg: msg, options: options)
                    pool.markAlive(url)
                    return verified
                } catch let error as VeritasError {
                    pool.markFailed(url)
                    lastError = .verify("\(error)")
                }
            } catch let error as FabricError {
                pool.markFailed(url)
                lastError = error
            } catch {
                pool.markFailed(url)
                lastError = .http("\(error)")
            }
        }

        throw lastError
    }

    // MARK: - Relay selection

    private func pickRelays(request: QueryRequest, count: Int) async -> [String] {
        let hintsQuery = hintsQueryString(request)
        let shuffled = pool.shuffledUrls()
        var ranked = [(url: String, hints: HintsResponse)]()

        for start in stride(from: 0, to: shuffled.count, by: count) {
            if ranked.count >= count { break }
            let end = min(start + count, shuffled.count)
            let batch = Array(shuffled[start..<end])

            await withTaskGroup(of: (String, HintsResponse?).self) { group in
                for url in batch {
                    group.addTask {
                        guard let hints = try? await self.fetchHints(url: url, query: hintsQuery) else {
                            return (url, nil)
                        }
                        return (url, hints)
                    }
                }
                for await (url, hints) in group {
                    if let hints {
                        ranked.append((url, hints))
                    } else {
                        pool.markFailed(url)
                    }
                }
            }
        }

        ranked.sort { compareHints($0.hints, $1.hints) > 0 }
        return ranked.map(\.url)
    }

    // MARK: - Chain proofs

    public func prove(_ request: Data) async throws -> Data {
        try await bootstrap()
        let urls = pool.shuffledUrls(4)
        var lastError: FabricError = .noPeers

        for url in urls {
            do {
                let data = try await post(
                    url: "\(url)/chain-proof",
                    body: request,
                    contentType: "application/json"
                )
                pool.markAlive(url)
                return data
            } catch let error as FabricError {
                pool.markFailed(url)
                lastError = error
            } catch {
                pool.markFailed(url)
                lastError = .http("\(error)")
            }
        }

        throw lastError
    }

    // MARK: - Broadcast

    public func broadcast(_ msgBytes: Data) async throws {
        try await bootstrap()
        let urls = pool.shuffledUrls(4)
        if urls.isEmpty { throw FabricError.noPeers }

        var anyOk = false
        var lastError: FabricError?

        for url in urls {
            do {
                let (_, resp) = try await session.data(for: makeRequest(
                    url: "\(url)/message",
                    method: "POST",
                    body: msgBytes,
                    contentType: "application/octet-stream"
                ))
                if let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 {
                    anyOk = true
                } else if let httpResp = resp as? HTTPURLResponse {
                    lastError = .relay(status: httpResp.statusCode, body: "")
                }
            } catch {
                lastError = .http("\(error)")
            }
        }

        if !anyOk {
            throw lastError ?? FabricError.noPeers
        }
    }

    // MARK: - Peers

    public func peers() async throws -> [PeerInfo] {
        let urls = pool.shuffledUrls(1)
        guard let url = urls.first else { throw FabricError.noPeers }
        return try await fetchPeers(from: url)
    }

    public func refreshPeers() async throws {
        let current = pool.urls
        var newUrls = Set<String>()
        for url in current {
            if let peers = try? await fetchPeers(from: url) {
                for peer in peers { newUrls.insert(peer.url) }
            }
        }
        pool.refresh(newUrls)
        if pool.isEmpty { throw FabricError.noPeers }
    }

    // MARK: - Trust helpers (private)

    private func areRootsTrusted(_ roots: [String]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let ts = trusted else { return false }
        return roots.allSatisfy { root in
            guard let rootBytes = Data(hexString: root) else { return false }
            return ts.roots.contains { Data($0) == rootBytes }
        }
    }

    private func areRootsObserved(_ roots: [String]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let ts = observed else { return false }
        return roots.allSatisfy { root in
            guard let rootBytes = Data(hexString: root) else { return false }
            return ts.roots.contains { Data($0) == rootBytes }
        }
    }

    private func areRootsSemiTrusted(_ roots: [String]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let ts = semiTrusted else { return false }
        return roots.allSatisfy { root in
            guard let rootBytes = Data(hexString: root) else { return false }
            return ts.roots.contains { Data($0) == rootBytes }
        }
    }

    // MARK: - Internal fetch helpers

    private func fetchPeers(from relayUrl: String) async throws -> [PeerInfo] {
        let (data, resp) = try await session.data(from: URL(string: "\(relayUrl)/peers")!)
        guard let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 else {
            let httpResp = resp as? HTTPURLResponse
            throw FabricError.relay(
                status: httpResp?.statusCode ?? 0,
                body: String(data: data, encoding: .utf8) ?? ""
            )
        }
        return try JSONDecoder().decode([PeerInfo].self, from: data)
    }

    private func fetchHints(url: String, query: String) async throws -> HintsResponse {
        var components = URLComponents(string: "\(url)/hints")!
        components.queryItems = [URLQueryItem(name: "q", value: query)]
        let (data, resp) = try await session.data(from: components.url!)
        guard let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 else {
            throw FabricError.relay(status: 0, body: "hints fetch failed")
        }
        return try JSONDecoder().decode(HintsResponse.self, from: data)
    }

    private func fetchLatestTrustID() async throws -> (hash: String, peers: [String]) {
        var votes = [String: (height: Int, peers: [String])]()

        for url in seeds {
            do {
                var req = URLRequest(url: URL(string: "\(url)/anchors")!)
                req.httpMethod = "HEAD"
                let (_, resp) = try await session.data(for: req)
                guard let httpResp = resp as? HTTPURLResponse else { continue }

                let root = httpResp.value(forHTTPHeaderField: "x-anchor-root")
                let height = Int(httpResp.value(forHTTPHeaderField: "x-anchor-height") ?? "0") ?? 0

                if let root {
                    let key = "\(root):\(height)"
                    var existing = votes[key] ?? (height: height, peers: [])
                    existing.peers.append(url)
                    votes[key] = existing
                }
            } catch {
                continue
            }
        }

        guard let best = votes.max(by: { a, b in
            let scoreA = a.value.peers.count * 1_000_000 + a.value.height
            let scoreB = b.value.peers.count * 1_000_000 + b.value.height
            return scoreA < scoreB
        }) else {
            throw FabricError.noPeers
        }

        let root = best.key.components(separatedBy: ":")[0]
        return (hash: root, peers: best.value.peers)
    }

    /// Fetch and verify anchors from a peer. Returns the Anchors and the raw entries JSON string.
    private func fetchAnchors(hash: String, peers: [String]) async throws -> (Anchors, String) {
        let expectedRoot = hexDecode(hash)
        var lastError: FabricError = .noPeers
        for url in peers {
            do {
                let (data, resp) = try await session.data(from: URL(string: "\(url)/anchors?root=\(hash)")!)
                guard let httpResp = resp as? HTTPURLResponse, httpResp.statusCode < 300 else {
                    let httpResp = resp as? HTTPURLResponse
                    lastError = .relay(
                        status: httpResp?.statusCode ?? 0,
                        body: String(data: data, encoding: .utf8) ?? ""
                    )
                    continue
                }
                guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let entries = json["entries"] else {
                    lastError = .decode("invalid anchor response")
                    continue
                }
                let entriesData = try JSONSerialization.data(withJSONObject: entries)
                let entriesStr = String(data: entriesData, encoding: .utf8)!
                let anchors = try Anchors.fromJson(json: entriesStr)
                let ts = anchors.computeTrustSet()
                if Data(ts.id) != expectedRoot {
                    lastError = .decode("anchor root mismatch")
                    continue
                }
                return (anchors, entriesStr)
            } catch let error as FabricError {
                lastError = error
            } catch {
                lastError = .http("\(error)")
            }
        }
        throw lastError
    }

    private func postBinary(url: String, body: Data) async throws -> Data {
        try await post(url: url, body: body, contentType: "application/octet-stream")
    }

    private func post(url: String, body: Data, contentType: String) async throws -> Data {
        let (data, resp) = try await session.data(for: makeRequest(
            url: url, method: "POST", body: body, contentType: contentType
        ))
        guard let httpResp = resp as? HTTPURLResponse else {
            throw FabricError.http("no HTTP response")
        }
        if httpResp.statusCode >= 300 {
            throw FabricError.relay(
                status: httpResp.statusCode,
                body: String(data: data, encoding: .utf8) ?? ""
            )
        }
        return data
    }

    private func makeRequest(url: String, method: String, body: Data, contentType: String) -> URLRequest {
        var req = URLRequest(url: URL(string: url)!)
        req.httpMethod = method
        req.httpBody = body
        req.setValue(contentType, forHTTPHeaderField: "Content-Type")
        return req
    }
}

// MARK: - Data hex extensions

extension Data {
    /// Hex-encode this data to a lowercase string.
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from a hex-encoded string. Returns nil on invalid input.
    init?(hexString hex: String) {
        var data = Data(capacity: hex.count / 2)
        var chars = hex.makeIterator()
        while let hi = chars.next(), let lo = chars.next() {
            guard let byte = UInt8(String([hi, lo]), radix: 16) else { return nil }
            data.append(byte)
        }
        self = data
    }
}

// MARK: - Utilities

private func parseHandle(_ handle: String) -> (space: String, label: String) {
    var sepIdx = handle.firstIndex(of: "@")
    if sepIdx == nil {
        sepIdx = handle.firstIndex(of: "#")
    }
    guard let sepIdx else {
        return (space: handle, label: "")
    }
    if sepIdx == handle.startIndex {
        return (space: handle, label: "")
    }
    return (
        space: String(handle[sepIdx...]),
        label: String(handle[..<sepIdx])
    )
}

private func hexDecode(_ hex: String) -> Data {
    var data = Data(capacity: hex.count / 2)
    var chars = hex.makeIterator()
    while let hi = chars.next(), let lo = chars.next() {
        guard let byte = UInt8(String([hi, lo]), radix: 16) else { break }
        data.append(byte)
    }
    return data
}

private func hintsQueryString(_ request: QueryRequest) -> String {
    var parts = Set<String>()
    for q in request.queries {
        parts.insert(q.space)
        for handle in q.handles {
            parts.insert("\(handle)\(q.space)")
        }
    }
    return parts.joined(separator: ",")
}
