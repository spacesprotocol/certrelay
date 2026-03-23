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

// MARK: - Fabric client

public final class Fabric: @unchecked Sendable {
    private let session: URLSession
    private let pool = RelayPool()
    private var _veritas: Veritas?
    private var zoneCache: [String: Zone] = [:]
    private let seeds: [String]
    private var _anchorSetHash: String?
    public var preferLatest: Bool
    private let devMode: Bool
    private let lock = NSLock()

    public var anchorSetHash: String? {
        lock.lock()
        defer { lock.unlock() }
        return _anchorSetHash
    }

    public var relays: [String] { pool.urls }

    /// The internal Veritas instance for offline verification.
    /// Returns nil if `bootstrap()` has not been called yet.
    public var veritas: Veritas? {
        lock.lock()
        defer { lock.unlock() }
        return _veritas
    }

    public init(
        seeds: [String] = defaultSeeds,
        anchorSetHash: String? = nil,
        preferLatest: Bool = true,
        devMode: Bool = false
    ) {
        self.seeds = seeds
        self._anchorSetHash = anchorSetHash
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
            try await updateAnchors(hash: _anchorSetHash)
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

    public func updateAnchors(hash: String? = nil) async throws {
        let anchorSetHash: String
        var peers: [String]

        if let hash {
            anchorSetHash = hash
            peers = pool.shuffledUrls(4)
        } else {
            let result = try await fetchLatestAnchorSetHash()
            anchorSetHash = result.hash
            peers = result.peers
        }

        let anchors = try await fetchAnchors(hash: anchorSetHash, peers: peers)
        let v = try Veritas(anchors: anchors)

        lock.lock()
        _veritas = v
        _anchorSetHash = anchorSetHash
        lock.unlock()
    }

    // MARK: - Resolution

    /// Resolve a single handle. Supports dotted names like `hello.alice@bitcoin`.
    public func resolve(_ handle: String) async throws -> Zone {
        let zones = try await resolveAll([handle])
        guard let zone = zones.first(where: { $0.handle == handle }) else {
            throw FabricError.decode("\(handle) not found")
        }
        return zone
    }

    /// Resolve multiple handles, including dotted names like `hello.alice@bitcoin`.
    ///
    /// Returns expanded zones for all requested handles.
    /// Uses the Lookup type from libveritas for dotted-name resolution.
    public func resolveAll(_ handles: [String]) async throws -> [Zone] {
        let lookup = try Lookup(names: handles)
        var allZones = [Zone]()

        var prevBatch = [String]()
        var batch = lookup.start()
        while !batch.isEmpty {
            if batch == prevBatch { break }
            let verified = try await resolveFlat(batch)
            let zones = verified.zones()
            prevBatch = batch
            batch = try lookup.advance(zones: zones)
            allZones.append(contentsOf: zones)
        }

        return try lookup.expandZones(zones: allZones)
    }

    /// Export a certificate chain for a handle in `.spacecert` format.
    public func export(_ handle: String) async throws -> Data {
        let lookup = try Lookup(names: [handle])
        var allCertBytes = [Data]()

        var prevBatch = [String]()
        var batch = lookup.start()
        while !batch.isEmpty {
            if batch == prevBatch { break }
            let verified = try await resolveFlat(batch)
            allCertBytes.append(contentsOf: verified.certificates())
            let zones = verified.zones()
            prevBatch = batch
            batch = try lookup.advance(zones: zones)
        }

        return try createCertificateChain(subject: handle, certBytesList: allCertBytes)
    }

    /// Resolve a flat list of non-dotted handles in a single relay query.
    private func resolveFlat(_ handles: [String]) async throws -> VerifiedMessage {
        var bySpace = [String: [String]]()
        for h in handles {
            let parsed = parseHandle(h)
            bySpace[parsed.space, default: []].append(parsed.label)
        }

        var queries = [Query]()
        for (space, labels) in bySpace {
            var q = Query(space: space, handles: labels)
            lock.lock()
            let cached = zoneCache[space]
            lock.unlock()
            if let cached, case .exists(let stateRoot, _, _, let blockHeight, _) = cached.commitment {
                q.epoch_hint = EpochHint(
                    root: stateRoot.map { String(format: "%02x", $0) }.joined(),
                    height: blockHeight
                )
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
        for q in request.queries {
            try ctx.addRequest(handle: q.space)
            for handle in q.handles where !handle.isEmpty {
                try ctx.addRequest(handle: "\(handle)\(q.space)")
            }
        }

        let body = try JSONEncoder().encode(request)
        var lastError: FabricError = .noPeers

        for url in relays {
            do {
                let responseData = try await postBinary(url: "\(url)/query", body: body)
                do {
                    lock.lock()
                    let v = veritas
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

    private func fetchLatestAnchorSetHash() async throws -> (hash: String, peers: [String]) {
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

    /// Fetch and verify anchors from a peer.
    private func fetchAnchors(hash: String, peers: [String]) async throws -> Anchors {
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
                if anchors.computeAnchorSetHash() != expectedRoot {
                    lastError = .decode("anchor root mismatch")
                    continue
                }
                return anchors
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
