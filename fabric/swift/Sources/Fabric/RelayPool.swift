import Foundation

struct RelayEntry {
    let url: String
    var failures: Int
}

final class RelayPool: @unchecked Sendable {
    private var entries: [RelayEntry] = []
    private let lock = NSLock()

    var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return entries.isEmpty
    }

    var urls: [String] {
        lock.lock()
        defer { lock.unlock() }
        return entries.map(\.url)
    }

    func shuffledUrls(_ n: Int = .max) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        entries.shuffle()
        entries.sort { $0.failures < $1.failures }
        return Array(entries.prefix(n).map(\.url))
    }

    func markFailed(_ url: String) {
        lock.lock()
        defer { lock.unlock() }
        if let idx = entries.firstIndex(where: { $0.url == url }) {
            entries[idx].failures += 1
        }
    }

    func markAlive(_ url: String) {
        lock.lock()
        defer { lock.unlock() }
        if let idx = entries.firstIndex(where: { $0.url == url }) {
            entries[idx].failures = 0
        }
    }

    func refresh(_ newUrls: some Sequence<String>) {
        lock.lock()
        defer { lock.unlock() }
        let existing = Set(entries.map(\.url))
        for url in newUrls where !existing.contains(url) {
            entries.append(RelayEntry(url: url, failures: 0))
        }
    }
}
