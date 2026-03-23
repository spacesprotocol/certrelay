package org.spacesprotocol.fabric

class RelayPool {
    private data class Entry(val url: String, var failures: Int = 0)

    private val entries = mutableListOf<Entry>()

    val isEmpty: Boolean
        get() = synchronized(entries) { entries.isEmpty() }

    fun urls(): List<String> = synchronized(entries) {
        entries.map { it.url }
    }

    fun shuffledUrls(n: Int = 0): List<String> = synchronized(entries) {
        entries.shuffle()
        entries.sortBy { it.failures }
        val limit = if (n <= 0 || n > entries.size) entries.size else n
        entries.take(limit).map { it.url }
    }

    fun markFailed(url: String) = synchronized(entries) {
        entries.find { it.url == url }?.let { it.failures++ }
    }

    fun markAlive(url: String) = synchronized(entries) {
        entries.find { it.url == url }?.let { it.failures = 0 }
    }

    fun refresh(urls: List<String>) = synchronized(entries) {
        val existing = entries.map { it.url }.toSet()
        for (url in urls) {
            if (url !in existing) {
                entries.add(Entry(url))
            }
        }
    }
}
