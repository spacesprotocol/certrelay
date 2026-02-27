interface RelayEntry {
  url: string;
  failures: number;
}

/** Tracks relay URLs with failure counts and provides shuffled selection. */
export class RelayPool {
  private entries: RelayEntry[] = [];

  /** Shuffle entries, sort failures to back, return up to n URLs. */
  shuffledUrls(n: number = Infinity): string[] {
    // Fisher-Yates shuffle
    for (let i = this.entries.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [this.entries[i], this.entries[j]] = [this.entries[j], this.entries[i]];
    }
    // Stable sort by failures ascending
    this.entries.sort((a, b) => a.failures - b.failures);
    return this.entries.slice(0, n).map((e) => e.url);
  }

  markFailed(url: string): void {
    const entry = this.entries.find((e) => e.url === url);
    if (entry) entry.failures++;
  }

  markAlive(url: string): void {
    const entry = this.entries.find((e) => e.url === url);
    if (entry) entry.failures = 0;
  }

  /** Add new URLs to the pool (deduplicates). */
  refresh(urls: Iterable<string>): void {
    const existing = new Set(this.entries.map((e) => e.url));
    for (const url of urls) {
      if (!existing.has(url)) {
        this.entries.push({ url, failures: 0 });
        existing.add(url);
      }
    }
  }

  get isEmpty(): boolean {
    return this.entries.length === 0;
  }

  get urls(): string[] {
    return this.entries.map((e) => e.url);
  }
}
