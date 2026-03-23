package fabric

import (
	"math/rand"
	"sort"
	"sync"
)

type relayEntry struct {
	url      string
	failures int
}

type RelayPool struct {
	mu      sync.Mutex
	entries []relayEntry
}

func (p *RelayPool) IsEmpty() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries) == 0
}

func (p *RelayPool) URLs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	urls := make([]string, len(p.entries))
	for i, e := range p.entries {
		urls[i] = e.url
	}
	return urls
}

func (p *RelayPool) ShuffledURLs(n int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	rand.Shuffle(len(p.entries), func(i, j int) {
		p.entries[i], p.entries[j] = p.entries[j], p.entries[i]
	})
	sort.SliceStable(p.entries, func(i, j int) bool {
		return p.entries[i].failures < p.entries[j].failures
	})
	limit := n
	if limit <= 0 || limit > len(p.entries) {
		limit = len(p.entries)
	}
	urls := make([]string, limit)
	for i := 0; i < limit; i++ {
		urls[i] = p.entries[i].url
	}
	return urls
}

func (p *RelayPool) MarkFailed(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.entries {
		if p.entries[i].url == url {
			p.entries[i].failures++
			return
		}
	}
}

func (p *RelayPool) MarkAlive(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.entries {
		if p.entries[i].url == url {
			p.entries[i].failures = 0
			return
		}
	}
}

func (p *RelayPool) Refresh(urls []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	existing := make(map[string]bool, len(p.entries))
	for _, e := range p.entries {
		existing[e.url] = true
	}
	for _, url := range urls {
		if !existing[url] {
			p.entries = append(p.entries, relayEntry{url: url, failures: 0})
		}
	}
}
