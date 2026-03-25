package fabric

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	libveritas "github.com/spacesprotocol/libveritas-go"
)

type EpochHint struct {
	Root   string `json:"root"`
	Height uint32 `json:"height"`
}

type Query struct {
	Space    string     `json:"space"`
	Handles  []string   `json:"handles"`
	EpochHint *EpochHint `json:"epoch_hint,omitempty"`
}

type QueryRequest struct {
	Queries []Query `json:"queries"`
}

type PeerInfo struct {
	SourceIP     string `json:"source_ip"`
	URL          string `json:"url"`
	Capabilities int    `json:"capabilities"`
}

type FabricError struct {
	Code    string
	Message string
	Status  int
}

func (e *FabricError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ScanParams holds parsed parameters from a veritas://scan?... URI.
type ScanParams struct {
	ID string // hex-encoded trust ID
}

// ParseScanURI parses a veritas://scan?id=... URI.
func ParseScanURI(uri string) (ScanParams, error) {
	uri = strings.TrimSpace(uri)
	const prefix = "veritas://scan?"
	if !strings.HasPrefix(uri, prefix) {
		return ScanParams{}, &FabricError{Code: "decode", Message: "expected veritas://scan?... URI"}
	}
	query := uri[len(prefix):]
	var id string
	for _, pair := range strings.Split(query, "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && parts[0] == "id" {
			id = parts[1]
		}
	}
	if id == "" {
		return ScanParams{}, &FabricError{Code: "decode", Message: "missing id parameter"}
	}
	return ScanParams{ID: id}, nil
}

// VerificationBadge represents the trust state for a resolved handle.
type VerificationBadge string

const (
	BadgeOrange     VerificationBadge = "orange"
	BadgeUnverified VerificationBadge = "unverified"
	BadgeNone       VerificationBadge = "none"
)

type trustKind int

const (
	trustKindObserved    trustKind = iota
	trustKindTrusted
	trustKindSemiTrusted
)

// Resolved wraps a single zone with its verification roots.
type Resolved struct {
	Zone  libveritas.Zone
	Roots []string // hex-encoded root IDs
}

// ResolvedBatch wraps multiple zones with shared verification roots.
type ResolvedBatch struct {
	Zones []libveritas.Zone
	Roots []string // hex-encoded root IDs
}

type anchorPool struct {
	trusted     string // raw entries JSON
	semiTrusted string // raw entries JSON
	observed    string // raw entries JSON
}

func (p *anchorPool) merged() (string, error) {
	allEntries := make([]json.RawMessage, 0)
	for _, src := range []string{p.trusted, p.semiTrusted, p.observed} {
		if src == "" {
			continue
		}
		var entries []json.RawMessage
		if err := json.Unmarshal([]byte(src), &entries); err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
	}
	data, err := json.Marshal(allEntries)
	return string(data), err
}

type Fabric struct {
	client       *http.Client
	pool         RelayPool
	veritas      *libveritas.Veritas
	anchors      anchorPool
	zoneCache    map[string]libveritas.Zone
	seeds        []string
	trusted      *libveritas.TrustSet
	semiTrusted  *libveritas.TrustSet
	observed     *libveritas.TrustSet
	preferLatest bool
	devMode      bool
	mu           sync.Mutex
}

func New(seeds []string) *Fabric {
	if seeds == nil {
		seeds = DefaultSeeds
	}
	return &Fabric{
		client:       &http.Client{},
		seeds:        seeds,
		zoneCache:    make(map[string]libveritas.Zone),
		preferLatest: true,
	}
}

func (f *Fabric) SetDevMode(v bool)     { f.devMode = v }
func (f *Fabric) SetPreferLatest(v bool) { f.preferLatest = v }

func (f *Fabric) Relays() []string { return f.pool.URLs() }

// Veritas returns the internal Veritas instance for offline verification.
// Returns nil if Bootstrap has not been called yet.
func (f *Fabric) Veritas() *libveritas.Veritas {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.veritas
}

// Trust pins a specific trust ID (hex-encoded 32-byte hash).
// Bootstraps peers if needed, then fetches the anchor set for this ID.
func (f *Fabric) Trust(trustID string) error {
	if f.pool.IsEmpty() {
		if err := f.bootstrapPeers(); err != nil {
			return err
		}
	}
	return f.updateAnchors(trustID, trustKindTrusted)
}

// TrustFromQr parses a veritas://scan?id=... QR payload and pins as trusted.
func (f *Fabric) TrustFromQr(payload string) error {
	params, err := ParseScanURI(payload)
	if err != nil {
		return err
	}
	return f.Trust(params.ID)
}

// SemiTrustFromQr parses a veritas://scan?id=... QR payload and pins as semi-trusted.
func (f *Fabric) SemiTrustFromQr(payload string) error {
	params, err := ParseScanURI(payload)
	if err != nil {
		return err
	}
	return f.SemiTrust(params.ID)
}

// Trusted returns the hex-encoded trusted trust ID, or empty string if none.
func (f *Fabric) Trusted() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trusted == nil {
		return ""
	}
	return hex.EncodeToString(f.trusted.Id)
}

// Observed returns the hex-encoded observed trust ID, or empty string if none.
func (f *Fabric) Observed() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.observed == nil {
		return ""
	}
	return hex.EncodeToString(f.observed.Id)
}

// SemiTrust sets a semi-trusted anchor from an external source (e.g. public explorer).
func (f *Fabric) SemiTrust(trustID string) error {
	if f.pool.IsEmpty() {
		if err := f.bootstrapPeers(); err != nil {
			return err
		}
	}
	return f.updateAnchors(trustID, trustKindSemiTrusted)
}

// SemiTrusted returns the hex-encoded semi-trusted trust ID, or empty string if none.
func (f *Fabric) SemiTrusted() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.semiTrusted == nil {
		return ""
	}
	return hex.EncodeToString(f.semiTrusted.Id)
}

// ClearTrusted clears the pinned trusted state.
func (f *Fabric) ClearTrusted() {
	f.mu.Lock()
	f.trusted = nil
	f.mu.Unlock()
}

// Badge returns the verification badge for a Resolved handle.
func (f *Fabric) Badge(resolved Resolved) VerificationBadge {
	return f.BadgeFor(resolved.Zone.Sovereignty, resolved.Roots)
}

// BadgeFor returns the verification badge given sovereignty and root IDs.
func (f *Fabric) BadgeFor(sovereignty string, roots []string) VerificationBadge {
	isTrusted := f.areRootsTrusted(roots)
	isObserved := isTrusted || f.areRootsObserved(roots)
	isSemiTrusted := isTrusted || f.areRootsSemiTrusted(roots)

	if isTrusted && sovereignty == "sovereign" {
		return BadgeOrange
	}
	if isObserved && !isTrusted && !isSemiTrusted {
		return BadgeUnverified
	}
	return BadgeNone
}

func (f *Fabric) areRootsTrusted(roots []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trusted == nil {
		return false
	}
	for _, root := range roots {
		rootBytes, err := hex.DecodeString(root)
		if err != nil {
			return false
		}
		if !containsRoot(f.trusted.Roots, rootBytes) {
			return false
		}
	}
	return true
}

func (f *Fabric) areRootsObserved(roots []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.observed == nil {
		return false
	}
	for _, root := range roots {
		rootBytes, err := hex.DecodeString(root)
		if err != nil {
			return false
		}
		if !containsRoot(f.observed.Roots, rootBytes) {
			return false
		}
	}
	return true
}

func (f *Fabric) areRootsSemiTrusted(roots []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.semiTrusted == nil {
		return false
	}
	for _, root := range roots {
		rootBytes, err := hex.DecodeString(root)
		if err != nil {
			return false
		}
		if !containsRoot(f.semiTrusted.Roots, rootBytes) {
			return false
		}
	}
	return true
}

func containsRoot(roots [][]byte, target []byte) bool {
	for _, r := range roots {
		if bytes.Equal(r, target) {
			return true
		}
	}
	return false
}

// Bootstrap discovers peers and fetches anchors.
func (f *Fabric) Bootstrap() error {
	if f.pool.IsEmpty() {
		if err := f.bootstrapPeers(); err != nil {
			return err
		}
	}
	if f.veritas == nil || f.veritas.NewestAnchor() == 0 {
		return f.updateAnchors("", trustKindObserved)
	}
	return nil
}

func (f *Fabric) bootstrapPeers() error {
	urls := make(map[string]bool)
	for _, seed := range f.seeds {
		urls[seed] = true
		if peers, err := fetchPeers(f.client, seed); err == nil {
			for _, p := range peers {
				urls[p.URL] = true
			}
		}
	}
	if len(urls) == 0 {
		return &FabricError{Code: "no_peers", Message: "no peers available"}
	}
	list := make([]string, 0, len(urls))
	for u := range urls {
		list = append(list, u)
	}
	f.pool.Refresh(list)
	return nil
}

func (f *Fabric) updateAnchors(trustID string, kind trustKind) error {
	var hash string
	var peers []string

	if kind == trustKindTrusted || kind == trustKindSemiTrusted {
		hash = trustID
		peers = f.pool.ShuffledURLs(4)
	} else {
		h, p, err := f.fetchLatestTrustID()
		if err != nil {
			return err
		}
		hash = h
		peers = p
	}

	anchors, entriesJSON, err := f.fetchAnchors(hash, peers)
	if err != nil {
		return err
	}

	ts := anchors.ComputeTrustSet()
	if hex.EncodeToString(ts.Id) != hash {
		return &FabricError{Code: "decode", Message: "anchor root mismatch"}
	}

	f.mu.Lock()
	// Store raw entries JSON into the appropriate pool slot
	switch kind {
	case trustKindTrusted:
		f.anchors.trusted = entriesJSON
		f.trusted = &ts
	case trustKindSemiTrusted:
		f.anchors.semiTrusted = entriesJSON
		f.semiTrusted = &ts
	default:
		f.anchors.observed = entriesJSON
		f.observed = &ts
	}

	// Rebuild veritas from merged anchor entries
	mergedJSON, mergeErr := f.anchors.merged()
	f.mu.Unlock()

	if mergeErr != nil {
		return fmt.Errorf("merging anchors: %w", mergeErr)
	}

	mergedAnchors, mergeErr := libveritas.AnchorsFromJson(mergedJSON)
	if mergeErr != nil {
		return fmt.Errorf("parsing merged anchors: %w", mergeErr)
	}

	v, err := libveritas.NewVeritas(mergedAnchors)
	if err != nil {
		return fmt.Errorf("creating veritas: %w", err)
	}

	f.mu.Lock()
	f.veritas = v
	f.mu.Unlock()
	return nil
}

// Resolve a single handle. Supports dotted names like "hello.alice@bitcoin".
func (f *Fabric) Resolve(handle string) (Resolved, error) {
	batch, err := f.ResolveAll([]string{handle})
	if err != nil {
		return Resolved{}, err
	}
	for _, z := range batch.Zones {
		if z.Handle == handle {
			return Resolved{Zone: z, Roots: batch.Roots}, nil
		}
	}
	return Resolved{}, &FabricError{Code: "decode", Message: handle + " not found"}
}

// ResolveAll resolves multiple handles including dotted names.
func (f *Fabric) ResolveAll(handles []string) (ResolvedBatch, error) {
	lookup, err := libveritas.NewLookup(handles)
	if err != nil {
		return ResolvedBatch{}, fmt.Errorf("creating lookup: %w", err)
	}
	defer lookup.Destroy()

	var allZones []libveritas.Zone
	var roots []string
	var prevBatch []string
	batch := lookup.Start()
	for len(batch) > 0 {
		if slicesEqual(batch, prevBatch) {
			break
		}
		verified, err := f.resolveFlat(batch)
		if err != nil {
			return ResolvedBatch{}, err
		}
		zones := verified.Zones()
		prevBatch = batch
		var next []string
		next, err = lookup.Advance(zones)
		if err != nil {
			return ResolvedBatch{}, fmt.Errorf("lookup advance: %w", err)
		}
		allZones = append(allZones, zones...)
		roots = append(roots, hex.EncodeToString(verified.RootId()))
		batch = next
	}

	expanded, err := lookup.ExpandZones(allZones)
	if err != nil {
		return ResolvedBatch{}, fmt.Errorf("expand zones: %w", err)
	}

	return ResolvedBatch{Zones: expanded, Roots: roots}, nil
}

// Export resolves a handle and returns the raw certificate chain bytes.
func (f *Fabric) Export(handle string) ([]byte, error) {
	lookup, err := libveritas.NewLookup([]string{handle})
	if err != nil {
		return nil, err
	}
	defer lookup.Destroy()

	var allCertBytes [][]byte
	var prevBatch []string
	batch := lookup.Start()
	for len(batch) > 0 {
		if slicesEqual(batch, prevBatch) {
			break
		}
		verified, err := f.resolveFlat(batch)
		if err != nil {
			return nil, err
		}
		allCertBytes = append(allCertBytes, verified.Certificates()...)
		zones := verified.Zones()
		prevBatch = batch
		next, err := lookup.Advance(zones)
		if err != nil {
			return nil, err
		}
		batch = next
	}

	return libveritas.CreateCertificateChain(handle, allCertBytes)
}

// Publish builds a message from a certificate chain and signed records, then broadcasts.
// cert: .spacecert bytes from Export()
// signedRecords: borsh-encoded OffchainRecords from SignRecords()
func (f *Fabric) Publish(cert []byte, signedRecords []byte) error {
	builder := libveritas.NewMessageBuilder()
	if err := builder.AddHandle(cert, signedRecords); err != nil {
		return fmt.Errorf("adding handle to builder: %w", err)
	}
	proofReqJSON, err := builder.ChainProofRequest()
	if err != nil {
		return fmt.Errorf("chain proof request: %w", err)
	}
	proofBytes, err := f.Prove([]byte(proofReqJSON))
	if err != nil {
		return err
	}
	msg, err := builder.Build(proofBytes)
	if err != nil {
		return fmt.Errorf("building message: %w", err)
	}
	return f.Broadcast(msg.ToBytes())
}

func (f *Fabric) resolveFlat(handles []string) (*libveritas.VerifiedMessage, error) {
	bySpace := make(map[string][]string)
	for _, h := range handles {
		space, label := parseHandle(h)
		bySpace[space] = append(bySpace[space], label)
	}

	var queries []Query
	for space, labels := range bySpace {
		q := Query{Space: space, Handles: labels}
		f.mu.Lock()
		if cached, ok := f.zoneCache[space]; ok {
			if hint := epochHintFromZone(cached); hint != nil {
				q.EpochHint = hint
			}
		}
		f.mu.Unlock()
		queries = append(queries, q)
	}

	return f.query(QueryRequest{Queries: queries})
}

func (f *Fabric) query(request QueryRequest) (*libveritas.VerifiedMessage, error) {
	if err := f.Bootstrap(); err != nil {
		return nil, err
	}

	ctx := libveritas.NewQueryContext()
	f.mu.Lock()
	for _, q := range request.Queries {
		if cached, ok := f.zoneCache[q.Space]; ok {
			if b, err := libveritas.ZoneToBytes(cached); err == nil {
				ctx.AddZone(b)
			}
		}
	}
	f.mu.Unlock()

	var relays []string
	if f.preferLatest {
		relays = f.pickRelays(request, 4)
	} else {
		relays = f.pool.ShuffledURLs(4)
	}

	verified, err := f.sendQuery(ctx, request, relays)
	if err != nil {
		return nil, err
	}

	zones := verified.Zones()
	f.mu.Lock()
	for _, z := range zones {
		if strings.HasPrefix(z.Handle, "@") || strings.HasPrefix(z.Handle, "#") {
			f.zoneCache[z.Handle] = z
		}
	}
	f.mu.Unlock()

	return verified, nil
}

func (f *Fabric) sendQuery(ctx *libveritas.QueryContext, request QueryRequest, relays []string) (*libveritas.VerifiedMessage, error) {
	for _, q := range request.Queries {
		ctx.AddRequest(q.Space)
		for _, h := range q.Handles {
			if h != "" {
				ctx.AddRequest(h + q.Space)
			}
		}
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}

	var lastErr error = &FabricError{Code: "no_peers", Message: "no peers available"}

	for _, u := range relays {
		respBytes, err := postBinary(f.client, u+"/query", body)
		if err != nil {
			f.pool.MarkFailed(u)
			lastErr = err
			continue
		}

		msg, err := libveritas.NewMessage(respBytes)
		if err != nil {
			f.pool.MarkFailed(u)
			lastErr = &FabricError{Code: "decode", Message: fmt.Sprintf("%s/query: %s", u, err)}
			continue
		}

		f.mu.Lock()
		v := f.veritas
		f.mu.Unlock()
		if v == nil {
			return nil, &FabricError{Code: "no_peers", Message: "no veritas instance"}
		}

		var options uint32
		if f.devMode {
			options = libveritas.VerifyDevMode()
		}
		verified, err := v.VerifyWithOptions(ctx, msg, options)
		if err != nil {
			f.pool.MarkFailed(u)
			lastErr = &FabricError{Code: "verify", Message: err.Error()}
			continue
		}

		f.pool.MarkAlive(u)
		return verified, nil
	}

	return nil, lastErr
}

func (f *Fabric) pickRelays(request QueryRequest, count int) []string {
	hintsQuery := hintsQueryString(request)
	shuffled := f.pool.ShuffledURLs(0)

	type ranked struct {
		url   string
		hints HintsResponse
	}
	var results []ranked

	for i := 0; i < len(shuffled); i += count {
		if len(results) >= count {
			break
		}
		end := i + count
		if end > len(shuffled) {
			end = len(shuffled)
		}
		batch := shuffled[i:end]

		type result struct {
			url   string
			hints *HintsResponse
		}
		ch := make(chan result, len(batch))
		for _, u := range batch {
			go func(u string) {
				h, err := fetchHints(f.client, u, hintsQuery)
				if err != nil {
					ch <- result{url: u}
					return
				}
				ch <- result{url: u, hints: h}
			}(u)
		}
		for range batch {
			r := <-ch
			if r.hints != nil {
				results = append(results, ranked{url: r.url, hints: *r.hints})
			} else {
				f.pool.MarkFailed(r.url)
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return CompareHints(results[i].hints, results[j].hints) > 0
	})

	urls := make([]string, len(results))
	for i, r := range results {
		urls[i] = r.url
	}
	return urls
}

// Peers returns the peer list from a random relay.
func (f *Fabric) Peers() ([]PeerInfo, error) {
	urls := f.pool.ShuffledURLs(1)
	if len(urls) == 0 {
		return nil, &FabricError{Code: "no_peers", Message: "no peers available"}
	}
	return fetchPeers(f.client, urls[0])
}

// RefreshPeers re-fetches peers from all known relays.
func (f *Fabric) RefreshPeers() error {
	current := f.pool.URLs()
	var newURLs []string
	for _, u := range current {
		if peers, err := fetchPeers(f.client, u); err == nil {
			for _, p := range peers {
				newURLs = append(newURLs, p.URL)
			}
		}
	}
	f.pool.Refresh(newURLs)
	if f.pool.IsEmpty() {
		return &FabricError{Code: "no_peers", Message: "no peers available"}
	}
	return nil
}

// -- Prove & Broadcast --

// Prove requests a chain proof from a relay.
func (f *Fabric) Prove(request []byte) ([]byte, error) {
	if err := f.Bootstrap(); err != nil {
		return nil, err
	}
	urls := f.pool.ShuffledURLs(4)
	var lastErr error = &FabricError{Code: "no_peers", Message: "no peers available"}

	for _, u := range urls {
		resp, err := postJSON(f.client, u+"/chain-proof", request)
		if err != nil {
			f.pool.MarkFailed(u)
			lastErr = err
			continue
		}
		f.pool.MarkAlive(u)
		return resp, nil
	}
	return nil, lastErr
}

// Broadcast sends a message to up to 4 random relays for gossip propagation.
// Returns nil if at least one relay accepted.
func (f *Fabric) Broadcast(msgBytes []byte) error {
	if err := f.Bootstrap(); err != nil {
		return err
	}
	urls := f.pool.ShuffledURLs(4)
	if len(urls) == 0 {
		return &FabricError{Code: "no_peers", Message: "no peers available"}
	}

	anyOk := false
	var lastErr error
	for _, u := range urls {
		_, err := postBinary(f.client, u+"/message", msgBytes)
		if err != nil {
			lastErr = err
			continue
		}
		anyOk = true
	}
	if anyOk {
		return nil
	}
	return lastErr
}

// -- Internal fetch helpers --

func (f *Fabric) fetchLatestTrustID() (string, []string, error) {
	type vote struct {
		height int
		peers  []string
	}
	votes := make(map[string]*vote)

	for _, seed := range f.seeds {
		req, err := http.NewRequest("HEAD", seed+"/anchors", nil)
		if err != nil {
			continue
		}
		resp, err := f.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		root := resp.Header.Get("X-Anchor-Root")
		height := 0
		fmt.Sscanf(resp.Header.Get("X-Anchor-Height"), "%d", &height)

		if root != "" {
			key := fmt.Sprintf("%s:%d", root, height)
			if v, ok := votes[key]; ok {
				v.peers = append(v.peers, seed)
			} else {
				votes[key] = &vote{height: height, peers: []string{seed}}
			}
		}
	}

	var bestKey string
	bestScore := -1
	for key, v := range votes {
		score := len(v.peers)*1_000_000 + v.height
		if score > bestScore {
			bestScore = score
			bestKey = key
		}
	}

	if bestKey == "" {
		return "", nil, &FabricError{Code: "no_peers", Message: "no peers available"}
	}

	parts := strings.SplitN(bestKey, ":", 2)
	return parts[0], votes[bestKey].peers, nil
}

func (f *Fabric) fetchAnchors(hash string, peers []string) (*libveritas.Anchors, string, error) {
	var lastErr error = &FabricError{Code: "no_peers", Message: "no peers available"}

	for _, u := range peers {
		resp, err := f.client.Get(u + "/anchors?root=" + hash)
		if err != nil {
			lastErr = &FabricError{Code: "http", Message: err.Error()}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 300 {
			lastErr = &FabricError{Code: "relay", Status: resp.StatusCode, Message: string(body)}
			continue
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			lastErr = &FabricError{Code: "decode", Message: "invalid anchor response"}
			continue
		}
		entriesJSON, ok := raw["entries"]
		if !ok {
			lastErr = &FabricError{Code: "decode", Message: "missing entries in anchor response"}
			continue
		}

		anchors, err := libveritas.AnchorsFromJson(string(entriesJSON))
		if err != nil {
			lastErr = &FabricError{Code: "decode", Message: fmt.Sprintf("parsing anchors: %s", err)}
			continue
		}

		return anchors, string(entriesJSON), nil
	}

	return nil, "", lastErr
}

func fetchPeers(client *http.Client, relayURL string) ([]PeerInfo, error) {
	resp, err := client.Get(relayURL + "/peers")
	if err != nil {
		return nil, &FabricError{Code: "http", Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, &FabricError{Code: "relay", Status: resp.StatusCode, Message: string(body)}
	}
	var peers []PeerInfo
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, &FabricError{Code: "decode", Message: err.Error()}
	}
	return peers, nil
}

func fetchHints(client *http.Client, relayURL, query string) (*HintsResponse, error) {
	u, _ := url.Parse(relayURL + "/hints")
	u.RawQuery = url.Values{"q": {query}}.Encode()
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hints: status %d", resp.StatusCode)
	}
	var hints HintsResponse
	if err := json.NewDecoder(resp.Body).Decode(&hints); err != nil {
		return nil, err
	}
	return &hints, nil
}

func postJSON(client *http.Client, url string, body []byte) ([]byte, error) {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, &FabricError{Code: "http", Message: err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, &FabricError{Code: "relay", Status: resp.StatusCode, Message: string(data)}
	}
	return data, nil
}

func postBinary(client *http.Client, url string, body []byte) ([]byte, error) {
	resp, err := client.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		return nil, &FabricError{Code: "http", Message: err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, &FabricError{Code: "relay", Status: resp.StatusCode, Message: string(data)}
	}
	return data, nil
}

// -- Utilities --

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseHandle(handle string) (space, label string) {
	sep := strings.IndexAny(handle, "@#")
	if sep < 0 {
		return handle, ""
	}
	if sep == 0 {
		return handle, ""
	}
	return handle[sep:], handle[:sep]
}

func hintsQueryString(request QueryRequest) string {
	parts := make(map[string]bool)
	for _, q := range request.Queries {
		parts[q.Space] = true
		for _, h := range q.Handles {
			parts[h+q.Space] = true
		}
	}
	list := make([]string, 0, len(parts))
	for p := range parts {
		list = append(list, p)
	}
	return strings.Join(list, ",")
}

func epochHintFromZone(z libveritas.Zone) *EpochHint {
	c, ok := z.Commitment.(libveritas.CommitmentStateExists)
	if !ok {
		return nil
	}
	return &EpochHint{
		Root:   hex.EncodeToString(c.StateRoot),
		Height: c.BlockHeight,
	}
}
