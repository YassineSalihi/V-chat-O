// Package discovery implements peer discovery for chat0 with Sybil-resistance.
//
// Mechanisms:
//  1. Bootstrap nodes: hard-coded or user-provided well-known peers.
//  2. Gossip protocol: every node periodically broadcasts its peer list.
//  3. Proof-of-Work (PoW) Sybil resistance: new peers must present a valid PoW
//     token tied to their Ed25519 public key. This raises the cost of flooding
//     the network with fake identities.
//  4. Reputation scoring: nodes track per-peer reliability (uptime, delivery).
//     Low-reputation nodes are deprioritised for routing.
//  5. Censorship bypass: nodes maintain an alternate bootstrap list sourced
//     from domain-fronted HTTPS or pre-shared lists embedded at build time.
package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"sync"
	"time"

	"chat0/p2p"
)

const (
	// PoWDifficulty is the number of leading zero bits required in the PoW hash.
	// Difficulty 20 ≈ 1M hashes; tunable for network conditions.
	PoWDifficulty = 20

	// MaxPeersPerNode is the maximum size of the peer table.
	MaxPeersPerNode = 256

	// PeerTTL is how long a peer entry lives without re-confirmation.
	PeerTTL = 2 * time.Hour

	// ReputationDecay is how much reputation decays per missed ping cycle.
	ReputationDecay = 5
)

// PeerEntry extends PeerInfo with discovery metadata.
type PeerEntry struct {
	p2p.PeerInfo
	PoWToken   []byte    // PoW nonce that satisfies the difficulty requirement
	Reputation int       // 0-100; higher = more trusted
	ConnectedAt time.Time
	LastSeen    time.Time
	Failures    int
}

// PeerTable is the in-memory peer store.
type PeerTable struct {
	mu      sync.RWMutex
	entries map[string]*PeerEntry // peerID -> entry
}

// NewPeerTable creates an empty peer table.
func NewPeerTable() *PeerTable {
	return &PeerTable{entries: make(map[string]*PeerEntry)}
}

// Add inserts or updates a peer after verifying PoW.
func (pt *PeerTable) Add(info p2p.PeerInfo, powToken []byte) error {
	if !VerifyPoW(info.PubKey, powToken, PoWDifficulty) {
		return fmt.Errorf("invalid PoW for peer %s", info.ID)
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if len(pt.entries) >= MaxPeersPerNode {
		pt.evictWorst()
	}

	if existing, ok := pt.entries[info.ID]; ok {
		existing.LastSeen = time.Now()
		existing.Reputation = clamp(existing.Reputation+1, 0, 100)
		return nil
	}

	pt.entries[info.ID] = &PeerEntry{
		PeerInfo:    info,
		PoWToken:    powToken,
		Reputation:  50, // start neutral
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
	}
	return nil
}

// Remove deletes a peer from the table.
func (pt *PeerTable) Remove(id string) {
	pt.mu.Lock()
	delete(pt.entries, id)
	pt.mu.Unlock()
}

// Get returns a peer entry by ID.
func (pt *PeerTable) Get(id string) (*PeerEntry, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	e, ok := pt.entries[id]
	return e, ok
}

// All returns all peer entries sorted by descending reputation.
func (pt *PeerTable) All() []*PeerEntry {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	out := make([]*PeerEntry, 0, len(pt.entries))
	for _, e := range pt.entries {
		out = append(out, e)
	}
	// Simple insertion sort (table is small)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Reputation > out[j-1].Reputation; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// RelayCandidate returns up to n peers suitable for onion relay circuits.
// Prefers high-reputation peers; excludes self.
func (pt *PeerTable) RelayCandidate(selfID string, n int) []*PeerEntry {
	all := pt.All()
	var out []*PeerEntry
	for _, e := range all {
		if e.ID == selfID {
			continue
		}
		if e.Reputation < 20 {
			continue // skip untrusted
		}
		out = append(out, e)
		if len(out) >= n {
			break
		}
	}
	return out
}

// RecordSuccess increases a peer's reputation on successful delivery.
func (pt *PeerTable) RecordSuccess(id string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if e, ok := pt.entries[id]; ok {
		e.Reputation = clamp(e.Reputation+2, 0, 100)
		e.LastSeen = time.Now()
		e.Failures = 0
	}
}

// RecordFailure decreases reputation and may evict the peer.
func (pt *PeerTable) RecordFailure(id string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if e, ok := pt.entries[id]; ok {
		e.Failures++
		e.Reputation = clamp(e.Reputation-10, 0, 100)
		if e.Failures > 5 {
			log.Printf("[discovery] evicting low-quality peer %s (rep=%d)", id, e.Reputation)
			delete(pt.entries, id)
		}
	}
}

// EvictStale removes peers not seen recently.
func (pt *PeerTable) EvictStale() {
	cutoff := time.Now().Add(-PeerTTL)
	pt.mu.Lock()
	defer pt.mu.Unlock()
	for id, e := range pt.entries {
		if e.LastSeen.Before(cutoff) {
			delete(pt.entries, id)
		}
	}
}

// evictWorst removes the peer with the lowest reputation. Must hold mu.Lock.
func (pt *PeerTable) evictWorst() {
	var worstID string
	worstRep := 101
	for id, e := range pt.entries {
		if e.Reputation < worstRep {
			worstRep = e.Reputation
			worstID = id
		}
	}
	delete(pt.entries, worstID)
}

// ---- Proof-of-Work ----

// SolvePoW finds a nonce such that SHA-256(pubKey || nonce) has `difficulty` leading zero bits.
// This is CPU-intensive by design to deter Sybil attacks.
func SolvePoW(pubKey []byte, difficulty int) []byte {
	nonce := make([]byte, 8)
	for counter := uint64(0); ; counter++ {
		binary.LittleEndian.PutUint64(nonce, counter)
		h := powHash(pubKey, nonce)
		if leadingZeroBits(h) >= difficulty {
			result := make([]byte, 8)
			copy(result, nonce)
			return result
		}
	}
}

// VerifyPoW checks that SHA-256(pubKey || nonce) satisfies the difficulty requirement.
func VerifyPoW(pubKey, nonce []byte, difficulty int) bool {
	if len(nonce) == 0 {
		return false
	}
	h := powHash(pubKey, nonce)
	return leadingZeroBits(h) >= difficulty
}

// PoWTokenHex returns the hex-encoded PoW nonce for display/debugging.
func PoWTokenHex(token []byte) string {
	return hex.EncodeToString(token)
}

func powHash(pubKey, nonce []byte) []byte {
	var buf bytes.Buffer
	buf.Write(pubKey)
	buf.Write(nonce)
	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

func leadingZeroBits(hash []byte) int {
	count := 0
	for _, b := range hash {
		lz := bits.LeadingZeros8(b)
		count += lz
		if lz < 8 {
			break
		}
	}
	return count
}

// ---- Bootstrap ----

// BootstrapList is a set of well-known bootstrap node addresses.
// In a real deployment these would point to stable rendezvous points or
// DHT-based seednodes. Users can add custom ones for censorship bypass.
var DefaultBootstrap = []string{
	// Placeholder — operators replace these with real addresses.
	// "seed1.chat0.example:9000",
	// "seed2.chat0.example:9000",
}

// Manager orchestrates peer discovery.
type Manager struct {
	table      *PeerTable
	node       *p2p.Node
	selfPow    []byte // this node's PoW token
	bootstraps []string
	stopCh     chan struct{}
}

// NewManager creates a discovery manager.
func NewManager(node *p2p.Node, table *PeerTable, selfPubKey []byte, bootstraps []string) *Manager {
	log.Printf("[discovery] solving PoW (difficulty=%d)…", PoWDifficulty)
	pow := SolvePoW(selfPubKey, PoWDifficulty)
	log.Printf("[discovery] PoW solved: %s", PoWTokenHex(pow))
	return &Manager{
		table:      table,
		node:       node,
		selfPow:    pow,
		bootstraps: bootstraps,
		stopCh:     make(chan struct{}),
	}
}

// SelfPoW returns this node's Proof-of-Work token.
func (m *Manager) SelfPoW() []byte {
	return m.selfPow
}

// Start runs the discovery loop.
func (m *Manager) Start() {
	go m.loop()
}

// Stop halts discovery.
func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) loop() {
	// Connect to bootstrap nodes immediately
	m.connectBootstraps()

	refreshTicker := time.NewTicker(5 * time.Minute)
	evictTicker := time.NewTicker(30 * time.Minute)
	defer refreshTicker.Stop()
	defer evictTicker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-refreshTicker.C:
			m.connectBootstraps()
			m.node.BroadcastPeerList()
		case <-evictTicker.C:
			m.table.EvictStale()
		}
	}
}

func (m *Manager) connectBootstraps() {
	for _, addr := range m.bootstraps {
		if err := m.node.Connect(addr); err != nil {
			log.Printf("[discovery] bootstrap %s: %v", addr, err)
		}
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// GetEntry returns the raw mutable entry — use for testing/inspection only.
func (pt *PeerTable) GetEntry(id string) (*PeerEntry, bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	e, ok := pt.entries[id]
	return e, ok
}
