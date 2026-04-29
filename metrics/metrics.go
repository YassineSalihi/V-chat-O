// Package metrics collects real-time stats for the chat0 P2P network:
// latency per peer, message delivery rate, and censorship-simulation counters.
package metrics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Collector gathers network statistics.
type Collector struct {
	mu sync.RWMutex

	// Per-peer latency samples (sliding window of last 100)
	latencies map[string][]time.Duration

	// Message counters
	sent     int64
	received int64
	dropped  int64 // simulated censorship drops

	// Peer churn
	peerConnects    int64
	peerDisconnects int64

	// Per-second throughput samples
	throughputSamples []throughputSample

	// Censorship simulation toggle
	CensorshipMode bool
	// DropRate is the fraction of messages to drop when CensorshipMode is on (0.0–1.0).
	DropRate float64
}

type throughputSample struct {
	at    time.Time
	bytes int
}

// NewCollector creates a Collector.
func NewCollector() *Collector {
	return &Collector{
		latencies: make(map[string][]time.Duration),
		DropRate:  0.3, // 30% drop under simulated censorship
	}
}

// RecordLatency records a round-trip latency sample for a peer.
func (c *Collector) RecordLatency(peerID string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	samples := append(c.latencies[peerID], d)
	if len(samples) > 100 {
		samples = samples[len(samples)-100:]
	}
	c.latencies[peerID] = samples
}

// MessageReceived records an inbound message.
func (c *Collector) MessageReceived(peerID string, bytes int) {
	c.mu.Lock()
	c.received++
	c.throughputSamples = append(c.throughputSamples, throughputSample{at: time.Now(), bytes: bytes})
	c.mu.Unlock()
}

// MessageSent records an outbound message.
func (c *Collector) MessageSent() {
	c.mu.Lock()
	c.sent++
	c.mu.Unlock()
}

// MessageDropped records a censorship-simulated drop.
func (c *Collector) MessageDropped() {
	c.mu.Lock()
	c.dropped++
	c.mu.Unlock()
}

// PeerConnected records a peer join.
func (c *Collector) PeerConnected(id string) {
	c.mu.Lock()
	c.peerConnects++
	c.mu.Unlock()
}

// PeerDisconnected records a peer leave.
func (c *Collector) PeerDisconnected(id string) {
	c.mu.Lock()
	c.peerDisconnects++
	c.mu.Unlock()
}

// Snapshot is a point-in-time view of all metrics.
type Snapshot struct {
	Sent            int64            `json:"sent"`
	Received        int64            `json:"received"`
	Dropped         int64            `json:"dropped"`
	DeliveryRate    float64          `json:"delivery_rate"`    // received / (sent+received)
	PeerConnects    int64            `json:"peer_connects"`
	PeerDisconnects int64            `json:"peer_disconnects"`
	ActivePeers     int              `json:"active_peers"`
	AvgLatencyMs    float64          `json:"avg_latency_ms"`
	P99LatencyMs    float64          `json:"p99_latency_ms"`
	ThroughputBps   float64          `json:"throughput_bps"`
	PerPeerLatency  map[string]float64 `json:"per_peer_latency_ms"`
	CensorshipMode  bool             `json:"censorship_mode"`
	DropRate        float64          `json:"drop_rate"`
}

// Snapshot collects and returns the current metrics snapshot.
func (c *Collector) Snapshot(activePeers int) Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.sent + c.received
	deliveryRate := 0.0
	if total > 0 {
		deliveryRate = float64(c.received) / float64(total) * 100
	}

	// Aggregate all latency samples
	var allSamples []time.Duration
	perPeer := make(map[string]float64, len(c.latencies))
	for id, samples := range c.latencies {
		if len(samples) == 0 {
			continue
		}
		var sum time.Duration
		for _, s := range samples {
			sum += s
			allSamples = append(allSamples, s)
		}
		perPeer[id] = float64(sum.Milliseconds()) / float64(len(samples))
	}

	avgMs, p99Ms := latencyStats(allSamples)

	// Throughput: bytes received in last 5s
	cutoff := time.Now().Add(-5 * time.Second)
	var recentBytes int
	for _, s := range c.throughputSamples {
		if s.at.After(cutoff) {
			recentBytes += s.bytes
		}
	}
	throughputBps := float64(recentBytes) / 5.0

	return Snapshot{
		Sent:            c.sent,
		Received:        c.received,
		Dropped:         c.dropped,
		DeliveryRate:    deliveryRate,
		PeerConnects:    c.peerConnects,
		PeerDisconnects: c.peerDisconnects,
		ActivePeers:     activePeers,
		AvgLatencyMs:    avgMs,
		P99LatencyMs:    p99Ms,
		ThroughputBps:   throughputBps,
		PerPeerLatency:  perPeer,
		CensorshipMode:  c.CensorshipMode,
		DropRate:        c.DropRate,
	}
}

// FormatSummary returns a human-readable one-liner.
func (s Snapshot) FormatSummary() string {
	return fmt.Sprintf(
		"peers=%d sent=%d recv=%d dropped=%d delivery=%.1f%% avg_lat=%.1fms p99=%.1fms bw=%.0fB/s censorship=%v",
		s.ActivePeers, s.Sent, s.Received, s.Dropped,
		s.DeliveryRate, s.AvgLatencyMs, s.P99LatencyMs,
		s.ThroughputBps, s.CensorshipMode,
	)
}

func latencyStats(samples []time.Duration) (avg, p99 float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	sorted := make([]float64, len(samples))
	var sum float64
	for i, s := range samples {
		ms := float64(s.Milliseconds())
		sorted[i] = ms
		sum += ms
	}
	sort.Float64s(sorted)
	avg = sum / float64(len(sorted))
	p99 = sorted[int(math.Ceil(float64(len(sorted))*0.99))-1]
	return
}
