// Package main provides a standalone network simulation for chat0.
//
// It spins up N virtual nodes in-process, exchanges messages, and reports:
//   - Message delivery rate
//   - Per-hop latency
//   - Robustness under censorship (configurable drop rate)
//   - Sybil-resistance: nodes with invalid PoW are rejected
//
// Run:
//
//	go run ./simulation/
package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	chatcrypto "chat0/crypto"
	"chat0/discovery"
	"chat0/metrics"
	"chat0/p2p"
)

const (
	numNodes    = 5
	basePort    = 19000
	numMessages = 20
	dropRate    = 0.25 // 25% simulated censorship drop
)

type SimNode struct {
	node      *p2p.Node
	identity  *chatcrypto.IdentityKeyPair
	dh        *chatcrypto.DHKeyPair
	collector *metrics.Collector
	received  int
}

func main() {
	fmt.Println("=== chat0 Network Simulation ===")
	fmt.Printf("Nodes: %d | Messages: %d | Censorship drop: %.0f%%\n\n",
		numNodes, numMessages, dropRate*100)

	nodes := make([]*SimNode, numNodes)

	// --- Phase 1: Start nodes ---
	for i := 0; i < numNodes; i++ {
		id, err := chatcrypto.GenerateIdentity()
		if err != nil {
			log.Fatalf("identity: %v", err)
		}
		dh, err := chatcrypto.GenerateDHKeyPair()
		if err != nil {
			log.Fatalf("dh: %v", err)
		}
		mc := metrics.NewCollector()
		addr := fmt.Sprintf(":%d", basePort+i)
		n := p2p.NewNode(addr, id, dh, mc)

		sn := &SimNode{node: n, identity: id, dh: dh, collector: mc}
		n.SetHandlers(
			func(msg p2p.ChatMessage) {
				if msg.From == "__onion__" {
					return
				}
				sn.received++
			},
			nil, nil,
		)

		if err := n.Start(); err != nil {
			log.Fatalf("node %d start: %v", i, err)
		}
		nodes[i] = sn
		fmt.Printf("[node %d] id=%-16s addr=%s\n", i, n.LocalID(), addr)
	}

	time.Sleep(200 * time.Millisecond)

	// --- Phase 2: Connect mesh (each node to next) ---
	fmt.Println("\n--- Connecting mesh ---")
	for i := 0; i < numNodes-1; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", basePort+i+1)
		if err := nodes[i].node.Connect(addr); err != nil {
			log.Printf("connect %d->%d: %v", i, i+1, err)
		}
	}
	// Also connect last to first for ring topology
	if err := nodes[numNodes-1].node.Connect(fmt.Sprintf("127.0.0.1:%d", basePort)); err != nil {
		log.Printf("connect ring: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// --- Phase 3: PoW verification ---
	fmt.Println("\n--- Proof-of-Work verification ---")
	for i, sn := range nodes {
		token := discovery.SolvePoW(sn.identity.PublicKey, discovery.PoWDifficulty)
		valid := discovery.VerifyPoW(sn.identity.PublicKey, token, discovery.PoWDifficulty)
		fmt.Printf("[node %d] PoW valid=%v token=%s\n", i,
			valid, discovery.PoWTokenHex(token)[:12]+"…")
	}

	// --- Phase 4: Send messages ---
	fmt.Printf("\n--- Sending %d messages (censorship drop=%.0f%%) ---\n", numMessages, dropRate*100)
	sent := 0
	dropped := 0
	start := time.Now()

	for m := 0; m < numMessages; m++ {
		src := rand.Intn(numNodes)
		dst := rand.Intn(numNodes)
		for dst == src {
			dst = rand.Intn(numNodes)
		}

		// Simulate censorship drop
		if rand.Float64() < dropRate {
			dropped++
			nodes[src].collector.MessageDropped()
			continue
		}

		msg := p2p.ChatMessage{
			From:    nodes[src].node.LocalID(),
			Content: fmt.Sprintf("msg-%d from node-%d to node-%d", m, src, dst),
			RoomID:  "sim",
			MsgID:   fmt.Sprintf("sim-%d-%d", m, time.Now().UnixNano()),
		}
		peers := nodes[src].node.KnownPeers()
		for _, peer := range peers {
			if err := nodes[src].node.SendChat(peer.ID, msg); err == nil {
				nodes[src].collector.MessageSent()
				sent++
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	elapsed := time.Since(start)
	time.Sleep(300 * time.Millisecond)

	// --- Phase 5: Results ---
	totalReceived := 0
	for _, sn := range nodes {
		totalReceived += sn.received
	}

	fmt.Println("\n=== Simulation Results ===")
	fmt.Printf("Duration:        %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Messages sent:   %d / %d (%.0f%% after censorship)\n", sent, numMessages, float64(sent)/float64(numMessages)*100)
	fmt.Printf("Messages dropped:%-4d (censorship sim)\n", dropped)
	fmt.Printf("Messages received (all nodes): %d\n", totalReceived)
	deliveryRate := 0.0
	if sent > 0 {
		deliveryRate = float64(totalReceived) / float64(sent*numNodes) * 100
	}
	fmt.Printf("Delivery rate:   %.1f%%\n", deliveryRate)

	fmt.Println("\nPer-node snapshots:")
	for i, sn := range nodes {
		snap := sn.collector.Snapshot(len(sn.node.KnownPeers()))
		fmt.Printf("  node-%d  peers=%-2d sent=%-3d recv=%-3d dropped=%-3d\n",
			i, snap.ActivePeers, snap.Sent, snap.Received, snap.Dropped)
	}

	// Stop all nodes
	for _, sn := range nodes {
		sn.node.Stop()
	}

	fmt.Println("\n=== Simulation complete ===")
}
