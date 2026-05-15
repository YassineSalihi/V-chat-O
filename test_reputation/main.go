package main

import (
	"fmt"
	"time"

	"chat0/crypto"
	"chat0/discovery"
	"chat0/p2p"
)

func main() {
	table := discovery.NewPeerTable()

	// Create two real identities with valid PoW
	idA, _ := crypto.GenerateIdentity()
	idB, _ := crypto.GenerateIdentity()

	fmt.Println("Solving PoW for peer A...")
	powA := discovery.SolvePoW(idA.PublicKey, discovery.PoWDifficulty)
	fmt.Println("Solving PoW for peer B...")
	powB := discovery.SolvePoW(idB.PublicKey, discovery.PoWDifficulty)

	infoA := p2p.PeerInfo{ID: crypto.PubKeyID(idA.PublicKey), Addr: ":9001", PubKey: idA.PublicKey}
	infoB := p2p.PeerInfo{ID: crypto.PubKeyID(idB.PublicKey), Addr: ":9002", PubKey: idB.PublicKey}

	table.Add(infoA, powA)
	table.Add(infoB, powB)

	fmt.Println("\n=== Initial state ===")
	printTable(table)

	// --- Sybil rejection ---
	fmt.Println("\n=== Sybil rejection (invalid PoW) ===")
	idFake, _ := crypto.GenerateIdentity()
	fakeInfo := p2p.PeerInfo{
		ID:     crypto.PubKeyID(idFake.PublicKey),
		Addr:   ":9999",
		PubKey: idFake.PublicKey,
	}
	err := table.Add(fakeInfo, make([]byte, 8)) // zero nonce, won't satisfy PoW
	fmt.Printf("  fake peer admitted: %v  (err: %v)\n", err == nil, err)

	// --- Reputation degradation ---
	fmt.Println("\n=== Simulating failures for peer B ===")
	for i := 1; i <= 6; i++ {
		table.RecordFailure(infoB.ID)
		if e, ok := table.Get(infoB.ID); ok {
			fmt.Printf("  failure %d: rep=%d failures=%d\n", i, e.Reputation, e.Failures)
		} else {
			fmt.Printf("  failure %d: EVICTED from table\n", i)
		}
	}

	fmt.Println("\n=== After eviction ===")
	printTable(table)

	// --- Relay selection excludes evicted peer ---
	fmt.Println("\n=== Relay candidates (peer B should be absent) ===")
	candidates := table.RelayCandidate("self", 5)
	if len(candidates) == 0 {
		fmt.Println("  (none — not enough peers)")
	}
	for _, c := range candidates {
		fmt.Printf("  candidate %s  rep=%d\n", c.ID[:8], c.Reputation)
	}

	// --- Reward peer A ---
	fmt.Println("\n=== Rewarding peer A (5 successes) ===")
	for i := 0; i < 5; i++ {
		table.RecordSuccess(infoA.ID)
	}
	printTable(table)

	// --- Stale eviction ---
	fmt.Println("\n=== Stale TTL eviction ===")
	// Re-add peer B with valid PoW so we can test stale eviction
	idC, _ := crypto.GenerateIdentity()
	fmt.Println("  Solving PoW for peer C...")
	powC := discovery.SolvePoW(idC.PublicKey, discovery.PoWDifficulty)
	infoC := p2p.PeerInfo{ID: crypto.PubKeyID(idC.PublicKey), Addr: ":9003", PubKey: idC.PublicKey}
	table.Add(infoC, powC)

	// Backdate C's LastSeen beyond TTL (2 hours)
	if e, ok := table.GetEntry(infoC.ID); ok {
		e.LastSeen = time.Now().Add(-3 * time.Hour)
		fmt.Printf("  peer C LastSeen backdated to 3h ago\n")
	}
	table.EvictStale()
	_, stillHere := table.Get(infoC.ID)
	fmt.Printf("  peer C evicted after TTL: %v\n", !stillHere)

	fmt.Println("\n=== Final table ===")
	printTable(table)
}

func printTable(table *discovery.PeerTable) {
	entries := table.All()
	if len(entries) == 0 {
		fmt.Println("  (empty)")
		return
	}
	for _, e := range entries {
		fmt.Printf("  peer %-10s  addr=%-6s  rep=%3d  failures=%d\n",
			e.ID[:8], e.Addr, e.Reputation, e.Failures)
	}
}
