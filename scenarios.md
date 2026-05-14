# Scenarios

A "scenario" here means running multiple `chat0` nodes and testing specific behaviours. Here are the main ones:

## Scenario 1 — Basic 2-node chat (same machine)

The simplest test. Two nodes talk directly.

```bash
# Terminal 1
./build/bin/chat0
# Note the Listen address shown in sidebar: :9000

# Terminal 2
./build/bin/chat0
# This one gets :9001 automatically
```

* In Terminal 2's UI → **Connect box** → type `127.0.0.1:9000` → **Connect**.
* Now type in the general room on either side and messages appear on the other.
* **What you're testing:** handshake, AES-256-GCM encryption, Ed25519 signature verification.

---

## Scenario 2 — Onion routing (3+ nodes needed)

Onion routing only anonymises when there are real relay hops. You need at least 3 nodes.

```bash
# Terminal 1 — Node A (:9000)
./build/bin/chat0

# Terminal 2 — Node B (:9001)
./build/bin/chat0

# Terminal 3 — Node C (:9002)
./build/bin/chat0
```

Connect them into a chain:

* Node B connects to `127.0.0.1:9000`
* Node C connects to `127.0.0.1:9001`

Now on Node A, toggle **Onion routing ON** in the sidebar, then send a message. Node A wraps it in 3 AES layers: A→B→C→destination. Messages arrive with the 🧅 badge.

* **What you're testing:** `onion.WrapMessage` / `PeelLayer`, relay forwarding, per-layer X25519 key agreement.

---

## Scenario 3 — Gossip peer discovery

Tests that nodes find each other automatically without manual connection.

```bash
# Start 3 nodes as above, but only connect A→B
# Do NOT manually connect C to anyone
```

Wait ~60 seconds. Node B broadcasts its peer list (which includes A) to C. Node C then auto-connects to A. You'll see the peer count increase on all nodes without doing anything.

* **What you're testing:** `BroadcastPeerList`, gossip propagation, automatic connect on peer-list receipt.

---

## Scenario 4 — Censorship simulation

Tests message delivery under packet loss, without needing a real firewall. On any running node, in the sidebar:

1. Check **Censorship sim**.
2. Set the drop rate slider to e.g., **50%**.
3. Send messages from another node through this one as a relay.
4. Watch the **Dropped** counter in the metrics panel climb. Delivery rate will fall below 100%. You can compare delivery rate at 0%, 25%, 50%, and 75% drop to evaluate robustness.

* **What you're testing:** `SetCensorshipSimulation`, `metrics.MessageDropped`, how onion circuits degrade under loss.

---

## Scenario 5 — Sybil attack resistance

Tests that fake identities are rejected without valid PoW. Run the simulation harness and read the output:

```bash
go run ./simulation/
```

The harness explicitly calls `VerifyPoW` on each node's token and prints pass or fail. To simulate a Sybil attacker, you can edit `simulation/main.go` and add a node with a zeroed PoW token:

```go
// Fake attacker node — invalid PoW
fakeToken := make([]byte, 8) // all zeros, won't satisfy difficulty 20
valid := discovery.VerifyPoW(nodes.identity.PublicKey, fakeToken, discovery.PoWDifficulty)
fmt.Printf("Attacker admitted: %v\n", valid) // prints: false
```

* **What you're testing:** `SolvePoW` / `VerifyPoW`, the SHA-256 difficulty check, `PeerTable.Add` rejection.

---

## Scenario 6 — Peer reputation and eviction

Tests that unreliable peers get deprioritised. In `simulation/main.go`, after nodes are connected, manually record failures for one node:

```go
// Simulate node-1 being unreliable
for i := 0; i < 6; i++ {
    nodes.peerTable.RecordFailure(nodes.node.LocalID())
}
// Check it got evicted
_, stillPresent := nodes.peerTable.Get(nodes.node.LocalID())
fmt.Printf("Unreliable peer evicted: %v\n", !stillPresent) // true after 5 failures
```

* **What you're testing:** `discovery.RecordFailure`, eviction threshold, that evicted peers are excluded from onion relay selection.

---

## Scenario 7 — Network partition and recovery

Simulates a node going offline and reconnecting.

```bash
# Start nodes A, B, C connected in a ring
# Kill node B (Ctrl+C in its terminal)
# Wait 30 seconds — A and C detect the dead peer via ping timeout

# Restart node B
./build/bin/chat0
# B reconnects to A; gossip re-establishes the ring within 60s
```

Watch the peer count in the metrics panel drop to 1 when B dies, then recover to 2 when B comes back.

* **What you're testing:** ping keepalive, connection error handling, gossip-based reconnection.

---

## Running All Scenarios Automatically

The fastest way to test everything in one shot — no UI needed:

```bash
go run ./simulation/
```

This covers scenarios 1, 3, 4, and 5 automatically. For scenarios 2, 6, and 7, you can extend `simulation/main.go` with the code snippets provided above and re-run.
