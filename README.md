# chat0 — P2P End-to-End Encrypted Chat

A fully decentralised, censorship-resistant instant messaging app built with Wails (Go + TypeScript).

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Wails Desktop App  (Go backend + TS frontend)   │
├────────────┬─────────────┬────────────┬──────────┤
│  crypto/   │   onion/    │  p2p/      │discovery/│
│ X25519 ECDH│ 3-hop onion │ TCP mesh   │PoW+gossip│
│ AES-256-GCM│ layered enc │ E2E frames │ reputation│
│ Ed25519 sig│ traffic pad │ peer gossip│ Sybil res│
└────────────┴─────────────┴────────────┴──────────┘
```

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per message, X25519 session key |
| Integrity | Ed25519 signature on every packet |
| Forward secrecy | Ephemeral DH keypair per session |
| Anonymity | 3-hop onion routing, X25519 per layer, fixed-size padding |
| Sybil resistance | SHA-256 Proof-of-Work (difficulty 20) per identity |
| Censorship resistance | Gossip discovery, custom bootstrap nodes, onion bypass |
| Replay protection | Random message IDs + 10-minute dedup window |

## Packages

### `crypto/`
- `GenerateIdentity()` — Ed25519 keypair for node identity & signatures
- `GenerateDHKeyPair()` — X25519 ephemeral keypair
- `DeriveSharedSecret()` — ECDH + HKDF-SHA256 key derivation
- `Encrypt()` / `Decrypt()` — AES-256-GCM with random nonce

### `onion/`
- `WrapMessage(plaintext, hops)` — layers 3 encryption envelopes
- `PeelLayer(packet, myDHPriv)` — relay: strip one layer and get next hop
- Fixed-size padding (4096 bytes) to prevent traffic-analysis correlation

### `p2p/`
- TCP listener with length-prefixed framing
- X25519 handshake on every connection
- Message types: Chat, Onion relay, Ping, PeerList gossip
- In-memory dedup of message IDs (10-minute window)

### `discovery/`
- `SolvePoW` / `VerifyPoW` — SHA-256 Hashcash with configurable difficulty
- `PeerTable` — reputation-scored peer store with TTL eviction
- `Manager` — periodic bootstrap reconnect + gossip broadcast

### `metrics/`
- Per-peer latency tracking (avg + P99)
- Delivery rate (sent vs received)
- Throughput in bytes/second
- Censorship simulation: configurable packet drop rate

## Building

```bash
# Prerequisites: Go 1.23+, Node.js 18+, Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Dev mode (hot reload)
wails dev

# Production build
wails build
```

## Running the Simulation

```bash
go run ./simulation/
```

Outputs:
- Message delivery rate
- Per-node sent/received/dropped counts
- Proof-of-Work validation
- Censorship-simulation results (default 25% drop rate)

## Adding Bootstrap Nodes

Edit `discovery/discovery.go`:
```go
var DefaultBootstrap = []string{
    "seed1.yourdomain.com:9000",
    "seed2.yourdomain.com:9000",
}
```

Or add them at runtime via the UI's **Bootstrap** input.

## Threat Model

- **Central server**: None. No DNS required after initial bootstrap.
- **Traffic analysis**: Onion routing + fixed-size padding obscures message size and timing.
- **Sybil attacks**: PoW (difficulty 20 ≈ 1M SHA-256 hashes) raises cost per fake identity.
- **Censorship**: Ring gossip mesh + user-supplied bootstrap list; nodes auto-reconnect.
- **Wiretapping**: All traffic encrypted; relay nodes see only previous and next hop.
