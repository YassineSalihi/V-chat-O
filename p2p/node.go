// Package p2p implements the peer-to-peer networking layer for chat0.
//
// Architecture:
//   - Each node listens on a TCP port and maintains a peer table.
//   - Messages are framed with a 4-byte big-endian length prefix.
//   - All wire traffic is encrypted with the shared session key derived via X25519.
//   - Nodes relay onion-routed packets for other peers (mix-net relay).
package p2p

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	chatcrypto "chat0/crypto"
	"chat0/metrics"
)

// MessageType identifies the purpose of a wire message.
type MessageType uint8

const (
	MsgChat      MessageType = 1 // Decrypted chat message (final destination)
	MsgOnion     MessageType = 2 // Onion-routed packet to relay or peel
	MsgHandshake MessageType = 3 // Key-exchange handshake
	MsgPing      MessageType = 4 // Keepalive
	MsgPeerList  MessageType = 5 // Peer discovery gossip
)

// WireMessage is the top-level framed message on the wire.
type WireMessage struct {
	Type      MessageType `json:"t"`
	Payload   []byte      `json:"p"`
	SenderID  string      `json:"sid"`
	Signature []byte      `json:"sig"`
	Timestamp int64       `json:"ts"`
}

// ChatMessage is the plaintext content of a delivered chat message.
type ChatMessage struct {
	From    string `json:"from"`
	Content string `json:"content"`
	RoomID  string `json:"room"`
	MsgID   string `json:"mid"` // Random ID for dedup
}

// PeerInfo contains metadata about a known peer.
type PeerInfo struct {
	ID      string    `json:"id"`   // Hex pubkey fingerprint
	Addr    string    `json:"addr"` // "host:port"
	PubKey  []byte    `json:"pub"`  // Ed25519 pubkey bytes
	DHPub   [32]byte  `json:"dh"`   // X25519 pubkey for onion
	SeenAt  time.Time `json:"seen"`
	Latency time.Duration
}

// Node is a chat0 P2P network node.
type Node struct {
	identity   *chatcrypto.IdentityKeyPair
	dhKeyPair  *chatcrypto.DHKeyPair
	listenAddr string
	listener   net.Listener

	mu         sync.RWMutex
	peers      map[string]*Peer // peerID -> Peer
	sessions   map[string][]byte // peerID -> symmetric session key

	onMessage  func(msg ChatMessage)
	onPeerJoin func(info PeerInfo)
	onPeerLeave func(id string)

	metrics    *metrics.Collector
	ctx        context.Context
	cancel     context.CancelFunc

	// seenMessages caches recent message IDs for deduplication
	seenMu   sync.Mutex
	seenMsgs map[string]time.Time
}

// Peer represents an active TCP connection to a remote node.
type Peer struct {
	info       PeerInfo
	conn       net.Conn
	sessionKey []byte
	sendMu     sync.Mutex
	lastPing   time.Time
}

// NewNode creates a new P2P node.
// listenAddr e.g. ":9000" or "0.0.0.0:9000".
func NewNode(listenAddr string, identity *chatcrypto.IdentityKeyPair, dh *chatcrypto.DHKeyPair, mc *metrics.Collector) *Node {
	ctx, cancel := context.WithCancel(context.Background())
	return &Node{
		identity:   identity,
		dhKeyPair:  dh,
		listenAddr: listenAddr,
		peers:      make(map[string]*Peer),
		sessions:   make(map[string][]byte),
		metrics:    mc,
		ctx:        ctx,
		cancel:     cancel,
		seenMsgs:   make(map[string]time.Time),
	}
}

// SetHandlers sets the application callbacks.
func (n *Node) SetHandlers(onMsg func(ChatMessage), onJoin func(PeerInfo), onLeave func(string)) {
	n.onMessage = onMsg
	n.onPeerJoin = onJoin
	n.onPeerLeave = onLeave
}

// Start begins listening for incoming connections.
func (n *Node) Start() error {
	ln, err := net.Listen("tcp", n.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", n.listenAddr, err)
	}
	n.listener = ln
	log.Printf("[p2p] listening on %s (id=%s)", n.listenAddr, n.LocalID())
	go n.acceptLoop()
	go n.maintenanceLoop()
	return nil
}

// Stop shuts down the node.
func (n *Node) Stop() {
	n.cancel()
	if n.listener != nil {
		n.listener.Close()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range n.peers {
		p.conn.Close()
	}
}

// LocalID returns the node's identity fingerprint.
func (n *Node) LocalID() string {
	return chatcrypto.PubKeyID(n.identity.PublicKey)
}

// LocalDHPub returns the node's X25519 public key.
func (n *Node) LocalDHPub() [32]byte {
	return n.dhKeyPair.PublicKey
}

// Connect dials a remote peer and performs the handshake.
func (n *Node) Connect(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	go n.handleConnection(conn, true)
	return nil
}

// KnownPeers returns a snapshot of currently connected peers.
func (n *Node) KnownPeers() []PeerInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]PeerInfo, 0, len(n.peers))
	for _, p := range n.peers {
		out = append(out, p.info)
	}
	return out
}

// SendChat sends a plaintext chat message directly to a peer (encrypted with session key).
func (n *Node) SendChat(peerID string, msg ChatMessage) error {
	n.mu.RLock()
	peer, ok := n.peers[peerID]
	n.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s not connected", peerID)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	encrypted, err := chatcrypto.Encrypt(peer.sessionKey, data)
	if err != nil {
		return err
	}

	return n.sendWire(peer, WireMessage{
		Type:      MsgChat,
		Payload:   encrypted,
		SenderID:  n.LocalID(),
		Signature: chatcrypto.Sign(n.identity.PrivateKey, encrypted),
		Timestamp: time.Now().UnixMilli(),
	})
}

// RelayOnion forwards a raw onion packet to the next hop (used by relay nodes).
func (n *Node) RelayOnion(addr string, packet []byte) error {
	n.mu.RLock()
	var target *Peer
	for _, p := range n.peers {
		if p.info.Addr == addr {
			target = p
			break
		}
	}
	n.mu.RUnlock()

	if target == nil {
		// Try to connect on-demand
		if err := n.Connect(addr); err != nil {
			return fmt.Errorf("relay connect to %s: %w", addr, err)
		}
		// Retry after short delay to let handshake complete
		time.Sleep(300 * time.Millisecond)
		n.mu.RLock()
		for _, p := range n.peers {
			if p.info.Addr == addr {
				target = p
				break
			}
		}
		n.mu.RUnlock()
		if target == nil {
			return fmt.Errorf("relay: could not reach %s", addr)
		}
	}

	return n.sendWire(target, WireMessage{
		Type:      MsgOnion,
		Payload:   packet,
		SenderID:  n.LocalID(),
		Signature: chatcrypto.Sign(n.identity.PrivateKey, packet),
		Timestamp: time.Now().UnixMilli(),
	})
}

// BroadcastPeerList gossips our peer list to all connected nodes.
func (n *Node) BroadcastPeerList() {
	infos := n.KnownPeers()
	data, err := json.Marshal(infos)
	if err != nil {
		return
	}
	n.mu.RLock()
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.mu.RUnlock()

	for _, p := range peers {
		_ = n.sendWire(p, WireMessage{
			Type:      MsgPeerList,
			Payload:   data,
			SenderID:  n.LocalID(),
			Timestamp: time.Now().UnixMilli(),
		})
	}
}

// --- internal ---

func (n *Node) acceptLoop() {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
				log.Printf("[p2p] accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		go n.handleConnection(conn, false)
	}
}

func (n *Node) handleConnection(conn net.Conn, weDialed bool) {
	defer conn.Close()

	// Perform handshake
	peer, err := n.doHandshake(conn, weDialed)
	if err != nil {
		log.Printf("[p2p] handshake failed with %s: %v", conn.RemoteAddr(), err)
		return
	}

	n.mu.Lock()
	n.peers[peer.info.ID] = peer
	n.mu.Unlock()

	log.Printf("[p2p] peer connected: %s @ %s", peer.info.ID, peer.info.Addr)
	if n.onPeerJoin != nil {
		n.onPeerJoin(peer.info)
	}
	n.metrics.PeerConnected(peer.info.ID)

	defer func() {
		n.mu.Lock()
		delete(n.peers, peer.info.ID)
		n.mu.Unlock()
		if n.onPeerLeave != nil {
			n.onPeerLeave(peer.info.ID)
		}
		n.metrics.PeerDisconnected(peer.info.ID)
		log.Printf("[p2p] peer disconnected: %s", peer.info.ID)
	}()

	// Read loop
	for {
		msg, err := n.readWire(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[p2p] read from %s: %v", peer.info.ID, err)
			}
			return
		}
		n.metrics.MessageReceived(peer.info.ID, len(msg.Payload))
		n.handleMessage(peer, msg)
	}
}

// HandshakeMsg is exchanged during connection setup.
type HandshakeMsg struct {
	PeerID  string   `json:"id"`
	PubKey  []byte   `json:"pub"`   // Ed25519
	DHPub   [32]byte `json:"dh"`    // X25519
	Addr    string   `json:"addr"`  // listener address
	Nonce   []byte   `json:"nonce"` // 32 random bytes
}

func (n *Node) doHandshake(conn net.Conn, weDialed bool) (*Peer, error) {
	nonce, _ := chatcrypto.RandomBytes(32)
	mine := HandshakeMsg{
		PeerID: n.LocalID(),
		PubKey: n.identity.PublicKey,
		DHPub:  n.dhKeyPair.PublicKey,
		Addr:   n.listenAddr,
		Nonce:  nonce,
	}
	mineBytes, _ := json.Marshal(mine)
	if err := writeFrame(conn, mineBytes); err != nil {
		return nil, fmt.Errorf("send handshake: %w", err)
	}

	theirBytes, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("recv handshake: %w", err)
	}
	var their HandshakeMsg
	if err := json.Unmarshal(theirBytes, &their); err != nil {
		return nil, fmt.Errorf("decode handshake: %w", err)
	}

	// Derive session key from DH
	theirEd := ed25519.PublicKey(their.PubKey)
	sessionKey, err := chatcrypto.DeriveSharedSecret(n.dhKeyPair.PrivateKey, their.DHPub, "chat0-session")
	if err != nil {
		return nil, fmt.Errorf("session DH: %w", err)
	}

	peer := &Peer{
		info: PeerInfo{
			ID:     chatcrypto.PubKeyID(theirEd),
			Addr:   their.Addr,
			PubKey: their.PubKey,
			DHPub:  their.DHPub,
			SeenAt: time.Now(),
		},
		conn:       conn,
		sessionKey: sessionKey,
		lastPing:   time.Now(),
	}

	// Detect real remote address if they don't know their external addr
	if peer.info.Addr == "" || peer.info.Addr == ":0" {
		peer.info.Addr = conn.RemoteAddr().String()
	}
	_ = weDialed
	return peer, nil
}

func (n *Node) handleMessage(peer *Peer, msg WireMessage) {
	switch msg.Type {
	case MsgChat:
		// Verify signature
		if !chatcrypto.Verify(ed25519.PublicKey(peer.info.PubKey), msg.Payload, msg.Signature) {
			log.Printf("[p2p] signature verification failed from %s", peer.info.ID)
			return
		}
		// Decrypt
		plain, err := chatcrypto.Decrypt(peer.sessionKey, msg.Payload)
		if err != nil {
			log.Printf("[p2p] decrypt chat from %s: %v", peer.info.ID, err)
			return
		}
		var chat ChatMessage
		if err := json.Unmarshal(plain, &chat); err != nil {
			return
		}
		if n.dedup(chat.MsgID) {
			return
		}
		if n.onMessage != nil {
			n.onMessage(chat)
		}

	case MsgOnion:
		// This node is a relay or destination for an onion packet.
		// The node-level handler (App) will peel the layer.
		// Here we just pass the raw packet up.
		if n.onMessage != nil {
			// Signal as an onion relay task (App will handle peel+forward)
			n.onMessage(ChatMessage{
				From:    "__onion__",
				Content: string(msg.Payload),
				MsgID:   fmt.Sprintf("onion-%d", msg.Timestamp),
			})
		}

	case MsgPeerList:
		var peerInfos []PeerInfo
		if err := json.Unmarshal(msg.Payload, &peerInfos); err != nil {
			return
		}
		// Merge into our known peers and try to connect to unknown ones
		for _, info := range peerInfos {
			if info.ID == n.LocalID() {
				continue
			}
			n.mu.RLock()
			_, known := n.peers[info.ID]
			n.mu.RUnlock()
			if !known {
				// REPLACE WITH:
				go func(knownAddr, advertisedAddr string) {
					addr := resolveGossipAddr(knownAddr, advertisedAddr)
					if err := n.Connect(addr); err != nil {
						log.Printf("[p2p] gossip-connect to %s: %v", addr, err)
					}
				}(peer.info.Addr, info.Addr)
			}
		}

	case MsgPing:
		// Reply with a pong (reuse ping type)
		_ = n.sendWire(peer, WireMessage{
			Type:      MsgPing,
			SenderID:  n.LocalID(),
			Timestamp: time.Now().UnixMilli(),
		})

	default:
		log.Printf("[p2p] unknown message type %d from %s", msg.Type, peer.info.ID)
	}
}

func (n *Node) maintenanceLoop() {
	ticker := time.NewTicker(30 * time.Second)
	gossipTicker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer gossipTicker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.pingPeers()
			n.cleanSeenMsgs()
		case <-gossipTicker.C:
			n.BroadcastPeerList()
		}
	}
}

func (n *Node) pingPeers() {
	n.mu.RLock()
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.mu.RUnlock()

	for _, p := range peers {
		start := time.Now()
		err := n.sendWire(p, WireMessage{
			Type:      MsgPing,
			SenderID:  n.LocalID(),
			Timestamp: start.UnixMilli(),
		})
		if err != nil {
			log.Printf("[p2p] ping %s failed: %v", p.info.ID, err)
		} else {
			p.info.Latency = time.Since(start)
			n.metrics.RecordLatency(p.info.ID, p.info.Latency)
		}
	}
}

func (n *Node) dedup(msgID string) bool {
	if msgID == "" {
		return false
	}
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	if _, seen := n.seenMsgs[msgID]; seen {
		return true
	}
	n.seenMsgs[msgID] = time.Now()
	return false
}

func (n *Node) cleanSeenMsgs() {
	cutoff := time.Now().Add(-10 * time.Minute)
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	for id, t := range n.seenMsgs {
		if t.Before(cutoff) {
			delete(n.seenMsgs, id)
		}
	}
}

// sendWire serializes and sends a WireMessage to a peer.
func (n *Node) sendWire(peer *Peer, msg WireMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	peer.sendMu.Lock()
	defer peer.sendMu.Unlock()
	peer.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return writeFrame(peer.conn, data)
}

// readWire reads and deserializes a WireMessage.
func (n *Node) readWire(conn net.Conn) (WireMessage, error) {
	conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	data, err := readFrame(conn)
	if err != nil {
		return WireMessage{}, err
	}
	var msg WireMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return WireMessage{}, err
	}
	return msg, nil
}

// writeFrame writes a length-prefixed frame.
func writeFrame(conn net.Conn, data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// readFrame reads a length-prefixed frame.
func readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size > 10*1024*1024 { // 10MB sanity cap
		return nil, fmt.Errorf("frame too large: %d bytes", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

// resolveGossipAddr builds a dialable address from a known connection's host
// and the port from a gossip-advertised address.
// e.g. knownAddr="192.168.1.5:9001", advertisedAddr=":9002" -> "192.168.1.5:9002"
func resolveGossipAddr(knownAddr, advertisedAddr string) string {
	host, _, err := net.SplitHostPort(knownAddr)
	if err != nil || host == "" {
		host = "127.0.0.1"
	}
	_, port, err := net.SplitHostPort(advertisedAddr)
	if err != nil {
		return advertisedAddr
	}
	return net.JoinHostPort(host, port)
}
