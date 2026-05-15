// Package main implements the chat0 Wails application backend.
//
// On startup the App:
//  1. Generates (or loads) an Ed25519 identity and X25519 DH keypair.
//  2. Starts the P2P node (TCP listener).
//  3. Solves a Proof-of-Work token and starts the discovery manager.
//  4. Exposes Wails-bound methods to the TypeScript frontend.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"chat0/crypto"
	"chat0/discovery"
	"chat0/metrics"
	"chat0/onion"
	"chat0/p2p"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails application struct.
type App struct {
	ctx context.Context

	identity  *crypto.IdentityKeyPair
	dhKeyPair *crypto.DHKeyPair

	node       *p2p.Node
	peerTable  *discovery.PeerTable
	discMgr    *discovery.Manager
	collector  *metrics.Collector

	mu       sync.RWMutex
	messages []UIMessage
	rooms    map[string][]UIMessage

	listenAddr string
	powToken   []byte
}

// UIMessage is the shape of a message sent to the frontend.
type UIMessage struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	FromID    string `json:"fromId"`
	Content   string `json:"content"`
	RoomID    string `json:"room"`
	Timestamp int64  `json:"ts"`
	Encrypted bool   `json:"encrypted"`
	Onion     bool   `json:"onion"`
}

// UINodeInfo is returned to the frontend on startup.
type UINodeInfo struct {
	NodeID     string `json:"nodeId"`
	ListenAddr string `json:"listenAddr"`
	PowToken   string `json:"powToken"`
}

// UIPeer is a peer as displayed in the UI.
type UIPeer struct {
	ID         string  `json:"id"`
	Addr       string  `json:"addr"`
	Reputation int     `json:"reputation"`
	LatencyMs  float64 `json:"latencyMs"`
}

// NewApp creates the App struct.
func NewApp() *App {
	return &App{
		rooms: make(map[string][]UIMessage),
	}
}

// startup is called by Wails after the frontend is ready.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	id, err := crypto.GenerateIdentity()
	if err != nil {
		log.Fatalf("generate identity: %v", err)
	}
	a.identity = id

	dh, err := crypto.GenerateDHKeyPair()
	if err != nil {
		log.Fatalf("generate DH keypair: %v", err)
	}
	a.dhKeyPair = dh

	a.collector = metrics.NewCollector()

// REPLACE WITH:
	started := false
	for port := 9000; port < 9010; port++ {
		a.listenAddr = fmt.Sprintf(":%d", port)
		a.node = p2p.NewNode(a.listenAddr, a.identity, a.dhKeyPair, a.collector)
		a.node.SetHandlers(a.onMessage, a.onPeerJoin, a.onPeerLeave)
		if err := a.node.Start(); err == nil {
			started = true
			break
		}
	}
	if !started {
		log.Fatalf("p2p: could not bind any port in range 9000-9009")
	}

	a.peerTable = discovery.NewPeerTable()
	a.discMgr = discovery.NewManager(a.node, a.peerTable, a.identity.PublicKey, discovery.DefaultBootstrap)
	a.powToken = a.discMgr.SelfPoW()
	a.discMgr.Start()

	log.Printf("[app] node id=%s  addr=%s  pow=%s",
		a.node.LocalID(), a.listenAddr, hex.EncodeToString(a.powToken))
}

// GetNodeInfo returns this node's identity and address.
func (a *App) GetNodeInfo() UINodeInfo {
	return UINodeInfo{
		NodeID:     a.node.LocalID(),
		ListenAddr: a.listenAddr,
		PowToken:   hex.EncodeToString(a.powToken),
	}
}

// ConnectPeer connects to a remote peer by address.
func (a *App) ConnectPeer(addr string) string {
	if err := a.node.Connect(addr); err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return "connecting to " + addr
}

// GetPeers returns the list of connected peers.
func (a *App) GetPeers() []UIPeer {
	peers := a.node.KnownPeers()
	out := make([]UIPeer, 0, len(peers))
	for _, p := range peers {
		e, ok := a.peerTable.Get(p.ID)
		rep := 50
		lat := 0.0
		if ok {
			rep = e.Reputation
			lat = float64(p.Latency.Milliseconds())
		}
		out = append(out, UIPeer{
			ID:         p.ID,
			Addr:       p.Addr,
			Reputation: rep,
			LatencyMs:  lat,
		})
	}
	return out
}

// SendMessage sends a chat message to all peers in a room.
func (a *App) SendMessage(room, content string, useOnion bool) string {
	if content == "" {
		return "error: empty message"
	}
	msgID := randHex(8)
	msg := p2p.ChatMessage{
		From:    a.node.LocalID(),
		Content: content,
		RoomID:  room,
		MsgID:   msgID,
	}

	peers := a.node.KnownPeers()
	if len(peers) == 0 {
		a.storeMessage(UIMessage{
			ID: msgID, From: "me", FromID: a.node.LocalID(),
			Content: content, RoomID: room,
			Timestamp: time.Now().UnixMilli(), Encrypted: true,
		})
		return "no peers (stored locally)"
	}

	sent := 0
	for _, peer := range peers {
		if useOnion {
			if err := a.sendViaOnion(peer, msg); err != nil {
				log.Printf("[app] onion send to %s: %v", peer.ID, err)
			} else {
				sent++
			}
		} else {
			if err := a.node.SendChat(peer.ID, msg); err != nil {
				log.Printf("[app] direct send to %s: %v", peer.ID, err)
			} else {
				sent++
				a.collector.MessageSent()
			}
		}
	}

	a.storeMessage(UIMessage{
		ID: msgID, From: "me", FromID: a.node.LocalID(),
		Content: content, RoomID: room,
		Timestamp: time.Now().UnixMilli(), Encrypted: true, Onion: useOnion,
	})
	return fmt.Sprintf("sent to %d/%d peers", sent, len(peers))
}

// GetMessages returns stored messages for a room.
func (a *App) GetMessages(room string) []UIMessage {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if room == "" {
		return a.messages
	}
	return a.rooms[room]
}

// GetMetrics returns a JSON snapshot of network metrics.
func (a *App) GetMetrics() string {
	snap := a.collector.Snapshot(len(a.node.KnownPeers()))
	data, _ := json.Marshal(snap)
	return string(data)
}

// SetCensorshipSimulation toggles the censorship simulation.
func (a *App) SetCensorshipSimulation(enabled bool, dropRate float64) string {
	a.collector.CensorshipMode = enabled
	a.collector.DropRate = dropRate
	if enabled {
		return fmt.Sprintf("censorship simulation ON (drop=%.0f%%)", dropRate*100)
	}
	return "censorship simulation OFF"
}

// AddBootstrap adds and connects to a bootstrap node.
func (a *App) AddBootstrap(addr string) string {
	if err := a.node.Connect(addr); err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return "bootstrap added: " + addr
}

// GetNetworkSummary returns a human-readable one-liner for the status bar.
func (a *App) GetNetworkSummary() string {
	snap := a.collector.Snapshot(len(a.node.KnownPeers()))
	return snap.FormatSummary()
}

// ---- internal helpers ----

func (a *App) onMessage(msg p2p.ChatMessage) {
	if msg.From == "__onion__" {
		a.handleOnionPacket([]byte(msg.Content))
		return
	}
	uiMsg := UIMessage{
		ID: randHex(8), From: msg.From, FromID: msg.From,
		Content: msg.Content, RoomID: msg.RoomID,
		Timestamp: time.Now().UnixMilli(), Encrypted: true,
	}
	a.storeMessage(uiMsg)
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "chat:message", uiMsg)
	}
}

func (a *App) onPeerJoin(info p2p.PeerInfo) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "peer:join", UIPeer{ID: info.ID, Addr: info.Addr})
	}
}

func (a *App) onPeerLeave(id string) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "peer:leave", id)
	}
}

func (a *App) storeMessage(msg UIMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.messages = append(a.messages, msg)
	a.rooms[msg.RoomID] = append(a.rooms[msg.RoomID], msg)
}

func (a *App) sendViaOnion(dest p2p.PeerInfo, msg p2p.ChatMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	relays := a.peerTable.RelayCandidate(a.node.LocalID(), onion.DefaultCircuitLen-1)
	hops := make([]onion.Hop, 0, len(relays)+1)
	for _, r := range relays {
		hops = append(hops, onion.Hop{Address: r.Addr, DHPub: r.DHPub})
	}
	hops = append(hops, onion.Hop{Address: dest.Addr, DHPub: dest.DHPub})
	if len(hops) == 1 {
		return a.node.SendChat(dest.ID, msg)
	}
	packet, err := onion.WrapMessage(data, hops)
	if err != nil {
		return fmt.Errorf("wrap onion: %w", err)
	}
	return a.node.RelayOnion(hops[0].Address, packet)
}

func (a *App) handleOnionPacket(packet []byte) {
	nextHop, inner, err := onion.PeelLayer(packet, a.dhKeyPair.PrivateKey)
	if err != nil {
		log.Printf("[app] onion peel: %v", err)
		return
	}
	if nextHop == "" {
		plain := onion.UnpadMessage(inner)
		var msg p2p.ChatMessage
		if err := json.Unmarshal(plain, &msg); err != nil {
			log.Printf("[app] onion decode: %v", err)
			return
		}
		uiMsg := UIMessage{
			ID: randHex(8), From: msg.From, FromID: msg.From,
			Content: msg.Content, RoomID: msg.RoomID,
			Timestamp: time.Now().UnixMilli(), Encrypted: true, Onion: true,
		}
		a.storeMessage(uiMsg)
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "chat:message", uiMsg)
		}
		return
	}
	// Censorship simulation
	if a.collector.CensorshipMode {
		b := make([]byte, 1)
		rand.Read(b)
		if float64(b[0])/255.0 < a.collector.DropRate {
			a.collector.MessageDropped()
			return
		}
	}
	if err := a.node.RelayOnion(nextHop, inner); err != nil {
		log.Printf("[app] relay to %s: %v", nextHop, err)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
