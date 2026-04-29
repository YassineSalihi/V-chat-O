// Package onion implements a lightweight onion-routing layer for chat0.
//
// Design:
//   - Each message is wrapped in 3 encryption layers (configurable).
//   - Each hop node strips one layer, revealing the next-hop address and payload.
//   - The final hop decrypts and delivers the plaintext.
//   - Ephemeral X25519 keys are used per-circuit; relay nodes learn only
//     the previous and next hop—never source and destination simultaneously.
//
// Packet format (per layer, binary):
//
//	[2 bytes: next-hop addr len][next-hop addr][32 bytes: ephemeral pub][encrypted(rest)]
package onion

import (
	"bytes"
	"encoding/binary"
	"fmt"

	chatcrypto "chat0/crypto"
)

const (
	// DefaultCircuitLen is the number of relay hops used by default.
	DefaultCircuitLen = 3
	// FixedPaddingSize pads packets to this size to resist traffic analysis.
	FixedPaddingSize = 4096
)

// Hop describes a single relay node in a circuit.
type Hop struct {
	// Address is the network address of this relay (e.g. "host:port").
	Address string
	// DHPub is the node's X25519 public key used for key agreement.
	DHPub [32]byte
}

// OnionPacket is the wire-level structure passed between hops.
type OnionPacket struct {
	// NextHop is the address the current holder should forward to.
	NextHop string
	// EphPub is the ephemeral public key for this layer's DH.
	EphPub [32]byte
	// Payload is the (still-layered) encrypted remainder.
	Payload []byte
}

// WrapMessage wraps plaintext in onion layers for the given circuit.
// hops[0] is the entry node; hops[len-1] is the exit/destination node.
// Each hop must have Address and DHPub set.
func WrapMessage(plaintext []byte, hops []Hop) ([]byte, error) {
	if len(hops) < 1 {
		return nil, fmt.Errorf("circuit must have at least 1 hop")
	}

	// Pad plaintext to fixed size to prevent size-based correlation.
	padded := padToSize(plaintext, FixedPaddingSize)

	// Build layers from innermost (exit) outward.
	current := padded
	for i := len(hops) - 1; i >= 0; i-- {
		hop := hops[i]
		// Ephemeral keypair for this layer.
		eph, err := chatcrypto.GenerateDHKeyPair()
		if err != nil {
			return nil, fmt.Errorf("layer %d keygen: %w", i, err)
		}
		sharedKey, err := chatcrypto.DeriveSharedSecret(eph.PrivateKey, hop.DHPub, "chat0-onion-layer")
		if err != nil {
			return nil, fmt.Errorf("layer %d DH: %w", i, err)
		}

		// next-hop address: for the final hop this is empty (we are the destination).
		nextHop := ""
		if i < len(hops)-1 {
			nextHop = hops[i+1].Address
		}

		// Encode inner payload: [nextHop_len(2)][nextHop][current_payload]
		inner := encodeInner(nextHop, current)

		// Encrypt inner payload.
		encrypted, err := chatcrypto.Encrypt(sharedKey, inner)
		if err != nil {
			return nil, fmt.Errorf("layer %d encrypt: %w", i, err)
		}

		// Encode outer packet: [nextHop_len(2)][nextHop][ephPub(32)][encrypted]
		outer := encodeOuter(hop.Address, eph.PublicKey, encrypted)
		current = outer
	}
	return current, nil
}

// PeelLayer removes one onion layer using this node's DH private key.
// Returns the next-hop address and the inner payload (still encrypted if
// there are more hops, or plaintext at the exit node).
func PeelLayer(packet []byte, myDHPriv [32]byte) (nextHop string, inner []byte, err error) {
	// Decode outer: [nextHop_len(2)][nextHop][ephPub(32)][encrypted]
	_, ephPub, encrypted, err := decodeOuter(packet)
	if err != nil {
		return "", nil, fmt.Errorf("decode outer: %w", err)
	}

	sharedKey, err := chatcrypto.DeriveSharedSecret(myDHPriv, ephPub, "chat0-onion-layer")
	if err != nil {
		return "", nil, fmt.Errorf("DH: %w", err)
	}

	decrypted, err := chatcrypto.Decrypt(sharedKey, encrypted)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt: %w", err)
	}

	nextHop, innerPayload, err := decodeInner(decrypted)
	if err != nil {
		return "", nil, fmt.Errorf("decode inner: %w", err)
	}

	return nextHop, innerPayload, nil
}

// UnpadMessage removes the fixed padding added by WrapMessage.
func UnpadMessage(padded []byte) []byte {
	// Padding: null bytes appended. Find last non-null from end.
	i := len(padded) - 1
	for i >= 0 && padded[i] == 0 {
		i--
	}
	return padded[:i+1]
}

// --- encoding helpers ---

func encodeInner(nextHop string, payload []byte) []byte {
	addr := []byte(nextHop)
	buf := make([]byte, 2+len(addr)+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(addr)))
	copy(buf[2:], addr)
	copy(buf[2+len(addr):], payload)
	return buf
}

func decodeInner(data []byte) (nextHop string, payload []byte, err error) {
	if len(data) < 2 {
		return "", nil, fmt.Errorf("inner too short")
	}
	addrLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+addrLen > len(data) {
		return "", nil, fmt.Errorf("inner addr overflow")
	}
	nextHop = string(data[2 : 2+addrLen])
	payload = data[2+addrLen:]
	return
}

func encodeOuter(addr string, ephPub [32]byte, encrypted []byte) []byte {
	addrBytes := []byte(addr)
	var buf bytes.Buffer
	addrLen := make([]byte, 2)
	binary.BigEndian.PutUint16(addrLen, uint16(len(addrBytes)))
	buf.Write(addrLen)
	buf.Write(addrBytes)
	buf.Write(ephPub[:])
	buf.Write(encrypted)
	return buf.Bytes()
}

func decodeOuter(data []byte) (addr string, ephPub [32]byte, encrypted []byte, err error) {
	if len(data) < 2 {
		return "", ephPub, nil, fmt.Errorf("outer too short")
	}
	addrLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+addrLen+32 > len(data) {
		return "", ephPub, nil, fmt.Errorf("outer header overflow")
	}
	addr = string(data[2 : 2+addrLen])
	copy(ephPub[:], data[2+addrLen:2+addrLen+32])
	encrypted = data[2+addrLen+32:]
	return
}

func padToSize(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	padded := make([]byte, size)
	copy(padded, data)
	return padded
}
