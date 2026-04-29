// Package crypto provides end-to-end encryption primitives for chat0.
// Key exchange: X25519 ECDH
// Symmetric encryption: AES-256-GCM
// Identity signatures: Ed25519
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// IdentityKeyPair holds an Ed25519 signing keypair used as the node identity.
type IdentityKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// DHKeyPair holds an X25519 keypair used for ephemeral Diffie-Hellman.
type DHKeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// GenerateIdentity creates a new Ed25519 identity keypair.
func GenerateIdentity() (*IdentityKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return &IdentityKeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// GenerateDHKeyPair creates a new X25519 ephemeral keypair.
func GenerateDHKeyPair() (*DHKeyPair, error) {
	kp := &DHKeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("generate DH keypair: %w", err)
	}
	// Clamp private key per RFC 7748
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute public key: %w", err)
	}
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// DeriveSharedSecret performs X25519 ECDH and derives a symmetric key via HKDF-SHA256.
// info is domain-separation context (e.g. "chat0-session").
func DeriveSharedSecret(privKey, peerPubKey [32]byte, info string) ([]byte, error) {
	shared, err := curve25519.X25519(privKey[:], peerPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}
	hkdfReader := hkdf.New(sha256.New, shared, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM using the provided 32-byte key.
// Returns nonce || ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts AES-256-GCM ciphertext (nonce || ciphertext).
func Decrypt(key, ciphertextWithNonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM open: %w", err)
	}
	return plaintext, nil
}

// Sign produces an Ed25519 signature over the message.
func Sign(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// Verify checks an Ed25519 signature.
func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}

// PubKeyID returns a short hex identifier (first 8 bytes of SHA-256) of a public key.
func PubKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
