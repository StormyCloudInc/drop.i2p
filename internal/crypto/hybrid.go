package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	// Key sizes
	X25519PubKeySize     = 32
	X25519PrivKeySize    = 32
	MLKEMSeedSize        = 64
	MLKEMCiphertextSize  = 1088 // ML-KEM-768 ciphertext
	MLKEMEncapKeySize    = 1184 // ML-KEM-768 encapsulation key
	KeyVersionSize       = 4
	HybridCiphertextSize = KeyVersionSize + X25519PubKeySize + MLKEMCiphertextSize // 1124 bytes

	// Derived key sizes
	SharedKeySize  = 32
	DerivedKeySize = 32
	NonceSize      = 24 // XChaCha20-Poly1305

	// Domain separation label for hybrid combination
	domainSeparator = "drop.i2p-hybrid-v1"
)

// ServerKeys holds the server's long-term key pair for hybrid KEM
type ServerKeys struct {
	Version       uint32
	X25519Private *ecdh.PrivateKey
	X25519Public  *ecdh.PublicKey
	MLKEMDecap    *mlkem.DecapsulationKey768
}

// HybridCiphertext is the encapsulated data stored per-file
type HybridCiphertext struct {
	KeyVersion         uint32 // 4 bytes
	X25519EphemeralPub []byte // 32 bytes
	MLKEMCiphertext    []byte // 1088 bytes
}

// NewServerKeysFromSeeds creates ServerKeys from X25519 and ML-KEM seeds
func NewServerKeysFromSeeds(x25519Seed, mlkemSeed []byte, version uint32) (*ServerKeys, error) {
	if len(x25519Seed) != X25519PrivKeySize {
		return nil, errors.New("invalid X25519 seed size")
	}
	if len(mlkemSeed) != MLKEMSeedSize {
		return nil, errors.New("invalid ML-KEM seed size")
	}

	// Derive X25519 private key from seed
	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519Seed)
	if err != nil {
		return nil, err
	}

	// Derive ML-KEM-768 keys from seed
	mlkemDecap, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, err
	}

	return &ServerKeys{
		Version:       version,
		X25519Private: x25519Priv,
		X25519Public:  x25519Priv.PublicKey(),
		MLKEMDecap:    mlkemDecap,
	}, nil
}

// Encapsulate performs hybrid X25519 + ML-KEM-768 encapsulation
// Returns the shared secret and the ciphertext to store
func Encapsulate(serverKeys *ServerKeys) ([]byte, *HybridCiphertext, error) {
	// Generate ephemeral X25519 key pair
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// X25519 ECDH with server's public key
	x25519Shared, err := ephemeralPriv.ECDH(serverKeys.X25519Public)
	if err != nil {
		return nil, nil, err
	}

	// ML-KEM encapsulation with server's encapsulation key
	mlkemShared, mlkemCiphertext := serverKeys.MLKEMDecap.EncapsulationKey().Encapsulate()

	// Combine shared secrets with domain separation using SHA3-256
	// This follows X-Wing-like hybrid construction principles
	combinedSecret := combineSecrets(x25519Shared, mlkemShared)

	ct := &HybridCiphertext{
		KeyVersion:         serverKeys.Version,
		X25519EphemeralPub: ephemeralPriv.PublicKey().Bytes(),
		MLKEMCiphertext:    mlkemCiphertext,
	}

	return combinedSecret, ct, nil
}

// Decapsulate performs hybrid X25519 + ML-KEM-768 decapsulation
func Decapsulate(serverKeys *ServerKeys, ct *HybridCiphertext) ([]byte, error) {
	if ct.KeyVersion != serverKeys.Version {
		return nil, errors.New("key version mismatch")
	}

	// Parse ephemeral X25519 public key
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ct.X25519EphemeralPub)
	if err != nil {
		return nil, err
	}

	// X25519 ECDH with ephemeral public key
	x25519Shared, err := serverKeys.X25519Private.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}

	// ML-KEM decapsulation
	mlkemShared, err := serverKeys.MLKEMDecap.Decapsulate(ct.MLKEMCiphertext)
	if err != nil {
		return nil, err
	}

	// Combine shared secrets with domain separation
	combinedSecret := combineSecrets(x25519Shared, mlkemShared)

	return combinedSecret, nil
}

// combineSecrets combines X25519 and ML-KEM shared secrets using SHA3-256
// with domain separation for security
func combineSecrets(x25519Shared, mlkemShared []byte) []byte {
	h := sha3.New256()
	h.Write([]byte(domainSeparator))
	h.Write(x25519Shared)
	h.Write(mlkemShared)
	return h.Sum(nil)
}

// DeriveFileKey derives a per-file encryption key from the shared secret and file ID
func DeriveFileKey(sharedSecret []byte, fileID string) ([]byte, error) {
	// Use HKDF-SHA256 for key derivation
	info := []byte("file-key:" + fileID)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)

	key := make([]byte, DerivedKeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeriveChunkKey derives a per-chunk encryption key from the file key and chunk index
func DeriveChunkKey(fileKey []byte, chunkIndex int) ([]byte, []byte, error) {
	// Use HKDF-SHA256 to derive chunk key and nonce
	info := make([]byte, 8)
	binary.BigEndian.PutUint64(info, uint64(chunkIndex))
	hkdfReader := hkdf.New(sha256.New, fileKey, []byte("chunk"), info)

	// Derive key
	key := make([]byte, DerivedKeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, nil, err
	}

	// Derive nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(hkdfReader, nonce); err != nil {
		return nil, nil, err
	}

	return key, nonce, nil
}

// EncryptChunk encrypts a chunk using XChaCha20-Poly1305
func EncryptChunk(fileKey []byte, chunkIndex int, plaintext []byte) ([]byte, error) {
	key, nonce, err := DeriveChunkKey(fileKey, chunkIndex)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptChunk decrypts a chunk using XChaCha20-Poly1305
func DecryptChunk(fileKey []byte, chunkIndex int, ciphertext []byte) ([]byte, error) {
	key, nonce, err := DeriveChunkKey(fileKey, chunkIndex)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// MarshalHybridCiphertext serializes a HybridCiphertext to bytes
func MarshalHybridCiphertext(ct *HybridCiphertext) []byte {
	buf := make([]byte, HybridCiphertextSize)
	binary.BigEndian.PutUint32(buf[0:4], ct.KeyVersion)
	copy(buf[4:36], ct.X25519EphemeralPub)
	copy(buf[36:], ct.MLKEMCiphertext)
	return buf
}

// UnmarshalHybridCiphertext deserializes bytes to a HybridCiphertext
func UnmarshalHybridCiphertext(data []byte) (*HybridCiphertext, error) {
	if len(data) != HybridCiphertextSize {
		return nil, errors.New("invalid hybrid ciphertext size")
	}

	return &HybridCiphertext{
		KeyVersion:         binary.BigEndian.Uint32(data[0:4]),
		X25519EphemeralPub: data[4:36],
		MLKEMCiphertext:    data[36:],
	}, nil
}

// AuthTagSize returns the authentication tag size for XChaCha20-Poly1305
func AuthTagSize() int {
	return chacha20poly1305.Overhead
}
