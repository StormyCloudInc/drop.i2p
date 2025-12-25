package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// KeyManager manages multiple key versions for key rotation support
type KeyManager struct {
	mu         sync.RWMutex
	keys       map[uint32]*ServerKeys
	currentVer uint32
}

// NewKeyManager creates a new KeyManager with the initial key pair
func NewKeyManager(x25519SeedB64, mlkemSeedB64 string, version uint32) (*KeyManager, error) {
	x25519Seed, err := base64.StdEncoding.DecodeString(x25519SeedB64)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 seed base64: %w", err)
	}
	if len(x25519Seed) != X25519PrivKeySize {
		return nil, fmt.Errorf("X25519 seed must be %d bytes, got %d", X25519PrivKeySize, len(x25519Seed))
	}

	mlkemSeed, err := base64.StdEncoding.DecodeString(mlkemSeedB64)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM seed base64: %w", err)
	}
	if len(mlkemSeed) != MLKEMSeedSize {
		return nil, fmt.Errorf("ML-KEM seed must be %d bytes, got %d", MLKEMSeedSize, len(mlkemSeed))
	}

	keys, err := NewServerKeysFromSeeds(x25519Seed, mlkemSeed, version)
	if err != nil {
		return nil, fmt.Errorf("failed to create server keys: %w", err)
	}

	km := &KeyManager{
		keys:       make(map[uint32]*ServerKeys),
		currentVer: version,
	}
	km.keys[version] = keys

	return km, nil
}

// AddKeyVersion adds a new key version to the manager
func (km *KeyManager) AddKeyVersion(x25519SeedB64, mlkemSeedB64 string, version uint32) error {
	x25519Seed, err := base64.StdEncoding.DecodeString(x25519SeedB64)
	if err != nil {
		return fmt.Errorf("invalid X25519 seed base64: %w", err)
	}
	if len(x25519Seed) != X25519PrivKeySize {
		return fmt.Errorf("X25519 seed must be %d bytes, got %d", X25519PrivKeySize, len(x25519Seed))
	}

	mlkemSeed, err := base64.StdEncoding.DecodeString(mlkemSeedB64)
	if err != nil {
		return fmt.Errorf("invalid ML-KEM seed base64: %w", err)
	}
	if len(mlkemSeed) != MLKEMSeedSize {
		return fmt.Errorf("ML-KEM seed must be %d bytes, got %d", MLKEMSeedSize, len(mlkemSeed))
	}

	keys, err := NewServerKeysFromSeeds(x25519Seed, mlkemSeed, version)
	if err != nil {
		return fmt.Errorf("failed to create server keys: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	km.keys[version] = keys
	return nil
}

// SetCurrentVersion sets which key version to use for new encryptions
func (km *KeyManager) SetCurrentVersion(version uint32) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if _, exists := km.keys[version]; !exists {
		return fmt.Errorf("key version %d not found", version)
	}
	km.currentVer = version
	return nil
}

// CurrentKeys returns the current key pair for encryption
func (km *KeyManager) CurrentKeys() *ServerKeys {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keys[km.currentVer]
}

// CurrentVersion returns the current key version
func (km *KeyManager) CurrentVersion() uint32 {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentVer
}

// KeysForVersion returns keys for a specific version (for decryption)
func (km *KeyManager) KeysForVersion(version uint32) (*ServerKeys, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys, exists := km.keys[version]
	if !exists {
		return nil, fmt.Errorf("key version %d not found", version)
	}
	return keys, nil
}

// HasVersion checks if a key version exists
func (km *KeyManager) HasVersion(version uint32) bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	_, exists := km.keys[version]
	return exists
}

// Versions returns all available key versions
func (km *KeyManager) Versions() []uint32 {
	km.mu.RLock()
	defer km.mu.RUnlock()

	versions := make([]uint32, 0, len(km.keys))
	for v := range km.keys {
		versions = append(versions, v)
	}
	return versions
}

// EncryptForFile performs hybrid encapsulation and returns the ciphertext to store
func (km *KeyManager) EncryptForFile(fileID string) (fileKey []byte, kemCiphertext []byte, err error) {
	keys := km.CurrentKeys()
	if keys == nil {
		return nil, nil, errors.New("no current keys available")
	}

	sharedSecret, ct, err := Encapsulate(keys)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	fileKey, err = DeriveFileKey(sharedSecret, fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}

	kemCiphertext = MarshalHybridCiphertext(ct)
	return fileKey, kemCiphertext, nil
}

// DecryptForFile performs hybrid decapsulation and returns the file key
func (km *KeyManager) DecryptForFile(fileID string, kemCiphertext []byte) ([]byte, error) {
	ct, err := UnmarshalHybridCiphertext(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	keys, err := km.KeysForVersion(ct.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("key lookup failed: %w", err)
	}

	sharedSecret, err := Decapsulate(keys, ct)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	fileKey, err := DeriveFileKey(sharedSecret, fileID)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return fileKey, nil
}
