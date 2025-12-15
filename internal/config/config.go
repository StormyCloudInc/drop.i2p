package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port              string
	UploadFolder      string
	DatabasePath      string
	EncryptionKey     string // Legacy - kept for backward compatibility
	AdminPasswordHash string
	AdminURL          string
	FlaskDebug        bool // Keeping name for compat, or mapped to Debug

	// Hybrid PQ encryption keys (X25519 + ML-KEM-768)
	X25519Seed string // Base64-encoded 32-byte seed
	MLKEMSeed  string // Base64-encoded 64-byte seed
	KeyVersion uint32 // Current key version (default: 1)
}

func Load() *Config {
	keyVersion := uint32(1)
	if v, err := strconv.ParseUint(getEnv("SSP_KEY_VERSION", "1"), 10, 32); err == nil {
		keyVersion = uint32(v)
	}

	return &Config{
		Port:              getEnv("SSP_PORT", "8080"),
		UploadFolder:      getEnv("SSP_UPLOAD_FOLDER", "uploads"),
		DatabasePath:      getEnv("SSP_DATABASE_PATH", "database.db"),
		EncryptionKey:     getEnv("SSP_ENCRYPTION_KEY", ""),
		AdminPasswordHash: getEnv("SSP_ADMIN_PASSWORD_HASH", ""),
		AdminURL:          getEnv("SSP_ADMIN_URL", "/admin"),
		FlaskDebug:        getEnv("SSP_FLASK_DEBUG", "false") == "true",
		X25519Seed:        getEnv("SSP_X25519_SEED", ""),
		MLKEMSeed:         getEnv("SSP_MLKEM_SEED", ""),
		KeyVersion:        keyVersion,
	}
}

// HasHybridKeys returns true if hybrid encryption keys are configured
func (c *Config) HasHybridKeys() bool {
	return c.X25519Seed != "" && c.MLKEMSeed != ""
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
