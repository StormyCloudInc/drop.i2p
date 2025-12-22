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

	// PhotoDNA CSAM scanning
	PhotoDNAAPIKey   string // Microsoft PhotoDNA API key
	PhotoDNAEnabled  bool   // Enable/disable scanning (auto-enabled if API key present)
	PhotoDNAFailOpen bool   // If true, allow uploads when API fails; if false, reject
	PhotoDNATimeout  int    // API timeout in seconds

	// ClamAV virus scanning
	ClamAVEnabled  bool   // Enable/disable scanning (auto-enabled if clamd accessible)
	ClamAVSocket   string // Unix socket path for clamd
	ClamAVHost     string // TCP host:port for clamd (fallback)
	ClamAVTimeout  int    // Scan timeout in seconds
	ClamAVFailOpen bool   // If true, allow uploads when scan fails; if false, reject

	// Webhook notifications
	WebhookURL     string // SSP_WEBHOOK_URL - URL to send webhooks to
	WebhookSecret  string // SSP_WEBHOOK_SECRET - HMAC signing secret
	WebhookEvents  string // SSP_WEBHOOK_EVENTS - comma-separated events: report,storage
	WebhookTimeout int    // SSP_WEBHOOK_TIMEOUT - timeout in seconds (default: 10)
	StorageAlertGB int    // SSP_STORAGE_ALERT_GB - threshold for storage alerts

	// Announcement banner
	AnnouncementFile string // SSP_ANNOUNCEMENT_FILE - path to announcement.txt file
}

func Load() *Config {
	keyVersion := uint32(1)
	if v, err := strconv.ParseUint(getEnv("SSP_KEY_VERSION", "1"), 10, 32); err == nil {
		keyVersion = uint32(v)
	}

	// PhotoDNA: auto-enable if API key is present, unless explicitly disabled
	photoDNAAPIKey := getEnv("SSP_PHOTODNA_API_KEY", "")
	photoDNAEnabled := photoDNAAPIKey != ""
	if e := getEnv("SSP_PHOTODNA_ENABLED", ""); e != "" {
		photoDNAEnabled = e == "true" || e == "1"
	}

	photoDNATimeout := 10
	if t, err := strconv.Atoi(getEnv("SSP_PHOTODNA_TIMEOUT", "10")); err == nil && t > 0 {
		photoDNATimeout = t
	}

	// ClamAV: auto-enable by default (will check if clamd is accessible)
	clamAVEnabled := true
	if e := getEnv("SSP_CLAMAV_ENABLED", ""); e != "" {
		clamAVEnabled = e == "true" || e == "1"
	}

	clamAVTimeout := 30
	if t, err := strconv.Atoi(getEnv("SSP_CLAMAV_TIMEOUT", "30")); err == nil && t > 0 {
		clamAVTimeout = t
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
		PhotoDNAAPIKey:    photoDNAAPIKey,
		PhotoDNAEnabled:   photoDNAEnabled,
		PhotoDNAFailOpen:  getEnv("SSP_PHOTODNA_FAIL_OPEN", "true") == "true",
		PhotoDNATimeout:   photoDNATimeout,
		ClamAVEnabled:     clamAVEnabled,
		ClamAVSocket:      getEnv("SSP_CLAMAV_SOCKET", "/var/run/clamav/clamd.sock"),
		ClamAVHost:        getEnv("SSP_CLAMAV_HOST", "localhost:3310"),
		ClamAVTimeout:     clamAVTimeout,
		ClamAVFailOpen:    getEnv("SSP_CLAMAV_FAIL_OPEN", "true") == "true",
		WebhookURL:        getEnv("SSP_WEBHOOK_URL", ""),
		WebhookSecret:     getEnv("SSP_WEBHOOK_SECRET", ""),
		WebhookEvents:     getEnv("SSP_WEBHOOK_EVENTS", "report,storage"),
		WebhookTimeout:    parseIntEnv("SSP_WEBHOOK_TIMEOUT", 10),
		StorageAlertGB:    parseIntEnv("SSP_STORAGE_ALERT_GB", 0),
		AnnouncementFile:  getEnv("SSP_ANNOUNCEMENT_FILE", "announcement.txt"),
	}
}

func parseIntEnv(key string, defaultVal int) int {
	if v, err := strconv.Atoi(getEnv(key, "")); err == nil && v > 0 {
		return v
	}
	return defaultVal
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
