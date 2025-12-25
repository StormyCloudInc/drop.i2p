package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"drop-i2p/internal/clamav"
	"drop-i2p/internal/config"
	"drop-i2p/internal/db"
	"drop-i2p/internal/photodna"
	"drop-i2p/internal/server"
	"drop-i2p/internal/storage"
	"drop-i2p/internal/webhook"
)

// Version is the application version, set during build or manually updated
const Version = "2.1"

func main() {
	cfg := config.Load()

	// Initialize database
	if err := db.Init(cfg.DatabasePath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize storage manager
	store := storage.NewManager(cfg)

	// Initialize PhotoDNA scanner and attach to storage manager for chunked uploads
	photoDNAScanner := photodna.NewScanner(cfg)
	store.SetPhotoDNAChecker(photoDNAScanner)

	// Initialize ClamAV scanner and attach to storage manager for chunked uploads
	clamAVScanner := clamav.NewScanner(cfg)
	store.SetClamAVChecker(clamAVScanner)

	srv := server.New(cfg, store, Version)

	// Start background tasks
	go startBackgroundTasks(cfg, store, srv.Webhook())

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Starting server on %s", addr)
	log.Printf("Admin panel available at %s", cfg.AdminURL)

	if err := http.ListenAndServe(addr, srv.Router()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// startBackgroundTasks runs periodic background tasks:
// - Hourly stats snapshots for analytics
// - Storage threshold monitoring for webhooks
func startBackgroundTasks(cfg *config.Config, store *storage.Manager, notifier *webhook.Notifier) {
	// Stats snapshot ticker (hourly)
	statsTicker := time.NewTicker(1 * time.Hour)

	// Storage monitor ticker (every 15 minutes)
	storageTicker := time.NewTicker(15 * time.Minute)

	thresholdBytes := int64(cfg.StorageAlertGB) * 1024 * 1024 * 1024
	alertSent := false

	log.Printf("[background] Started background tasks")
	if cfg.StorageAlertGB > 0 {
		log.Printf("[background] Storage alert threshold: %d GB", cfg.StorageAlertGB)
	}

	// Record initial stats snapshot on startup
	if err := store.RecordStatsSnapshot(); err != nil {
		log.Printf("[background] Failed to record initial stats snapshot: %v", err)
	} else {
		log.Printf("[background] Recorded initial stats snapshot")
	}

	for {
		select {
		case <-statsTicker.C:
			// Record stats snapshot for analytics
			if err := store.RecordStatsSnapshot(); err != nil {
				log.Printf("[background] Failed to record stats snapshot: %v", err)
			}
			// Cleanup old stats history (keep 90 days)
			if err := store.CleanupOldStatsHistory(90); err != nil {
				log.Printf("[background] Failed to cleanup old stats history: %v", err)
			}
			// Cleanup expired collections
			if count, err := store.CleanupExpiredCollections(); err != nil {
				log.Printf("[background] Failed to cleanup expired collections: %v", err)
			} else if count > 0 {
				log.Printf("[background] Cleaned up %d expired collections", count)
			}

		case <-storageTicker.C:
			// Check storage threshold for webhooks
			if cfg.StorageAlertGB > 0 {
				currentBytes := store.GetTotalBytesStored()
				if currentBytes >= thresholdBytes {
					if !alertSent {
						log.Printf("[background] Storage threshold exceeded: %d bytes >= %d bytes", currentBytes, thresholdBytes)
						notifier.SendStorageWarning(currentBytes, thresholdBytes)
						alertSent = true
					}
				} else {
					alertSent = false
				}
			}
		}
	}
}
