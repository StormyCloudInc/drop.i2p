package storage

import (
	"drop-i2p/internal/db"
	"log"
	"os"
	"path/filepath"
	"time"
)

// CleanupExpired scans the database for expired files and deletes them.
// It also checks for "Project Garbage Collector" issue: orphan files on disk.
func (m *Manager) CleanupExpired() {
	log.Println("Running Garbage Collection...")

	// 1. Delete Expired Files from DB and Disk
	// Find expired IDs
	rows, err := db.DB.Query("SELECT id FROM files WHERE expiry_time IS NOT NULL AND expiry_time < ?", time.Now())
	if err != nil {
		log.Printf("Error querying expired files: %v", err)
		return
	}
	
	var idsToDelete []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			idsToDelete = append(idsToDelete, id)
		}
	}
	rows.Close()

	for _, id := range idsToDelete {
		log.Printf("Deleting expired file: %s", id)
		if err := m.DeleteFile(id); err != nil {
			log.Printf("Error deleting file %s: %v", id, err)
		}
	}

	// 2. Orphan Cleanup (Files on disk not in DB)
	// This fixes the "files unknown to DB not getting deleted" issue.
	// Get all known chunk paths
	knownChunks := make(map[string]bool)
	rows, err = db.DB.Query("SELECT chunk_path FROM chunks")
	if err != nil {
		log.Printf("Error querying chunks: %v", err)
		return
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			knownChunks[p] = true
		}
	}
	rows.Close()

	// Walk upload directory
	entries, err := os.ReadDir(m.cfg.UploadFolder)
	if err != nil {
		log.Printf("Error reading upload dir: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
        // Assuming chunk_path stored in DB is just the filename (UUID)
        // If it was relative path, we need to match carefully.
        // In SaveFile, we stored just the UUID as chunkPath if we stored relative? 
        // Wait, SaveFile: `filepath.Join(m.cfg.UploadFolder, chunkUUID)` is the disk path.
        // DB `chunk_path` value: `chunkUUID`.
        // So `knownChunks` has just the UUIDs.
        // `entry.Name()` is the UUID.
		if !knownChunks[entry.Name()] {
            info, _ := entry.Info()
            // Grace period: Don't delete files created in the last 1 hour (in case an upload is in progress/transaction active but not committed yet)
            if time.Since(info.ModTime()) > 1*time.Hour {
                log.Printf("Deleting orphan file: %s", entry.Name())
                os.Remove(filepath.Join(m.cfg.UploadFolder, entry.Name()))
            }
		}
	}
}
