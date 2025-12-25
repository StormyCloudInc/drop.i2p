package metadata

import (
	"log"
	"os/exec"
	"strings"
	"sync"
)

// Stripper handles metadata removal from files using exiftool
type Stripper struct {
	available bool
	mu        sync.RWMutex
}

// SupportedMimeTypes lists MIME types that can have metadata stripped
var SupportedMimeTypes = map[string]bool{
	// Images
	"image/jpeg":    true,
	"image/png":     true,
	"image/gif":     true,
	"image/webp":    true,
	"image/tiff":    true,
	"image/bmp":     true,
	"image/heic":    true,
	"image/heif":    true,
	"image/avif":    true,
	// Videos
	"video/mp4":       true,
	"video/quicktime": true,
	"video/x-msvideo": true,
	"video/x-matroska": true,
	"video/webm":      true,
	"video/mpeg":      true,
	// Audio
	"audio/mpeg":  true,
	"audio/mp4":   true,
	"audio/ogg":   true,
	"audio/flac":  true,
	"audio/wav":   true,
	"audio/x-wav": true,
	// Documents
	"application/pdf": true,
}

// NewStripper creates a new metadata stripper and checks for exiftool availability
func NewStripper() *Stripper {
	s := &Stripper{}
	s.checkAvailability()
	return s
}

// checkAvailability verifies if exiftool is installed
func (s *Stripper) checkAvailability() {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := exec.LookPath("exiftool")
	s.available = err == nil
	if s.available {
		log.Println("Metadata stripper: exiftool found, metadata stripping enabled")
	} else {
		log.Println("Metadata stripper: exiftool not found, metadata stripping disabled")
	}
}

// IsAvailable returns whether exiftool is available
func (s *Stripper) IsAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.available
}

// CanStrip checks if a file type can have metadata stripped
func (s *Stripper) CanStrip(mimeType string) bool {
	// Normalize mime type (remove parameters like charset)
	if idx := strings.Index(mimeType, ";"); idx > 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}
	return SupportedMimeTypes[mimeType]
}

// Strip removes all metadata from a file in place
// Returns true if stripping was performed, false if skipped
func (s *Stripper) Strip(filePath string, mimeType string) (bool, error) {
	s.mu.RLock()
	available := s.available
	s.mu.RUnlock()

	if !available {
		return false, nil
	}

	if !s.CanStrip(mimeType) {
		return false, nil
	}

	// Run exiftool to strip all metadata
	// -all= removes all metadata
	// -overwrite_original prevents creating backup files
	cmd := exec.Command("exiftool", "-all=", "-overwrite_original", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Metadata stripper: failed to strip %s: %v (output: %s)", filePath, err, string(output))
		// Don't return error - stripping failure shouldn't block upload
		return false, nil
	}

	log.Printf("Metadata stripper: successfully stripped metadata from %s", filePath)
	return true, nil
}

// StripToTemp strips metadata and writes to a new temp file
// This is useful when the original file shouldn't be modified
func (s *Stripper) StripToTemp(srcPath, destPath string, mimeType string) (bool, error) {
	s.mu.RLock()
	available := s.available
	s.mu.RUnlock()

	if !available {
		return false, nil
	}

	if !s.CanStrip(mimeType) {
		return false, nil
	}

	// Copy file first, then strip metadata from the copy
	// exiftool doesn't support writing to a different output file for all formats
	cmd := exec.Command("cp", srcPath, destPath)
	if err := cmd.Run(); err != nil {
		return false, err
	}

	return s.Strip(destPath, mimeType)
}
