package clamav

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"drop-i2p/internal/config"
)

// Image MIME types that PhotoDNA handles - ClamAV skips these
var imageMimeTypes = map[string]bool{
	"image/jpeg":    true,
	"image/png":     true,
	"image/gif":     true,
	"image/webp":    true,
	"image/bmp":     true,
	"image/tiff":    true,
	"image/x-icon":  true,
	"image/svg+xml": true,
}

// Scanner handles ClamAV virus scanning via clamd daemon
type Scanner struct {
	mu        sync.RWMutex
	available bool
	socket    string        // Unix socket path
	host      string        // TCP host:port fallback
	timeout   time.Duration // Scan timeout
	failOpen  bool          // Allow uploads on errors
	useSocket bool          // true = unix socket, false = TCP
}

// NewScanner creates a new ClamAV scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		socket:   cfg.ClamAVSocket,
		host:     cfg.ClamAVHost,
		timeout:  time.Duration(cfg.ClamAVTimeout) * time.Second,
		failOpen: cfg.ClamAVFailOpen,
	}

	if cfg.ClamAVEnabled {
		s.initialize()
	}

	return s
}

// initialize checks if clamd is available
func (s *Scanner) initialize() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try Unix socket first
	if s.socket != "" {
		conn, err := net.DialTimeout("unix", s.socket, 5*time.Second)
		if err == nil {
			conn.Close()
			s.available = true
			s.useSocket = true
			log.Printf("ClamAV: connected via socket %s", s.socket)
			return
		}
	}

	// Fall back to TCP
	if s.host != "" {
		conn, err := net.DialTimeout("tcp", s.host, 5*time.Second)
		if err == nil {
			conn.Close()
			s.available = true
			s.useSocket = false
			log.Printf("ClamAV: connected via TCP %s", s.host)
			return
		}
	}

	log.Printf("ClamAV: not available (clamd not running or not accessible)")
}

// IsAvailable returns whether ClamAV scanning is available
func (s *Scanner) IsAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.available
}

// ShouldCheck returns true if this file type should be scanned by ClamAV
// ClamAV handles non-image files; PhotoDNA handles images
func (s *Scanner) ShouldCheck(mimeType string) bool {
	if !s.IsAvailable() {
		return false
	}

	// Normalize MIME type (remove charset, lowercase)
	mimeType = strings.ToLower(strings.Split(mimeType, ";")[0])

	// Skip image types - PhotoDNA handles those
	return !imageMimeTypes[mimeType]
}

// CheckFile scans file data for viruses using ClamAV's INSTREAM command
// Returns: infected (bool), threat name (string), error
func (s *Scanner) CheckFile(ctx context.Context, data []byte) (bool, string, error) {
	if !s.IsAvailable() {
		return false, "", nil
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Connect to clamd
	var conn net.Conn
	var err error

	s.mu.RLock()
	useSocket := s.useSocket
	socket := s.socket
	host := s.host
	failOpen := s.failOpen
	s.mu.RUnlock()

	if useSocket {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "unix", socket)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", host)
	}

	if err != nil {
		log.Printf("ClamAV: connection error: %v", err)
		if failOpen {
			return false, "", nil
		}
		return true, "", fmt.Errorf("ClamAV connection failed: %w", err)
	}
	defer conn.Close()

	// Set deadline based on context
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// Send INSTREAM command
	_, err = conn.Write([]byte("nINSTREAM\n"))
	if err != nil {
		log.Printf("ClamAV: failed to send command: %v", err)
		if failOpen {
			return false, "", nil
		}
		return true, "", fmt.Errorf("ClamAV command failed: %w", err)
	}

	// Send data in chunks (max 2KB per chunk as per ClamAV protocol)
	const chunkSize = 2048
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Send chunk length (4 bytes, big endian)
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(chunk)))
		_, err = conn.Write(lengthBuf)
		if err != nil {
			log.Printf("ClamAV: failed to send chunk length: %v", err)
			if failOpen {
				return false, "", nil
			}
			return true, "", fmt.Errorf("ClamAV send failed: %w", err)
		}

		// Send chunk data
		_, err = conn.Write(chunk)
		if err != nil {
			log.Printf("ClamAV: failed to send chunk data: %v", err)
			if failOpen {
				return false, "", nil
			}
			return true, "", fmt.Errorf("ClamAV send failed: %w", err)
		}
	}

	// Send zero-length chunk to signal EOF
	_, err = conn.Write([]byte{0, 0, 0, 0})
	if err != nil {
		log.Printf("ClamAV: failed to send EOF: %v", err)
		if failOpen {
			return false, "", nil
		}
		return true, "", fmt.Errorf("ClamAV EOF failed: %w", err)
	}

	// Read response
	response, err := io.ReadAll(conn)
	if err != nil {
		log.Printf("ClamAV: failed to read response: %v", err)
		if failOpen {
			return false, "", nil
		}
		return true, "", fmt.Errorf("ClamAV read failed: %w", err)
	}

	result := strings.TrimSpace(string(response))

	// Parse response: "stream: OK" or "stream: VirusName FOUND"
	if strings.HasSuffix(result, "OK") {
		return false, "", nil
	}

	if strings.Contains(result, "FOUND") {
		// Extract virus name: "stream: Eicar-Test-Signature FOUND"
		parts := strings.Split(result, ":")
		if len(parts) >= 2 {
			threatPart := strings.TrimSpace(parts[1])
			threatName := strings.TrimSuffix(threatPart, " FOUND")
			log.Printf("ClamAV: threat detected: %s", threatName)
			return true, threatName, nil
		}
		return true, "Unknown threat", nil
	}

	// Unexpected response
	log.Printf("ClamAV: unexpected response: %s", result)
	if failOpen {
		return false, "", nil
	}
	return true, "", fmt.Errorf("ClamAV unexpected response: %s", result)
}
