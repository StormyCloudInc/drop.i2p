package photodna

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"drop-i2p/internal/config"
)

// Result codes from Python script
const (
	ResultNoMatch      = 0 // Safe
	ResultMatch        = 1 // CSAM detected
	ResultInvalidImage = 2 // Not an image or decoding failed
	ResultAPIError     = 3 // API communication error
	ResultHashError    = 4 // Hash generation error
	ResultConfigError  = 5 // Configuration error
)

// CheckResult contains the result of a PhotoDNA check
type CheckResult struct {
	Code    int                    `json:"code"`
	Message string                 `json:"message"`
	Match   bool                   `json:"match"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ImageMimeTypes lists MIME types that should be checked
var ImageMimeTypes = map[string]bool{
	"image/jpeg":    true,
	"image/png":     true,
	"image/gif":     true,
	"image/webp":    true,
	"image/bmp":     true,
	"image/tiff":    true,
	"image/x-icon":  true,
	"image/svg+xml": false, // SVG is not supported by PhotoDNA
}

// Scanner handles PhotoDNA image scanning
type Scanner struct {
	cfg        *config.Config
	scriptPath string
	pythonPath string
	available  bool
	mu         sync.RWMutex
}

// NewScanner creates a new PhotoDNA scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{cfg: cfg}
	s.initialize()
	return s
}

// initialize checks if PhotoDNA scanning is available
func (s *Scanner) initialize() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if enabled
	if !s.cfg.PhotoDNAEnabled || s.cfg.PhotoDNAAPIKey == "" {
		log.Println("PhotoDNA: disabled (no API key configured)")
		s.available = false
		return
	}

	// Find Python interpreter
	// On Windows, prefer "python" as "python3" often redirects to Microsoft Store
	var pythonPath string
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("python"); err != nil {
			log.Println("PhotoDNA: disabled (Python not found)")
			s.available = false
			return
		}
		pythonPath = "python"
	} else {
		// On Unix-like systems, prefer python3
		pythonPath = "python3"
		if _, err := exec.LookPath("python3"); err != nil {
			if _, err := exec.LookPath("python"); err != nil {
				log.Println("PhotoDNA: disabled (Python not found)")
				s.available = false
				return
			}
			pythonPath = "python"
		}
	}
	s.pythonPath = pythonPath

	// Find script path relative to executable or working directory
	scriptPath := ""
	candidates := []string{
		"internal/photodna/check_image.py",
		"./internal/photodna/check_image.py",
	}

	// Also try relative to executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates = append(candidates,
			filepath.Join(execDir, "internal/photodna/check_image.py"),
			filepath.Join(execDir, "..", "internal/photodna/check_image.py"),
		)
	}

	for _, p := range candidates {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				scriptPath = abs
				break
			}
		}
	}

	if scriptPath == "" {
		log.Println("PhotoDNA: disabled (check_image.py script not found)")
		s.available = false
		return
	}

	s.scriptPath = scriptPath
	s.available = true
	log.Printf("PhotoDNA: enabled (script: %s, python: %s)", s.scriptPath, s.pythonPath)
}

// IsAvailable returns whether PhotoDNA scanning is available
func (s *Scanner) IsAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.available
}

// ShouldCheck returns true if this MIME type should be scanned
func (s *Scanner) ShouldCheck(mimeType string) bool {
	if !s.IsAvailable() {
		return false
	}

	// Normalize mime type (remove charset etc)
	if idx := strings.Index(mimeType, ";"); idx > 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}
	mimeType = strings.ToLower(mimeType)

	shouldCheck, exists := ImageMimeTypes[mimeType]
	return exists && shouldCheck
}

// CheckImage checks image bytes against PhotoDNA
// Returns: (isBlocked, error)
// - isBlocked=true: CSAM match found, reject upload
// - isBlocked=false, error=nil: Safe to continue
// - isBlocked depends on FailOpen setting when error occurs
func (s *Scanner) CheckImage(ctx context.Context, imageData []byte) (bool, error) {
	s.mu.RLock()
	available := s.available
	scriptPath := s.scriptPath
	pythonPath := s.pythonPath
	s.mu.RUnlock()

	if !available {
		return false, nil // Not available, allow upload
	}

	// Create context with timeout
	timeout := time.Duration(s.cfg.PhotoDNATimeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second) // Extra buffer for process startup
	defer cancel()

	// Prepare command
	cmd := exec.CommandContext(ctx, pythonPath, scriptPath)
	cmd.Stdin = bytes.NewReader(imageData)

	// Set environment
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PHOTODNA_API_KEY=%s", s.cfg.PhotoDNAAPIKey),
		fmt.Sprintf("PHOTODNA_TIMEOUT=%d", s.cfg.PhotoDNATimeout),
	)

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run
	err := cmd.Run()

	// Parse result
	var result CheckResult
	if stdout.Len() > 0 {
		if parseErr := json.Unmarshal(stdout.Bytes(), &result); parseErr != nil {
			log.Printf("PhotoDNA: failed to parse output: %v (stdout: %s, stderr: %s)",
				parseErr, stdout.String(), stderr.String())
			return s.handleError(fmt.Errorf("invalid script output"))
		}
	}

	// Handle exit codes
	if err != nil {
		// Check if it's just a non-zero exit (expected for some results)
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			switch exitCode {
			case ResultMatch:
				// Match found
				log.Printf("PhotoDNA: MATCH DETECTED - blocking upload (details: %v)", result.Details)
				return true, nil
			case ResultInvalidImage:
				// Not a valid image - skip check, allow upload
				log.Printf("PhotoDNA: invalid/unsupported image, skipping check: %s", result.Message)
				return false, nil
			case ResultAPIError, ResultHashError, ResultConfigError:
				// Error occurred
				log.Printf("PhotoDNA: error (code %d): %s", exitCode, result.Message)
				return s.handleError(fmt.Errorf(result.Message))
			}
		}
		// Context timeout or other error
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("PhotoDNA: check timed out")
			return s.handleError(fmt.Errorf("timeout"))
		}
		log.Printf("PhotoDNA: execution error: %v (stderr: %s)", err, stderr.String())
		return s.handleError(err)
	}

	// Exit code 0 = no match
	log.Printf("PhotoDNA: check complete - no match found")
	return false, nil
}

// handleError decides whether to block or allow based on FailOpen setting
func (s *Scanner) handleError(err error) (bool, error) {
	if s.cfg.PhotoDNAFailOpen {
		// Fail open: allow upload but log the error
		log.Printf("PhotoDNA: error occurred but failing open (allowing upload): %v", err)
		return false, nil
	}
	// Fail closed: reject upload on error
	log.Printf("PhotoDNA: error occurred, failing closed (rejecting upload): %v", err)
	return true, err
}
