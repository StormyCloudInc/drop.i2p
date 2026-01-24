package server

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"drop-i2p/internal/clamav"
	"drop-i2p/internal/config"
	"drop-i2p/internal/i2p"
	"drop-i2p/internal/imaging"
	"drop-i2p/internal/metadata"
	mw "drop-i2p/internal/middleware"
	"drop-i2p/internal/storage"
	"drop-i2p/internal/webhook"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// AnnouncementReader reads and caches announcement content from file
type AnnouncementReader struct {
	filePath    string
	content     string
	lastModTime time.Time
	mu          sync.RWMutex
}

// NewAnnouncementReader creates a new announcement reader
func NewAnnouncementReader(filePath string) *AnnouncementReader {
	ar := &AnnouncementReader{filePath: filePath}
	ar.refresh() // Initial load
	return ar
}

// Get returns the current announcement message (empty if no file or empty file)
func (ar *AnnouncementReader) Get() string {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return ar.content
}

// refresh checks if file has changed and reloads if necessary
func (ar *AnnouncementReader) refresh() {
	if ar.filePath == "" {
		return
	}

	info, err := os.Stat(ar.filePath)
	if err != nil {
		// File doesn't exist or can't be read - clear announcement
		ar.mu.Lock()
		ar.content = ""
		ar.mu.Unlock()
		return
	}

	// Check if file was modified
	if !info.ModTime().After(ar.lastModTime) {
		return
	}

	// Read file content
	data, err := os.ReadFile(ar.filePath)
	if err != nil {
		ar.mu.Lock()
		ar.content = ""
		ar.mu.Unlock()
		return
	}

	ar.mu.Lock()
	ar.content = strings.TrimSpace(string(data))
	ar.lastModTime = info.ModTime()
	ar.mu.Unlock()
}

// StartAutoRefresh starts a goroutine that periodically checks for file changes
func (ar *AnnouncementReader) StartAutoRefresh(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ar.refresh()
		}
	}()
}

type Server struct {
	cfg          *config.Config
	store        *storage.Manager
	transport    i2p.Transport
	rateLimiter  *mw.RateLimiter
	stripper     *metadata.Stripper
	clamAV       *clamav.Scanner
	webhook      *webhook.Notifier
	announcement *AnnouncementReader
	imageProc    *imaging.Processor
}

func New(cfg *config.Config, store *storage.Manager) *Server {
	// Initialize HTTP bridge transport (works with Java I2P's i2ptunnel)
	transport := i2p.NewHTTPBridgeTransport()

	// Initialize rate limiter
	rateLimiter := mw.NewRateLimiter(mw.DefaultRateLimitConfig())

	// Initialize metadata stripper
	stripper := metadata.NewStripper()

	// Initialize ClamAV scanner
	clamAVScanner := clamav.NewScanner(cfg)

	// Initialize webhook notifier
	webhookNotifier := webhook.NewNotifier(cfg)

	// Initialize announcement reader (auto-refreshes every 30 seconds)
	announcementReader := NewAnnouncementReader(cfg.AnnouncementFile)
	announcementReader.StartAutoRefresh(30 * time.Second)

	// Initialize image processor (converts images to WebP for I2P bandwidth savings)
	imageProcessor := imaging.NewProcessor(imaging.DefaultConfig())

	return &Server{
		cfg:          cfg,
		store:        store,
		transport:    transport,
		rateLimiter:  rateLimiter,
		stripper:     stripper,
		clamAV:       clamAVScanner,
		webhook:      webhookNotifier,
		announcement: announcementReader,
		imageProc:    imageProcessor,
	}
}

// Webhook returns the webhook notifier for use by background tasks
func (s *Server) Webhook() *webhook.Notifier {
	return s.webhook
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// Gzip compression for responses (significant bandwidth savings on I2P)
	// Note: chi requires exact content-type match, so include charset variants
	r.Use(middleware.Compress(5,
		"text/html",
		"text/html; charset=utf-8",
		"text/css",
		"text/css; charset=utf-8",
		"text/plain",
		"text/plain; charset=utf-8",
		"text/javascript",
		"application/javascript",
		"application/json",
		"application/json; charset=utf-8",
		"application/xml",
		"image/svg+xml",
	))

	// I2P middleware to extract destination from headers
	r.Use(i2p.I2PMiddleware)

	// Rate limiting middleware (per I2P destination)
	r.Use(mw.RateLimitMiddleware(s.rateLimiter))

	// Static Files
	// Static Files
	fs := http.FileServer(http.Dir("static"))
	r.Get("/static/*", func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		opts := rctx.URLParams
		pathPrefix := "/static/"
		if len(opts.Keys) > 0 { // Should not happen with * wildcard but to be safe
			// ..
		}
		// Clean the path to avoid traversal/confusion
		path := r.URL.Path
		if strings.HasSuffix(path, "/") {
			http.NotFound(w, r)
			return
		}
		http.StripPrefix(pathPrefix, fs).ServeHTTP(w, r)
	})
	r.Get("/", s.handleIndex)
	r.Post("/upload", s.handleUpload)
	r.Get("/view/{fileID}", s.handleViewFile)
	r.Post("/view/{fileID}/unlock", s.handleUnlockFile)
	r.Get("/f/{fileID}", s.handleDownload)
	r.Get("/f/{fileID}/manifest", s.handleManifest)
	r.Get("/d/{fileID}/{token}", s.handleDelete)

	// Paste routes
	r.Post("/upload/paste", s.handleUploadPaste)
	r.Get("/p/{pasteID}", s.handleViewPaste)
	r.Get("/p/{pasteID}/raw", s.handleRawPaste)
	r.Get("/pd/{pasteID}/{token}", s.handleDeletePaste)

	// Collection routes
	r.Get("/c/{collectionID}", s.handleViewCollection)
	r.Post("/c/{collectionID}/unlock", s.handleUnlockCollection)
	r.Get("/cd/{collectionID}/{token}", s.handleDeleteCollection)

	// Static pages
	r.Get("/donate", s.handleDonate)
	r.Get("/report", s.handleReportPage)
	r.Post("/report", s.handleReportSubmit)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/upload", s.handleAPIUpload)
		r.Post("/upload/paste", s.handleAPIPaste)
		r.Post("/report", s.handleReport)

		// Collection API routes
		r.Post("/collection/create", s.handleAPICreateCollection)

		// Chunked upload routes
		r.Post("/upload/chunked/init", s.handleChunkedInit)
		r.Post("/upload/chunked/{uploadID}/{chunkIndex}", s.handleChunkedUpload)
		r.Post("/upload/chunked/{uploadID}/complete", s.handleChunkedComplete)
		r.Get("/upload/chunked/{uploadID}/status", s.handleChunkedStatus)
	})

	// Custom 404 handler
	r.NotFound(handleNotFound)

	// Admin routes (configurable via SSP_ADMIN_URL, default: /admin)
	r.Route(s.cfg.AdminURL, func(r chi.Router) {
		r.Use(s.adminAuth)
		r.Get("/", s.handleAdminDashboard)
		r.Post("/delete/{fileID}", s.handleAdminDelete)
		r.Post("/block/{fileID}", s.handleAdminBlock)
		r.Get("/reports", s.handleAdminReports)
		r.Post("/reports/{reportID}/action", s.handleAdminReportAction)
		r.Get("/bans", s.handleAdminBans)
		r.Post("/bans", s.handleAdminCreateBan)
		r.Delete("/bans/{banID}", s.handleAdminDeleteBan)
		r.Get("/tools", s.handleAdminTools)
		r.Post("/tools/cleanup", s.handleAdminCleanup)
		r.Get("/analytics", s.handleAdminAnalytics)
	})

	return r
}
