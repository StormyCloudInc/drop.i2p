package server

import (
	"net/http"

	"drop-i2p/internal/config"
	"drop-i2p/internal/i2p"
	"drop-i2p/internal/metadata"
	mw "drop-i2p/internal/middleware"
	"drop-i2p/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	cfg         *config.Config
	store       *storage.Manager
	transport   i2p.Transport
	rateLimiter *mw.RateLimiter
	stripper    *metadata.Stripper
}

func New(cfg *config.Config, store *storage.Manager) *Server {
	// Initialize HTTP bridge transport (works with Java I2P's i2ptunnel)
	transport := i2p.NewHTTPBridgeTransport()

	// Initialize rate limiter
	rateLimiter := mw.NewRateLimiter(mw.DefaultRateLimitConfig())

	// Initialize metadata stripper
	stripper := metadata.NewStripper()

	return &Server{
		cfg:         cfg,
		store:       store,
		transport:   transport,
		rateLimiter: rateLimiter,
		stripper:    stripper,
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// I2P middleware to extract destination from headers
	r.Use(i2p.I2PMiddleware)

	// Rate limiting middleware (per I2P destination)
	r.Use(mw.RateLimitMiddleware(s.rateLimiter))

	// Static Files
	fs := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fs))

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

	// Static pages
	r.Get("/donate", s.handleDonate)
	r.Get("/report", s.handleReportPage)
	r.Post("/report", s.handleReportSubmit)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/upload", s.handleAPIUpload)
		r.Post("/upload/paste", s.handleAPIPaste)
		r.Post("/report", s.handleReport)

		// Chunked upload routes
		r.Post("/upload/chunked/init", s.handleChunkedInit)
		r.Post("/upload/chunked/{uploadID}/{chunkIndex}", s.handleChunkedUpload)
		r.Post("/upload/chunked/{uploadID}/complete", s.handleChunkedComplete)
		r.Get("/upload/chunked/{uploadID}/status", s.handleChunkedStatus)
	})


	// Custom 404 handler
	r.NotFound(handleNotFound)

	// Admin routes
	r.Route("/admin", func(r chi.Router) {
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
	})

	return r
}
