package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"drop-i2p/internal/i2p"
	"drop-i2p/internal/models"
	"drop-i2p/internal/storage"
	"drop-i2p/internal/validator"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Templates - caching for performance
// Only load the templates used by the Go server (not the legacy Flask templates)
var templates = template.Must(template.ParseFiles(
	"templates/index.html",
	"templates/upload_result.html",
	"templates/view_file.html",
	"templates/view_paste.html",
	"templates/admin.html",
	"templates/admin_reports.html",
	"templates/admin_bans.html",
	"templates/admin_tools.html",
	"templates/report.html",
	"templates/error.html",
	"templates/message.html",
))

// renderError renders a styled error page
func renderError(w http.ResponseWriter, statusCode int, icon, title, message, details string) {
	w.WriteHeader(statusCode)
	data := map[string]interface{}{
		"Icon":    icon,
		"Title":   title,
		"Message": message,
		"Details": details,
	}
	templates.ExecuteTemplate(w, "error.html", data)
}

// renderMessage renders a styled message page (success, error, warning, info)
// msgType should be: "success", "error", "warning", or "info"
func renderMessage(w http.ResponseWriter, statusCode int, msgType, title, message string) {
	w.WriteHeader(statusCode)
	data := map[string]interface{}{
		"Type":    msgType,
		"Title":   title,
		"Message": message,
	}
	templates.ExecuteTemplate(w, "message.html", data)
}

// handleNotFound renders a styled 404 page
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	renderMessage(w, http.StatusNotFound, "error", "Page Not Found", "The page you are looking for does not exist.")
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	data := map[string]interface{}{
		"Stats": stats,
		"Host":  r.Host,
	}
	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Parse Multipart Form
	// Limit to 55MB to accommodate 50MB files + multipart overhead
	r.Body = http.MaxBytesReader(w, r.Body, 55<<20)
	if err := r.ParseMultipartForm(55 << 20); err != nil {
		renderMessage(w, http.StatusRequestEntityTooLarge, "error", "File Too Large", "The file exceeds the maximum upload size of 50MB.")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Get uploader's I2P destination from context (set by I2P middleware)
	uploaderDest := i2p.GetDestinationFromRequest(r)

	// Check if destination is banned
	if uploaderDest != "" {
		if banned, _ := s.store.IsDestinationBanned(uploaderDest); banned {
			http.Error(w, "Upload not allowed", http.StatusForbidden)
			return
		}
	}

	// Validate file type (extension and MIME type blacklist)
	mimeType := header.Header.Get("Content-Type")
	if valid, reason := validator.ValidateFile(header.Filename, mimeType); !valid {
		http.Error(w, reason, http.StatusBadRequest)
		return
	}

	// Read Options
	expiryStr := r.FormValue("expiry")

	// Parse expiry - max 30 days, no permanent option
	// Default 24h if not specified
	duration := 24 * time.Hour
	if expiryStr != "" && expiryStr != "permanent" {
		if d, err := time.ParseDuration(expiryStr); err == nil {
			duration = d
		}
	}
	// Cap at 30 days maximum
	maxDuration := 30 * 24 * time.Hour
	if duration > maxDuration {
		duration = maxDuration
	}
	t := time.Now().Add(duration)
	expiryTime := &t

	// Build upload options
	opts := &storage.UploadOptions{
		MetadataStripped: true, // Default: strip metadata
	}

	// Check if user wants to keep metadata
	keepMetadata := r.FormValue("keep_metadata") == "on" || r.FormValue("keep_metadata") == "true"
	opts.MetadataStripped = !keepMetadata

	// Handle password protection
	password := r.FormValue("password")
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}
		opts.PasswordHash = string(hash)
	}

	// Handle max downloads
	maxDownloadsStr := r.FormValue("max_downloads")
	if maxDownloadsStr != "" {
		if maxVal, err := strconv.Atoi(maxDownloadsStr); err == nil && maxVal > 0 {
			opts.MaxDownloads = &maxVal
		}
	}

	// Generate ID and Token
	fileID := uuid.New().String()
	deleteToken := uuid.New().String()

	// Save File
	savedFile, err := s.store.SaveFile(fileID, file, header.Filename, mimeType, expiryTime, deleteToken, uploaderDest, opts)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save file: %v", err), http.StatusInternalServerError)
		return
	}

	// Strip metadata if not keeping it
	if !keepMetadata && s.stripper.CanStrip(mimeType) {
		// For non-chunked uploads, we need to strip metadata from the assembled file
		// This is handled at download time for chunked uploads
		// TODO: Implement temp file metadata stripping for regular uploads
	}

	// Check if content hash is blocked (post-upload check)
	if blocked, _ := s.store.IsHashBlocked(savedFile.ContentHash); blocked {
		// Delete the file we just uploaded
		s.store.DeleteFile(fileID)
		renderMessage(w, http.StatusForbidden, "error", "Content Not Allowed", "This content has been blocked and cannot be uploaded.")
		return
	}

	// Redirect to view page with delete token as query param (so user sees it once)
	http.Redirect(w, r, fmt.Sprintf("/view/%s?token=%s", savedFile.ID, deleteToken), http.StatusSeeOther)
}

// handleViewFile shows the file view page
func (s *Server) handleViewFile(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	deleteToken := r.URL.Query().Get("token")
	flash := r.URL.Query().Get("flash")
	flashType := r.URL.Query().Get("flash_type")

	file, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		renderError(w, http.StatusNotFound, "&#x1F50D;", "File Not Found",
			"The file you're looking for doesn't exist or has been deleted.",
			"It may have expired or been removed by the uploader.")
		return
	}

	if file.IsBlocked {
		renderError(w, http.StatusForbidden, "&#x1F6AB;", "File Unavailable",
			"This file has been blocked and is no longer available.",
			"It was removed for violating our terms of service.")
		return
	}

	// Check if file is password protected and if user is unlocked
	isPasswordProtected := file.PasswordHash != ""
	isUnlocked := false
	if isPasswordProtected {
		// Check cookie for unlock status
		cookie, err := r.Cookie("unlocked_" + fileID)
		if err == nil && cookie.Value == "true" {
			isUnlocked = true
		}
	}

	// Calculate time left
	var timeLeft string
	if file.ExpiryTime != nil {
		remaining := time.Until(*file.ExpiryTime)
		if remaining > 0 {
			if remaining > 24*time.Hour {
				timeLeft = fmt.Sprintf("~%d days", int(remaining.Hours()/24))
			} else if remaining > time.Hour {
				timeLeft = fmt.Sprintf("~%d hours", int(remaining.Hours()))
			} else {
				timeLeft = fmt.Sprintf("~%d minutes", int(remaining.Minutes()))
			}
		}
	}

	// Determine if it's an image
	isImage := false
	fileType := "file"
	switch file.MimeType {
	case "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml":
		isImage = true
		fileType = "image"
	case "application/pdf":
		fileType = "pdf"
	case "application/zip", "application/x-tar", "application/gzip", "application/x-7z-compressed":
		fileType = "archive"
	case "video/mp4", "video/webm", "video/ogg":
		fileType = "video"
	case "audio/mpeg", "audio/ogg", "audio/wav":
		fileType = "audio"
	}

	// Format file size
	fileSizeFormatted := formatSize(file.Size)

	// Determine host (use X-Forwarded-Host if behind proxy)
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = fh
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	// Calculate remaining downloads (download_count starts at -1, so actual downloads = count + 1)
	var remainingDownloads *int
	if file.MaxDownloads != nil {
		remaining := *file.MaxDownloads - (file.DownloadCount + 1)
		if remaining < 0 {
			remaining = 0
		}
		remainingDownloads = &remaining
	}

	// Show delete button when token is in URL - the uploader just uploaded and got redirected here
	showDeleteButton := deleteToken != ""

	data := map[string]interface{}{
		"File":                file,
		"TimeLeft":            timeLeft,
		"IsImage":             isImage,
		"FileType":            fileType,
		"FileSizeFormatted":   fileSizeFormatted,
		"DeleteToken":         deleteToken,
		"ShowDeleteButton":    showDeleteButton,
		"Host":                scheme + "://" + host,
		"IsPasswordProtected": isPasswordProtected,
		"IsUnlocked":          isUnlocked,
		"NeedsPassword":       isPasswordProtected && !isUnlocked, // Show password form if protected and not yet unlocked
		"HasMaxDownloads":     file.MaxDownloads != nil,
		"MaxDownloads":        file.MaxDownloads,
		"RemainingDownloads":  remainingDownloads,
		"DownloadCount":       file.DownloadCount + 1, // Actual download count (since it starts at -1)
		"Flash":               flash,
		"FlashType":           flashType,
	}

	if err := templates.ExecuteTemplate(w, "view_file.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleUnlockFile handles password verification for protected files
func (s *Server) handleUnlockFile(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/view/%s?flash=Invalid+form&flash_type=error", fileID), http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Redirect(w, r, fmt.Sprintf("/view/%s?flash=Password+required&flash_type=error", fileID), http.StatusSeeOther)
		return
	}

	file, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(file.PasswordHash), []byte(password)); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/view/%s?flash=Invalid+password&flash_type=error", fileID), http.StatusSeeOther)
		return
	}

	// Set unlock cookie (HTTP-only, session-based)
	http.SetCookie(w, &http.Cookie{
		Name:     "unlocked_" + fileID,
		Value:    "true",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// No Expires = session cookie
	})

	http.Redirect(w, r, fmt.Sprintf("/view/%s?flash=File+unlocked&flash_type=success", fileID), http.StatusSeeOther)
}

// formatSize formats bytes to human-readable size
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")

	file, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		renderError(w, http.StatusNotFound, "&#x1F50D;", "File Not Found",
			"The file you're looking for doesn't exist or has been deleted.",
			"It may have expired or been removed by the uploader.")
		return
	}

	// Check if file is blocked
	if file.IsBlocked {
		renderError(w, http.StatusForbidden, "&#x1F6AB;", "File Unavailable",
			"This file has been blocked and is no longer available.",
			"It was removed for violating our terms of service.")
		return
	}

	// Check password protection
	if file.PasswordHash != "" {
		cookie, err := r.Cookie("unlocked_" + fileID)
		if err != nil || cookie.Value != "true" {
			http.Redirect(w, r, fmt.Sprintf("/view/%s?flash=Password+required+to+download&flash_type=error", fileID), http.StatusSeeOther)
			return
		}
	}

	// Check max downloads BEFORE serving (download_count starts at -1)
	// After increment, count will be: 0 for first download, 1 for second, etc.
	if file.MaxDownloads != nil {
		// Current actual downloads = download_count + 1 (since it starts at -1)
		actualDownloads := file.DownloadCount + 1
		if actualDownloads >= *file.MaxDownloads {
			// Max reached, delete file and return error
			s.store.DeleteFile(fileID)
			renderError(w, http.StatusGone, "&#x1F4A8;", "Download Limit Reached",
				"This file has reached its maximum download limit and has been deleted.",
				"The uploader set a limit on how many times this file could be downloaded.")
			return
		}
	}

	// Set common headers
	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", file.Filename))
	w.Header().Set("Accept-Ranges", "bytes")

	// Check for Range header (resumable downloads)
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		s.handleRangeDownload(w, r, file, rangeHeader)
		return
	}

	// Track download stats (increments download_count from -1 to 0 on first download)
	s.store.IncrementStat("total_downloads")
	s.store.IncrementFileDownloads(fileID)

	// Full download
	w.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))

	if err := s.store.RetrieveFile(fileID, w); err != nil {
		fmt.Printf("Error streaming file: %v\n", err)
	}
}

// handleRangeDownload handles HTTP Range requests for partial/resumable downloads
func (s *Server) handleRangeDownload(w http.ResponseWriter, _ *http.Request, file *models.File, rangeHeader string) {
	// Parse Range header: "bytes=start-end" or "bytes=start-"
	var start, end int64

	// Simple range parsing (only supports single range)
	_, err := fmt.Sscanf(rangeHeader, "bytes=%d-%d", &start, &end)
	if err != nil {
		// Try parsing "bytes=start-" format
		_, err = fmt.Sscanf(rangeHeader, "bytes=%d-", &start)
		if err != nil {
			http.Error(w, "Invalid Range header", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		end = file.Size - 1
	}

	// Validate range
	if start < 0 || start >= file.Size || end >= file.Size || start > end {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", file.Size))
		http.Error(w, "Range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	contentLength := end - start + 1

	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, file.Size))
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.WriteHeader(http.StatusPartialContent)

	// Stream the partial content
	if err := s.store.RetrieveFileRange(file.ID, w, start, end); err != nil {
		fmt.Printf("Error streaming partial file: %v\n", err)
	}
}

// FileManifest represents file metadata for resumable downloads
type FileManifest struct {
	FileID     string   `json:"file_id"`
	Filename   string   `json:"filename"`
	Size       int64    `json:"size"`
	MimeType   string   `json:"mime_type"`
	ChunkSize  int      `json:"chunk_size"`
	ChunkCount int      `json:"chunk_count"`
	Checksums  []string `json:"checksums"`
}

// handleManifest returns file metadata for resumable downloads
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")

	file, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if file.IsBlocked {
		http.Error(w, "File not available", http.StatusForbidden)
		return
	}

	// Get chunk info
	chunks, err := s.store.GetChunks(fileID)
	if err != nil {
		http.Error(w, "Failed to get chunk info", http.StatusInternalServerError)
		return
	}

	checksums := make([]string, len(chunks))
	for i, chunk := range chunks {
		checksums[i] = chunk.Checksum
	}

	manifest := FileManifest{
		FileID:     file.ID,
		Filename:   file.Filename,
		Size:       file.Size,
		MimeType:   file.MimeType,
		ChunkSize:  256 * 1024, // Current chunk size
		ChunkCount: len(chunks),
		Checksums:  checksums,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
    fileID := chi.URLParam(r, "fileID")
    token := chi.URLParam(r, "token")
    
    // Verify token
    meta, err := s.store.GetFileMetadata(fileID)
    if err != nil {
         http.Error(w, "File not found", http.StatusNotFound)
         return
    }
    
    if meta.DeleteToken != token {
        http.Error(w, "Invalid delete token", http.StatusForbidden)
        return
    }
    
    if err := s.store.DeleteFile(fileID); err != nil {
        http.Error(w, "Failed to delete", http.StatusInternalServerError)
        return
    }

    renderMessage(w, http.StatusOK, "success", "File Deleted", "Your file has been permanently deleted.")
}

func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no password hash configured, deny access
		if s.cfg.AdminPasswordHash == "" {
			http.Error(w, "Admin access not configured. Set SSP_ADMIN_PASSWORD_HASH environment variable.", http.StatusForbidden)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Check username (default: admin)
		if username != "admin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Check password against bcrypt hash
		// Note: SSP_ADMIN_PASSWORD_HASH should be a bcrypt hash
		// Generate with: htpasswd -nbBC 10 "" password | tr -d ':\n'
		// Or use: go run -e 'import "golang.org/x/crypto/bcrypt"; h,_:=bcrypt.GenerateFromPassword([]byte("yourpassword"),10); println(string(h))'
		if err := checkPasswordHash(s.cfg.AdminPasswordHash, password); err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// checkPasswordHash verifies a password against a bcrypt hash
func checkPasswordHash(hash, password string) error {
	if len(hash) > 0 && hash[0] == '$' {
		// bcrypt hash
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	}
	// Plain text comparison (for development only - not recommended)
	if hash == password {
		return nil
	}
	return fmt.Errorf("invalid password")
}

// AdminFileView represents a file with formatted fields for admin display
type AdminFileView struct {
	*models.File
	SizeFormatted     string
	EncryptionType    string
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	flash := r.URL.Query().Get("flash")
	flashType := r.URL.Query().Get("flash_type")

	// List recent files
	files, _ := s.store.ListFiles(100) // Get top 100

	// Create admin views with formatted fields
	adminFiles := make([]AdminFileView, len(files))
	for i, f := range files {
		encType := "Legacy AES"
		if f.EncryptionVersion == 2 {
			encType = "Hybrid PQ"
		}
		adminFiles[i] = AdminFileView{
			File:           f,
			SizeFormatted:  formatSize(f.Size),
			EncryptionType: encType,
		}
	}

	// Get stats
	stats, _ := s.store.GetStats()

	// Get reports
	reports, _ := s.store.ListReports("pending", 100)

	// Get bans
	bans, _ := s.store.ListBans(100)

	data := map[string]interface{}{
		"Files":         adminFiles,
		"Stats":         stats,
		"Reports":       reports,
		"Bans":          bans,
		"Flash":         flash,
		"FlashType":     flashType,
		"HasHybridKeys": s.cfg.HasHybridKeys(),
		"KeyVersion":    s.cfg.KeyVersion,
	}
	templates.ExecuteTemplate(w, "admin.html", data)
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	s.store.DeleteFile(fileID)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleReport handles content reports from users
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FileID string `json:"file_id"`
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.FileID == "" || req.Reason == "" {
		http.Error(w, "file_id and reason are required", http.StatusBadRequest)
		return
	}

	// Get reporter's I2P destination
	reporterDest := i2p.GetDestinationFromRequest(r)

	// Create report
	reportID := uuid.New().String()
	if err := s.store.CreateReport(reportID, req.FileID, reporterDest, req.Reason); err != nil {
		http.Error(w, "Failed to create report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"report_id": reportID,
	})
}

// handleAdminReports lists pending reports
func (s *Server) handleAdminReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.store.ListReports("pending", 100)
	if err != nil {
		http.Error(w, "Failed to list reports", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Reports": reports,
	}
	templates.ExecuteTemplate(w, "admin_reports.html", data)
}

// handleAdminReportAction handles admin actions on reports
func (s *Server) handleAdminReportAction(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "reportID")
	action := r.FormValue("action") // "dismiss", "delete_file", "ban_hash", "ban_uploader"

	switch action {
	case "dismiss":
		s.store.UpdateReportStatus(reportID, "dismissed", "Dismissed by admin")
	case "delete_file":
		report, err := s.store.GetReport(reportID)
		if err == nil && report != nil {
			s.store.DeleteFile(report.FileID)
			s.store.UpdateReportStatus(reportID, "actioned", "File deleted")
		}
	case "ban_hash":
		report, err := s.store.GetReport(reportID)
		if err == nil && report != nil {
			file, _ := s.store.GetFileMetadata(report.FileID)
			if file != nil && file.ContentHash != "" {
				s.store.CreateBan(uuid.New().String(), "file_hash", file.ContentHash, "Banned via report", nil)
				s.store.DeleteFile(report.FileID)
				s.store.UpdateReportStatus(reportID, "actioned", "Content hash banned and file deleted")
			}
		}
	case "ban_uploader":
		report, err := s.store.GetReport(reportID)
		if err == nil && report != nil {
			file, _ := s.store.GetFileMetadata(report.FileID)
			if file != nil && file.UploaderDest != "" {
				s.store.CreateBan(uuid.New().String(), "destination", file.UploaderDest, "Banned via report", nil)
				s.store.UpdateReportStatus(reportID, "actioned", "Uploader banned")
			}
		}
	}

	http.Redirect(w, r, "/admin/reports", http.StatusSeeOther)
}

// handleAdminBans lists active bans
func (s *Server) handleAdminBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.store.ListBans(100)
	if err != nil {
		http.Error(w, "Failed to list bans", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Bans": bans,
	}
	templates.ExecuteTemplate(w, "admin_bans.html", data)
}

// handleAdminCreateBan creates a new ban
func (s *Server) handleAdminCreateBan(w http.ResponseWriter, r *http.Request) {
	banType := r.FormValue("ban_type")   // "destination" or "file_hash"
	value := r.FormValue("value")        // The destination or hash to ban
	reason := r.FormValue("reason")
	expiresStr := r.FormValue("expires") // Duration string or empty for permanent

	if banType == "" || value == "" {
		http.Error(w, "ban_type and value are required", http.StatusBadRequest)
		return
	}

	var expiresAt *time.Time
	if expiresStr != "" {
		if d, err := time.ParseDuration(expiresStr); err == nil {
			t := time.Now().Add(d)
			expiresAt = &t
		}
	}

	banID := uuid.New().String()
	if err := s.store.CreateBan(banID, banType, value, reason, expiresAt); err != nil {
		http.Error(w, "Failed to create ban", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/bans", http.StatusSeeOther)
}

// handleAdminDeleteBan removes a ban
func (s *Server) handleAdminDeleteBan(w http.ResponseWriter, r *http.Request) {
	banID := chi.URLParam(r, "banID")
	s.store.DeleteBan(banID)
	http.Redirect(w, r, "/admin/bans", http.StatusSeeOther)
}

// handleAdminBlock blocks a file from being accessed
func (s *Server) handleAdminBlock(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	s.store.BlockFile(fileID)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAdminTools shows the admin tools page
func (s *Server) handleAdminTools(w http.ResponseWriter, r *http.Request) {
	flash := r.URL.Query().Get("flash")
	flashType := r.URL.Query().Get("flash_type")

	data := map[string]interface{}{
		"Flash":     flash,
		"FlashType": flashType,
		"HasHybridKeys": s.cfg.HasHybridKeys(),
		"KeyVersion": s.cfg.KeyVersion,
	}
	templates.ExecuteTemplate(w, "admin_tools.html", data)
}

// handleAdminCleanup runs garbage collection manually
func (s *Server) handleAdminCleanup(w http.ResponseWriter, r *http.Request) {
	go func() {
		s.store.CleanupExpired()
		s.store.CleanupExpiredPastes()
		s.store.CleanupExpiredChunkedUploads()
	}()
	http.Redirect(w, r, "/admin?flash=Cleanup+started&flash_type=success", http.StatusSeeOther)
}

// ========== Paste Handlers ==========

// handleUploadPaste creates a new paste
func (s *Server) handleUploadPaste(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	language := r.FormValue("language")
	if language == "" {
		language = "text"
	}

	expiryStr := r.FormValue("expiry")
	uploaderDest := i2p.GetDestinationFromRequest(r)

	// Check if destination is banned
	if uploaderDest != "" {
		if banned, _ := s.store.IsDestinationBanned(uploaderDest); banned {
			http.Error(w, "Upload not allowed", http.StatusForbidden)
			return
		}
	}

	// Parse expiry - max 30 days, no permanent option
	// Default 1h for pastes if not specified
	duration := 1 * time.Hour
	if expiryStr != "" && expiryStr != "permanent" {
		if d, err := time.ParseDuration(expiryStr); err == nil {
			duration = d
		}
	}
	// Cap at 30 days maximum
	maxDuration := 30 * 24 * time.Hour
	if duration > maxDuration {
		duration = maxDuration
	}
	t := time.Now().Add(duration)
	expiryTime := &t

	pasteID := uuid.New().String()
	deleteToken := uuid.New().String()

	_, err := s.store.SavePaste(pasteID, []byte(content), language, expiryTime, deleteToken, uploaderDest)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save paste: %v", err), http.StatusInternalServerError)
		return
	}

	// Set delete token in a session cookie (not in URL to prevent accidental sharing)
	http.SetCookie(w, &http.Cookie{
		Name:     "paste_delete_" + pasteID,
		Value:    deleteToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// No Expires = session cookie (deleted when browser closes)
	})

	http.Redirect(w, r, fmt.Sprintf("/p/%s", pasteID), http.StatusSeeOther)
}

// handleViewPaste shows the paste view page
func (s *Server) handleViewPaste(w http.ResponseWriter, r *http.Request) {
	pasteID := chi.URLParam(r, "pasteID")

	// Check for delete token in cookie (set after paste creation)
	// The cookie is deleted after the first view so the delete link is only shown once
	var deleteToken string
	if cookie, err := r.Cookie("paste_delete_" + pasteID); err == nil {
		deleteToken = cookie.Value
		// Clear the cookie so the delete link is only shown on initial upload
		http.SetCookie(w, &http.Cookie{
			Name:     "paste_delete_" + pasteID,
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // Delete the cookie
			HttpOnly: true,
		})
	}

	paste, err := s.store.GetPaste(pasteID)
	if err != nil {
		renderError(w, http.StatusNotFound, "&#x1F4DD;", "Paste Not Found",
			"The paste you're looking for doesn't exist or has been deleted.",
			"It may have expired or been removed by the creator.")
		return
	}

	if paste.IsBlocked {
		renderError(w, http.StatusForbidden, "&#x1F6AB;", "Paste Unavailable",
			"This paste has been blocked and is no longer available.",
			"It was removed for violating our terms of service.")
		return
	}

	// Increment view count (only if not showing with token AND not a syntax change)
	// Syntax changes via ?lang= should not count as a view (like Python version)
	if deleteToken == "" && r.URL.Query().Get("lang") == "" {
		s.store.IncrementPasteViewCount(pasteID)
	}

	// Check for language override via query parameter
	displayLanguage := paste.Language
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		// Validate it's a supported language
		validLanguages := map[string]bool{
			"text": true, "bash": true, "c": true, "cpp": true, "css": true,
			"go": true, "html": true, "java": true, "javascript": true, "json": true,
			"python": true, "ruby": true, "rust": true, "sql": true, "typescript": true,
			"xml": true, "yaml": true,
		}
		if validLanguages[langParam] {
			displayLanguage = langParam
		}
	}

	// Calculate time left
	var timeLeft string
	if paste.ExpiryTime != nil {
		remaining := time.Until(*paste.ExpiryTime)
		if remaining > 0 {
			if remaining > 24*time.Hour {
				timeLeft = fmt.Sprintf("~%d days", int(remaining.Hours()/24))
			} else if remaining > time.Hour {
				timeLeft = fmt.Sprintf("~%d hours", int(remaining.Hours()))
			} else {
				timeLeft = fmt.Sprintf("~%d minutes", int(remaining.Minutes()))
			}
		}
	}

	// Determine host
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = fh
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	data := map[string]interface{}{
		"Paste":           paste,
		"Content":         string(paste.Content),
		"TimeLeft":        timeLeft,
		"DeleteToken":     deleteToken,
		"Host":            scheme + "://" + host,
		"DisplayLanguage": displayLanguage,
	}

	if err := templates.ExecuteTemplate(w, "view_paste.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleRawPaste returns the raw paste content
func (s *Server) handleRawPaste(w http.ResponseWriter, r *http.Request) {
	pasteID := chi.URLParam(r, "pasteID")

	paste, err := s.store.GetPaste(pasteID)
	if err != nil {
		renderError(w, http.StatusNotFound, "&#x1F4DD;", "Paste Not Found",
			"The paste you're looking for doesn't exist or has been deleted.",
			"It may have expired or been removed by the creator.")
		return
	}

	if paste.IsBlocked {
		renderError(w, http.StatusForbidden, "&#x1F6AB;", "Paste Unavailable",
			"This paste has been blocked and is no longer available.",
			"It was removed for violating our terms of service.")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(paste.Content)
}

// handleDeletePaste deletes a paste with token verification
func (s *Server) handleDeletePaste(w http.ResponseWriter, r *http.Request) {
	pasteID := chi.URLParam(r, "pasteID")
	token := chi.URLParam(r, "token")

	paste, err := s.store.GetPaste(pasteID)
	if err != nil {
		http.Error(w, "Paste not found", http.StatusNotFound)
		return
	}

	if paste.DeleteToken != token {
		http.Error(w, "Invalid delete token", http.StatusForbidden)
		return
	}

	if err := s.store.DeletePaste(pasteID); err != nil {
		http.Error(w, "Failed to delete", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Paste deleted successfully."))
}

// handleAPIUpload handles API file uploads (returns JSON)
func (s *Server) handleAPIUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 55<<20)
	if err := r.ParseMultipartForm(55 << 20); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(map[string]string{"error": "File too large"})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	uploaderDest := i2p.GetDestinationFromRequest(r)
	mimeType := header.Header.Get("Content-Type")

	if valid, reason := validator.ValidateFile(header.Filename, mimeType); !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": reason})
		return
	}

	expiryStr := r.FormValue("expiry")
	// Parse expiry - max 30 days, no permanent option
	// Default 24h if not specified
	duration := 24 * time.Hour
	if expiryStr != "" && expiryStr != "permanent" {
		if d, err := time.ParseDuration(expiryStr); err == nil {
			duration = d
		}
	}
	// Cap at 30 days maximum
	maxDuration := 30 * 24 * time.Hour
	if duration > maxDuration {
		duration = maxDuration
	}
	t := time.Now().Add(duration)
	expiryTime := &t

	// Parse upload options
	keepMetadata := r.FormValue("keep_metadata") == "true" || r.FormValue("keep_metadata") == "1"
	password := r.FormValue("password")
	maxDownloadsStr := r.FormValue("max_downloads")

	var passwordHash string
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process password"})
			return
		}
		passwordHash = string(hash)
	}

	var maxDownloads *int
	if maxDownloadsStr != "" {
		if md, err := strconv.Atoi(maxDownloadsStr); err == nil && md > 0 {
			maxDownloads = &md
		}
	}

	fileID := uuid.New().String()
	deleteToken := uuid.New().String()

	// Prepare upload options
	opts := &storage.UploadOptions{
		PasswordHash:     passwordHash,
		MaxDownloads:     maxDownloads,
		MetadataStripped: !keepMetadata,
	}

	savedFile, err := s.store.SaveFile(fileID, file, header.Filename, mimeType, expiryTime, deleteToken, uploaderDest, opts)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save file"})
		return
	}

	// Track API upload stats
	s.store.IncrementStat("total_api_uploads")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           savedFile.ID,
		"url":          fmt.Sprintf("/f/%s", savedFile.ID),
		"delete_url":   fmt.Sprintf("/d/%s/%s", savedFile.ID, deleteToken),
		"delete_token": deleteToken,
		"size":         savedFile.Size,
		"filename":     savedFile.Filename,
	})
}

// handleAPIPaste handles API paste creation (returns JSON)
func (s *Server) handleAPIPaste(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content  string `json:"content"`
		Language string `json:"language"`
		Expiry   string `json:"expiry"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Content is required"})
		return
	}

	language := req.Language
	if language == "" {
		language = "text"
	}

	uploaderDest := i2p.GetDestinationFromRequest(r)

	// Parse expiry - max 30 days, no permanent option
	// Default 1h for pastes if not specified
	duration := 1 * time.Hour
	if req.Expiry != "" && req.Expiry != "permanent" {
		if d, err := time.ParseDuration(req.Expiry); err == nil {
			duration = d
		}
	}
	// Cap at 30 days maximum
	maxDuration := 30 * 24 * time.Hour
	if duration > maxDuration {
		duration = maxDuration
	}
	t := time.Now().Add(duration)
	expiryTime := &t

	pasteID := uuid.New().String()
	deleteToken := uuid.New().String()

	_, err := s.store.SavePaste(pasteID, []byte(req.Content), language, expiryTime, deleteToken, uploaderDest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save paste"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           pasteID,
		"url":          fmt.Sprintf("/p/%s", pasteID),
		"raw_url":      fmt.Sprintf("/p/%s/raw", pasteID),
		"delete_url":   fmt.Sprintf("/pd/%s/%s", pasteID, deleteToken),
		"delete_token": deleteToken,
	})
}

// handleDonate shows the donation page
func (s *Server) handleDonate(w http.ResponseWriter, r *http.Request) {
	// For now, redirect to static donate.html if it exists
	http.ServeFile(w, r, "templates/donate.html")
}

// handleReportPage shows the public report page
func (s *Server) handleReportPage(w http.ResponseWriter, r *http.Request) {
	flash := r.URL.Query().Get("flash")
	flashType := r.URL.Query().Get("flash_type")

	data := map[string]interface{}{
		"Flash":     flash,
		"FlashType": flashType,
	}
	templates.ExecuteTemplate(w, "report.html", data)
}

// handleReportSubmit handles form submission from the public report page
func (s *Server) handleReportSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/report?flash=Invalid+form&flash_type=error", http.StatusSeeOther)
		return
	}

	fileURL := r.FormValue("file_url")
	reason := r.FormValue("reason")

	if fileURL == "" || reason == "" {
		http.Redirect(w, r, "/report?flash=URL+and+reason+are+required&flash_type=error", http.StatusSeeOther)
		return
	}

	// Check rate limiting
	reporterDest := i2p.GetDestinationFromRequest(r)
	if !s.rateLimiter.AllowReport(reporterDest) {
		http.Redirect(w, r, "/report?flash=Too+many+reports.+Please+try+again+later.&flash_type=error", http.StatusSeeOther)
		return
	}

	// Parse file ID from URL
	// URL formats: /f/UUID, /view/UUID, /p/UUID, http://host/f/UUID, etc.
	fileID := extractFileIDFromURL(fileURL)
	if fileID == "" {
		http.Redirect(w, r, "/report?flash=Invalid+file+URL.+Please+provide+a+valid+file+link.&flash_type=error", http.StatusSeeOther)
		return
	}

	// Verify file or paste exists
	_, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		// Also check if it's a paste
		_, pasteErr := s.store.GetPaste(fileID)
		if pasteErr != nil {
			http.Redirect(w, r, "/report?flash=File+not+found.+It+may+have+been+deleted+or+expired.&flash_type=error", http.StatusSeeOther)
			return
		}
	}

	// Create report
	reportID := uuid.New().String()
	if err := s.store.CreateReport(reportID, fileID, reporterDest, reason); err != nil {
		http.Redirect(w, r, "/report?flash=Failed+to+submit+report.+Please+try+again.&flash_type=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/report?flash=Report+submitted+successfully.+Thank+you.&flash_type=success", http.StatusSeeOther)
}

// extractFileIDFromURL parses a file ID from various URL formats
func extractFileIDFromURL(fileURL string) string {
	// Try to parse as URL first
	parsed, err := url.Parse(fileURL)
	if err == nil && parsed.Path != "" {
		// Extract path: /f/UUID, /view/UUID, or /p/UUID
		path := parsed.Path
		if strings.HasPrefix(path, "/f/") {
			return strings.TrimPrefix(path, "/f/")
		}
		if strings.HasPrefix(path, "/view/") {
			return strings.TrimPrefix(path, "/view/")
		}
		if strings.HasPrefix(path, "/p/") {
			return strings.TrimPrefix(path, "/p/")
		}
	}

	// Try direct patterns in the input string
	if strings.Contains(fileURL, "/f/") {
		parts := strings.Split(fileURL, "/f/")
		if len(parts) >= 2 {
			// Get the ID part, trimming any query params or path suffix
			id := parts[len(parts)-1]
			if idx := strings.Index(id, "?"); idx != -1 {
				id = id[:idx]
			}
			if idx := strings.Index(id, "/"); idx != -1 {
				id = id[:idx]
			}
			return strings.TrimSpace(id)
		}
	}

	if strings.Contains(fileURL, "/view/") {
		parts := strings.Split(fileURL, "/view/")
		if len(parts) >= 2 {
			id := parts[len(parts)-1]
			if idx := strings.Index(id, "?"); idx != -1 {
				id = id[:idx]
			}
			if idx := strings.Index(id, "/"); idx != -1 {
				id = id[:idx]
			}
			return strings.TrimSpace(id)
		}
	}

	if strings.Contains(fileURL, "/p/") {
		parts := strings.Split(fileURL, "/p/")
		if len(parts) >= 2 {
			id := parts[len(parts)-1]
			if idx := strings.Index(id, "?"); idx != -1 {
				id = id[:idx]
			}
			if idx := strings.Index(id, "/"); idx != -1 {
				id = id[:idx]
			}
			return strings.TrimSpace(id)
		}
	}

	// If input looks like a UUID directly, return it
	if len(fileURL) == 36 && strings.Count(fileURL, "-") == 4 {
		return fileURL
	}

	return ""
}

// ========== Chunked Upload Handlers ==========

// handleChunkedInit initializes a chunked upload session
func (s *Server) handleChunkedInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename     string `json:"filename"`
		MimeType     string `json:"mime_type"`
		TotalSize    int64  `json:"total_size"`
		TotalChunks  int    `json:"total_chunks"`
		Expiry       string `json:"expiry"`
		Password     string `json:"password"`
		MaxDownloads *int   `json:"max_downloads"`
		KeepMetadata bool   `json:"keep_metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.Filename == "" || req.TotalSize <= 0 || req.TotalChunks <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "filename, total_size, and total_chunks are required"})
		return
	}

	// Check if destination is banned
	uploaderDest := i2p.GetDestinationFromRequest(r)
	if uploaderDest != "" {
		if banned, _ := s.store.IsDestinationBanned(uploaderDest); banned {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Upload not allowed"})
			return
		}
	}

	// Hash password if provided
	var passwordHash string
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process password"})
			return
		}
		passwordHash = string(hash)
	}

	uploadID := uuid.New().String()
	upload, err := s.store.InitChunkedUpload(uploadID, req.Filename, req.MimeType, req.TotalSize, req.TotalChunks, req.Expiry, uploaderDest, passwordHash, req.MaxDownloads, req.KeepMetadata)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to initialize upload"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"upload_id":    upload.ID,
		"chunk_size":   upload.ChunkSize,
		"total_chunks": upload.TotalChunks,
		"expires_at":   upload.ExpiresAt,
	})
}

// handleChunkedUpload receives an individual chunk
func (s *Server) handleChunkedUpload(w http.ResponseWriter, r *http.Request) {
	uploadID := chi.URLParam(r, "uploadID")
	chunkIndexStr := chi.URLParam(r, "chunkIndex")

	chunkIndex, err := strconv.Atoi(chunkIndexStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid chunk index"})
		return
	}

	// Verify upload session exists
	upload, err := s.store.GetChunkedUpload(uploadID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Upload session not found"})
		return
	}

	// Validate chunk index
	if chunkIndex < 0 || chunkIndex >= upload.TotalChunks {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chunk index out of range"})
		return
	}

	// Limit chunk size (3MB max to allow for overhead)
	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)

	// Read chunk data
	data, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read chunk data"})
		return
	}

	// Save chunk
	if err := s.store.SaveUploadChunk(uploadID, chunkIndex, data); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save chunk"})
		return
	}

	// Get updated status
	upload, _ = s.store.GetChunkedUpload(uploadID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"chunk_index":     chunkIndex,
		"received_chunks": upload.ReceivedChunks,
		"total_chunks":    upload.TotalChunks,
		"complete":        upload.ReceivedChunks == upload.TotalChunks,
	})
}

// handleChunkedComplete finalizes a chunked upload
func (s *Server) handleChunkedComplete(w http.ResponseWriter, r *http.Request) {
	uploadID := chi.URLParam(r, "uploadID")

	file, deleteToken, err := s.store.CompleteChunkedUpload(uploadID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           file.ID,
		"url":          fmt.Sprintf("/f/%s", file.ID),
		"view_url":     fmt.Sprintf("/view/%s", file.ID),
		"delete_url":   fmt.Sprintf("/d/%s/%s", file.ID, deleteToken),
		"delete_token": deleteToken,
		"size":         file.Size,
		"filename":     file.Filename,
	})
}

// handleChunkedStatus returns the status of a chunked upload
func (s *Server) handleChunkedStatus(w http.ResponseWriter, r *http.Request) {
	uploadID := chi.URLParam(r, "uploadID")

	upload, err := s.store.GetChunkedUpload(uploadID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Upload session not found"})
		return
	}

	// Get received chunk indices
	chunks, _ := s.store.GetUploadChunks(uploadID)
	receivedIndices := make([]int, len(chunks))
	for i, c := range chunks {
		receivedIndices[i] = c.ChunkIndex
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"upload_id":        upload.ID,
		"filename":         upload.Filename,
		"total_size":       upload.TotalSize,
		"total_chunks":     upload.TotalChunks,
		"received_chunks":  upload.ReceivedChunks,
		"received_indices": receivedIndices,
		"complete":         upload.ReceivedChunks == upload.TotalChunks,
		"expires_at":       upload.ExpiresAt,
	})
}
