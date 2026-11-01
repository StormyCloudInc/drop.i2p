package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"drop-i2p/internal/models"
	"drop-i2p/internal/ncmec"
	"drop-i2p/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ncmecMode describes how reporting is configured, for display and policy.
func (s *Server) ncmecMode() string {
	switch {
	case s.ncmec == nil:
		return "not configured"
	case s.ncmec.IsProduction():
		return "production"
	default:
		return "test"
	}
}

// newNCMECClient builds the client from config, or nil if credentials are missing.
func newNCMECClient(cfgEnv, user, pass, email string) *ncmec.Client {
	if user == "" || pass == "" || email == "" {
		return nil
	}
	return ncmec.NewClient(cfgEnv, user, pass)
}

func (s *Server) evidenceHold() time.Duration {
	days := s.cfg.EvidenceHoldDays
	if days < 365 {
		// 18 U.S.C. 2258A(h) requires at least one year once reported.
		days = 365
	}
	return time.Duration(days) * 24 * time.Hour
}

func redirectFlash(w http.ResponseWriter, r *http.Request, path, msg, kind string) {
	http.Redirect(w, r, path+"?flash="+url.QueryEscape(msg)+"&flash_type="+kind, http.StatusSeeOther)
}

var validClassifications = map[string]bool{"": true, ncmec.ClassA1: true, ncmec.ClassA2: true, ncmec.ClassB1: true, ncmec.ClassB2: true}

// handleAdminNCMEC lists taken-down files and their reporting state.
func (s *Server) handleAdminNCMEC(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListEvidence(500)
	if err != nil {
		http.Error(w, "Failed to list evidence", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"AdminURL":  s.cfg.AdminURL,
		"Items":     items,
		"Mode":      s.ncmecMode(),
		"Flash":     r.URL.Query().Get("flash"),
		"FlashType": r.URL.Query().Get("flash_type"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_ncmec.html", data); err != nil {
		log.Printf("render admin_ncmec: %v", err)
	}
}

// handleAdminTakedownForm shows the confirmation page. It never displays the file itself.
func (s *Server) handleAdminTakedownForm(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	file, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		redirectFlash(w, r, s.cfg.AdminURL+"/ncmec", "File not found: "+fileID, "error")
		return
	}
	ev, _ := s.store.GetEvidence(fileID)
	data := map[string]interface{}{
		"AdminURL": s.cfg.AdminURL,
		"File":     file,
		"Evidence": ev,
		"ReportID": r.URL.Query().Get("report"),
		"Mode":     s.ncmecMode(),
		"HoldDays": int(s.evidenceHold().Hours() / 24),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "admin_takedown.html", data); err != nil {
		log.Printf("render admin_takedown: %v", err)
	}
}

// handleAdminTakedown takes a file down immediately and queues the NCMEC report.
// Takedown never waits on NCMEC: the file is blocked, preserved and banned
// before any network call, and the report is filed in the background.
func (s *Server) handleAdminTakedown(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	file, err := s.store.GetFileMetadata(fileID)
	if err != nil {
		redirectFlash(w, r, s.cfg.AdminURL+"/ncmec", "File not found", "error")
		return
	}

	viewed := r.FormValue("viewed") == "on"
	classification := strings.TrimSpace(r.FormValue("classification"))
	if !validClassifications[classification] {
		classification = ""
	}
	if !viewed {
		classification = "" // only someone who looked may classify
	}
	notes := strings.TrimSpace(r.FormValue("notes"))
	if len(notes) > 2000 {
		notes = notes[:2000]
	}
	queue := r.FormValue("report") != "skip"

	if err := s.store.QuarantineFile(fileID, s.evidenceHold(), queue, viewed, classification, notes); err != nil {
		log.Printf("takedown %s: quarantine failed: %v", fileID, err)
		redirectFlash(w, r, s.cfg.AdminURL+"/ncmec", "Takedown FAILED: "+err.Error(), "error")
		return
	}

	nBans, err := s.store.BanFileContent(file, "Takedown "+fileID)
	if err != nil {
		log.Printf("takedown %s: ban failed: %v", fileID, err)
	}
	if r.FormValue("ban_uploader") == "on" && file.UploaderDest != "" {
		if banned, _ := s.store.IsDestinationBanned(file.UploaderDest); !banned {
			if err := s.store.CreateBan(uuid.New().String(), models.BanTypeDestination, file.UploaderDest, "Takedown "+fileID, nil); err == nil {
				nBans++
			}
		}
	}
	if reportID := r.FormValue("report_id"); reportID != "" {
		s.store.UpdateReportStatus(reportID, models.ReportStatusActioned, "Taken down and preserved as evidence")
	}
	log.Printf("takedown %s: blocked, preserved, %d bans, queued=%v", fileID, nBans, queue)

	msg := fmt.Sprintf("File taken down and preserved. %d ban(s) added.", nBans)
	if queue {
		go s.sendToNCMEC(fileID)
		msg += " NCMEC report queued; status updates below."
	}
	redirectFlash(w, r, s.cfg.AdminURL+"/ncmec", msg, "success")
}

// handleAdminNCMECSend re-queues and sends a report (retry or first send).
func (s *Server) handleAdminNCMECSend(w http.ResponseWriter, r *http.Request) {
	fileID := chi.URLParam(r, "fileID")
	if err := s.store.QueueNCMEC(fileID); err != nil {
		redirectFlash(w, r, s.cfg.AdminURL+"/ncmec", "Could not queue: "+err.Error(), "error")
		return
	}
	go s.sendToNCMEC(fileID)
	redirectFlash(w, r, s.cfg.AdminURL+"/ncmec", "Report queued.", "success")
}

// sendToNCMEC files one report. Safe to call concurrently: the claim step
// guarantees a single sender per file.
func (s *Server) sendToNCMEC(fileID string) {
	if !s.store.ClaimForNCMEC(fileID) {
		return
	}
	result := func(status, reportID, msg string) {
		if err := s.store.SetNCMECResult(fileID, status, reportID, msg); err != nil {
			log.Printf("ncmec %s: failed to record result %s: %v", fileID, status, err)
		}
		log.Printf("ncmec %s: %s %s %s", fileID, status, reportID, msg)
	}

	switch s.ncmecMode() {
	case "not configured":
		result(storage.NCMECNotSent, "", "NCMEC credentials are not configured on the server.")
		return
	case "test":
		// Real uploads are never transmitted to the test environment.
		result(storage.NCMECNotSent, "", "Reporting is in TEST mode. Real files are never sent to the test environment. Set SSP_NCMEC_ENV=production, restart, then click Send.")
		return
	}

	ev, err := s.store.GetEvidence(fileID)
	if err != nil {
		result(storage.NCMECFailed, "", "evidence record not found: "+err.Error())
		return
	}
	if ev.IsClientEncrypted {
		result(storage.NCMECNotSendable, "", "File is end-to-end encrypted; the server only holds ciphertext. File a manual report at report.cybertip.org if you have other evidence.")
		return
	}

	var buf bytes.Buffer
	if err := s.store.RetrieveFile(fileID, &buf); err != nil {
		result(storage.NCMECFailed, "", "could not read preserved file: "+err.Error())
		return
	}

	rep, file := ncmec.BuildFileReport(ncmec.ReporterInfo{
		FirstName: s.cfg.NCMECReporterFirst,
		LastName:  s.cfg.NCMECReporterLast,
		Email:     s.cfg.NCMECReporterEmail,
		Platform:  "drop.i2p",
		Service:   "drop.i2p file hosting",
	}, ncmec.FileIncident{
		FileID:           ev.FileID,
		PublicURL:        strings.TrimRight(s.cfg.PublicURL, "/") + "/f/" + ev.FileID,
		OriginalFilename: ev.Filename,
		UploadTime:       ev.UploadTime,
		UploaderID:       ev.UploaderDest,
		SHA256:           ev.ContentHash,
		PerceptualHash:   ev.PerceptualHash,
		ViewedByESP:      ev.Viewed,
		Classification:   ev.Classification,
		Notes:            ev.Notes,
	})
	file.Content = buf.Bytes()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := s.ncmec.SubmitComplete(ctx, rep, []ncmec.FileToReport{file})
	if err != nil {
		var apiErr *ncmec.APIError
		msg := err.Error()
		if errors.As(err, &apiErr) && apiErr.RequestID != "" {
			msg += " (quote Request-ID " + apiErr.RequestID + " to NCMEC support)"
		}
		result(storage.NCMECFailed, "", msg)
		return
	}
	result(storage.NCMECReported, res.ReportID, "")
}

// resumeNCMEC sends anything left queued, e.g. after a restart.
func (s *Server) resumeNCMEC() {
	s.store.ResetStuckNCMEC()
	ids, err := s.store.ListNCMECPending()
	if err != nil {
		log.Printf("ncmec resume: %v", err)
		return
	}
	for _, id := range ids {
		s.sendToNCMEC(id)
	}
}

// SetNCMECClient replaces the reporting client. Used by tests.
func (s *Server) SetNCMECClient(c *ncmec.Client) { s.ncmec = c }
