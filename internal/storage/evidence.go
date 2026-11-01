package storage

import (
	"database/sql"
	"errors"
	"time"

	"drop-i2p/internal/db"
)

// ErrPreserved is returned by DeleteFile while a file is under an evidence hold.
var ErrPreserved = errors.New("file is preserved as evidence and cannot be deleted yet")

// NCMEC report states stored in files.ncmec_status.
const (
	NCMECNone        = ""             // quarantined, not queued for reporting
	NCMECPending     = "pending"      // queued, will be sent
	NCMECSending     = "sending"      // a sender has claimed it
	NCMECReported    = "reported"     // NCMEC accepted the finished report
	NCMECFailed      = "failed"       // last attempt failed; can be retried
	NCMECNotSent     = "not_sent"     // not sent by policy (test mode or no credentials); can be retried
	NCMECNotSendable = "not_sendable" // E2EE: the server only has ciphertext
)

// Evidence is a taken-down file and its reporting state.
type Evidence struct {
	FileID            string
	Filename          string
	MimeType          string
	Size              int64
	UploadTime        time.Time
	UploaderDest      string
	ContentHash       string
	PerceptualHash    string
	IsClientEncrypted bool
	TakedownAt        *time.Time
	PreservedUntil    *time.Time
	Status            string
	ReportID          string
	Error             string
	ReportedAt        *time.Time
	Viewed            bool
	Classification    string
	Notes             string
}

func now() time.Time { return time.Now().UTC() }

// IsPreserved reports whether a file is under an active evidence hold.
func (m *Manager) IsPreserved(fileID string) bool {
	var until *time.Time
	if err := db.DB.QueryRow(`SELECT preserved_until FROM files WHERE id = ?`, fileID).Scan(&until); err != nil {
		return false
	}
	return until != nil && until.After(now())
}

// QuarantineFile removes a file from public access and preserves it as
// evidence for hold. It never shortens an existing hold. If queue is true the
// file is queued for NCMEC reporting, unless it was already reported.
func (m *Manager) QuarantineFile(fileID string, hold time.Duration, queue, viewed bool, classification, notes string) error {
	until := now().Add(hold)
	status := NCMECNone
	if queue {
		status = NCMECPending
	}
	res, err := db.DB.Exec(`
		UPDATE files SET
			is_blocked = 1,
			preserved_until = CASE WHEN preserved_until IS NOT NULL AND preserved_until > ? THEN preserved_until ELSE ? END,
			takedown_at = COALESCE(takedown_at, ?),
			ncmec_status = CASE
				WHEN ncmec_status = 'reported' THEN ncmec_status
				WHEN ? = '' THEN COALESCE(ncmec_status, '')
				ELSE ? END,
			ncmec_viewed = CASE WHEN ? THEN 1 ELSE COALESCE(ncmec_viewed, 0) END,
			ncmec_classification = CASE WHEN ? != '' THEN ? ELSE ncmec_classification END,
			ncmec_notes = CASE WHEN ? != '' THEN ? ELSE ncmec_notes END
		WHERE id = ?`,
		until, until, now(), status, status, viewed, classification, classification, notes, notes, fileID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// QueueNCMEC marks a quarantined file for (re)sending, unless already reported.
func (m *Manager) QueueNCMEC(fileID string) error {
	_, err := db.DB.Exec(`UPDATE files SET ncmec_status = ?, ncmec_error = NULL
		WHERE id = ? AND takedown_at IS NOT NULL AND COALESCE(ncmec_status, '') != ?`,
		NCMECPending, fileID, NCMECReported)
	return err
}

// ClaimForNCMEC atomically moves a file from pending to sending. Only one
// caller can win, so a report is never filed twice concurrently.
func (m *Manager) ClaimForNCMEC(fileID string) bool {
	res, err := db.DB.Exec(`UPDATE files SET ncmec_status = ? WHERE id = ? AND ncmec_status = ?`,
		NCMECSending, fileID, NCMECPending)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// SetNCMECResult records the outcome of a reporting attempt.
func (m *Manager) SetNCMECResult(fileID, status, reportID, errMsg string) error {
	var reportedAt interface{}
	if status == NCMECReported {
		reportedAt = now()
	}
	_, err := db.DB.Exec(`UPDATE files SET ncmec_status = ?, ncmec_report_id = COALESCE(NULLIF(?, ''), ncmec_report_id),
		ncmec_error = NULLIF(?, ''), ncmec_reported_at = COALESCE(?, ncmec_reported_at) WHERE id = ?`,
		status, reportID, errMsg, reportedAt, fileID)
	return err
}

// ResetStuckNCMEC returns reports left in "sending" by a crash to "pending".
func (m *Manager) ResetStuckNCMEC() {
	db.DB.Exec(`UPDATE files SET ncmec_status = ? WHERE ncmec_status = ?`, NCMECPending, NCMECSending)
}

// ListNCMECPending returns IDs of files queued for reporting.
func (m *Manager) ListNCMECPending() ([]string, error) {
	rows, err := db.DB.Query(`SELECT id FROM files WHERE ncmec_status = ? ORDER BY takedown_at`, NCMECPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

const evidenceColumns = `id, filename, COALESCE(mime_type, ''), COALESCE(size, 0), upload_time,
	COALESCE(uploader_dest, ''), COALESCE(content_hash, ''), COALESCE(NULLIF(perceptual_hash, '-'), ''),
	COALESCE(is_client_encrypted, 0), takedown_at, preserved_until, COALESCE(ncmec_status, ''),
	COALESCE(ncmec_report_id, ''), COALESCE(ncmec_error, ''), ncmec_reported_at,
	COALESCE(ncmec_viewed, 0), COALESCE(ncmec_classification, ''), COALESCE(ncmec_notes, '')`

func scanEvidence(sc interface{ Scan(...interface{}) error }) (*Evidence, error) {
	var e Evidence
	err := sc.Scan(&e.FileID, &e.Filename, &e.MimeType, &e.Size, &e.UploadTime,
		&e.UploaderDest, &e.ContentHash, &e.PerceptualHash,
		&e.IsClientEncrypted, &e.TakedownAt, &e.PreservedUntil, &e.Status,
		&e.ReportID, &e.Error, &e.ReportedAt,
		&e.Viewed, &e.Classification, &e.Notes)
	return &e, err
}

// GetEvidence returns the evidence record for one file.
func (m *Manager) GetEvidence(fileID string) (*Evidence, error) {
	return scanEvidence(db.DB.QueryRow(`SELECT `+evidenceColumns+` FROM files WHERE id = ?`, fileID))
}

// ListEvidence returns all taken-down files, newest first.
func (m *Manager) ListEvidence(limit int) ([]*Evidence, error) {
	rows, err := db.DB.Query(`SELECT `+evidenceColumns+` FROM files WHERE takedown_at IS NOT NULL
		ORDER BY takedown_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Evidence
	for rows.Next() {
		if e, err := scanEvidence(rows); err == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}
