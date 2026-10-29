package storage

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"log"

	"drop-i2p/internal/db"
	"drop-i2p/internal/models"
	"drop-i2p/internal/phash"

	"github.com/google/uuid"
)

// BanMatch describes the ban that caused content to be refused.
type BanMatch struct {
	BanID    string
	BanType  string // models.BanTypeFileHash or models.BanTypePerceptualHash
	Distance int    // Hamming distance for perceptual matches; 0 for exact matches
}

// Exact reports whether the match was a byte-identical SHA-256 match.
func (b *BanMatch) Exact() bool { return b.BanType == models.BanTypeFileHash }

// ContentBannedError is returned when an upload matches a hash ban.
type ContentBannedError struct{ Match *BanMatch }

func (e *ContentBannedError) Error() string { return "upload not allowed" }

// AsContentBanned extracts a ContentBannedError from err, if present.
func AsContentBanned(err error) (*ContentBannedError, bool) {
	var cb *ContentBannedError
	ok := errors.As(err, &cb)
	return cb, ok
}

// SHA256Hex returns the hex SHA-256 of data, matching how files.content_hash is computed.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PerceptualHashOf returns the dHash of data if it decodes as an image with
// enough detail, or "" otherwise. It deliberately ignores the client-supplied
// MIME type: an image renamed to .bin or sent as octet-stream is still hashed.
func PerceptualHashOf(data []byte) string {
	h, err := phash.FromBytes(data)
	if err != nil {
		return ""
	}
	return h.String()
}

// looksLikeImage cheaply checks the header without decoding pixels.
func looksLikeImage(head []byte) bool {
	_, _, err := image.DecodeConfig(bytes.NewReader(head))
	return err == nil
}

// CheckContentBan reports whether content matches an active ban, by exact
// SHA-256 or by perceptual hash within the configured threshold.
// sha256Hex is required; perceptualHex may be empty.
func (m *Manager) CheckContentBan(sha256Hex, perceptualHex string) (*BanMatch, error) {
	var banID string
	err := db.DB.QueryRow(`
		SELECT id FROM bans
		WHERE ban_type = ? AND value = ?
		AND (expires_at IS NULL OR expires_at > datetime('now'))
		LIMIT 1`, models.BanTypeFileHash, sha256Hex).Scan(&banID)
	if err == nil {
		return &BanMatch{BanID: banID, BanType: models.BanTypeFileHash}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	threshold := m.cfg.PHashThreshold
	if perceptualHex == "" || threshold <= 0 {
		return nil, nil
	}
	want, err := phash.Parse(perceptualHex)
	if err != nil || !phash.Reliable(want) {
		return nil, nil
	}

	rows, err := db.DB.Query(`
		SELECT id, value FROM bans
		WHERE ban_type = ?
		AND (expires_at IS NULL OR expires_at > datetime('now'))`, models.BanTypePerceptualHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var best *BanMatch
	for rows.Next() {
		var id, value string
		if err := rows.Scan(&id, &value); err != nil {
			return nil, err
		}
		h, err := phash.Parse(value)
		if err != nil {
			continue
		}
		if d := phash.Distance(want, h); d <= threshold && (best == nil || d < best.Distance) {
			best = &BanMatch{BanID: id, BanType: models.BanTypePerceptualHash, Distance: d}
		}
	}
	return best, rows.Err()
}

// RecordBannedUpload handles an upload that matched a ban: counts it, logs it,
// and for exact matches bans the uploading destination when configured to.
// A perceptual match alone never auto-bans, since near-duplicate matching can
// in rare cases hit an unrelated image.
func (m *Manager) RecordBannedUpload(uploaderDest string, match *BanMatch) {
	m.IncrementStat("hash_ban_blocked")
	log.Printf("content-ban: refused upload from dest=%q ban=%s type=%s distance=%d",
		uploaderDest, match.BanID, match.BanType, match.Distance)

	if !match.Exact() || !m.cfg.AutoBanOnHashMatch || uploaderDest == "" {
		return
	}
	if banned, _ := m.IsDestinationBanned(uploaderDest); banned {
		return
	}
	reason := fmt.Sprintf("Auto: uploaded content matching hash ban %s", match.BanID)
	if err := m.CreateBan(uuid.New().String(), models.BanTypeDestination, uploaderDest, reason, nil); err != nil {
		log.Printf("content-ban: failed to auto-ban destination: %v", err)
		return
	}
	m.IncrementStat("hash_ban_autobanned_dests")
}

// BanFileContent creates bans for a file's SHA-256 and, when available, its
// perceptual hash. It returns how many bans were created.
func (m *Manager) BanFileContent(file *models.File, reason string) (int, error) {
	created := 0
	if file.ContentHash != "" {
		if match, _ := m.CheckContentBan(file.ContentHash, ""); match == nil {
			if err := m.CreateBan(uuid.New().String(), models.BanTypeFileHash, file.ContentHash, reason, nil); err != nil {
				return created, err
			}
			created++
		}
	}
	if file.PerceptualHash != "" {
		if h, err := phash.Parse(file.PerceptualHash); err == nil && phash.Reliable(h) {
			var exists int
			db.DB.QueryRow(`SELECT COUNT(*) FROM bans WHERE ban_type = ? AND value = ?`,
				models.BanTypePerceptualHash, file.PerceptualHash).Scan(&exists)
			if exists == 0 {
				if err := m.CreateBan(uuid.New().String(), models.BanTypePerceptualHash, file.PerceptualHash, reason, nil); err != nil {
					return created, err
				}
				created++
			}
		}
	}
	return created, nil
}

// SetPerceptualHash stores a file's perceptual hash.
func (m *Manager) SetPerceptualHash(fileID, perceptualHex string) error {
	_, err := db.DB.Exec(`UPDATE files SET perceptual_hash = ? WHERE id = ?`, perceptualHex, fileID)
	return err
}

// BackfillResult summarises a perceptual-hash backfill run.
type BackfillResult struct {
	Scanned, Hashed, NotImage, Errors, MatchedBans int
}

// BackfillPerceptualHashes computes perceptual hashes for stored files that do
// not have one yet. Client-encrypted (E2EE) files are skipped because the
// server cannot see their contents. Files that turn out to match an existing
// ban are blocked immediately.
func (m *Manager) BackfillPerceptualHashes() (*BackfillResult, error) {
	rows, err := db.DB.Query(`
		SELECT id, COALESCE(content_hash, '') FROM files
		WHERE (perceptual_hash IS NULL OR perceptual_hash = '')
		AND COALESCE(is_client_encrypted, 0) = 0
		AND size <= ?`, phash.MaxDecodeBytes)
	if err != nil {
		return nil, err
	}
	type pending struct{ id, sha string }
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.sha); err == nil {
			todo = append(todo, p)
		}
	}
	rows.Close()

	res := &BackfillResult{}
	for _, p := range todo {
		res.Scanned++
		var buf bytes.Buffer
		if err := m.RetrieveFile(p.id, &buf); err != nil {
			res.Errors++
			continue
		}
		ph := PerceptualHashOf(buf.Bytes())
		if ph == "" {
			// Mark as checked so later runs skip it.
			m.SetPerceptualHash(p.id, "-")
			res.NotImage++
			continue
		}
		if err := m.SetPerceptualHash(p.id, ph); err != nil {
			res.Errors++
			continue
		}
		res.Hashed++
		if match, _ := m.CheckContentBan(p.sha, ph); match != nil {
			m.BlockFile(p.id)
			res.MatchedBans++
			log.Printf("content-ban: backfill blocked existing file %s (ban %s, distance %d)", p.id, match.BanID, match.Distance)
		}
	}
	return res, nil
}

// nullIfEmpty stores "" as SQL NULL.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
