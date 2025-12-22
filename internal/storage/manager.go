package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"drop-i2p/internal/config"
	"drop-i2p/internal/crypto"
	"drop-i2p/internal/db"
	"drop-i2p/internal/models"

	"github.com/google/uuid"
)

const ChunkSize = 256 * 1024 // 256KB chunks - optimized for I2P retry economics

// Encryption version constants
const (
	EncryptionVersionLegacy = 1 // Legacy AES-GCM with static key
	EncryptionVersionHybrid = 2 // Hybrid X25519 + ML-KEM-768 with XChaCha20-Poly1305
)

// UploadOptions contains optional file upload settings
type UploadOptions struct {
	PasswordHash     string
	MaxDownloads     *int
	MetadataStripped bool
}

// PhotoDNAChecker interface for image content checking
type PhotoDNAChecker interface {
	ShouldCheck(mimeType string) bool
	CheckImage(ctx context.Context, imageData []byte) (blocked bool, err error)
}

// ClamAVChecker interface for virus/malware scanning
type ClamAVChecker interface {
	ShouldCheck(mimeType string) bool
	CheckFile(ctx context.Context, data []byte) (infected bool, threat string, err error)
}

type Manager struct {
	cfg        *config.Config
	keyManager *crypto.KeyManager
	photoDNA   PhotoDNAChecker
	clamAV     ClamAVChecker
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

// NewManagerWithKeys creates a Manager with hybrid PQ encryption support
func NewManagerWithKeys(cfg *config.Config, km *crypto.KeyManager) *Manager {
	return &Manager{cfg: cfg, keyManager: km}
}

// SetPhotoDNAChecker sets the PhotoDNA checker for image content scanning
func (m *Manager) SetPhotoDNAChecker(checker PhotoDNAChecker) {
	m.photoDNA = checker
}

// SetClamAVChecker sets the ClamAV checker for virus/malware scanning
func (m *Manager) SetClamAVChecker(checker ClamAVChecker) {
	m.clamAV = checker
}

// HasHybridEncryption returns true if hybrid PQ encryption is available
func (m *Manager) HasHybridEncryption() bool {
	return m.keyManager != nil
}

// SaveFile splits the stream into chunks, encrypts them, saves to disk, and records in DB.
func (m *Manager) SaveFile(fileID string, reader io.Reader, filename, mimeType string, expiryTime *time.Time, deleteToken, uploaderDest string, opts *UploadOptions) (*models.File, error) {
	if opts == nil {
		opts = &UploadOptions{MetadataStripped: true} // Default: strip metadata
	}
	// Create upload dir if not exists
	if err := os.MkdirAll(m.cfg.UploadFolder, 0700); err != nil {
		return nil, err
	}

	// Determine encryption version and get file key
	var fileKey []byte
	var kemCiphertext []byte
	var keyVersion int
	encryptionVersion := EncryptionVersionHybrid

	if m.keyManager != nil {
		// Use hybrid PQ encryption
		var err error
		fileKey, kemCiphertext, err = m.keyManager.EncryptForFile(fileID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate file key: %w", err)
		}
		keyVersion = int(m.keyManager.CurrentVersion())
	} else {
		// Fallback to legacy AES-GCM
		encryptionVersion = EncryptionVersionLegacy
		keyVersion = 0
	}

	buf := make([]byte, ChunkSize)
	chunkIndex := 0
	totalSize := int64(0)

	// Content hash for deduplication and blocking
	var contentHasher hash.Hash = sha256.New()

	// Begin Transaction
	tx, err := db.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for {
		n, err := io.ReadFull(reader, buf)
		if n > 0 {
			// Update content hash with plaintext
			contentHasher.Write(buf[:n])

			// Compute chunk checksum
			chunkHash := sha256.Sum256(buf[:n])
			chunkChecksum := hex.EncodeToString(chunkHash[:])

			// Encrypt chunk
			var ciphertext []byte
			if m.keyManager != nil {
				// Use hybrid encryption (XChaCha20-Poly1305)
				ciphertext, err = crypto.EncryptChunk(fileKey, chunkIndex, buf[:n])
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt chunk: %w", err)
				}
			} else {
				// Legacy AES-GCM encryption
				gcm, err := m.getGCM()
				if err != nil {
					return nil, err
				}
				nonce := make([]byte, gcm.NonceSize())
				if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
					return nil, err
				}
				ciphertext = gcm.Seal(nonce, nonce, buf[:n], nil)
			}

			// Save chunk
			chunkUUID := uuid.New().String()
			chunkPath := filepath.Join(m.cfg.UploadFolder, chunkUUID)
			if err := os.WriteFile(chunkPath, ciphertext, 0600); err != nil {
				return nil, err
			}

			// Record chunk in DB with size and checksum
			_, err = tx.Exec("INSERT INTO chunks (file_id, chunk_index, chunk_path, chunk_size, checksum) VALUES (?, ?, ?, ?, ?)",
				fileID, chunkIndex, chunkUUID, n, chunkChecksum)
			if err != nil {
				return nil, err
			}

			totalSize += int64(n)
			chunkIndex++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	contentHash := hex.EncodeToString(contentHasher.Sum(nil))

	// Insert File Record with extended fields including hybrid encryption fields
	_, err = tx.Exec(`
		INSERT INTO files (id, filename, original_filename, size, mime_type, content_hash, expiry_time, delete_token, is_encrypted, uploader_dest, password_hash, max_downloads, metadata_stripped, kem_ciphertext, key_version, encryption_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, fileID, filename, filename, totalSize, mimeType, contentHash, expiryTime, deleteToken, true, uploaderDest, opts.PasswordHash, opts.MaxDownloads, opts.MetadataStripped, kemCiphertext, keyVersion, encryptionVersion)

	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Update stats
	m.IncrementStat("total_files")
	m.IncrementStatByAmount("total_bytes_stored", totalSize)

	return &models.File{
		ID:                fileID,
		Filename:          filename,
		OriginalFilename:  filename,
		Size:              totalSize,
		MimeType:          mimeType,
		ContentHash:       contentHash,
		ExpiryTime:        expiryTime,
		DeleteToken:       deleteToken,
		UploaderDest:      uploaderDest,
		IsEncrypted:       true,
		PasswordHash:      opts.PasswordHash,
		MaxDownloads:      opts.MaxDownloads,
		MetadataStripped:  opts.MetadataStripped,
		KEMCiphertext:     kemCiphertext,
		KeyVersion:        keyVersion,
		EncryptionVersion: encryptionVersion,
	}, nil
}

// RetrieveFile streams the decrypted file content
func (m *Manager) RetrieveFile(fileID string, writer io.Writer) error {
	// Get file metadata to determine encryption version
	file, err := m.GetFileMetadata(fileID)
	if err != nil {
		return fmt.Errorf("failed to get file metadata: %w", err)
	}

	// Get chunks
	rows, err := db.DB.Query("SELECT chunk_path, chunk_index FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC", fileID)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Determine decryption method based on encryption version
	var fileKey []byte
	if file.EncryptionVersion == EncryptionVersionHybrid && len(file.KEMCiphertext) > 0 {
		// Use hybrid PQ decryption
		if m.keyManager == nil {
			return fmt.Errorf("hybrid encryption keys not configured")
		}
		fileKey, err = m.keyManager.DecryptForFile(fileID, file.KEMCiphertext)
		if err != nil {
			return fmt.Errorf("failed to decrypt file key: %w", err)
		}
	}

	for rows.Next() {
		var chunkPathRelative string
		var chunkIndex int
		if err := rows.Scan(&chunkPathRelative, &chunkIndex); err != nil {
			return err
		}

		chunkPath := filepath.Join(m.cfg.UploadFolder, chunkPathRelative)
		cipherData, err := os.ReadFile(chunkPath)
		if err != nil {
			return err
		}

		var plaintext []byte
		if file.EncryptionVersion == EncryptionVersionHybrid && fileKey != nil {
			// Hybrid decryption (XChaCha20-Poly1305)
			plaintext, err = crypto.DecryptChunk(fileKey, chunkIndex, cipherData)
			if err != nil {
				return fmt.Errorf("failed to decrypt chunk %d: %w", chunkIndex, err)
			}
		} else {
			// Legacy AES-GCM decryption
			gcm, err := m.getGCM()
			if err != nil {
				return err
			}
			if len(cipherData) < gcm.NonceSize() {
				return fmt.Errorf("chunk too small")
			}
			nonce, ciphertext := cipherData[:gcm.NonceSize()], cipherData[gcm.NonceSize():]
			plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return err
			}
		}

		if _, err := writer.Write(plaintext); err != nil {
			return err
		}
	}
	return nil
}

// RetrieveFileRange streams a specific byte range of decrypted file content
// This enables HTTP Range requests for resumable downloads
func (m *Manager) RetrieveFileRange(fileID string, writer io.Writer, startByte, endByte int64) error {
	// Get file metadata to determine encryption version
	file, err := m.GetFileMetadata(fileID)
	if err != nil {
		return fmt.Errorf("failed to get file metadata: %w", err)
	}

	// Get chunks with sizes
	rows, err := db.DB.Query(`
		SELECT chunk_path, COALESCE(chunk_size, ?) as chunk_size, chunk_index
		FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC`, ChunkSize, fileID)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Determine decryption method based on encryption version
	var fileKey []byte
	if file.EncryptionVersion == EncryptionVersionHybrid && len(file.KEMCiphertext) > 0 {
		// Use hybrid PQ decryption
		if m.keyManager == nil {
			return fmt.Errorf("hybrid encryption keys not configured")
		}
		fileKey, err = m.keyManager.DecryptForFile(fileID, file.KEMCiphertext)
		if err != nil {
			return fmt.Errorf("failed to decrypt file key: %w", err)
		}
	}

	var currentOffset int64 = 0
	bytesRemaining := endByte - startByte + 1

	for rows.Next() && bytesRemaining > 0 {
		var chunkPathRelative string
		var chunkSize int64
		var chunkIndex int
		if err := rows.Scan(&chunkPathRelative, &chunkSize, &chunkIndex); err != nil {
			return err
		}

		chunkEndOffset := currentOffset + chunkSize

		// Skip chunks before the requested range
		if chunkEndOffset <= startByte {
			currentOffset = chunkEndOffset
			continue
		}

		// Read and decrypt chunk
		chunkPath := filepath.Join(m.cfg.UploadFolder, chunkPathRelative)
		cipherData, err := os.ReadFile(chunkPath)
		if err != nil {
			return err
		}

		var plaintext []byte
		if file.EncryptionVersion == EncryptionVersionHybrid && fileKey != nil {
			// Hybrid decryption (XChaCha20-Poly1305)
			plaintext, err = crypto.DecryptChunk(fileKey, chunkIndex, cipherData)
			if err != nil {
				return fmt.Errorf("failed to decrypt chunk %d: %w", chunkIndex, err)
			}
		} else {
			// Legacy AES-GCM decryption
			gcm, err := m.getGCM()
			if err != nil {
				return err
			}
			if len(cipherData) < gcm.NonceSize() {
				return fmt.Errorf("chunk too small")
			}
			nonce, ciphertext := cipherData[:gcm.NonceSize()], cipherData[gcm.NonceSize():]
			plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return err
			}
		}

		// Calculate which part of this chunk to write
		chunkStart := int64(0)
		if startByte > currentOffset {
			chunkStart = startByte - currentOffset
		}

		chunkEnd := int64(len(plaintext))
		if currentOffset+int64(len(plaintext)) > endByte+1 {
			chunkEnd = endByte + 1 - currentOffset
		}

		// Write the relevant portion
		if chunkStart < chunkEnd && chunkStart < int64(len(plaintext)) {
			toWrite := plaintext[chunkStart:chunkEnd]
			if _, err := writer.Write(toWrite); err != nil {
				return err
			}
			bytesRemaining -= int64(len(toWrite))
		}

		currentOffset = chunkEndOffset
	}

	return nil
}

// getGCM returns a GCM cipher for encryption/decryption
func (m *Manager) getGCM() (cipher.AEAD, error) {
	key := []byte(m.cfg.EncryptionKey)
	if len(key) != 32 {
		newKey := make([]byte, 32)
		copy(newKey, key)
		key = newKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DeleteFile removes a file and its chunks
func (m *Manager) DeleteFile(fileID string) error {
	// Get chunks to delete from disk
	rows, err := db.DB.Query("SELECT chunk_path FROM chunks WHERE file_id = ?", fileID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			paths = append(paths, filepath.Join(m.cfg.UploadFolder, p))
		}
	}

	// Delete details from DB
	// Use transaction
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}

	if _, err := tx.Exec("DELETE FROM chunks WHERE file_id = ?", fileID); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec("DELETE FROM files WHERE id = ?", fileID); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Best effort delete from disk
	for _, p := range paths {
		os.Remove(p)
	}

	return nil
}

// GetFileMetadata returns the file record from DB
func (m *Manager) GetFileMetadata(id string) (*models.File, error) {
	row := db.DB.QueryRow(`
		SELECT id, filename, COALESCE(original_filename, filename), size, mime_type,
		       COALESCE(content_hash, ''), upload_time, expiry_time, delete_token,
		       is_encrypted, COALESCE(is_blocked, 0), COALESCE(uploader_dest, ''), download_count,
		       COALESCE(password_hash, ''), max_downloads, COALESCE(metadata_stripped, 1),
		       kem_ciphertext, COALESCE(key_version, 0), COALESCE(encryption_version, 1)
		FROM files WHERE id = ?`, id)

	var f models.File
	if err := row.Scan(&f.ID, &f.Filename, &f.OriginalFilename, &f.Size, &f.MimeType,
		&f.ContentHash, &f.UploadTime, &f.ExpiryTime, &f.DeleteToken,
		&f.IsEncrypted, &f.IsBlocked, &f.UploaderDest, &f.DownloadCount,
		&f.PasswordHash, &f.MaxDownloads, &f.MetadataStripped,
		&f.KEMCiphertext, &f.KeyVersion, &f.EncryptionVersion); err != nil {
		return nil, err
	}
	return &f, nil
}

// ListFiles returns recent files for admin
func (m *Manager) ListFiles(limit int) ([]*models.File, error) {
	rows, err := db.DB.Query(`
		SELECT id, filename, COALESCE(original_filename, filename), size, mime_type,
		       COALESCE(content_hash, ''), upload_time, expiry_time, is_encrypted,
		       COALESCE(is_blocked, 0), COALESCE(uploader_dest, ''), download_count
		FROM files ORDER BY upload_time DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		var f models.File
		if err := rows.Scan(&f.ID, &f.Filename, &f.OriginalFilename, &f.Size, &f.MimeType,
			&f.ContentHash, &f.UploadTime, &f.ExpiryTime, &f.IsEncrypted,
			&f.IsBlocked, &f.UploaderDest, &f.DownloadCount); err == nil {
			files = append(files, &f)
		}
	}
	return files, nil
}

// IsHashBlocked checks if a content hash is blocked
func (m *Manager) IsHashBlocked(contentHash string) (bool, error) {
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM bans WHERE ban_type = 'file_hash' AND value = ?", contentHash).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// IsDestinationBanned checks if an I2P destination is banned
func (m *Manager) IsDestinationBanned(destB32 string) (bool, error) {
	var count int
	err := db.DB.QueryRow(`
		SELECT COUNT(*) FROM bans
		WHERE ban_type = 'destination' AND value = ?
		AND (expires_at IS NULL OR expires_at > datetime('now'))
	`, destB32).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// BlockFile blocks a file from being accessed
func (m *Manager) BlockFile(fileID string) error {
	_, err := db.DB.Exec("UPDATE files SET is_blocked = 1 WHERE id = ?", fileID)
	return err
}

// GetChunks returns all chunks for a file
func (m *Manager) GetChunks(fileID string) ([]*models.Chunk, error) {
	rows, err := db.DB.Query(`
		SELECT file_id, chunk_index, chunk_path, COALESCE(chunk_size, 0), COALESCE(checksum, '')
		FROM chunks WHERE file_id = ? ORDER BY chunk_index`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []*models.Chunk
	for rows.Next() {
		var c models.Chunk
		if err := rows.Scan(&c.FileID, &c.ChunkIndex, &c.ChunkPath, &c.ChunkSize, &c.Checksum); err == nil {
			chunks = append(chunks, &c)
		}
	}
	return chunks, nil
}

// ========== Report Management ==========

// CreateReport creates a new content report
func (m *Manager) CreateReport(id, fileID, reporterDest, reason string) error {
	_, err := db.DB.Exec(`
		INSERT INTO reports (id, file_id, reporter_dest, reason, status, created_at)
		VALUES (?, ?, ?, ?, 'pending', datetime('now'))
	`, id, fileID, reporterDest, reason)
	return err
}

// GetReport retrieves a report by ID
func (m *Manager) GetReport(id string) (*models.Report, error) {
	row := db.DB.QueryRow(`
		SELECT id, file_id, COALESCE(reporter_dest, ''), reason, COALESCE(details, ''),
		       status, created_at, reviewed_at, COALESCE(reviewed_by, ''), COALESCE(action_taken, '')
		FROM reports WHERE id = ?`, id)

	var r models.Report
	if err := row.Scan(&r.ID, &r.FileID, &r.ReporterDest, &r.Reason, &r.Details,
		&r.Status, &r.CreatedAt, &r.ReviewedAt, &r.ReviewedBy, &r.ActionTaken); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListReports returns reports with a given status
func (m *Manager) ListReports(status string, limit int) ([]*models.Report, error) {
	rows, err := db.DB.Query(`
		SELECT id, file_id, COALESCE(reporter_dest, ''), reason, COALESCE(details, ''),
		       status, created_at, reviewed_at, COALESCE(reviewed_by, ''), COALESCE(action_taken, '')
		FROM reports WHERE status = ? ORDER BY created_at DESC LIMIT ?`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []*models.Report
	for rows.Next() {
		var r models.Report
		if err := rows.Scan(&r.ID, &r.FileID, &r.ReporterDest, &r.Reason, &r.Details,
			&r.Status, &r.CreatedAt, &r.ReviewedAt, &r.ReviewedBy, &r.ActionTaken); err == nil {
			reports = append(reports, &r)
		}
	}
	return reports, nil
}

// UpdateReportStatus updates a report's status and action
func (m *Manager) UpdateReportStatus(id, status, action string) error {
	_, err := db.DB.Exec(`
		UPDATE reports SET status = ?, action_taken = ?, reviewed_at = datetime('now')
		WHERE id = ?
	`, status, action, id)
	return err
}

// ========== Ban Management ==========

// CreateBan creates a new ban
func (m *Manager) CreateBan(id, banType, value, reason string, expiresAt *time.Time) error {
	_, err := db.DB.Exec(`
		INSERT INTO bans (id, ban_type, value, reason, created_at, expires_at)
		VALUES (?, ?, ?, ?, datetime('now'), ?)
	`, id, banType, value, reason, expiresAt)
	return err
}

// GetBan retrieves a ban by ID
func (m *Manager) GetBan(id string) (*models.Ban, error) {
	row := db.DB.QueryRow(`
		SELECT id, ban_type, value, COALESCE(reason, ''), created_at, expires_at, COALESCE(created_by, '')
		FROM bans WHERE id = ?`, id)

	var b models.Ban
	if err := row.Scan(&b.ID, &b.BanType, &b.Value, &b.Reason, &b.CreatedAt, &b.ExpiresAt, &b.CreatedBy); err != nil {
		return nil, err
	}
	return &b, nil
}

// ListBans returns active bans
func (m *Manager) ListBans(limit int) ([]*models.Ban, error) {
	rows, err := db.DB.Query(`
		SELECT id, ban_type, value, COALESCE(reason, ''), created_at, expires_at, COALESCE(created_by, '')
		FROM bans
		WHERE expires_at IS NULL OR expires_at > datetime('now')
		ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []*models.Ban
	for rows.Next() {
		var b models.Ban
		if err := rows.Scan(&b.ID, &b.BanType, &b.Value, &b.Reason, &b.CreatedAt, &b.ExpiresAt, &b.CreatedBy); err == nil {
			bans = append(bans, &b)
		}
	}
	return bans, nil
}

// DeleteBan removes a ban
func (m *Manager) DeleteBan(id string) error {
	_, err := db.DB.Exec("DELETE FROM bans WHERE id = ?", id)
	return err
}

// ========== Paste Management ==========

// SavePaste creates a new encrypted paste
func (m *Manager) SavePaste(id string, content []byte, language string, expiryTime *time.Time, deleteToken, uploaderDest string) (*models.Paste, error) {
	var encryptedContent []byte
	var kemCiphertext []byte
	var keyVersion int
	encryptionVersion := EncryptionVersionHybrid

	if m.keyManager != nil {
		// Use hybrid PQ encryption
		fileKey, kemCT, err := m.keyManager.EncryptForFile(id)
		if err != nil {
			return nil, fmt.Errorf("failed to generate paste key: %w", err)
		}
		kemCiphertext = kemCT
		keyVersion = int(m.keyManager.CurrentVersion())

		// Encrypt content using XChaCha20-Poly1305 (chunk index 0 for single paste)
		encryptedContent, err = crypto.EncryptChunk(fileKey, 0, content)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt paste: %w", err)
		}
	} else {
		// Legacy AES-GCM encryption
		encryptionVersion = EncryptionVersionLegacy
		gcm, err := m.getGCM()
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
		encryptedContent = gcm.Seal(nonce, nonce, content, nil)
	}

	_, err := db.DB.Exec(`
		INSERT INTO pastes (id, content, language, expiry_time, delete_token, uploader_dest, created_at, kem_ciphertext, key_version, encryption_version)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?)
	`, id, encryptedContent, language, expiryTime, deleteToken, uploaderDest, kemCiphertext, keyVersion, encryptionVersion)

	if err != nil {
		return nil, err
	}

	// Update stats
	m.IncrementStat("total_pastes")
	m.IncrementStatByAmount("total_bytes_stored", int64(len(content)))

	return &models.Paste{
		ID:                id,
		Content:           content,
		Language:          language,
		ExpiryTime:        expiryTime,
		DeleteToken:       deleteToken,
		UploaderDest:      uploaderDest,
		CreatedAt:         time.Now(),
		KEMCiphertext:     kemCiphertext,
		KeyVersion:        keyVersion,
		EncryptionVersion: encryptionVersion,
	}, nil
}

// GetPaste retrieves and decrypts a paste
func (m *Manager) GetPaste(id string) (*models.Paste, error) {
	row := db.DB.QueryRow(`
		SELECT id, content, language, expiry_time, delete_token, COALESCE(uploader_dest, ''),
		       view_count, created_at, COALESCE(is_blocked, 0),
		       kem_ciphertext, COALESCE(key_version, 0), COALESCE(encryption_version, 1)
		FROM pastes WHERE id = ?`, id)

	var p models.Paste
	var encryptedContent []byte
	if err := row.Scan(&p.ID, &encryptedContent, &p.Language, &p.ExpiryTime, &p.DeleteToken,
		&p.UploaderDest, &p.ViewCount, &p.CreatedAt, &p.IsBlocked,
		&p.KEMCiphertext, &p.KeyVersion, &p.EncryptionVersion); err != nil {
		return nil, err
	}

	// Decrypt content based on encryption version
	var plaintext []byte
	if p.EncryptionVersion == EncryptionVersionHybrid && len(p.KEMCiphertext) > 0 {
		// Use hybrid PQ decryption
		if m.keyManager == nil {
			return nil, fmt.Errorf("hybrid encryption keys not configured")
		}
		fileKey, err := m.keyManager.DecryptForFile(id, p.KEMCiphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt paste key: %w", err)
		}
		plaintext, err = crypto.DecryptChunk(fileKey, 0, encryptedContent)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt paste: %w", err)
		}
	} else {
		// Legacy AES-GCM decryption
		gcm, err := m.getGCM()
		if err != nil {
			return nil, err
		}

		if len(encryptedContent) < gcm.NonceSize() {
			return nil, fmt.Errorf("encrypted content too small")
		}

		nonce, ciphertext := encryptedContent[:gcm.NonceSize()], encryptedContent[gcm.NonceSize():]
		plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	}

	p.Content = plaintext
	return &p, nil
}

// DeletePaste removes a paste
func (m *Manager) DeletePaste(id string) error {
	_, err := db.DB.Exec("DELETE FROM pastes WHERE id = ?", id)
	return err
}

// IncrementPasteViewCount increments the view count for a paste
func (m *Manager) IncrementPasteViewCount(id string) error {
	_, err := db.DB.Exec("UPDATE pastes SET view_count = view_count + 1 WHERE id = ?", id)
	return err
}

// ListPastes returns recent pastes for admin
func (m *Manager) ListPastes(limit int) ([]*models.Paste, error) {
	rows, err := db.DB.Query(`
		SELECT id, language, expiry_time, view_count, created_at, COALESCE(is_blocked, 0)
		FROM pastes ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pastes []*models.Paste
	for rows.Next() {
		var p models.Paste
		if err := rows.Scan(&p.ID, &p.Language, &p.ExpiryTime, &p.ViewCount, &p.CreatedAt, &p.IsBlocked); err == nil {
			pastes = append(pastes, &p)
		}
	}
	return pastes, nil
}

// ========== Stats Management ==========

// GetStats returns service statistics
func (m *Manager) GetStats() (*models.Stats, error) {
	stats := &models.Stats{}

	rows, err := db.DB.Query("SELECT stat_key, stat_value FROM stats")
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var value int64
		if err := rows.Scan(&key, &value); err == nil {
			switch key {
			case "total_files":
				stats.TotalFiles = value
			case "total_pastes":
				stats.TotalPastes = value
			case "total_downloads":
				stats.TotalDownloads = value
			case "total_api_uploads":
				stats.TotalAPIUploads = value
			case "total_bytes_stored":
				stats.TotalStoredFormatted = formatBytes(value)
			case "photodna_blocked":
				stats.PhotoDNABlocked = value
			case "clamav_blocked":
				stats.ClamAVBlocked = value
			}
		}
	}

	// If total_bytes_stored wasn't in stats table, show 0
	if stats.TotalStoredFormatted == "" {
		stats.TotalStoredFormatted = "0 B"
	}

	return stats, nil
}

// IncrementStat increments a stat value
func (m *Manager) IncrementStat(key string) error {
	_, err := db.DB.Exec("UPDATE stats SET stat_value = stat_value + 1 WHERE stat_key = ?", key)
	return err
}

// IncrementStatByAmount increments a stat value by a specific amount
func (m *Manager) IncrementStatByAmount(key string, amount int64) error {
	_, err := db.DB.Exec("UPDATE stats SET stat_value = stat_value + ? WHERE stat_key = ?", amount, key)
	return err
}

// GetStatValue returns the raw value of a stat key
func (m *Manager) GetStatValue(key string) (int64, error) {
	var value int64
	err := db.DB.QueryRow("SELECT stat_value FROM stats WHERE stat_key = ?", key).Scan(&value)
	if err != nil {
		return 0, err
	}
	return value, nil
}

// GetTotalBytesStored returns the total bytes stored
func (m *Manager) GetTotalBytesStored() int64 {
	val, _ := m.GetStatValue("total_bytes_stored")
	return val
}

// ========== Analytics Methods ==========

// RecordStatsSnapshot records a snapshot of current stats for analytics
func (m *Manager) RecordStatsSnapshot() error {
	stats, err := m.GetStats()
	if err != nil {
		return err
	}

	totalBytes := m.GetTotalBytesStored()

	_, err = db.DB.Exec(`
		INSERT INTO stats_history (total_files, total_pastes, total_bytes, total_downloads)
		VALUES (?, ?, ?, ?)
	`, stats.TotalFiles, stats.TotalPastes, totalBytes, stats.TotalDownloads)
	return err
}

// GetStatsHistory returns stats history for the specified number of days
func (m *Manager) GetStatsHistory(days int) ([]models.StatsSnapshot, error) {
	var snapshots []models.StatsSnapshot

	rows, err := db.DB.Query(`
		SELECT id, recorded_at, total_files, total_pastes, total_bytes, total_downloads
		FROM stats_history
		WHERE recorded_at >= datetime('now', ? || ' days')
		ORDER BY recorded_at ASC
	`, -days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var s models.StatsSnapshot
		if err := rows.Scan(&s.ID, &s.RecordedAt, &s.TotalFiles, &s.TotalPastes, &s.TotalBytes, &s.TotalDownloads); err != nil {
			continue
		}
		snapshots = append(snapshots, s)
	}
	return snapshots, nil
}

// GetTopUploaders returns the top uploaders by file count
func (m *Manager) GetTopUploaders(limit int) ([]models.UploaderStats, error) {
	var uploaders []models.UploaderStats

	rows, err := db.DB.Query(`
		SELECT uploader_dest, COUNT(*) as file_count, COALESCE(SUM(size), 0) as total_bytes
		FROM files
		WHERE uploader_dest IS NOT NULL AND uploader_dest != '' AND is_blocked = 0
		GROUP BY uploader_dest
		ORDER BY file_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var u models.UploaderStats
		if err := rows.Scan(&u.Destination, &u.FileCount, &u.TotalBytes); err != nil {
			continue
		}
		uploaders = append(uploaders, u)
	}
	return uploaders, nil
}

// GetFileTypeDistribution returns distribution of files by MIME type
func (m *Manager) GetFileTypeDistribution() ([]models.FileTypeStats, error) {
	var stats []models.FileTypeStats

	rows, err := db.DB.Query(`
		SELECT
			CASE
				WHEN mime_type LIKE 'image/%' THEN 'Images'
				WHEN mime_type LIKE 'video/%' THEN 'Videos'
				WHEN mime_type LIKE 'audio/%' THEN 'Audio'
				WHEN mime_type LIKE 'text/%' THEN 'Text'
				WHEN mime_type LIKE 'application/pdf' THEN 'PDF'
				WHEN mime_type LIKE 'application/%zip%' OR mime_type LIKE 'application/%tar%' OR mime_type LIKE 'application/%compress%' OR mime_type LIKE 'application/%archive%' THEN 'Archives'
				ELSE 'Other'
			END as category,
			COUNT(*) as count,
			COALESCE(SUM(size), 0) as bytes
		FROM files
		WHERE is_blocked = 0
		GROUP BY category
		ORDER BY count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var s models.FileTypeStats
		if err := rows.Scan(&s.MimeType, &s.Count, &s.Bytes); err != nil {
			continue
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// CleanupOldStatsHistory removes stats history older than the specified days
func (m *Manager) CleanupOldStatsHistory(days int) error {
	_, err := db.DB.Exec(`
		DELETE FROM stats_history
		WHERE recorded_at < datetime('now', ? || ' days')
	`, -days)
	return err
}

// ========== Collection Methods ==========

// CreateCollection creates a new collection
func (m *Manager) CreateCollection(c *models.Collection) error {
	_, err := db.DB.Exec(`
		INSERT INTO collections (id, title, description, uploader_dest, delete_token, password_hash, expiry_time)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, c.ID, c.Title, c.Description, c.UploaderDest, c.DeleteToken, c.PasswordHash, c.ExpiryTime)
	return err
}

// GetCollection returns a collection by ID
func (m *Manager) GetCollection(id string) (*models.Collection, error) {
	c := &models.Collection{}
	err := db.DB.QueryRow(`
		SELECT id, title, description, uploader_dest, delete_token, password_hash, expiry_time, created_at, view_count, is_blocked
		FROM collections WHERE id = ?
	`, id).Scan(&c.ID, &c.Title, &c.Description, &c.UploaderDest, &c.DeleteToken, &c.PasswordHash, &c.ExpiryTime, &c.CreatedAt, &c.ViewCount, &c.IsBlocked)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// AddFileToCollection adds a file to a collection
func (m *Manager) AddFileToCollection(collectionID, fileID string, position int) error {
	_, err := db.DB.Exec(`
		INSERT INTO collection_files (collection_id, file_id, position)
		VALUES (?, ?, ?)
	`, collectionID, fileID, position)
	return err
}

// AddFilesToCollection adds multiple files to a collection
func (m *Manager) AddFilesToCollection(collectionID string, fileIDs []string) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}

	for i, fileID := range fileIDs {
		if _, err := tx.Exec(`
			INSERT INTO collection_files (collection_id, file_id, position)
			VALUES (?, ?, ?)
		`, collectionID, fileID, i); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// GetCollectionFiles returns all files in a collection
func (m *Manager) GetCollectionFiles(collectionID string) ([]*models.File, error) {
	rows, err := db.DB.Query(`
		SELECT f.id, f.filename, f.original_filename, f.size, f.mime_type, f.content_hash,
		       f.upload_time, f.expiry_time, f.delete_token, f.is_encrypted, f.is_blocked,
		       f.uploader_dest, f.download_count, f.password_hash, f.max_downloads,
		       f.metadata_stripped, f.kem_ciphertext, f.key_version, f.encryption_version
		FROM files f
		INNER JOIN collection_files cf ON f.id = cf.file_id
		WHERE cf.collection_id = ?
		ORDER BY cf.position ASC
	`, collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		f := &models.File{}
		if err := rows.Scan(&f.ID, &f.Filename, &f.OriginalFilename, &f.Size, &f.MimeType, &f.ContentHash,
			&f.UploadTime, &f.ExpiryTime, &f.DeleteToken, &f.IsEncrypted, &f.IsBlocked,
			&f.UploaderDest, &f.DownloadCount, &f.PasswordHash, &f.MaxDownloads,
			&f.MetadataStripped, &f.KEMCiphertext, &f.KeyVersion, &f.EncryptionVersion); err != nil {
			continue
		}
		files = append(files, f)
	}
	return files, nil
}

// GetCollectionFileCount returns the number of files in a collection
func (m *Manager) GetCollectionFileCount(collectionID string) (int, error) {
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM collection_files WHERE collection_id = ?", collectionID).Scan(&count)
	return count, err
}

// DeleteCollection deletes a collection (files remain)
func (m *Manager) DeleteCollection(id string) error {
	_, err := db.DB.Exec("DELETE FROM collections WHERE id = ?", id)
	return err
}

// IncrementCollectionViews increments the view count for a collection
func (m *Manager) IncrementCollectionViews(id string) error {
	_, err := db.DB.Exec("UPDATE collections SET view_count = view_count + 1 WHERE id = ?", id)
	return err
}

// BlockCollection blocks a collection
func (m *Manager) BlockCollection(id string) error {
	_, err := db.DB.Exec("UPDATE collections SET is_blocked = 1 WHERE id = ?", id)
	return err
}

// CleanupExpiredCollections removes expired collections
func (m *Manager) CleanupExpiredCollections() (int64, error) {
	result, err := db.DB.Exec(`
		DELETE FROM collections
		WHERE expiry_time IS NOT NULL AND expiry_time < datetime('now')
	`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ListCollections returns all collections (for admin)
func (m *Manager) ListCollections(limit int) ([]*models.Collection, error) {
	rows, err := db.DB.Query(`
		SELECT id, title, description, uploader_dest, delete_token, password_hash, expiry_time, created_at, view_count, is_blocked
		FROM collections
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var collections []*models.Collection
	for rows.Next() {
		c := &models.Collection{}
		if err := rows.Scan(&c.ID, &c.Title, &c.Description, &c.UploaderDest, &c.DeleteToken, &c.PasswordHash, &c.ExpiryTime, &c.CreatedAt, &c.ViewCount, &c.IsBlocked); err != nil {
			continue
		}
		collections = append(collections, c)
	}
	return collections, nil
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int64) string {
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

// IncrementFileDownloads increments both file download count and global stats
func (m *Manager) IncrementFileDownloads(fileID string) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}

	if _, err := tx.Exec("UPDATE files SET download_count = download_count + 1 WHERE id = ?", fileID); err != nil {
		tx.Rollback()
		return err
	}

	if _, err := tx.Exec("UPDATE stats SET stat_value = stat_value + 1 WHERE stat_key = 'total_downloads'"); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// IncrementAndCheckDownloadLimit increments download count and checks against max downloads atomically
// Returns:
// - allowed: true if download is allowed (limit not reached)
// - currentCount: the new download count
// - err: any database error
func (m *Manager) IncrementAndCheckDownloadLimit(fileID string) (allowed bool, currentCount int, err error) {
	// Use atomic UPDATE ... RETURNING (SQLite 3.35+)
	// to avoid transaction locking issues (SQLITE_BUSY)
	var newCount int
	var maxDownloads *int

	query := `UPDATE files SET download_count = download_count + 1 WHERE id = ? RETURNING download_count, max_downloads`
	err = db.DB.QueryRow(query, fileID).Scan(&newCount, &maxDownloads)
	if err != nil {
		return false, 0, err
	}

	// Update stats (best effort)
	m.IncrementStat("total_downloads")

	// Check limit
	if maxDownloads != nil {
		// download_count starts at -1. First download sets it to 0.
		// So actual downloads = newCount + 1.
		// Example: Max=1.
		// Req 1: -1 -> 0. Actual=1. 1 >= 1 (TRUE).
		// Wait, if 1>=1, we block?
		// If max=1, we want 1 download.
		// If actual=1, that IS the 1 allowed download. We should ALLOW it.
		// So block only if actual > max.

		actualDownloads := newCount + 1
		if actualDownloads > *maxDownloads {
			return false, newCount, nil
		}
	}

	return true, newCount, nil
}

// CleanupExpiredPastes removes expired pastes
func (m *Manager) CleanupExpiredPastes() {
	db.DB.Exec("DELETE FROM pastes WHERE expiry_time IS NOT NULL AND expiry_time < datetime('now')")
}

// ========== Chunked Upload Management ==========

// ClientChunkSize is the size of chunks the client should send (2MB - fits well within I2P timeout)
const ClientChunkSize = 2 * 1024 * 1024

// InitChunkedUpload creates a new chunked upload session
func (m *Manager) InitChunkedUpload(id, filename, mimeType string, totalSize int64, totalChunks int, expiry, uploaderDest, passwordHash string, maxDownloads *int, keepMetadata bool) (*models.ChunkedUpload, error) {
	// Session expires in 24 hours (cleanup stale uploads)
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err := db.DB.Exec(`
		INSERT INTO chunked_uploads (id, filename, mime_type, total_size, total_chunks, chunk_size, expiry, uploader_dest, created_at, expires_at, password_hash, max_downloads, keep_metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?)
	`, id, filename, mimeType, totalSize, totalChunks, ClientChunkSize, expiry, uploaderDest, expiresAt, passwordHash, maxDownloads, keepMetadata)

	if err != nil {
		return nil, err
	}

	return &models.ChunkedUpload{
		ID:           id,
		Filename:     filename,
		MimeType:     mimeType,
		TotalSize:    totalSize,
		TotalChunks:  totalChunks,
		ChunkSize:    ClientChunkSize,
		Expiry:       expiry,
		UploaderDest: uploaderDest,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiresAt,
		PasswordHash: passwordHash,
		MaxDownloads: maxDownloads,
		KeepMetadata: keepMetadata,
	}, nil
}

// GetChunkedUpload retrieves a chunked upload session
func (m *Manager) GetChunkedUpload(id string) (*models.ChunkedUpload, error) {
	row := db.DB.QueryRow(`
		SELECT id, filename, COALESCE(mime_type, ''), total_size, total_chunks, chunk_size,
		       received_chunks, COALESCE(expiry, ''), COALESCE(uploader_dest, ''),
		       created_at, expires_at, COALESCE(password_hash, ''), max_downloads, COALESCE(keep_metadata, 0)
		FROM chunked_uploads WHERE id = ?`, id)

	var u models.ChunkedUpload
	if err := row.Scan(&u.ID, &u.Filename, &u.MimeType, &u.TotalSize, &u.TotalChunks,
		&u.ChunkSize, &u.ReceivedChunks, &u.Expiry, &u.UploaderDest,
		&u.CreatedAt, &u.ExpiresAt, &u.PasswordHash, &u.MaxDownloads, &u.KeepMetadata); err != nil {
		return nil, err
	}
	return &u, nil
}

// SaveUploadChunk saves an individual chunk for a chunked upload
func (m *Manager) SaveUploadChunk(uploadID string, chunkIndex int, data []byte) error {
	// Create upload dir if not exists
	if err := os.MkdirAll(m.cfg.UploadFolder, 0700); err != nil {
		return err
	}

	// Encrypt the chunk
	gcm, err := m.getGCM()
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Compute checksum
	chunkHash := sha256.Sum256(data)
	checksum := hex.EncodeToString(chunkHash[:])

	// Save to disk
	chunkUUID := uuid.New().String()
	chunkPath := filepath.Join(m.cfg.UploadFolder, chunkUUID)
	if err := os.WriteFile(chunkPath, ciphertext, 0600); err != nil {
		return err
	}

	// Use transaction to save chunk and update count
	tx, err := db.DB.Begin()
	if err != nil {
		os.Remove(chunkPath)
		return err
	}

	// Insert chunk record
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO upload_chunks (upload_id, chunk_index, chunk_path, chunk_size, checksum)
		VALUES (?, ?, ?, ?, ?)
	`, uploadID, chunkIndex, chunkUUID, len(data), checksum)
	if err != nil {
		tx.Rollback()
		os.Remove(chunkPath)
		return err
	}

	// Update received count
	_, err = tx.Exec(`
		UPDATE chunked_uploads SET received_chunks = (
			SELECT COUNT(*) FROM upload_chunks WHERE upload_id = ?
		) WHERE id = ?
	`, uploadID, uploadID)
	if err != nil {
		tx.Rollback()
		os.Remove(chunkPath)
		return err
	}

	return tx.Commit()
}

// GetUploadChunks returns all chunks for a chunked upload
func (m *Manager) GetUploadChunks(uploadID string) ([]*models.UploadChunk, error) {
	rows, err := db.DB.Query(`
		SELECT upload_id, chunk_index, chunk_path, chunk_size, COALESCE(checksum, '')
		FROM upload_chunks WHERE upload_id = ? ORDER BY chunk_index`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []*models.UploadChunk
	for rows.Next() {
		var c models.UploadChunk
		if err := rows.Scan(&c.UploadID, &c.ChunkIndex, &c.ChunkPath, &c.ChunkSize, &c.Checksum); err == nil {
			chunks = append(chunks, &c)
		}
	}
	return chunks, nil
}

// CompleteChunkedUpload assembles chunks into a final file
func (m *Manager) CompleteChunkedUpload(uploadID string) (*models.File, string, error) {
	// Get upload session
	upload, err := m.GetChunkedUpload(uploadID)
	if err != nil {
		return nil, "", fmt.Errorf("upload session not found: %w", err)
	}

	// Check all chunks received
	if upload.ReceivedChunks != upload.TotalChunks {
		return nil, "", fmt.Errorf("incomplete upload: received %d of %d chunks", upload.ReceivedChunks, upload.TotalChunks)
	}

	// Get all chunks in order
	chunks, err := m.GetUploadChunks(uploadID)
	if err != nil {
		return nil, "", err
	}

	if len(chunks) != upload.TotalChunks {
		return nil, "", fmt.Errorf("chunk count mismatch")
	}

	// Create new file ID and delete token
	fileID := uuid.New().String()
	deleteToken := uuid.New().String()

	// Parse expiry - max 30 days, no permanent option
	// Default 24h if not specified
	duration := 24 * time.Hour
	if upload.Expiry != "" && upload.Expiry != "permanent" {
		if d, err := time.ParseDuration(upload.Expiry); err == nil {
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

	// Prepare for content hash
	contentHasher := sha256.New()

	// Determine encryption settings for final file
	var fileKey []byte
	var kemCiphertext []byte
	var keyVersion int
	encryptionVersion := EncryptionVersionHybrid

	if m.keyManager != nil {
		// Generate file key for hybrid encryption
		fileKey, kemCiphertext, err = m.keyManager.EncryptForFile(fileID)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate file key: %w", err)
		}
		keyVersion = int(m.keyManager.CurrentVersion())
	} else {
		// Fallback to legacy
		encryptionVersion = EncryptionVersionLegacy
	}

	// Get legacy GCM for decrypting upload chunks (they're stored with legacy encryption)
	gcm, err := m.getGCM()
	if err != nil {
		return nil, "", err
	}

	// Check if this file needs scanning
	needsPhotoDNA := m.photoDNA != nil && m.photoDNA.ShouldCheck(upload.MimeType)
	needsClamAV := m.clamAV != nil && m.clamAV.ShouldCheck(upload.MimeType)
	needsBuffering := needsPhotoDNA || needsClamAV

	// First pass: Decrypt all chunks and optionally buffer for scanning
	var fileBuffer bytes.Buffer
	var decryptedChunks [][]byte

	for i, uc := range chunks {
		// Read encrypted chunk (these are always legacy encrypted during upload)
		chunkPath := filepath.Join(m.cfg.UploadFolder, uc.ChunkPath)
		cipherData, err := os.ReadFile(chunkPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read chunk %d: %w", i, err)
		}

		// Decrypt with legacy AES-GCM
		if len(cipherData) < gcm.NonceSize() {
			return nil, "", fmt.Errorf("chunk %d too small", i)
		}
		nonce, ciphertext := cipherData[:gcm.NonceSize()], cipherData[gcm.NonceSize():]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		decryptedChunks = append(decryptedChunks, plaintext)
		if needsBuffering {
			fileBuffer.Write(plaintext)
		}
	}

	// PhotoDNA check for images (before re-encryption/storage)
	if needsPhotoDNA {
		blocked, err := m.photoDNA.CheckImage(context.Background(), fileBuffer.Bytes())
		if blocked {
			m.IncrementStat("photodna_blocked")
			// Clean up upload chunks
			for _, uc := range chunks {
				os.Remove(filepath.Join(m.cfg.UploadFolder, uc.ChunkPath))
			}
			db.DB.Exec("DELETE FROM upload_chunks WHERE upload_id = ?", uploadID)
			db.DB.Exec("DELETE FROM chunked_uploads WHERE id = ?", uploadID)
			return nil, "", fmt.Errorf("content blocked")
		}
		if err != nil {
			// Error handling depends on fail-open setting (handled in CheckImage)
			// If we get here with an error, it means fail-closed rejected it
			for _, uc := range chunks {
				os.Remove(filepath.Join(m.cfg.UploadFolder, uc.ChunkPath))
			}
			db.DB.Exec("DELETE FROM upload_chunks WHERE upload_id = ?", uploadID)
			db.DB.Exec("DELETE FROM chunked_uploads WHERE id = ?", uploadID)
			return nil, "", fmt.Errorf("content check failed: %w", err)
		}
	}

	// ClamAV check for non-image files (before re-encryption/storage)
	if needsClamAV {
		infected, threat, err := m.clamAV.CheckFile(context.Background(), fileBuffer.Bytes())
		if infected {
			m.IncrementStat("clamav_blocked")
			// Clean up upload chunks
			for _, uc := range chunks {
				os.Remove(filepath.Join(m.cfg.UploadFolder, uc.ChunkPath))
			}
			db.DB.Exec("DELETE FROM upload_chunks WHERE upload_id = ?", uploadID)
			db.DB.Exec("DELETE FROM chunked_uploads WHERE id = ?", uploadID)
			return nil, "", fmt.Errorf("malware detected: %s", threat)
		}
		if err != nil {
			// Error handling depends on fail-open setting (handled in CheckFile)
			for _, uc := range chunks {
				os.Remove(filepath.Join(m.cfg.UploadFolder, uc.ChunkPath))
			}
			db.DB.Exec("DELETE FROM upload_chunks WHERE upload_id = ?", uploadID)
			db.DB.Exec("DELETE FROM chunked_uploads WHERE id = ?", uploadID)
			return nil, "", fmt.Errorf("virus scan failed: %w", err)
		}
	}

	// Begin transaction
	tx, err := db.DB.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	var totalSize int64 = 0

	// Second pass: Hash content and re-encrypt as file chunks
	for _, plaintext := range decryptedChunks {
		// Update content hash
		contentHasher.Write(plaintext)

		// Re-chunk and save as file chunks (256KB storage chunks)
		offset := 0
		for offset < len(plaintext) {
			end := offset + ChunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			chunkData := plaintext[offset:end]

			// Compute chunk checksum
			chunkHash := sha256.Sum256(chunkData)
			chunkChecksum := hex.EncodeToString(chunkHash[:])

			// Calculate storage chunk index based on total bytes processed
			storageChunkIndex := int(totalSize / int64(ChunkSize))

			// Encrypt storage chunk
			var encryptedChunk []byte
			if m.keyManager != nil {
				// Use hybrid encryption (XChaCha20-Poly1305)
				encryptedChunk, err = crypto.EncryptChunk(fileKey, storageChunkIndex, chunkData)
				if err != nil {
					return nil, "", fmt.Errorf("failed to encrypt chunk: %w", err)
				}
			} else {
				// Legacy AES-GCM encryption
				newNonce := make([]byte, gcm.NonceSize())
				if _, err := io.ReadFull(rand.Reader, newNonce); err != nil {
					return nil, "", err
				}
				encryptedChunk = gcm.Seal(newNonce, newNonce, chunkData, nil)
			}

			// Save chunk
			newChunkUUID := uuid.New().String()
			newChunkPath := filepath.Join(m.cfg.UploadFolder, newChunkUUID)
			if err := os.WriteFile(newChunkPath, encryptedChunk, 0600); err != nil {
				return nil, "", err
			}

			// Record in DB
			_, err = tx.Exec(`
				INSERT INTO chunks (file_id, chunk_index, chunk_path, chunk_size, checksum)
				VALUES (?, ?, ?, ?, ?)
			`, fileID, storageChunkIndex, newChunkUUID, len(chunkData), chunkChecksum)
			if err != nil {
				return nil, "", err
			}

			totalSize += int64(len(chunkData))
			offset = end
		}
	}

	contentHash := hex.EncodeToString(contentHasher.Sum(nil))

	// Determine metadata_stripped value (inverse of keep_metadata)
	metadataStripped := !upload.KeepMetadata

	// Insert file record with hybrid encryption fields
	_, err = tx.Exec(`
		INSERT INTO files (id, filename, original_filename, size, mime_type, content_hash, expiry_time, delete_token, is_encrypted, uploader_dest, password_hash, max_downloads, metadata_stripped, kem_ciphertext, key_version, encryption_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, fileID, upload.Filename, upload.Filename, totalSize, upload.MimeType, contentHash, expiryTime, deleteToken, true, upload.UploaderDest, upload.PasswordHash, upload.MaxDownloads, metadataStripped, kemCiphertext, keyVersion, encryptionVersion)
	if err != nil {
		return nil, "", err
	}

	if err := tx.Commit(); err != nil {
		return nil, "", err
	}

	// Clean up upload chunks (delete from disk and DB)
	for _, uc := range chunks {
		os.Remove(filepath.Join(m.cfg.UploadFolder, uc.ChunkPath))
	}
	db.DB.Exec("DELETE FROM upload_chunks WHERE upload_id = ?", uploadID)
	db.DB.Exec("DELETE FROM chunked_uploads WHERE id = ?", uploadID)

	// Update stats
	m.IncrementStat("total_files")
	m.IncrementStatByAmount("total_bytes_stored", totalSize)

	file := &models.File{
		ID:                fileID,
		Filename:          upload.Filename,
		OriginalFilename:  upload.Filename,
		Size:              totalSize,
		MimeType:          upload.MimeType,
		ContentHash:       contentHash,
		ExpiryTime:        expiryTime,
		DeleteToken:       deleteToken,
		UploaderDest:      upload.UploaderDest,
		IsEncrypted:       true,
		PasswordHash:      upload.PasswordHash,
		MaxDownloads:      upload.MaxDownloads,
		MetadataStripped:  metadataStripped,
		KEMCiphertext:     kemCiphertext,
		KeyVersion:        keyVersion,
		EncryptionVersion: encryptionVersion,
	}

	return file, deleteToken, nil
}

// CleanupExpiredChunkedUploads removes expired chunked upload sessions
func (m *Manager) CleanupExpiredChunkedUploads() {
	// Get expired uploads
	rows, err := db.DB.Query(`
		SELECT id FROM chunked_uploads WHERE expires_at < datetime('now')
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	var expiredIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			expiredIDs = append(expiredIDs, id)
		}
	}

	// Delete chunks for each expired upload
	for _, uploadID := range expiredIDs {
		chunks, _ := m.GetUploadChunks(uploadID)
		for _, c := range chunks {
			os.Remove(filepath.Join(m.cfg.UploadFolder, c.ChunkPath))
		}
		db.DB.Exec("DELETE FROM upload_chunks WHERE upload_id = ?", uploadID)
		db.DB.Exec("DELETE FROM chunked_uploads WHERE id = ?", uploadID)
	}
}
