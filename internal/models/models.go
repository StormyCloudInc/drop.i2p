package models

import (
	"time"
)

// File represents a file uploaded to the service
type File struct {
	ID               string     `db:"id" json:"id"`
	Filename         string     `db:"filename" json:"filename"`
	OriginalFilename string     `db:"original_filename" json:"original_filename"`
	Size             int64      `db:"size" json:"size"`
	MimeType         string     `db:"mime_type" json:"mime_type"`
	ContentHash      string     `db:"content_hash" json:"content_hash"`
	UploadTime       time.Time  `db:"upload_time" json:"upload_time"`
	ExpiryTime       *time.Time `db:"expiry_time" json:"expiry_time"`
	DeleteToken      string     `db:"delete_token" json:"-"`
	IsEncrypted      bool       `db:"is_encrypted" json:"is_encrypted"`
	IsBlocked        bool       `db:"is_blocked" json:"is_blocked"`
	UploaderDest     string     `db:"uploader_dest" json:"-"`
	DownloadCount    int        `db:"download_count" json:"download_count"`
	PasswordHash      string     `db:"password_hash" json:"-"`
	MaxDownloads      *int       `db:"max_downloads" json:"max_downloads"`
	MetadataStripped  bool       `db:"metadata_stripped" json:"metadata_stripped"`
	KEMCiphertext     []byte     `db:"kem_ciphertext" json:"-"`
	KeyVersion        int        `db:"key_version" json:"-"`
	EncryptionVersion int        `db:"encryption_version" json:"-"` // 1=legacy AES-GCM, 2=hybrid PQ
}

// Chunk represents a part of a larger file
type Chunk struct {
	FileID     string `db:"file_id"`
	ChunkIndex int    `db:"chunk_index"`
	ChunkPath  string `db:"chunk_path"`
	ChunkSize  int64  `db:"chunk_size"`
	Checksum   string `db:"checksum"`
}

// Report represents a content report for moderation
type Report struct {
	ID          string     `db:"id" json:"id"`
	FileID      string     `db:"file_id" json:"file_id"`
	ReporterDest string    `db:"reporter_dest" json:"-"`
	Reason      string     `db:"reason" json:"reason"`
	Details     string     `db:"details" json:"details"`
	Status      string     `db:"status" json:"status"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	ReviewedAt  *time.Time `db:"reviewed_at" json:"reviewed_at"`
	ReviewedBy  string     `db:"reviewed_by" json:"reviewed_by"`
	ActionTaken string     `db:"action_taken" json:"action_taken"`
}

// Ban represents a ban on a destination or content hash
type Ban struct {
	ID        string     `db:"id" json:"id"`
	BanType   string     `db:"ban_type" json:"ban_type"` // "destination" or "file_hash"
	Value     string     `db:"value" json:"value"`
	Reason    string     `db:"reason" json:"reason"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	ExpiresAt *time.Time `db:"expires_at" json:"expires_at"`
	CreatedBy string     `db:"created_by" json:"created_by"`
}

// Destination represents an I2P destination for tracking
type Destination struct {
	DestB32     string    `db:"dest_b32" json:"dest_b32"`
	FirstSeen   time.Time `db:"first_seen" json:"first_seen"`
	LastSeen    time.Time `db:"last_seen" json:"last_seen"`
	UploadCount int       `db:"upload_count" json:"upload_count"`
	TotalBytes  int64     `db:"total_bytes" json:"total_bytes"`
	BanStatus   int       `db:"ban_status" json:"ban_status"`
}

// Paste represents a text paste
type Paste struct {
	ID                string     `db:"id" json:"id"`
	Content           []byte     `db:"content" json:"-"`
	Language          string     `db:"language" json:"language"`
	ExpiryTime        *time.Time `db:"expiry_time" json:"expiry_time"`
	DeleteToken       string     `db:"delete_token" json:"-"`
	UploaderDest      string     `db:"uploader_dest" json:"-"`
	ViewCount         int        `db:"view_count" json:"view_count"`
	CreatedAt         time.Time  `db:"created_at" json:"created_at"`
	IsBlocked         bool       `db:"is_blocked" json:"is_blocked"`
	KEMCiphertext     []byte     `db:"kem_ciphertext" json:"-"`
	KeyVersion        int        `db:"key_version" json:"-"`
	EncryptionVersion int        `db:"encryption_version" json:"-"`
}

// Stats holds service statistics
type Stats struct {
	TotalFiles           int64  `json:"total_files"`
	TotalPastes          int64  `json:"total_pastes"`
	TotalDownloads       int64  `json:"total_downloads"`
	TotalAPIUploads      int64  `json:"total_api_uploads"`
	TotalStoredFormatted string `json:"total_stored_formatted"`
}

// ChunkedUpload represents an in-progress chunked upload session
type ChunkedUpload struct {
	ID             string    `db:"id" json:"id"`
	Filename       string    `db:"filename" json:"filename"`
	MimeType       string    `db:"mime_type" json:"mime_type"`
	TotalSize      int64     `db:"total_size" json:"total_size"`
	TotalChunks    int       `db:"total_chunks" json:"total_chunks"`
	ChunkSize      int64     `db:"chunk_size" json:"chunk_size"`
	ReceivedChunks int       `db:"received_chunks" json:"received_chunks"`
	Expiry         string    `db:"expiry" json:"expiry"`
	UploaderDest   string    `db:"uploader_dest" json:"-"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	ExpiresAt      time.Time `db:"expires_at" json:"expires_at"` // Session expiry (for cleanup)
	PasswordHash   string    `db:"password_hash" json:"-"`
	MaxDownloads   *int      `db:"max_downloads" json:"max_downloads"`
	KeepMetadata   bool      `db:"keep_metadata" json:"keep_metadata"`
}

// UploadChunk represents a received chunk for a chunked upload
type UploadChunk struct {
	UploadID   string `db:"upload_id"`
	ChunkIndex int    `db:"chunk_index"`
	ChunkPath  string `db:"chunk_path"`
	ChunkSize  int64  `db:"chunk_size"`
	Checksum   string `db:"checksum"`
}

// Report status constants
const (
	ReportStatusPending   = "pending"
	ReportStatusReviewed  = "reviewed"
	ReportStatusActioned  = "actioned"
	ReportStatusDismissed = "dismissed"
)

// Ban type constants
const (
	BanTypeDestination = "destination"
	BanTypeFileHash    = "file_hash"
)
