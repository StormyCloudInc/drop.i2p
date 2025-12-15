package db

import (
	"database/sql"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

var DB *sql.DB

func Init(dataSourceName string) error {
	var err error
	DB, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	return createTables()
}

func createTables() error {
	// Files table with extended fields for moderation
	sqlStmt := `
	CREATE TABLE IF NOT EXISTS files (
		id TEXT PRIMARY KEY,
		filename TEXT NOT NULL,
		original_filename TEXT,
		size INTEGER,
		mime_type TEXT,
		content_hash TEXT,
		upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		expiry_time DATETIME,
		delete_token TEXT,
		is_encrypted BOOLEAN DEFAULT 0,
		is_blocked BOOLEAN DEFAULT 0,
		uploader_dest TEXT,
		download_count INTEGER DEFAULT -1,
		password_hash TEXT,
		max_downloads INTEGER,
		metadata_stripped INTEGER DEFAULT 1,
		kem_ciphertext BLOB,
		key_version INTEGER DEFAULT 0,
		encryption_version INTEGER DEFAULT 2
	);
	CREATE INDEX IF NOT EXISTS idx_expiry ON files(expiry_time);
	CREATE INDEX IF NOT EXISTS idx_token ON files(delete_token);
	CREATE INDEX IF NOT EXISTS idx_content_hash ON files(content_hash);
	CREATE INDEX IF NOT EXISTS idx_uploader ON files(uploader_dest);

	CREATE TABLE IF NOT EXISTS chunks (
		file_id TEXT,
		chunk_index INTEGER,
		chunk_path TEXT,
		chunk_size INTEGER,
		checksum TEXT,
		PRIMARY KEY (file_id, chunk_index),
		FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	-- Reports table for content moderation (file_id can be a file or paste ID)
	CREATE TABLE IF NOT EXISTS reports (
		id TEXT PRIMARY KEY,
		file_id TEXT NOT NULL,
		reporter_dest TEXT,
		reason TEXT NOT NULL,
		details TEXT,
		status TEXT DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		reviewed_at DATETIME,
		reviewed_by TEXT,
		action_taken TEXT,
		content_type TEXT DEFAULT 'file'
	);
	CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
	CREATE INDEX IF NOT EXISTS idx_reports_file ON reports(file_id);

	-- Bans table for destination and content hash banning
	CREATE TABLE IF NOT EXISTS bans (
		id TEXT PRIMARY KEY,
		ban_type TEXT NOT NULL,
		value TEXT NOT NULL,
		reason TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		created_by TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_bans_type_value ON bans(ban_type, value);

	-- Destinations tracking for rate limiting and statistics
	CREATE TABLE IF NOT EXISTS destinations (
		dest_b32 TEXT PRIMARY KEY,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME,
		upload_count INTEGER DEFAULT 0,
		total_bytes INTEGER DEFAULT 0,
		ban_status INTEGER DEFAULT 0
	);

	-- Pastes table for pastebin feature
	CREATE TABLE IF NOT EXISTS pastes (
		id TEXT PRIMARY KEY,
		content BLOB NOT NULL,
		language TEXT NOT NULL DEFAULT 'text',
		expiry_time DATETIME,
		delete_token TEXT,
		uploader_dest TEXT,
		view_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_blocked BOOLEAN DEFAULT 0,
		kem_ciphertext BLOB,
		key_version INTEGER DEFAULT 0,
		encryption_version INTEGER DEFAULT 2
	);
	CREATE INDEX IF NOT EXISTS idx_pastes_expiry ON pastes(expiry_time);
	CREATE INDEX IF NOT EXISTS idx_pastes_token ON pastes(delete_token);

	-- Stats table for service statistics
	CREATE TABLE IF NOT EXISTS stats (
		stat_key TEXT PRIMARY KEY,
		stat_value INTEGER NOT NULL DEFAULT 0
	);
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('total_files', 0);
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('total_pastes', 0);
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('total_downloads', 0);
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('total_api_uploads', 0);
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('total_bytes_stored', 0);

	-- Chunked uploads table for resumable uploads
	CREATE TABLE IF NOT EXISTS chunked_uploads (
		id TEXT PRIMARY KEY,
		filename TEXT NOT NULL,
		mime_type TEXT,
		total_size INTEGER NOT NULL,
		total_chunks INTEGER NOT NULL,
		chunk_size INTEGER NOT NULL,
		received_chunks INTEGER DEFAULT 0,
		expiry TEXT,
		uploader_dest TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		password_hash TEXT,
		max_downloads INTEGER,
		keep_metadata INTEGER DEFAULT 0,
		kem_ciphertext BLOB,
		key_version INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_chunked_expires ON chunked_uploads(expires_at);

	-- Upload chunks table for individual chunks
	CREATE TABLE IF NOT EXISTS upload_chunks (
		upload_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		chunk_path TEXT NOT NULL,
		chunk_size INTEGER NOT NULL,
		checksum TEXT,
		PRIMARY KEY (upload_id, chunk_index),
		FOREIGN KEY(upload_id) REFERENCES chunked_uploads(id) ON DELETE CASCADE
	);
	`
	_, err := DB.Exec(sqlStmt)
	return err
}

func Close() {
	if DB != nil {
		DB.Close()
	}
}
