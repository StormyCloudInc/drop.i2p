package db

import (
	"database/sql"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

var DB *sql.DB

func Init(dataSourceName string) error {
	// Add pragmas for better concurrency
	dataSourceName = dataSourceName + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

	var err error
	DB, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		return err
	}

	// Set connection limits to avoid "database is locked" with too many writers,
	// although WAL supports concurrency, keeping it reasonable helps.
	// modernc/sqlite can be sensitive.
	DB.SetMaxOpenConns(1) // Strict serializability to prevent locking errors
	DB.SetMaxIdleConns(1)

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
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('photodna_blocked', 0);
	INSERT OR IGNORE INTO stats(stat_key, stat_value) VALUES('clamav_blocked', 0);

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

	-- Stats history for analytics dashboard
	CREATE TABLE IF NOT EXISTS stats_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		total_files INTEGER DEFAULT 0,
		total_pastes INTEGER DEFAULT 0,
		total_bytes INTEGER DEFAULT 0,
		total_downloads INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_stats_history_date ON stats_history(recorded_at);

	-- Collections for grouping files
	CREATE TABLE IF NOT EXISTS collections (
		id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		description TEXT,
		uploader_dest TEXT,
		delete_token TEXT,
		password_hash TEXT,
		expiry_time DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		view_count INTEGER DEFAULT 0,
		is_blocked BOOLEAN DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_collections_expiry ON collections(expiry_time);
	CREATE INDEX IF NOT EXISTS idx_collections_token ON collections(delete_token);

	-- Collection files junction table
	CREATE TABLE IF NOT EXISTS collection_files (
		collection_id TEXT NOT NULL,
		file_id TEXT NOT NULL,
		position INTEGER DEFAULT 0,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (collection_id, file_id),
		FOREIGN KEY(collection_id) REFERENCES collections(id) ON DELETE CASCADE,
		FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_collection_files_cid ON collection_files(collection_id);
	`
	_, err := DB.Exec(sqlStmt)
	return err
}

func Close() {
	if DB != nil {
		DB.Close()
	}
}
