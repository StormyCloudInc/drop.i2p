package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"drop-i2p/internal/i2p"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	UploadsPerHour   int   // Default: 10
	DownloadsPerHour int   // Default: 100
	ReportsPerHour   int   // Default: 5
	BytesPerDay      int64 // Default: 100MB
}

// DefaultRateLimitConfig returns default rate limit settings
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		UploadsPerHour:   10,
		DownloadsPerHour: 100,
		ReportsPerHour:   5,
		BytesPerDay:      100 * 1024 * 1024, // 100MB
	}
}

// RateLimiter implements per-destination rate limiting
type RateLimiter struct {
	config  RateLimitConfig
	buckets sync.Map // map[string]*destinationBucket
	mu      sync.Mutex
}

type destinationBucket struct {
	mu                sync.Mutex
	uploads           int
	downloads         int
	reports           int
	bytesUploaded     int64
	lastUploadReset   time.Time
	lastDownloadReset time.Time
	lastReportReset   time.Time
	lastBytesReset    time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config: config,
	}
}

// getBucket returns or creates a bucket for a destination
func (rl *RateLimiter) getBucket(destB32 string) *destinationBucket {
	if bucket, ok := rl.buckets.Load(destB32); ok {
		return bucket.(*destinationBucket)
	}

	// Create new bucket
	now := time.Now()
	bucket := &destinationBucket{
		lastUploadReset:   now,
		lastDownloadReset: now,
		lastReportReset:   now,
		lastBytesReset:    now,
	}
	actual, _ := rl.buckets.LoadOrStore(destB32, bucket)
	return actual.(*destinationBucket)
}

// AllowUpload checks if an upload is allowed for this destination
func (rl *RateLimiter) AllowUpload(destB32 string) (bool, time.Duration) {
	if destB32 == "" {
		return true, 0 // Allow if no destination (clearnet or testing)
	}

	bucket := rl.getBucket(destB32)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()

	// Reset counter if hour has passed
	if now.Sub(bucket.lastUploadReset) > time.Hour {
		bucket.uploads = 0
		bucket.lastUploadReset = now
	}

	if bucket.uploads >= rl.config.UploadsPerHour {
		wait := time.Hour - now.Sub(bucket.lastUploadReset)
		return false, wait
	}

	bucket.uploads++
	return true, 0
}

// AllowDownload checks if a download is allowed for this destination
func (rl *RateLimiter) AllowDownload(destB32 string) (bool, time.Duration) {
	if destB32 == "" {
		return true, 0
	}

	bucket := rl.getBucket(destB32)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()

	// Reset counter if hour has passed
	if now.Sub(bucket.lastDownloadReset) > time.Hour {
		bucket.downloads = 0
		bucket.lastDownloadReset = now
	}

	if bucket.downloads >= rl.config.DownloadsPerHour {
		wait := time.Hour - now.Sub(bucket.lastDownloadReset)
		return false, wait
	}

	bucket.downloads++
	return true, 0
}

// AllowReport checks if a report is allowed for this destination
func (rl *RateLimiter) AllowReport(destB32 string) bool {
	if destB32 == "" {
		return true
	}

	bucket := rl.getBucket(destB32)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()

	// Reset counter if hour has passed
	if now.Sub(bucket.lastReportReset) > time.Hour {
		bucket.reports = 0
		bucket.lastReportReset = now
	}

	if bucket.reports >= rl.config.ReportsPerHour {
		return false
	}

	bucket.reports++
	return true
}

// AllowBytes checks if byte upload is allowed for this destination
func (rl *RateLimiter) AllowBytes(destB32 string, bytes int64) bool {
	if destB32 == "" {
		return true
	}

	bucket := rl.getBucket(destB32)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()

	// Reset counter if day has passed
	if now.Sub(bucket.lastBytesReset) > 24*time.Hour {
		bucket.bytesUploaded = 0
		bucket.lastBytesReset = now
	}

	if bucket.bytesUploaded+bytes > rl.config.BytesPerDay {
		return false
	}

	bucket.bytesUploaded += bytes
	return true
}

// RateLimitMiddleware creates HTTP middleware for rate limiting
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			destB32 := i2p.GetDestinationFromRequest(r)

			// Apply rate limiting based on request type
			switch r.Method {
			case "POST":
				// Skip rate limiting for chunk upload requests (already linked to a valid session)
				// Chunk uploads are: /api/upload/chunked/{uploadID}/{chunkIndex}
				// Only count init and complete requests as uploads
				path := r.URL.Path
				isChunkUpload := strings.HasPrefix(path, "/api/upload/chunked/") &&
					path != "/api/upload/chunked/init" &&
					!strings.HasSuffix(path, "/complete") &&
					!strings.HasSuffix(path, "/status")

				if !isChunkUpload {
					// Regular uploads and chunked init/complete count against rate limit
					if allowed, wait := limiter.AllowUpload(destB32); !allowed {
						w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
						http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
						return
					}
				}
			case "GET":
				// Downloads (only for /f/ routes)
				if len(r.URL.Path) > 3 && r.URL.Path[:3] == "/f/" {
					if allowed, wait := limiter.AllowDownload(destB32); !allowed {
						w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
						http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Cleanup removes old buckets to prevent memory leaks
// Should be called periodically (e.g., every hour)
func (rl *RateLimiter) Cleanup() {
	now := time.Now()
	cutoff := now.Add(-24 * time.Hour) // Remove buckets inactive for 24h

	rl.buckets.Range(func(key, value interface{}) bool {
		bucket := value.(*destinationBucket)
		bucket.mu.Lock()
		defer bucket.mu.Unlock()

		// Check if bucket has been inactive
		if bucket.lastUploadReset.Before(cutoff) &&
			bucket.lastDownloadReset.Before(cutoff) &&
			bucket.lastReportReset.Before(cutoff) &&
			bucket.lastBytesReset.Before(cutoff) {
			rl.buckets.Delete(key)
		}
		return true
	})
}
