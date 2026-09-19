package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func hit(h http.Handler, method, path string) int {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-I2P-DestB32", "adminfakedest.b32.i2p")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestAdminExemptFromUploadRateLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{UploadsPerHour: 3, DownloadsPerHour: 100, ReportsPerHour: 5, BytesPerDay: 1 << 30})
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := RateLimitMiddleware(rl, "/admdash")(ok)

	// 30 admin moderation POSTs - far past the limit of 3
	for i := 0; i < 30; i++ {
		if got := hit(h, "POST", "/admdash/reports/abc-123/action"); got != 200 {
			t.Fatalf("admin POST #%d got %d, want 200 (admin must never be rate limited)", i+1, got)
		}
	}
	t.Log("30/30 admin moderation POSTs allowed")

	// Real uploads still limited to 3
	codes := []int{}
	for i := 0; i < 5; i++ {
		codes = append(codes, hit(h, "POST", "/api/upload"))
	}
	t.Logf("upload POST codes: %v", codes)
	for i := 0; i < 3; i++ {
		if codes[i] != 200 {
			t.Fatalf("upload #%d got %d, want 200", i+1, codes[i])
		}
	}
	for i := 3; i < 5; i++ {
		if codes[i] != 429 {
			t.Fatalf("upload #%d got %d, want 429 (limit must still apply)", i+1, codes[i])
		}
	}
}

func TestAdminPrefixNoFalsePositive(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{UploadsPerHour: 1, DownloadsPerHour: 100, ReportsPerHour: 5, BytesPerDay: 1 << 30})
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := RateLimitMiddleware(rl, "/admdash")(ok)

	// A path that merely starts with the same letters must NOT be exempt
	if got := hit(h, "POST", "/admdash-public/upload"); got != 200 {
		t.Fatalf("first request got %d, want 200", got)
	}
	if got := hit(h, "POST", "/admdash-public/upload"); got != 429 {
		t.Fatalf("/admdash-public got %d, want 429 - must not inherit admin exemption", got)
	}
	t.Log("/admdash-public correctly still rate limited")
}
