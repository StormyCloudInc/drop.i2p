package main

// End-to-end test of hash-ban enforcement through the real HTTP router and a
// real SQLite database. It lives at the repo root because the server package
// parses templates from "templates/..." at init, relative to the working dir.
//
// All images are synthetic test patterns.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"testing"

	"drop-i2p/internal/config"
	"drop-i2p/internal/crypto"
	"drop-i2p/internal/db"
	"drop-i2p/internal/models"
	"drop-i2p/internal/server"
	"drop-i2p/internal/storage"

	"github.com/disintegration/imaging"
)

func testPattern(seed int) *image.NRGBA {
	rng := rand.New(rand.NewSource(int64(seed)))
	const w, h = 640, 480
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetNRGBA(x, y, color.NRGBA{uint8(x * 255 / w), uint8(y * 255 / h), 128, 255})
		}
	}
	for i := 0; i < 14; i++ {
		x0, y0 := rng.Intn(w), rng.Intn(h)
		x1, y1 := x0+rng.Intn(w/2)+20, y0+rng.Intn(h/2)+20
		c := color.NRGBA{uint8(rng.Intn(256)), uint8(rng.Intn(256)), uint8(rng.Intn(256)), 255}
		for y := y0; y < y1 && y < h; y++ {
			for x := x0; x < x1 && x < w; x++ {
				img.SetNRGBA(x, y, c)
			}
		}
	}
	return img
}

func pngBytes(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func jpegBytes(t *testing.T, img image.Image, q int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: q}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type harness struct {
	t     *testing.T
	h     http.Handler
	store *storage.Manager
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SSP_CLAMAV_ENABLED", "false")
	cfg := config.Load()
	cfg.DatabasePath = filepath.Join(dir, "test.db")
	cfg.UploadFolder = dir
	cfg.AdminURL = "/admdash"
	cfg.PHashThreshold = 10
	cfg.AutoBanOnHashMatch = true

	if err := db.Init(cfg.DatabasePath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })

	seed := func(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)) }
	km, err := crypto.NewKeyManager(seed(crypto.X25519PrivKeySize), seed(crypto.MLKEMSeedSize), 1)
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewManagerWithKeys(cfg, km)
	return &harness{t: t, h: server.New(cfg, store).Router(), store: store}
}

// apiUpload posts a file to /api/upload and returns the status and file ID.
func (hs *harness) apiUpload(dest, filename, mimeType string, data []byte) (int, string) {
	hs.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, filename))
	hdr.Set("Content-Type", mimeType)
	part, _ := mw.CreatePart(hdr)
	part.Write(data)
	mw.Close()

	req := httptest.NewRequest("POST", "/api/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-I2P-DestB32", dest)
	rr := httptest.NewRecorder()
	hs.h.ServeHTTP(rr, req)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	id, _ := resp["id"].(string)
	return rr.Code, id
}

// chunkedUpload runs init, chunk uploads and complete; returns the complete status.
func (hs *harness) chunkedUpload(dest, filename, mimeType string, data []byte) int {
	hs.t.Helper()
	const chunk = 64 * 1024
	n := (len(data) + chunk - 1) / chunk
	initBody, _ := json.Marshal(map[string]interface{}{
		"filename": filename, "mime_type": mimeType, "total_size": len(data), "total_chunks": n, "expiry": "1h",
	})
	do := func(path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, bytes.NewReader(body))
		req.Header.Set("X-I2P-DestB32", dest)
		rr := httptest.NewRecorder()
		hs.h.ServeHTTP(rr, req)
		return rr
	}
	rr := do("/api/upload/chunked/init", initBody)
	var initResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &initResp)
	uploadID, _ := initResp["upload_id"].(string)
	if uploadID == "" {
		hs.t.Fatalf("chunked init failed: %d %s", rr.Code, rr.Body.String())
	}
	for i := 0; i < n; i++ {
		end := (i + 1) * chunk
		if end > len(data) {
			end = len(data)
		}
		if rr := do(fmt.Sprintf("/api/upload/chunked/%s/%d", uploadID, i), data[i*chunk:end]); rr.Code != 200 {
			hs.t.Fatalf("chunk %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}
	return do(fmt.Sprintf("/api/upload/chunked/%s/complete", uploadID), nil).Code
}

func TestHashBansEnforcedEndToEnd(t *testing.T) {
	hs := newHarness(t)
	original := testPattern(1)
	origPNG := pngBytes(t, original)

	// 1. Upload the original. It must be accepted and get a perceptual hash.
	code, id := hs.apiUpload("dest-original.b32.i2p", "a.png", "image/png", origPNG)
	if code != 200 || id == "" {
		t.Fatalf("original upload: got %d, want 200", code)
	}
	file, err := hs.store.GetFileMetadata(id)
	if err != nil {
		t.Fatal(err)
	}
	if file.PerceptualHash == "" {
		t.Fatal("perceptual hash was not stored on upload")
	}
	t.Logf("stored perceptual hash %s", file.PerceptualHash)

	// 2. Admin bans it. Both SHA-256 and perceptual bans are created.
	n, err := hs.store.BanFileContent(file, "test")
	if err != nil || n != 2 {
		t.Fatalf("BanFileContent: created %d bans, err %v; want 2", n, err)
	}
	if n2, _ := hs.store.BanFileContent(file, "test"); n2 != 0 {
		t.Fatalf("banning twice created %d duplicate bans", n2)
	}

	// 3. Exact re-upload: refused, and the uploader is auto-banned.
	if code, _ := hs.apiUpload("dest-exact.b32.i2p", "copy.png", "image/png", origPNG); code != 403 {
		t.Errorf("exact re-upload: got %d, want 403", code)
	}
	if banned, _ := hs.store.IsDestinationBanned("dest-exact.b32.i2p"); !banned {
		t.Error("exact re-upload did not auto-ban the uploading destination")
	}

	// 4. Re-encoded and resized copy: refused by perceptual match, no auto-ban.
	variant := jpegBytes(t, imaging.Resize(original, 320, 240, imaging.Lanczos), 45)
	if code, _ := hs.apiUpload("dest-variant.b32.i2p", "v.jpg", "image/jpeg", variant); code != 403 {
		t.Errorf("re-encoded variant: got %d, want 403", code)
	}
	if banned, _ := hs.store.IsDestinationBanned("dest-variant.b32.i2p"); banned {
		t.Error("perceptual match must not auto-ban (could be a false positive)")
	}

	// 5. MIME evasion: same image sent as a generic binary with a .bin name.
	if code, _ := hs.apiUpload("dest-evade.b32.i2p", "data.bin", "application/octet-stream", variant); code != 403 {
		t.Errorf("image disguised as octet-stream: got %d, want 403", code)
	}

	// 6. Chunked upload path: refused too.
	if code := hs.chunkedUpload("dest-chunked.b32.i2p", "big.jpg", "image/jpeg", jpegBytes(t, original, 70)); code != 403 {
		t.Errorf("chunked upload of banned image: got %d, want 403", code)
	}

	// 7. An unrelated image is still accepted, on both paths.
	if code, _ := hs.apiUpload("dest-innocent.b32.i2p", "ok.png", "image/png", pngBytes(t, testPattern(99))); code != 200 {
		t.Errorf("unrelated image: got %d, want 200", code)
	}
	if code := hs.chunkedUpload("dest-innocent2.b32.i2p", "ok2.jpg", "image/jpeg", jpegBytes(t, testPattern(77), 80)); code != 200 {
		t.Errorf("unrelated chunked image: got %d, want 200", code)
	}

	// 8. Non-image files are unaffected.
	if code, _ := hs.apiUpload("dest-text.b32.i2p", "notes.txt", "text/plain", []byte("hello world")); code != 200 {
		t.Errorf("text file: got %d, want 200", code)
	}
}

func TestBackfillBlocksExistingMatches(t *testing.T) {
	hs := newHarness(t)
	img := testPattern(5)

	// A file uploaded "before" perceptual hashing existed: clear its hash.
	code, id := hs.apiUpload("dest-old.b32.i2p", "old.png", "image/png", pngBytes(t, img))
	if code != 200 {
		t.Fatalf("upload: %d", code)
	}
	original, _ := hs.store.GetFileMetadata(id)
	db.DB.Exec(`UPDATE files SET perceptual_hash = NULL WHERE id = ?`, id)

	// Later, a re-encoded copy is reported and banned by perceptual hash only.
	if err := hs.store.CreateBan("ban-1", models.BanTypePerceptualHash, original.PerceptualHash, "test", nil); err != nil {
		t.Fatal(err)
	}

	res, err := hs.store.BackfillPerceptualHashes()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("backfill: %+v", *res)
	if res.Hashed != 1 || res.MatchedBans != 1 {
		t.Fatalf("backfill: hashed %d matched %d; want 1 and 1", res.Hashed, res.MatchedBans)
	}
	if f, _ := hs.store.GetFileMetadata(id); !f.IsBlocked {
		t.Error("backfill did not block the matching file")
	}

	// Running again is a no-op.
	if res2, _ := hs.store.BackfillPerceptualHashes(); res2.Scanned != 0 {
		t.Errorf("second backfill rescanned %d files", res2.Scanned)
	}
}
