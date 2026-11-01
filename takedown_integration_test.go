package main

// End-to-end tests for takedown, evidence preservation and NCMEC reporting,
// through the real router and database, against a fake NCMEC server.
// All file content is synthetic.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"drop-i2p/internal/db"
	"drop-i2p/internal/ncmec"
	"drop-i2p/internal/storage"
)

// fakeCyberTip records what it receives and accepts every report.
type fakeCyberTip struct {
	mu       sync.Mutex
	requests []string
	uploads  [][]byte
	n        int
}

func (f *fakeCyberTip) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/ispws")
	f.requests = append(f.requests, path)
	ok := func(reportID, fileID, hash string) {
		fmt.Fprintf(w, `<reportResponse><responseCode>0</responseCode><responseDescription>Success</responseDescription><reportId>%s</reportId><fileId>%s</fileId><hash>%s</hash></reportResponse>`, reportID, fileID, hash)
	}
	switch path {
	case "/submit":
		f.n++
		ok(fmt.Sprintf("%d", 900000+f.n), "", "")
	case "/upload":
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		data, _ := io.ReadAll(file)
		f.uploads = append(f.uploads, data)
		ok(r.FormValue("id"), "fakefile", "")
	case "/fileinfo":
		ok("", "", "")
	case "/finish":
		fmt.Fprintf(w, `<reportDoneResponse><responseCode>0</responseCode><reportId>%s</reportId><files><fileId>fakefile</fileId></files></reportDoneResponse>`, r.FormValue("id"))
	case "/retract":
		ok(r.FormValue("id"), "", "")
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeCyberTip) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (hs *harness) withNCMEC(env string) *fakeCyberTip {
	f := &fakeCyberTip{}
	ts := httptest.NewServer(f)
	hs.t.Cleanup(ts.Close)
	c := ncmec.NewClient(env, "u", "p")
	c.BaseURL = ts.URL + "/ispws"
	hs.cfg.NCMECReporterEmail = "abuse@example.org"
	hs.srv.SetNCMECClient(c)
	return f
}

func (hs *harness) admin(method, path string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.SetBasicAuth("admin", "test-admin-pw")
	rr := httptest.NewRecorder()
	hs.h.ServeHTTP(rr, req)
	return rr
}

func (hs *harness) get(path string) int {
	rr := httptest.NewRecorder()
	hs.h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	return rr.Code
}

func (hs *harness) waitStatus(fileID string, want ...string) *storage.Evidence {
	hs.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ev, err := hs.store.GetEvidence(fileID)
		if err == nil {
			for _, w := range want {
				if ev.Status == w {
					return ev
				}
			}
		}
		if time.Now().After(deadline) {
			hs.t.Fatalf("status never reached %v; last %+v err %v", want, ev, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (hs *harness) uploadSynthetic(dest string, seed int) (string, []byte) {
	hs.t.Helper()
	data := pngBytes(hs.t, testPattern(seed))
	code, id := hs.apiUpload(dest, fmt.Sprintf("img%d.png", seed), "image/png", data)
	if code != 200 {
		hs.t.Fatalf("upload: %d", code)
	}
	return id, data
}

func TestTakedownPreservesAndReports(t *testing.T) {
	hs := newHarness(t)
	fake := hs.withNCMEC("production")
	id, original := hs.uploadSynthetic("dest-bad.b32.i2p", 11)
	meta, _ := hs.store.GetFileMetadata(id)

	// The confirmation page must not embed the file.
	form := hs.admin("GET", "/admdash/ncmec/takedown/"+id, nil)
	if form.Code != 200 {
		t.Fatalf("takedown form: %d %s", form.Code, form.Body.String())
	}
	if strings.Contains(form.Body.String(), "<img src=\"/f/"+id) || strings.Contains(form.Body.String(), "/f/"+id+"\"") {
		t.Error("takedown page must not display or link the file")
	}

	rr := hs.admin("POST", "/admdash/ncmec/takedown/"+id, url.Values{
		"ban_uploader": {"on"}, "report": {"queue"}, "notes": {"found via user report"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("takedown: %d %s", rr.Code, rr.Body.String())
	}

	// Public access is gone immediately.
	if c := hs.get("/f/" + id); c != 403 {
		t.Errorf("download after takedown: %d, want 403", c)
	}
	if c := hs.get("/view/" + id); c != 403 {
		t.Errorf("view after takedown: %d, want 403", c)
	}

	// Report is filed in the background with the exact preserved bytes.
	ev := hs.waitStatus(id, storage.NCMECReported, storage.NCMECFailed)
	if ev.Status != storage.NCMECReported || ev.ReportID == "" {
		t.Fatalf("report not filed: %+v", ev)
	}
	if len(fake.uploads) != 1 || !bytes.Equal(fake.uploads[0], original) {
		t.Fatal("NCMEC did not receive the exact original file bytes")
	}
	if ev.PreservedUntil == nil || ev.PreservedUntil.Before(time.Now().Add(364*24*time.Hour)) {
		t.Errorf("hold too short: %v", ev.PreservedUntil)
	}
	t.Logf("reported as CyberTip %s, held until %s", ev.ReportID, ev.PreservedUntil.Format("2006-01-02"))

	// Every deletion path refuses while held.
	if c := hs.get("/d/" + id + "/" + meta.DeleteToken); c != http.StatusGone {
		t.Errorf("uploader delete link: %d, want 410 (neutral)", c)
	}
	hs.admin("POST", "/admdash/delete/"+id, url.Values{})
	db.DB.Exec(`UPDATE files SET expiry_time = ? WHERE id = ?`, time.Now().Add(-48*time.Hour), id)
	hs.store.CleanupExpired()
	var buf bytes.Buffer
	if err := hs.store.RetrieveFile(id, &buf); err != nil || !bytes.Equal(buf.Bytes(), original) {
		t.Fatalf("preserved file lost or altered: err=%v", err)
	}

	// Bans: uploader, and re-uploads of the content.
	if banned, _ := hs.store.IsDestinationBanned("dest-bad.b32.i2p"); !banned {
		t.Error("uploader destination not banned")
	}
	if code, _ := hs.apiUpload("dest-other.b32.i2p", "again.png", "image/png", original); code != 403 {
		t.Errorf("re-upload of taken-down content: %d, want 403", code)
	}

	// The NCMEC page shows the report.
	page := hs.admin("GET", "/admdash/ncmec", nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), ev.ReportID) {
		t.Errorf("ncmec page: %d, missing report id", page.Code)
	}

	// After the hold ends, normal cleanup purges it.
	db.DB.Exec(`UPDATE files SET preserved_until = ? WHERE id = ?`, time.Now().Add(-time.Hour).UTC(), id)
	hs.store.CleanupExpired()
	if _, err := hs.store.GetFileMetadata(id); err == nil {
		t.Error("file not purged after hold ended")
	}
}

func TestTestModeNeverSendsRealFiles(t *testing.T) {
	hs := newHarness(t)
	fake := hs.withNCMEC("test")
	id, _ := hs.uploadSynthetic("dest-a.b32.i2p", 12)
	hs.admin("POST", "/admdash/ncmec/takedown/"+id, url.Values{"report": {"queue"}})
	ev := hs.waitStatus(id, storage.NCMECNotSent)
	if fake.count() != 0 {
		t.Fatalf("test mode contacted NCMEC %d times with a real upload", fake.count())
	}
	if c := hs.get("/f/" + id); c != 403 {
		t.Errorf("takedown must still work in test mode: %d", c)
	}
	t.Logf("test mode: %s", ev.Error)
}

func TestNotConfiguredStillTakesDown(t *testing.T) {
	hs := newHarness(t) // no NCMEC client
	id, _ := hs.uploadSynthetic("dest-b.b32.i2p", 13)
	hs.admin("POST", "/admdash/ncmec/takedown/"+id, url.Values{"report": {"queue"}})
	hs.waitStatus(id, storage.NCMECNotSent)
	if c := hs.get("/f/" + id); c != 403 {
		t.Errorf("download after takedown: %d", c)
	}
}

func TestRetryAfterProductionConfigured(t *testing.T) {
	hs := newHarness(t)
	id, original := hs.uploadSynthetic("dest-c.b32.i2p", 14)
	hs.admin("POST", "/admdash/ncmec/takedown/"+id, url.Values{"report": {"queue"}})
	hs.waitStatus(id, storage.NCMECNotSent)

	fake := hs.withNCMEC("production")
	hs.admin("POST", "/admdash/ncmec/send/"+id, url.Values{})
	ev := hs.waitStatus(id, storage.NCMECReported)
	if !bytes.Equal(fake.uploads[0], original) || ev.ReportID == "" {
		t.Fatal("retry did not file the report")
	}

	// Sending again must not file a duplicate.
	hs.admin("POST", "/admdash/ncmec/send/"+id, url.Values{})
	time.Sleep(200 * time.Millisecond)
	if fake.n != 1 {
		t.Errorf("duplicate report filed: %d submits", fake.n)
	}
}

func TestBanHashQuarantinesInsteadOfDeleting(t *testing.T) {
	hs := newHarness(t)
	id, original := hs.uploadSynthetic("dest-d.b32.i2p", 15)
	sum := sha256.Sum256(original)
	reportID := "rep-1"
	db.DB.Exec(`INSERT INTO reports (id, file_id, reason, status) VALUES (?, ?, 'test', 'pending')`, reportID, id)

	rr := hs.admin("POST", "/admdash/reports/"+reportID+"/action", url.Values{"action": {"ban_hash"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("ban_hash: %d %s", rr.Code, rr.Body.String())
	}
	var buf bytes.Buffer
	if err := hs.store.RetrieveFile(id, &buf); err != nil {
		t.Fatalf("ban_hash deleted the file: %v", err)
	}
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(func() []byte { s := sha256.Sum256(buf.Bytes()); return s[:] }()) {
		t.Fatal("preserved bytes differ")
	}
	if c := hs.get("/f/" + id); c != 403 {
		t.Errorf("file still public after ban_hash: %d", c)
	}
	if ev, _ := hs.store.GetEvidence(id); ev.TakedownAt == nil || ev.Status != "" {
		t.Errorf("ban_hash should quarantine without queueing a report: %+v", ev)
	}
}
