package ncmec

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNCMEC mimics the documented API closely enough to exercise the client.
type fakeNCMEC struct {
	mu       sync.Mutex
	calls    []string
	reports  map[string]string // reportID -> state: open, finished, retracted
	files    map[string][]string
	failStep string // "upload", "fileinfo" or "finish" to inject a failure
	badHash  bool   // return a wrong MD5 from /upload
	lastXML  map[string][]byte
	nextID   int
}

func newFake() *fakeNCMEC {
	return &fakeNCMEC{reports: map[string]string{}, files: map[string][]string{}, lastXML: map[string][]byte{}}
}

func respond(w http.ResponseWriter, code int, desc, reportID, fileID, hash string) {
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><reportResponse><responseCode>%d</responseCode><responseDescription>%s</responseDescription><reportId>%s</reportId><fileId>%s</fileId><hash>%s</hash></reportResponse>`,
		code, desc, reportID, fileID, hash)
}

func (f *fakeNCMEC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Request-ID", "req-123")
	path := strings.TrimPrefix(r.URL.Path, "/ispws")
	f.calls = append(f.calls, path)

	if u, p, ok := r.BasicAuth(); !ok || u != "esp-user" || p != "esp-pass" {
		w.WriteHeader(http.StatusUnauthorized)
		respond(w, CodeAuthRequired, "Authentication required", "", "", "")
		return
	}

	switch path {
	case "/status":
		respond(w, 0, "Remote User : esp-user, Remote Ip : 127.0.0.1", "", "", "")
	case "/submit":
		if ct := r.Header.Get("Content-Type"); ct != "text/xml; charset=utf-8" {
			w.WriteHeader(http.StatusBadRequest)
			respond(w, CodeMalformedXML, "bad content type "+ct, "", "", "")
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.lastXML["submit"] = body
		var rep Report
		if err := xml.Unmarshal(body, &rep); err != nil || rep.Reporter.ReportingPerson.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			respond(w, CodeValidationFailed, "validation failed", "", "", "")
			return
		}
		f.nextID++
		id := fmt.Sprintf("%d", 1000+f.nextID)
		f.reports[id] = "open"
		respond(w, 0, "Success", id, "", "")
	case "/upload":
		id := r.FormValue("id")
		file, hdr, err := r.FormFile("file")
		if err != nil || f.reports[id] != "open" {
			w.WriteHeader(http.StatusBadRequest)
			respond(w, CodeReportDoesNotExist, "no such open report", id, "", "")
			return
		}
		data, _ := io.ReadAll(file)
		if f.failStep == "upload" {
			w.WriteHeader(http.StatusInternalServerError)
			respond(w, 1111, "File upload failed", id, "", "")
			return
		}
		sum := md5.Sum(data)
		h := hex.EncodeToString(sum[:])
		if f.badHash {
			h = "00000000000000000000000000000000"
		}
		fid := fmt.Sprintf("file-%s-%d", id, len(f.files[id]))
		f.files[id] = append(f.files[id], fid+":"+hdr.Filename)
		respond(w, 0, "Success", id, fid, h)
	case "/fileinfo":
		body, _ := io.ReadAll(r.Body)
		f.lastXML["fileinfo"] = body
		if f.failStep == "fileinfo" {
			w.WriteHeader(http.StatusBadRequest)
			respond(w, CodeValidationFailed, "validation failed", "", "", "")
			return
		}
		respond(w, 0, "Success", "", "", "")
	case "/finish":
		id := r.FormValue("id")
		if f.failStep == "finish" {
			w.WriteHeader(http.StatusBadRequest)
			respond(w, CodeValidationFailed, "validation failed", id, "", "")
			return
		}
		f.reports[id] = "finished"
		var files strings.Builder
		for _, x := range f.files[id] {
			files.WriteString("<fileId>" + strings.SplitN(x, ":", 2)[0] + "</fileId>")
		}
		fmt.Fprintf(w, `<reportDoneResponse><responseCode>0</responseCode><reportId>%s</reportId><files>%s</files></reportDoneResponse>`, id, files.String())
	case "/retract":
		id := r.FormValue("id")
		if f.reports[id] == "finished" {
			w.WriteHeader(http.StatusBadRequest)
			respond(w, CodeReportAlreadyFinish, "Report already finished", id, "", "")
			return
		}
		f.reports[id] = "retracted"
		respond(w, 0, "Success", id, "", "")
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func testClient(t *testing.T, f *fakeNCMEC) *Client {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := NewClient("test", "esp-user", "esp-pass")
	c.BaseURL = srv.URL + "/ispws"
	return c
}

func sample() (*Report, []FileToReport) {
	rep, file := BuildFileReport(ReporterInfo{
		FirstName: "Trust", LastName: "Safety", Email: "abuse@example.org",
		Platform: "drop.i2p", Service: "drop.i2p file hosting",
	}, FileIncident{
		FileID: "abc", PublicURL: "http://drop.i2p/f/abc", OriginalFilename: "x.jpg",
		UploadTime: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), UploaderID: "uploaderdest.b32.i2p",
		SHA256: strings.Repeat("ab", 32), PerceptualHash: "1a1c8c242c2e2e04",
		ViewedByESP: false, Notes: "matched hash ban",
	})
	file.Content = []byte("synthetic test bytes, not real content")
	return rep, []FileToReport{file}
}

func TestDefaultsToTestEnvironment(t *testing.T) {
	for _, env := range []string{"", "test", "prod", "Production", "live"} {
		if NewClient(env, "u", "p").IsProduction() {
			t.Errorf("env %q selected production; only the exact string \"production\" may", env)
		}
	}
	if !NewClient("production", "u", "p").IsProduction() {
		t.Error("production not selected for \"production\"")
	}
}

func TestStatusAndAuth(t *testing.T) {
	f := newFake()
	c := testClient(t, f)
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatalf("status: %v", err)
	}
	c.Password = "wrong"
	_, err := c.Status(context.Background())
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodeAuthRequired || apiErr.RequestID != "req-123" {
		t.Fatalf("bad credentials: got %v", err)
	}
}

func TestSubmitCompleteHappyPath(t *testing.T) {
	f := newFake()
	c := testClient(t, f)
	rep, files := sample()

	res, err := c.SubmitComplete(context.Background(), rep, files)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReportID == "" || len(res.FileIDs) != 1 {
		t.Fatalf("result: %+v", res)
	}
	want := []string{"/submit", "/upload", "/fileinfo", "/finish"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("call order %v, want %v", f.calls, want)
	}
	if f.reports[res.ReportID] != "finished" {
		t.Fatal("report not finished")
	}

	sub := string(f.lastXML["submit"])
	for _, must := range []string{
		"<incidentType>" + IncidentChildPornography + "</incidentType>",
		"<email>abuse@example.org</email>",
		"<espIdentifier>uploaderdest.b32.i2p</espIdentifier>",
		"<url>http://drop.i2p/f/abc</url>",
		"<incidentDateTime>2026-10-01T12:00:00Z</incidentDateTime>",
		`xsi:noNamespaceSchemaLocation="`,
	} {
		if !strings.Contains(sub, must) {
			t.Errorf("submit XML missing %s\n%s", must, sub)
		}
	}
	if strings.Contains(sub, "<ipCaptureEvent>") {
		t.Error("report must not contain an ipCaptureEvent: there is no IP on I2P")
	}

	fi := string(f.lastXML["fileinfo"])
	for _, must := range []string{
		"<reportId>" + res.ReportID + "</reportId>",
		"<fileId>" + res.FileIDs[0] + "</fileId>",
		`<originalFileHash hashType="SHA256">`,
		"<fileViewedByEsp>false</fileViewedByEsp>",
	} {
		if !strings.Contains(fi, must) {
			t.Errorf("fileinfo XML missing %s\n%s", must, fi)
		}
	}
	if strings.Contains(fi, "industryClassification") {
		t.Error("classification must only be sent when a person viewed the file")
	}
}

func TestFailuresRetract(t *testing.T) {
	for _, step := range []string{"upload", "fileinfo", "finish"} {
		t.Run(step, func(t *testing.T) {
			f := newFake()
			f.failStep = step
			c := testClient(t, f)
			rep, files := sample()
			_, err := c.SubmitComplete(context.Background(), rep, files)
			if err == nil || !strings.Contains(err.Error(), "retracted") {
				t.Fatalf("want error mentioning retraction, got %v", err)
			}
			for id, state := range f.reports {
				if state != "retracted" {
					t.Errorf("report %s left %s after %s failure", id, state, step)
				}
			}
		})
	}
}

func TestUploadHashMismatchDetected(t *testing.T) {
	f := newFake()
	f.badHash = true
	c := testClient(t, f)
	rep, files := sample()
	if _, err := c.SubmitComplete(context.Background(), rep, files); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("want hash mismatch, got %v", err)
	}
}

func TestMissingEmailRejectedLocally(t *testing.T) {
	c := testClient(t, newFake())
	rep, _ := sample()
	rep.Reporter.ReportingPerson.Email = ""
	if _, err := c.Submit(context.Background(), rep); err == nil {
		t.Fatal("expected error for missing reporter email")
	}
}

// TestAgainstRealSchema validates generated XML against NCMEC's XSD, if it has
// been downloaded to testdata/ncmec.xsd and xmllint is installed.
func TestAgainstRealSchema(t *testing.T) {
	xsd := filepath.Join("testdata", "ncmec.xsd")
	if _, err := os.Stat(xsd); err != nil {
		t.Skip("testdata/ncmec.xsd not present; download it with GET /xsd to enable")
	}
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint not installed")
	}
	rep, files := sample()
	files[0].Details.ReportID, files[0].Details.FileID = "1", "f1"
	for name, doc := range map[string]interface{}{"report": rep, "fileDetails": &files[0].Details} {
		data, err := marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name+".xml")
		os.WriteFile(path, data, 0o600)
		out, err := exec.Command("xmllint", "--noout", "--schema", xsd, path).CombinedOutput()
		if err != nil {
			t.Errorf("%s does not validate against NCMEC schema:\n%s\n%s", name, out, data)
		}
	}
}
