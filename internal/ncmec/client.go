package ncmec

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Base URLs.
const (
	TestBaseURL       = "https://exttest.cybertip.org/ispws"
	ProductionBaseURL = "https://report.cybertip.org/ispws"
)

// Client talks to the CyberTipline Reporting API.
type Client struct {
	BaseURL  string
	Username string
	Password string
	HTTP     *http.Client
}

// NewClient returns a client for the given environment ("test" or "production").
// Anything other than "production" selects the test environment, so a typo
// never sends real reports.
func NewClient(env, username, password string) *Client {
	base := TestBaseURL
	if env == "production" {
		base = ProductionBaseURL
	}
	return &Client{
		BaseURL:  base,
		Username: username,
		Password: password,
		HTTP:     &http.Client{Timeout: 5 * time.Minute},
	}
}

// IsProduction reports whether the client targets the production API.
func (c *Client) IsProduction() bool { return c.BaseURL == ProductionBaseURL }

// APIError is a non-zero responseCode or an HTTP failure from NCMEC.
type APIError struct {
	HTTPStatus  int
	Code        int
	Description string
	RequestID   string // Request-ID response header; quote it to NCMEC support
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ncmec: http %d, code %d: %s (Request-ID %s)", e.HTTPStatus, e.Code, e.Description, e.RequestID)
}

// Response code 0 is success; these are the documented failures.
const (
	CodeSuccess              = 0
	CodeAuthRequired         = 2000
	CodeNotAuthorized        = 3000
	CodeValidationFailed     = 4100
	CodeMalformedXML         = 4110
	CodeReportDoesNotExist   = 5001
	CodeReportAlreadyRetract = 5101
	CodeReportAlreadyFinish  = 5102
)

func (c *Client) do(ctx context.Context, method, path, contentType string, body io.Reader) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return nil, nil, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return data, resp, err
}

// parse decodes a reportResponse and converts failures into *APIError.
func parse(data []byte, resp *http.Response) (*Response, error) {
	var r Response
	xmlErr := xml.Unmarshal(data, &r)
	if xmlErr != nil || resp.StatusCode/100 != 2 || r.ResponseCode != CodeSuccess {
		e := &APIError{HTTPStatus: resp.StatusCode, Code: r.ResponseCode, Description: r.ResponseDescription, RequestID: resp.Header.Get("Request-ID")}
		if xmlErr != nil {
			e.Code = -1
			switch {
			case resp.StatusCode == http.StatusUnauthorized:
				e.Code = CodeAuthRequired
				e.Description = "authentication failed: check username and password"
			case resp.StatusCode == http.StatusForbidden:
				e.Code = CodeNotAuthorized
				e.Description = "not authorized for this action"
			default:
				e.Description = "unparseable response: " + truncate(string(data), 300)
			}
		}
		return nil, e
	}
	return &r, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func marshal(v interface{}) ([]byte, error) {
	out, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

func (c *Client) postForm(ctx context.Context, path string, form url.Values) ([]byte, *http.Response, error) {
	return c.do(ctx, http.MethodPost, path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
}

// Status checks connectivity and credentials.
func (c *Client) Status(ctx context.Context) (*Response, error) {
	data, resp, err := c.do(ctx, http.MethodGet, "/status", "", nil)
	if err != nil {
		return nil, err
	}
	return parse(data, resp)
}

// Schema downloads the current XSD.
func (c *Client) Schema(ctx context.Context) ([]byte, error) {
	data, resp, err := c.do(ctx, http.MethodGet, "/xsd", "", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &APIError{HTTPStatus: resp.StatusCode, Code: -1, Description: truncate(string(data), 300), RequestID: resp.Header.Get("Request-ID")}
	}
	return data, nil
}

// Submit opens a report and returns its report ID. The report must then be
// finished with Finish, or it is deleted by NCMEC after 24 hours.
func (c *Client) Submit(ctx context.Context, r *Report) (string, error) {
	if r.Reporter.ReportingPerson.Email == "" {
		return "", errors.New("ncmec: reporter email is required")
	}
	body, err := marshal(r)
	if err != nil {
		return "", err
	}
	data, resp, err := c.do(ctx, http.MethodPost, "/submit", "text/xml; charset=utf-8", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	out, err := parse(data, resp)
	if err != nil {
		return "", err
	}
	if out.ReportID == "" {
		return "", errors.New("ncmec: submit succeeded but returned no reportId")
	}
	return out.ReportID, nil
}

// Upload attaches a file to an open report. It verifies that the MD5 NCMEC
// computed matches the bytes sent, and returns NCMEC's file ID.
func (c *Client) Upload(ctx context.Context, reportID, filename string, content []byte) (fileID string, err error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("id", reportID); err != nil {
		return "", err
	}
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(content); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	data, resp, err := c.do(ctx, http.MethodPost, "/upload", mw.FormDataContentType(), &body)
	if err != nil {
		return "", err
	}
	out, err := parse(data, resp)
	if err != nil {
		return "", err
	}
	sum := md5.Sum(content)
	if want := hex.EncodeToString(sum[:]); out.Hash != "" && !strings.EqualFold(out.Hash, want) {
		return "", fmt.Errorf("ncmec: upload hash mismatch: sent md5 %s, NCMEC reports %s", want, out.Hash)
	}
	if out.FileID == "" {
		return "", errors.New("ncmec: upload succeeded but returned no fileId")
	}
	return out.FileID, nil
}

// FileInfo submits details for an uploaded file.
func (c *Client) FileInfo(ctx context.Context, d *FileDetails) error {
	body, err := marshal(d)
	if err != nil {
		return err
	}
	data, resp, err := c.do(ctx, http.MethodPost, "/fileinfo", "text/xml; charset=utf-8", bytes.NewReader(body))
	if err != nil {
		return err
	}
	_, err = parse(data, resp)
	return err
}

// Finish completes the report. After this, nothing can be added or retracted.
func (c *Client) Finish(ctx context.Context, reportID string) (*DoneResponse, error) {
	data, resp, err := c.postForm(ctx, "/finish", url.Values{"id": {reportID}})
	if err != nil {
		return nil, err
	}
	var done DoneResponse
	if xerr := xml.Unmarshal(data, &done); xerr != nil || resp.StatusCode/100 != 2 || done.ResponseCode != CodeSuccess {
		// Failures come back as a reportResponse with a description.
		if _, perr := parse(data, resp); perr != nil {
			return nil, perr
		}
		return nil, &APIError{HTTPStatus: resp.StatusCode, Code: done.ResponseCode, Description: "finish failed", RequestID: resp.Header.Get("Request-ID")}
	}
	return &done, nil
}

// Retract cancels an unfinished report.
func (c *Client) Retract(ctx context.Context, reportID string) error {
	data, resp, err := c.postForm(ctx, "/retract", url.Values{"id": {reportID}})
	if err != nil {
		return err
	}
	_, err = parse(data, resp)
	return err
}

// FileToReport is one file to attach to a report.
type FileToReport struct {
	Filename string
	Content  []byte
	Details  FileDetails // ReportID and FileID are filled in automatically
}

// SubmitResult describes a completed report.
type SubmitResult struct {
	ReportID string
	FileIDs  []string
}

// SubmitComplete runs the whole workflow: submit, upload each file, send its
// details, and finish. If any step fails after the report is opened, the
// report is retracted so no half-built report is left behind, and the error
// is returned. Report IDs are only meaningful once Finish succeeds.
func (c *Client) SubmitComplete(ctx context.Context, r *Report, files []FileToReport) (*SubmitResult, error) {
	reportID, err := c.Submit(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("submit: %w", err)
	}
	fail := func(step string, err error) (*SubmitResult, error) {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if rerr := c.Retract(rctx, reportID); rerr != nil {
			return nil, fmt.Errorf("%s: %w (and retract of report %s failed: %v)", step, err, reportID, rerr)
		}
		return nil, fmt.Errorf("%s: %w (report %s retracted)", step, err, reportID)
	}

	for i, f := range files {
		fileID, err := c.Upload(ctx, reportID, f.Filename, f.Content)
		if err != nil {
			return fail(fmt.Sprintf("upload file %d", i), err)
		}
		d := f.Details
		d.ReportID, d.FileID = reportID, fileID
		if err := c.FileInfo(ctx, &d); err != nil {
			return fail(fmt.Sprintf("fileinfo file %d", i), err)
		}
	}

	done, err := c.Finish(ctx, reportID)
	if err != nil {
		return fail("finish", err)
	}
	return &SubmitResult{ReportID: done.ReportID, FileIDs: done.FileIDs}, nil
}
