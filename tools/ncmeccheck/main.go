// Command ncmeccheck verifies NCMEC CyberTipline API credentials and downloads
// the current XML schema so the ncmec package tests can validate against it.
//
//	NCMEC_USERNAME=... NCMEC_PASSWORD=... go run ./tools/ncmeccheck
//
// It uses the TEST environment unless NCMEC_ENV=production is set.
//
// With -submit it also files one complete test report (submit, upload,
// fileinfo, finish) containing a generated abstract image. -submit only ever
// runs against the test environment; it refuses to run in production.
//
//	NCMEC_USERNAME=... NCMEC_PASSWORD=... NCMEC_REPORTER_EMAIL=you@example.org \
//	    go run ./tools/ncmeccheck -submit
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"time"

	"drop-i2p/internal/ncmec"
)

func main() {
	submit := flag.Bool("submit", false, "also file one complete TEST report with a generated image")
	flag.Parse()
	user, pass := os.Getenv("NCMEC_USERNAME"), os.Getenv("NCMEC_PASSWORD")
	if user == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "set NCMEC_USERNAME and NCMEC_PASSWORD")
		os.Exit(2)
	}
	c := ncmec.NewClient(os.Getenv("NCMEC_ENV"), user, pass)
	if *submit && c.IsProduction() {
		fmt.Fprintln(os.Stderr, "refusing: -submit is for the test environment only")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("endpoint:", c.BaseURL)
	st, err := c.Status(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "status FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("status OK:", st.ResponseDescription)

	xsd, err := c.Schema(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "schema download FAILED:", err)
		os.Exit(1)
	}
	out := filepath.Join("internal", "ncmec", "testdata", "ncmec.xsd")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, xsd, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("saved schema (%d bytes) to %s\nnow run: go test ./internal/ncmec/ -run Schema -v\n", len(xsd), out)

	if *submit {
		runTestSubmit(c)
	}
}

// runTestSubmit files one complete report to the TEST environment.
func runTestSubmit(c *ncmec.Client) {
	if c.IsProduction() {
		fmt.Fprintln(os.Stderr, "refusing: -submit is for the test environment only")
		os.Exit(2)
	}
	email := os.Getenv("NCMEC_REPORTER_EMAIL")
	if email == "" {
		fmt.Fprintln(os.Stderr, "set NCMEC_REPORTER_EMAIL for -submit")
		os.Exit(2)
	}

	// A generated abstract gradient: clearly a test artifact, nothing more.
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.SetNRGBA(x, y, color.NRGBA{uint8(x * 4), uint8(y * 4), 160, 255})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)

	rep, file := ncmec.BuildFileReport(ncmec.ReporterInfo{
		Email: email, Platform: "drop.i2p", Service: "drop.i2p file hosting",
	}, ncmec.FileIncident{
		FileID:           "integration-test",
		PublicURL:        "http://drop.i2p/f/integration-test",
		OriginalFilename: "integration-test.png",
		UploadTime:       time.Now().Add(-time.Hour),
		UploaderID:       "integrationtestdestinationxxxxxxxxxxxxxxxxxxxxxxxxxxx.b32.i2p",
		Notes:            "INTEGRATION TEST from drop.i2p. Synthetic image. Not a real incident.",
	})
	rep.AdditionalInfo = "INTEGRATION TEST from drop.i2p against the test environment. Not a real incident."
	file.Content = buf.Bytes()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := c.SubmitComplete(ctx, rep, []ncmec.FileToReport{file})
	if err != nil {
		fmt.Fprintln(os.Stderr, "test report FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("test report OK: reportId=%s fileIds=%v\n", res.ReportID, res.FileIDs)
}
