// Command ncmeccheck verifies NCMEC CyberTipline API credentials and downloads
// the current XML schema so the ncmec package tests can validate against it.
//
//	NCMEC_USERNAME=... NCMEC_PASSWORD=... go run ./tools/ncmeccheck
//
// It uses the TEST environment unless NCMEC_ENV=production is set. It never
// submits a report.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"drop-i2p/internal/ncmec"
)

func main() {
	user, pass := os.Getenv("NCMEC_USERNAME"), os.Getenv("NCMEC_PASSWORD")
	if user == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "set NCMEC_USERNAME and NCMEC_PASSWORD")
		os.Exit(2)
	}
	c := ncmec.NewClient(os.Getenv("NCMEC_ENV"), user, pass)
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
}
