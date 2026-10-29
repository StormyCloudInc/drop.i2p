// Package phash computes perceptual image hashes so that banned content can be
// matched even after it is re-encoded, resized, recompressed, or lightly edited.
//
// SHA-256 only matches byte-identical files. Changing a single pixel, or simply
// re-saving a JPEG, defeats it. A perceptual hash describes what the image looks
// like, so near-duplicates produce hashes that differ in only a few bits.
//
// The algorithm is dHash (difference hash): shrink to 9x8 grayscale and record,
// for each row, whether each pixel is brighter than its right-hand neighbour.
// That yields 64 bits. Two images are considered the same picture when the
// Hamming distance between their hashes is at or below a threshold.
package phash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"  // register decoder
	_ "image/jpeg" // register decoder
	_ "image/png"  // register decoder
	"math/bits"
	"strconv"
	"strings"

	"github.com/disintegration/imaging"
	_ "golang.org/x/image/bmp"  // register decoder
	_ "golang.org/x/image/tiff" // register decoder
	_ "golang.org/x/image/webp" // register decoder
)

// DefaultThreshold is the maximum Hamming distance (out of 64 bits) at which
// two dHashes are treated as the same image. 10 tolerates recompression,
// resizing and small edits while keeping false positives rare.
const DefaultThreshold = 10

// MaxDecodeBytes caps how large an input we will try to decode, to bound memory.
const MaxDecodeBytes = 64 << 20

// MaxPixels caps decoded image dimensions to defend against decompression bombs.
const MaxPixels = 80_000_000

// ErrNotImage is returned when data cannot be decoded as a supported image.
var ErrNotImage = errors.New("phash: not a decodable image")

// ErrLowInformation is returned for near-uniform images (blank, solid colour).
// Their hashes are almost all zeros or ones and would match every other blank
// image, so they must never be stored as bans or matched against.
var ErrLowInformation = errors.New("phash: image has too little detail to hash reliably")

// Hash is a 64-bit perceptual hash.
type Hash uint64

// String returns the hash as 16 lowercase hex characters.
func (h Hash) String() string {
	return fmt.Sprintf("%016x", uint64(h))
}

// Parse decodes a 16-character hex hash produced by Hash.String.
func Parse(s string) (Hash, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 16 {
		return 0, fmt.Errorf("phash: want 16 hex chars, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return 0, fmt.Errorf("phash: invalid hex: %w", err)
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, err
	}
	return Hash(v), nil
}

// Distance returns the Hamming distance between two hashes (0 = identical).
func Distance(a, b Hash) int {
	return bits.OnesCount64(uint64(a) ^ uint64(b))
}

// Reliable reports whether a hash carries enough information to be used for
// matching. Hashes with very few or very many set bits come from flat images.
func Reliable(h Hash) bool {
	n := bits.OnesCount64(uint64(h))
	return n >= 8 && n <= 56
}

// FromImage computes the dHash of a decoded image.
func FromImage(img image.Image) (Hash, error) {
	// 9 columns x 8 rows: 8 comparisons per row x 8 rows = 64 bits.
	small := imaging.Resize(imaging.Grayscale(img), 9, 8, imaging.Lanczos)

	var h uint64
	bit := 0
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			left := small.NRGBAAt(x, y).R
			right := small.NRGBAAt(x+1, y).R
			if left > right {
				h |= 1 << uint(bit)
			}
			bit++
		}
	}

	hash := Hash(h)
	if !Reliable(hash) {
		return hash, ErrLowInformation
	}
	return hash, nil
}

// FromBytes decodes image data and computes its dHash.
func FromBytes(data []byte) (Hash, error) {
	if len(data) == 0 || len(data) > MaxDecodeBytes {
		return 0, ErrNotImage
	}

	// Check dimensions before a full decode so a tiny file claiming to be a
	// 50000x50000 image cannot exhaust memory.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, ErrNotImage
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > MaxPixels {
		return 0, ErrNotImage
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return 0, ErrNotImage
	}
	return FromImage(img)
}

// IsImageMIME reports whether a MIME type is one this package can hash.
func IsImageMIME(mimeType string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.SplitN(mimeType, ";", 2)[0])) {
	case "image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/gif",
		"image/webp", "image/bmp", "image/x-ms-bmp", "image/tiff":
		return true
	}
	return false
}
