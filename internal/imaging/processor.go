package imaging

import (
	"bytes"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"strings"

	"github.com/disintegration/imaging"
)

// Config holds image processing settings
type Config struct {
	// MaxWidth is the maximum width for resizing (0 = no limit)
	MaxWidth int
	// MaxHeight is the maximum height for resizing (0 = no limit)
	MaxHeight int
	// Quality is the JPEG quality (1-100, lower = smaller file)
	Quality int
	// Enabled controls whether image processing is active
	Enabled bool
}

// DefaultConfig returns sensible defaults for I2P
func DefaultConfig() *Config {
	return &Config{
		MaxWidth:  1920,
		MaxHeight: 1080,
		Quality:   70, // Good compression for I2P while maintaining quality
		Enabled:   true,
	}
}

// Processor handles image conversion and compression
type Processor struct {
	cfg *Config
}

// NewProcessor creates a new image processor
func NewProcessor(cfg *Config) *Processor {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Processor{cfg: cfg}
}

// CanProcess returns true if the MIME type is a processable image
func (p *Processor) CanProcess(mimeType string) bool {
	if !p.cfg.Enabled {
		return false
	}
	mt := strings.ToLower(mimeType)
	// Process common image formats (not GIFs to preserve animation)
	return mt == "image/jpeg" ||
		mt == "image/png" ||
		mt == "image/bmp" ||
		mt == "image/tiff"
}

// Process compresses an image
// Returns the processed image data, new filename, new mime type, and any error
func (p *Processor) Process(data []byte, filename, mimeType string) ([]byte, string, string, error) {
	if !p.CanProcess(mimeType) {
		return data, filename, mimeType, nil
	}

	// Decode the image
	img, err := p.decode(bytes.NewReader(data), mimeType)
	if err != nil {
		// If decoding fails, return original
		return data, filename, mimeType, nil
	}

	// Resize if needed
	img = p.resize(img)

	// Encode to JPEG with compression
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: p.cfg.Quality}); err != nil {
		// If encoding fails, return original
		return data, filename, mimeType, nil
	}

	// Only use converted version if it's smaller
	if buf.Len() >= len(data) {
		return data, filename, mimeType, nil
	}

	// Update filename to .jpg if it was PNG/BMP/TIFF
	newFilename := filename
	newMimeType := mimeType
	mt := strings.ToLower(mimeType)
	if mt != "image/jpeg" {
		newFilename = changeExtension(filename, ".jpg")
		newMimeType = "image/jpeg"
	}

	return buf.Bytes(), newFilename, newMimeType, nil
}

// decode decodes an image from various formats
func (p *Processor) decode(r io.Reader, mimeType string) (image.Image, error) {
	mt := strings.ToLower(mimeType)

	switch mt {
	case "image/jpeg":
		return jpeg.Decode(r)
	case "image/png":
		return png.Decode(r)
	case "image/gif":
		return gif.Decode(r)
	default:
		// Try generic decode
		img, _, err := image.Decode(r)
		return img, err
	}
}

// resize resizes the image if it exceeds max dimensions
func (p *Processor) resize(img image.Image) image.Image {
	if p.cfg.MaxWidth <= 0 && p.cfg.MaxHeight <= 0 {
		return img
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Check if resizing is needed
	needsResize := false
	if p.cfg.MaxWidth > 0 && width > p.cfg.MaxWidth {
		needsResize = true
	}
	if p.cfg.MaxHeight > 0 && height > p.cfg.MaxHeight {
		needsResize = true
	}

	if !needsResize {
		return img
	}

	// Use imaging library to resize with good quality
	return imaging.Fit(img, p.cfg.MaxWidth, p.cfg.MaxHeight, imaging.Lanczos)
}

// changeExtension changes the file extension
func changeExtension(filename, newExt string) string {
	// Find the last dot
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '.' {
			return filename[:i] + newExt
		}
	}
	// No extension found, append
	return filename + newExt
}
