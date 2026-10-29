package phash

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand"
	"testing"

	"github.com/disintegration/imaging"
)

// synthetic builds a deterministic image of random coloured rectangles on a
// gradient. Different seeds give structurally different pictures.
func synthetic(w, h, seed int) *image.NRGBA {
	rng := rand.New(rand.NewSource(int64(seed)))
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := uint8((x + y) * 255 / (w + h))
			img.SetNRGBA(x, y, color.NRGBA{v, v, v, 255})
		}
	}
	for i := 0; i < 12; i++ {
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

func encodeJPEG(t *testing.T, img image.Image, q int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: q}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func mustHash(t *testing.T, data []byte) Hash {
	t.Helper()
	h, err := FromBytes(data)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	return h
}

func TestSurvivesTransformations(t *testing.T) {
	orig := synthetic(800, 600, 1)
	base := mustHash(t, encodePNG(t, orig))

	cases := map[string][]byte{
		"jpeg q90":        encodeJPEG(t, orig, 90),
		"jpeg q30":        encodeJPEG(t, orig, 30),
		"resize 50%":      encodePNG(t, imaging.Resize(orig, 400, 300, imaging.Lanczos)),
		"resize 25% jpeg": encodeJPEG(t, imaging.Resize(orig, 200, 150, imaging.Box), 60),
		"slight brighten": encodePNG(t, imaging.AdjustBrightness(orig, 8)),
		"small crop":      encodePNG(t, imaging.Crop(orig, image.Rect(8, 6, 792, 594))),
	}
	for name, data := range cases {
		d := Distance(base, mustHash(t, data))
		t.Logf("%-16s distance %2d", name, d)
		if d > DefaultThreshold {
			t.Errorf("%s: distance %d exceeds threshold %d (should match)", name, d, DefaultThreshold)
		}
	}
}

func TestDifferentImagesDoNotMatch(t *testing.T) {
	a := mustHash(t, encodePNG(t, synthetic(640, 480, 1)))
	for seed := 2; seed <= 40; seed++ {
		b, err := FromBytes(encodePNG(t, synthetic(640, 480, seed)))
		if err == ErrLowInformation {
			continue // too flat to hash; such images are never stored or matched
		}
		if err != nil {
			t.Fatal(err)
		}
		d := Distance(a, b)
		t.Logf("seed 1 vs %d: distance %d", seed, d)
		if d <= DefaultThreshold {
			t.Errorf("unrelated images matched: distance %d", d)
		}
	}
}

func TestFlatImageRejected(t *testing.T) {
	flat := image.NewNRGBA(image.Rect(0, 0, 300, 300))
	for i := range flat.Pix {
		flat.Pix[i] = 200
	}
	if _, err := FromBytes(encodePNG(t, flat)); err != ErrLowInformation {
		t.Fatalf("flat image: got %v, want ErrLowInformation", err)
	}
}

func TestNotImage(t *testing.T) {
	if _, err := FromBytes([]byte("definitely not an image")); err != ErrNotImage {
		t.Fatalf("got %v, want ErrNotImage", err)
	}
}

func TestStringParseRoundTrip(t *testing.T) {
	h := Hash(0x0123456789abcdef)
	got, err := Parse(h.String())
	if err != nil || got != h {
		t.Fatalf("round trip: got %v %v", got, err)
	}
	if _, err := Parse("xyz"); err == nil {
		t.Fatal("expected error for bad input")
	}
}
