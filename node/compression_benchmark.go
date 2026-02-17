package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"strings"
)

const compressMinBytes = 64

var sampleLines = []string{
	"Hey, did you catch the second half of the match? I couldn't believe the comeback!",
	"Lunch at the cafe tomorrow? They just got new pastries and I'm craving something sweet.",
	"I pushed the latest update to the repo and squashed the merged config conflict.",
	"The power went out in my building for twenty minutes, now everything is back online.",
	"Remember to RSVP for the monthly meetup so we can give the venue an accurate headcount.",
	"Our group has been talking about running a collaborative art project again this spring.",
	"I started reading the book you recommended; the first chapter already got me hooked.",
	"Let's prep for the presentation by reviewing the slides and practicing transitions.",
	"I grabbed the meeting notes from the shared doc and highlighted the action items.",
	"We should probably sync up about the deployment plan before the weekend.",
	"When you have a sec can you review the schema changes? There's a new index that might help.",
	"I love how the new interface handles dark mode; the contrast feels way better.",
}

func main() {
	samples := append([]string{}, sampleLines...)
	longer := strings.Repeat("This is a long chat message to test zlib compression. ", 4)
	samples = append(samples, longer)

	var totalOriginal, totalSent, compressibleCount int
	fmt.Println("Compression benchmark for simulated chat sentences (min length=64).")
	fmt.Println("----------------------------------------------------------------")
	for idx, sample := range samples {
		compressed, err := compressZlib([]byte(sample))
		if err != nil {
			panic(err)
		}
		encoded := base64.StdEncoding.EncodeToString(compressed)
		useCompressed := len(sample) >= compressMinBytes && len(encoded) < len(sample)
		sentLen := len(sample)
		method := "raw"
		if useCompressed {
			sentLen = len(encoded)
			method = "zlib+base64"
			compressibleCount++
		}
		totalOriginal += len(sample)
		totalSent += sentLen

		display := sample
		if len(display) > 60 {
			display = display[:60] + "..."
		}
		fmt.Printf("%2d: %s (orig %3d) -> %3d bytes sent via %s\n", idx+1, display, len(sample), sentLen, method)
	}
	fmt.Println("----------------------------------------------------------------")
	saved := totalOriginal - totalSent
	percent := 0.0
	if totalOriginal > 0 {
		percent = float64(saved) / float64(totalOriginal) * 100
	}
	fmt.Printf("Total (orig %d -> sent %d) saved %d bytes (%.1f%%) with %d/%d samples compressible\n", totalOriginal, totalSent, saved, percent, compressibleCount, len(samples))
}

func compressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
