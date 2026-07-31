package hikws

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// samplePath points at the archived real-device capture. The sample is the
// whole reason it was collected: synthetic tests only prove the parser is
// self-consistent, while this replays bytes a real camera actually sent.
const samplePath = "../samples/ps_h265/stream.ps"

// TestReplaySample_PS_H265 replays the archived MPEG-PS/H.265 capture through
// the demuxer and asserts the properties measured on the live link.
//
// The two bugs this repo has hit — a misread PES header length and an
// unstripped SPS emulation-prevention byte — both left frame counts and
// keyframe counts looking perfectly normal while corrupting the payload. So
// this checks the payload structure, not just the tallies.
func TestReplaySample_PS_H265(t *testing.T) {
	raw, err := os.ReadFile(samplePath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("sample %s not present", filepath.Clean(samplePath))
		}
		t.Fatal(err)
	}

	// Feed in 16KiB chunks so access units are split across calls the way the
	// WebSocket layer splits them.
	d := &psDemuxer{}
	var frames []psFrame
	for off := 0; off < len(raw); off += 16 << 10 {
		end := off + 16<<10
		if end > len(raw) {
			end = len(raw)
		}
		frames = append(frames, d.Feed(raw[off:end])...)
	}
	frames = append(frames, d.Flush()...)

	const (
		wantFrames = 611
		wantKey    = 25
		wantW      = 1280
		wantH      = 720
	)
	if len(frames) != wantFrames {
		t.Fatalf("frames = %d, want %d", len(frames), wantFrames)
	}

	keys, withPTS := 0, 0
	var prevPTS int64
	for i, f := range frames {
		if AnalyzeFrame(f.Data, "H265") {
			keys++
		}
		if f.HasPTS {
			withPTS++
			if withPTS > 1 && f.PTS < prevPTS {
				t.Fatalf("frame %d: PTS went backwards (%d < %d)", i, f.PTS, prevPTS)
			}
			prevPTS = f.PTS
		}
		// Every access unit must start on an annex-b start code. A misread
		// PES header length shows up here first: the payload gets a garbage
		// prefix or loses its leading bytes.
		if !bytes.HasPrefix(f.Data, []byte{0, 0, 0, 1}) && !bytes.HasPrefix(f.Data, []byte{0, 0, 1}) {
			t.Fatalf("frame %d does not start with a start code: % x", i, f.Data[:min(8, len(f.Data))])
		}
	}
	if keys != wantKey {
		t.Errorf("keyframes = %d, want %d", keys, wantKey)
	}
	if withPTS != wantFrames {
		t.Errorf("frames carrying PTS = %d, want %d", withPTS, wantFrames)
	}

	// Resolution must come out of the in-stream SPS. Before the emulation
	// prevention fix this same stream parsed as 2x1.
	var gotW, gotH int
	var sps []byte
	for _, f := range frames {
		if w, h, s, ok := recoverResolution(f.Data, "H265"); ok {
			gotW, gotH, sps = w, h, s
			break
		}
	}
	if gotW != wantW || gotH != wantH {
		t.Fatalf("recovered resolution = %dx%d, want %dx%d", gotW, gotH, wantW, wantH)
	}
	// The recovered SPS must be one NAL, not the rest of the key frame.
	if len(sps) == 0 || len(sps) > 128 {
		t.Errorf("recovered SPS is %d bytes; expected a single SPS NAL", len(sps))
	}
	// sps starts at the 3-byte start code recoverResolution matched, so the
	// NAL header byte is at index 3 regardless of 3- or 4-byte start codes.
	if got := int(sps[3]>>1) & 0x3F; got != 33 {
		t.Errorf("recovered NAL type = %d, want 33 (SPS_NUT)", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
