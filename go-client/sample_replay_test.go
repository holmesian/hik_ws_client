package hikws

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// samples lists the archived real-device captures. They are the whole reason
// they were collected: synthetic tests only prove the parser is
// self-consistent, while these replay bytes real cameras actually sent.
var samples = []struct {
	dir           string
	codec         string
	frames, keys  int
	width, height int
	spsNAL        int // NAL type of the SPS recoverResolution must return
}{
	{dir: "../samples/ps_h265_720p", codec: "H265", frames: 611, keys: 25, width: 1280, height: 720, spsNAL: 33},
	{dir: "../samples/ps_h265_1080p", codec: "H265", frames: 614, keys: 13, width: 1920, height: 1080, spsNAL: 33},
	{dir: "../samples/ps_h264_720p", codec: "H264", frames: 655, keys: 26, width: 1280, height: 720, spsNAL: 7},
}

// TestReplaySamples replays each archived MPEG-PS capture through the demuxer
// and asserts the properties measured on the live link.
//
// Every parser bug this repo has hit — a misread PES header length, an
// unstripped SPS emulation-prevention byte, RTP headers left inside the
// payload — left frame counts and keyframe counts looking perfectly normal
// while corrupting the bitstream. So this checks the payload structure, not
// just the tallies.
func TestReplaySamples(t *testing.T) {
	for _, s := range samples {
		t.Run(filepath.Base(s.dir), func(t *testing.T) {
			path := filepath.Join(s.dir, "stream.ps")
			raw, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					t.Skipf("sample %s not present", path)
				}
				t.Fatal(err)
			}

			// Feed in 16KiB chunks so access units are split across calls the
			// way the WebSocket layer splits them.
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

			if len(frames) != s.frames {
				t.Fatalf("frames = %d, want %d", len(frames), s.frames)
			}

			keys, withPTS := 0, 0
			var prevPTS int64
			for i, f := range frames {
				if AnalyzeFrame(f.Data, s.codec) {
					keys++
				}
				if f.HasPTS {
					withPTS++
					if withPTS > 1 && f.PTS < prevPTS {
						t.Fatalf("frame %d: PTS went backwards (%d < %d)", i, f.PTS, prevPTS)
					}
					prevPTS = f.PTS
				}
				// Every access unit must start on an annex-b start code. A
				// misread PES header length shows up here first: the payload
				// gets a garbage prefix or loses its leading bytes.
				if !bytes.HasPrefix(f.Data, []byte{0, 0, 0, 1}) && !bytes.HasPrefix(f.Data, []byte{0, 0, 1}) {
					t.Fatalf("frame %d does not start with a start code: % x", i, f.Data[:min(8, len(f.Data))])
				}
			}
			if keys != s.keys {
				t.Errorf("keyframes = %d, want %d", keys, s.keys)
			}
			if withPTS != s.frames {
				t.Errorf("frames carrying PTS = %d, want %d", withPTS, s.frames)
			}

			// Resolution must come out of the in-stream SPS. Before the
			// emulation prevention fix the 720p stream parsed as 2x1.
			var gotW, gotH int
			var sps []byte
			for _, f := range frames {
				if w, h, sp, ok := recoverResolution(f.Data, s.codec); ok {
					gotW, gotH, sps = w, h, sp
					break
				}
			}
			if gotW != s.width || gotH != s.height {
				t.Fatalf("recovered resolution = %dx%d, want %dx%d", gotW, gotH, s.width, s.height)
			}
			// The recovered SPS must be one NAL, not the rest of the key frame.
			if len(sps) == 0 || len(sps) > 128 {
				t.Errorf("recovered SPS is %d bytes; expected a single SPS NAL", len(sps))
			}
			// sps starts at the 3-byte start code recoverResolution matched, so
			// the NAL header byte is at index 3 regardless of start code length.
			got := int(sps[3]) & 0x1F
			if s.codec == "H265" {
				got = int(sps[3]>>1) & 0x3F
			}
			if got != s.spsNAL {
				t.Errorf("recovered NAL type = %d, want %d (SPS)", got, s.spsNAL)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
