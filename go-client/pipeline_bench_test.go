package hikws

import (
	"bytes"
	"os"
	"testing"
)

// wsMessageSize is the payload size the proxy actually delivers, measured on
// the live link. Chunking the samples at this size is what makes the
// benchmark represent the real workload: allocation behaviour in this path is
// driven by how a stream is split across messages, not by its total size.
const wsMessageSize = 8192

// loadSample returns an archived capture, or skips when it is absent or is an
// unfetched Git LFS pointer.
func loadSample(tb testing.TB, dir string) []byte {
	tb.Helper()
	raw, err := os.ReadFile(dir + "/stream.ps")
	if err != nil {
		tb.Skipf("sample %s not present", dir)
	}
	if bytes.HasPrefix(raw, []byte("version https://git-lfs")) {
		tb.Skipf("sample %s is an unfetched LFS pointer; run `git lfs pull`", dir)
	}
	return raw
}

// BenchmarkStreamPipeline replays an archived capture through the same path a
// live stream takes — rtpDetector, container sniffing, PS demux, key frame
// analysis and the frame callback — one 8KiB WebSocket message at a time.
//
// This is where per-stream cost is measured rather than on the live link: the
// proxy link saturates at a few dozen streams, so live runs report the
// network's limit and cannot resolve a change in the client's own cost. Here
// the bytes are identical on every run.
func BenchmarkStreamPipeline(b *testing.B) {
	for _, s := range []struct{ name, dir string }{
		{"h264_1080p", "../samples/ps_h264_1080p"},
		{"h265_1080p", "../samples/ps_h265_1080p"},
	} {
		b.Run(s.name, func(b *testing.B) {
			raw := loadSample(b, s.dir)
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var frames, bytesOut int
				c := NewHikMediaClient(&HikConfig{})
				c.OnVideoFrame = func(m *FrameMeta, d []byte) {
					frames++
					bytesOut += len(d)
				}
				for off := 0; off < len(raw); off += wsMessageSize {
					end := off + wsMessageSize
					if end > len(raw) {
						end = len(raw)
					}
					c.feedVideo(raw[off:end])
				}
				c.flushPS()
				if frames == 0 {
					b.Fatal("no frames recovered")
				}
			}
		})
	}
}

// BenchmarkPSDemux isolates the demuxer, which the allocation profile of a
// 128-stream live run named as the second largest allocation source after the
// WebSocket read.
func BenchmarkPSDemux(b *testing.B) {
	raw := loadSample(b, "../samples/ps_h264_1080p")
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := &psDemuxer{}
		n := 0
		for off := 0; off < len(raw); off += wsMessageSize {
			end := off + wsMessageSize
			if end > len(raw) {
				end = len(raw)
			}
			n += len(d.Feed(raw[off:end]))
		}
		n += len(d.Flush())
		if n == 0 {
			b.Fatal("no frames")
		}
	}
}
