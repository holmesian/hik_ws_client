package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Wire-format bytes in this file are written by hand, never built with the
// helpers under test: a constructor shared with the implementation makes a
// test agree with whatever layout the implementation happens to use
// (.codebuddy/rules/testing.md, second rule).

// packHeader is 00 00 01 BA + 10 bytes, the last of which carries
// pack_stuffing_length in its low 3 bits.
func packHeader(stuffing int) []byte {
	b := []byte{
		0x00, 0x00, 0x01, 0xBA,
		0x44, 0x00, 0x04, 0x00, 0x04, 0x01, 0x00, 0x03, 0xF8,
		byte(0xF8 | stuffing),
	}
	return append(b, bytes.Repeat([]byte{0xFF}, stuffing)...)
}

// pesPacket is 00 00 01 <sid> <len16> <body>.
func pesPacket(sid byte, body []byte) []byte {
	out := []byte{0x00, 0x00, 0x01, sid, byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func TestPSScanner_ExtractsPrivateStreamOnly(t *testing.T) {
	private := bytes.Repeat([]byte{0xA5}, 24)
	// private_stream_1 body: 3-byte optional header (no PTS) + payload.
	privBody := append([]byte{0x80, 0x00, 0x00}, private...)
	// A video PES that happens to contain the private-stream start code in
	// its picture data. A byte search for 00 00 01 BD would report it as a
	// record; stepping the container will not.
	videoBody := append([]byte{0x80, 0x80, 0x05, 0x21, 0x00, 0x01, 0x00, 0x01},
		[]byte{0x00, 0x00, 0x01, 0xBD, 0xDE, 0xAD}...)

	stream := packHeader(0)
	stream = append(stream, pesPacket(0xBD, privBody)...)
	stream = append(stream, pesPacket(0xE0, videoBody)...)

	var got [][]byte
	s := psScanner{onPrivate: func(b []byte) { got = append(got, append([]byte(nil), b...)) }}
	s.Feed(stream)
	// A container element is only complete when the next start code proves
	// it ended; feed a trailing pack so the last PES is consumed.
	s.Feed(packHeader(0))

	if len(got) != 1 {
		t.Fatalf("got %d private records, want 1: %x", len(got), got)
	}
	if !bytes.Equal(got[0], privBody) {
		t.Errorf("record = %x, want %x", got[0], privBody)
	}
	hdr, payload := splitPES(got[0])
	if hdr != 3 || !bytes.Equal(payload, private) {
		t.Errorf("splitPES = (%d, %x), want (3, %x)", hdr, payload, private)
	}
}

func TestPSScanner_RecordSplitAcrossChunks(t *testing.T) {
	private := bytes.Repeat([]byte{0x5A}, 96)
	privBody := append([]byte{0x80, 0x00, 0x00}, private...)
	stream := append(packHeader(2), pesPacket(0xBD, privBody)...)
	stream = append(stream, packHeader(0)...)

	// One byte at a time is the worst case the proxy can produce: it already
	// splits a single RTP packet across two WebSocket messages.
	var got [][]byte
	s := psScanner{onPrivate: func(b []byte) { got = append(got, append([]byte(nil), b...)) }}
	for i := range stream {
		s.Feed(stream[i : i+1])
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if _, payload := splitPES(got[0]); !bytes.Equal(payload, private) {
		t.Errorf("payload = %x", payload)
	}
}

func TestScanSEI_H264UserDataUnregistered(t *testing.T) {
	// 20 payload bytes whose first three are 00 00 00, which the encoder
	// escapes to 00 00 03 00. Left unescaped, every payloadSize after it
	// shifts by one and the parse falls apart.
	payload := append([]byte{0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x11}, 17)...)
	escaped := append([]byte{0x00, 0x00, 0x03, 0x00}, bytes.Repeat([]byte{0x11}, 17)...)

	nal := []byte{0x06, 0x05, 0x14} // SEI NAL header, payloadType 5, size 20
	nal = append(nal, escaped...)
	nal = append(nal, 0x80) // rbsp_trailing_bits
	au := append([]byte{0x00, 0x00, 0x00, 0x01}, nal...)

	got := scanSEI(au, "H264")
	if len(got) != 1 {
		t.Fatalf("got %d SEI, want 1: %+v", len(got), got)
	}
	if got[0].NalType != 6 || got[0].PayloadType != 5 || got[0].PayloadSize != 20 {
		t.Errorf("sei = %+v, want nal 6 type 5 size 20", got[0])
	}
	if want := digest8(payload); got[0].Digest != want {
		t.Errorf("digest = %s, want %s (unescaped payload)", got[0].Digest, want)
	}
	// The recorded hex must be the de-escaped payload too, otherwise the
	// bytes quoted in the report are not the bytes the encoder wrote.
	if want := "000000" + strings.Repeat("11", 17); got[0].Hex != want {
		t.Errorf("hex = %s, want %s", got[0].Hex, want)
	}
}

func TestScanSEI_H265ExtendedTypeAndSize(t *testing.T) {
	// payloadType 256 and payloadSize 255 both need the 0xFF continuation
	// form: 0xFF 0x01 is 256, 0xFF 0x00 is 255.
	payload := bytes.Repeat([]byte{0x42}, 255)
	nal := []byte{0x4E, 0x01, 0xFF, 0x01, 0xFF, 0x00} // nal_type 39 (prefix SEI), tid 1
	nal = append(nal, payload...)
	nal = append(nal, 0x80)
	au := append([]byte{0x00, 0x00, 0x01}, nal...) // 3-byte start code

	got := scanSEI(au, "H265")
	if len(got) != 1 {
		t.Fatalf("got %d SEI, want 1: %+v", len(got), got)
	}
	if got[0].NalType != 39 || got[0].PayloadType != 256 || got[0].PayloadSize != 255 {
		t.Errorf("sei = %+v, want nal 39 type 256 size 255", got[0])
	}
	// 255 bytes is past the point where quoting the payload helps, so the
	// hex is dropped rather than flooding the report.
	if got[0].Hex != "" {
		t.Errorf("hex = %q, want empty for a 255-byte payload", got[0].Hex)
	}
	if want := digest8(payload); got[0].Digest != want {
		t.Errorf("digest = %s, want %s", got[0].Digest, want)
	}
}

func TestScanSEI_IgnoresNonSEINALs(t *testing.T) {
	// An H.265 IDR whose slice data contains a byte that reads as an H.264
	// SEI header. Reading it with the wrong codec's header layout is how a
	// scan invents SEI that is not there.
	au := []byte{0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0x06, 0x05, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}
	if got := scanSEI(au, "H265"); len(got) != 0 {
		t.Errorf("scanSEI found %d SEI in an IDR: %+v", len(got), got)
	}
}

// TestSamples_PrivateStreamCensus runs the layer-3 scanner over the archived
// real-device captures. Those were recorded with nothing moving, so they are
// this experiment's baseline: whatever shape the records have here is what a
// live capture has to be compared against.
func TestSamples_PrivateStreamCensus(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("..", "..", "..", "samples", "ps_*"))
	if len(dirs) == 0 {
		t.Skip("no samples checked out (git lfs pull)")
	}
	for _, dir := range dirs {
		raw, err := os.ReadFile(filepath.Join(dir, "stream.ps"))
		if err != nil || len(raw) < 1024 {
			t.Skipf("%s: sample not materialised (git lfs pull)", dir)
		}
		lens := map[int]int{}
		digests := map[string]int{}
		s := psScanner{onPrivate: func(b []byte) {
			_, payload := splitPES(b)
			lens[len(payload)]++
			digests[digest8(payload)]++
		}}
		s.Feed(raw)
		t.Logf("%-24s records=%d payloadLens=%v distinctPayloads=%d",
			filepath.Base(dir), sum(lens), lens, len(digests))
	}
}

func sum(m map[int]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func TestWindowClassification(t *testing.T) {
	s := &session{guardMs: 1000, Windows: []ptzWindow{
		{SendT: 10000, ReturnT: 11000, StartLatencyMs: 500},
	}}
	cases := []struct {
		t    float64
		want string
	}{
		{5000, "quiet"},
		{8900, "quiet"},
		{9500, "guard"},   // asked, not moving yet
		{10600, "motion"}, // after the platform's start latency
		{11000, "motion"},
		{11500, "guard"},
		{12500, "quiet"},
	}
	for _, c := range cases {
		if got := s.classify(c.t); got != c.want {
			t.Errorf("classify(%.0f) = %s, want %s", c.t, got, c.want)
		}
	}
}

func TestDetectScoresABurstAgainstItsOwnPast(t *testing.T) {
	// 25fps of flat 1000-byte inter frames, with one 1.5s stretch of 6000-byte
	// frames starting at t=20s. The statistic has to report ~6x there and ~1x
	// everywhere the stream is flat; anything else means the baseline is
	// leaking the burst into its own reference.
	var frames []frameSample
	for i := 0; i < 25*40; i++ {
		tms := float64(i) * 40
		size := 1000
		if tms >= 20000 && tms < 21500 {
			size = 6000
		}
		frames = append(frames, frameSample{T: tms, Size: size})
	}

	cands := detect(frames)
	if len(cands) == 0 {
		t.Fatal("no candidates produced")
	}
	var inBurst, outside []float64
	for _, c := range cands {
		if c.T >= 20000 && c.T <= 21500 {
			inBurst = append(inBurst, c.Ratio)
		} else if c.T < 18000 || c.T > 30000 {
			outside = append(outside, c.Ratio)
		}
	}
	if len(inBurst) == 0 || len(outside) == 0 {
		t.Fatalf("split failed: %d in burst, %d outside", len(inBurst), len(outside))
	}
	if got := pct(inBurst, 1); got < 5.9 || got > 6.1 {
		t.Errorf("peak ratio in burst = %.2f, want ~6", got)
	}
	if got := pct(outside, 1); got > 1.01 {
		t.Errorf("peak ratio on flat stream = %.2f, want ~1", got)
	}

	// Overlapping windows mean one burst lights up several candidates; the
	// alarm count has to collapse them or every false-alarm rate is inflated.
	if got := alarms(cands, 3); got != 1 {
		t.Errorf("alarms = %d, want 1 for a single burst", got)
	}
}

func TestReportDoesNotLeakCredentials(t *testing.T) {
	// The report and the JSON both get shared; neither may carry anything
	// that identifies the deployment (.codebuddy/rules/project.md).
	s := &session{ipc: 42, Codec: "H265", Container: "PS", guardMs: 1000}
	out := s.report()
	for _, bad := range []string{"http", "wss", "openUrl", "Bearer", "api.php"} {
		if bytes.Contains([]byte(out), []byte(bad)) {
			t.Errorf("report contains %q:\n%s", bad, out)
		}
	}
	if !bytes.Contains([]byte(out), []byte(fmt.Sprintf("ipc=%d", 42))) {
		t.Errorf("report lost the device id:\n%s", out)
	}
}
