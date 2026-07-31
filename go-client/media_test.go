package hikws

import (
	"encoding/hex"
	"testing"
)

func TestParseSDP_H264(t *testing.T) {
	sdp := "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=Session streamed by Hikvision\n" +
		"m=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n" +
		"a=fmtp:96 packetization-mode=1;profile-level-id=42001f;sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPI8YMZYA==,aM7A8g==\n"
	info := ParseSDP(sdp)
	if info.Codec != "H264" {
		t.Fatalf("codec = %q, want H264", info.Codec)
	}
	if info.ClockRate != 90000 {
		t.Fatalf("clock = %d, want 90000", info.ClockRate)
	}
	if len(info.ParameterSets) != 2 {
		t.Fatalf("paramsets = %d, want 2", len(info.ParameterSets))
	}
	if info.Width != 1280 {
		t.Fatalf("width = %d, want 1280", info.Width)
	}
	if info.Width != 1280 {
		t.Fatalf("width = %d, want 1280", info.Width)
	}
	if info.Height < 720 || info.Height > 736 {
		t.Fatalf("height = %d, want ~720", info.Height)
	}
}

func TestParseSDP_NoSprop(t *testing.T) {
	sdp := "m=video 0 RTP/AVP 96\na=rtpmap:96 H265/90000\n"
	info := ParseSDP(sdp)
	if info.Codec != "H265" {
		t.Fatalf("codec = %q, want H265", info.Codec)
	}
	if info.Width != 0 || info.Height != 0 {
		t.Fatalf("dims = %dx%d, want 0x0 (no sprop)", info.Width, info.Height)
	}
}

func TestAnalyzeFrame_H264IDR(t *testing.T) {
	// 00 00 00 01 start code + NAL header 0x65 (IDR slice)
	data := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x01, 0x02, 0x03}
	if !AnalyzeFrame(data, "H264") {
		t.Fatal("expected key frame")
	}
}

func TestAnalyzeFrame_H264PFrame(t *testing.T) {
	// SPS (0x67) then P slice (0x41)
	data := []byte{0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1f, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x00}
	if AnalyzeFrame(data, "H264") {
		t.Fatal("expected non-key frame")
	}
}

func TestAnalyzeFrame_H265IDR(t *testing.T) {
	// 4-byte start code + H.265 IDR_W_DLP (type 19): byte0 = (19<<1)|1 = 0x27
	data := []byte{0x00, 0x00, 0x00, 0x01, 0x27, 0x01, 0x02}
	if !AnalyzeFrame(data, "H265") {
		t.Fatal("expected H265 key frame")
	}
}

func TestUnpack(t *testing.T) {
	// type 0xC0 (0x40 | EncryptFlag) + length 2 + payload "AB"
	raw := []byte{0xC0, 0x00, 0x00, 0x00, 0x02, 'A', 'B', 0xFF}
	msg, err := Unpack(raw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MsgTypeVideoData {
		t.Fatalf("type = 0x%02x", msg.Type)
	}
	if !msg.Encrypted {
		t.Fatal("expected Encrypted true")
	}
	if string(msg.Payload) != "AB" {
		t.Fatalf("payload = %q", msg.Payload)
	}
	if len(msg.Remaining) != 1 || msg.Remaining[0] != 0xFF {
		t.Fatalf("remaining = %v", msg.Remaining)
	}
}

// TestParseSDP_MediaInfoHeader verifies the Hikvision MEDIAINFO header (carried
// in a=Media_header:MEDIAINFO=<hex>) overrides rtpmap and sets the container
// and codec. The cameras send this instead of sprop-parameter-sets, so the
// resolution stays 0 until an in-stream SPS is seen.
func TestParseSDP_MediaInfoHeader(t *testing.T) {
	hdr := make([]byte, 40)
	copy(hdr[:4], "IMKH")
	hdr[8] = 2  // container = PS
	hdr[9] = 0
	hdr[10] = 5 // codec = H265
	hdr[11] = 0
	hexHdr := hex.EncodeToString(hdr)

	sdp := "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=Session streamed by Hikvision\n" +
		"m=video 0 RTP/AVP 0\na=rtpmap:0 /0\n" +
		"a=Media_header:MEDIAINFO=" + hexHdr + ";\n"

	info := ParseSDP(sdp)
	if info.Container != "PS" {
		t.Fatalf("container = %q, want PS", info.Container)
	}
	if info.Codec != "H265" {
		t.Fatalf("codec = %q, want H265", info.Codec)
	}
	if info.ClockRate != 90000 {
		t.Fatalf("clock = %d, want 90000 (PS default)", info.ClockRate)
	}
	if info.Width != 0 || info.Height != 0 {
		t.Fatalf("dims = %dx%d, want 0x0 (MEDIAINFO has no resolution)", info.Width, info.Height)
	}
}

// TestParseH265SPS decodes a hand-built HEVC SPS and checks the recovered
// resolution. Resolution is what the MEDIAINFO header lacks, so this is the
// path that fills Width/Height for a PS/H265 stream.
func TestParseH265SPS(t *testing.T) {
	// Build an SPS NAL (2-byte NAL header + RBSP) with 1920x1080, chroma 1,
	// no conformance cropping.
	w := &testBitWriter{}
	w.putBits(0x42, 8) // NAL header byte 0
	w.putBits(0x01, 8) // NAL header byte 1 (type 33 = SPS_NUT)
	w.putBits(0, 4)    // sps_video_parameter_set_id
	w.putBits(0, 3)    // sps_max_sub_layers_minus1
	w.putBits(1, 1)    // sps_temporal_id_nesting_flag
	w.putBits(0, 2)    // general_profile_space
	w.putBits(0, 1)    // general_tier_flag
	w.putBits(1, 5)    // general_profile_idc
	w.putBits(0, 32)   // general_profile_compatibility_flag
	w.putBits(0, 48)   // general_constraint_indicator_flag
	w.putBits(93, 8)   // general_level_idc
	w.putUE(0)         // sps_seq_parameter_set_id
	w.putUE(1)         // chroma_format_idc
	w.putUE(1920)      // pic_width_in_luma_samples
	w.putUE(1080)      // pic_height_in_luma_samples
	w.putBits(1, 1)    // conformance_window_flag
	w.putUE(0)         // conf_win_left_offset
	w.putUE(0)         // conf_win_right_offset
	w.putUE(0)         // conf_win_top_offset
	w.putUE(0)         // conf_win_bottom_offset

	gotW, gotH, err := parseH265SPS(w.bytes())
	if err != nil {
		t.Fatalf("parseH265SPS: %v", err)
	}
	if gotW != 1920 || gotH != 1080 {
		t.Fatalf("dims = %dx%d, want 1920x1080", gotW, gotH)
	}
}

// TestRecoverResolutionInStream verifies an SPS NAL inside an access unit fills
// the resolution, which is how a PS/H265 stream (no sprop in SDP) gets sized.
func TestRecoverResolutionInStream(t *testing.T) {
	w := &testBitWriter{}
	w.putBits(0x42, 8)
	w.putBits(0x01, 8)
	w.putBits(0, 4)
	w.putBits(0, 3)
	w.putBits(1, 1)
	w.putBits(0, 2)
	w.putBits(0, 1)
	w.putBits(1, 5)
	w.putBits(0, 32)
	w.putBits(0, 48)
	w.putBits(93, 8)
	w.putUE(0)
	w.putUE(1)
	w.putUE(1280)
	w.putUE(720)
	w.putBits(1, 1)
	w.putUE(0)
	w.putUE(0)
	w.putUE(0)
	w.putUE(0)
	sps := w.bytes()

	// AU = SPS NAL (start code + NAL) then a slice NAL.
	au := append([]byte{0, 0, 0, 1}, sps...)
	au = append(au, 0, 0, 1, 0x26 /* H265 TRAIL_R */, 0x01)

	w2, h2, ok := recoverResolution(au, "H265")
	if !ok {
		t.Fatal("recoverResolution returned ok=false")
	}
	if w2 != 1280 || h2 != 720 {
		t.Fatalf("dims = %dx%d, want 1280x720", w2, h2)
	}
}

// testBitWriter is a helper for the SPS encoding tests above.
type testBitWriter struct {
	buf   []byte
	nbits int
}

func (w *testBitWriter) putBit(b int) {
	idx := w.nbits / 8
	if idx >= len(w.buf) {
		w.buf = append(w.buf, 0)
	}
	if b == 1 {
		w.buf[idx] |= byte(1) << (7 - (w.nbits % 8))
	}
	w.nbits++
}

func (w *testBitWriter) putBits(v uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		w.putBit(int((v >> uint(i)) & 1))
	}
}

func (w *testBitWriter) putUE(v int) {
	val := uint64(v + 1)
	bits := 0
	for tmp := val; tmp > 0; tmp >>= 1 {
		bits++
	}
	for i := 0; i < bits-1; i++ {
		w.putBit(0)
	}
	for i := bits - 1; i >= 0; i-- {
		w.putBit(int((val >> uint(i)) & 1))
	}
}

func (w *testBitWriter) bytes() []byte { return w.buf }
