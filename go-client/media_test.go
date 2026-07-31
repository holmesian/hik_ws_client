package hikws

import (
	"bytes"
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
	hdr[8] = 2 // container = PS
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

// TestParseSDP_UnknownMediaHeaderMagic covers the SDP a real H.264 camera
// sent: the MEDIAINFO header is 40 bytes but its magic is "HVAG", not "IMKH",
// and this client has no field layout for it. Leaving container and codec
// blank is correct — guessing at the fields would be worse — and the client
// then recovers both from the bitstream.
func TestParseSDP_UnknownMediaHeaderMagic(t *testing.T) {
	sdp := "v=0\ns=hikvision\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n" +
		"a=Media_header:MEDIAINFO=4856414701010000C400C001C0020000000000000000000064623333000000000000000000000000;\n"

	info := ParseSDP(sdp)
	if info.Container != "" || info.Codec != "" {
		t.Fatalf("container/codec = %q/%q, want both empty for an undecodable header",
			info.Container, info.Codec)
	}
}

// TestSniffCodec covers the fallback used when the MEDIAINFO header cannot be
// decoded. The NAL headers are the real ones taken from the archived captures.
func TestSniffCodec(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"h264 sps", []byte{0, 0, 0, 1, 0x67, 0x42, 0x00, 0x29, 0, 0, 0, 1, 0x68, 0xca}, "H264"},
		{"h264 sps ref_idc 1", []byte{0, 0, 1, 0x27, 0x42, 0x00, 0x29}, "H264"},
		{"h265 vps", []byte{0, 0, 0, 1, 0x40, 0x01, 0x0c, 0x01, 0, 0, 0, 1, 0x42, 0x01}, "H265"},
		{"h265 sps only", []byte{0, 0, 1, 0x42, 0x01, 0x01, 0x01, 0x60}, "H265"},
		// A slice-only access unit names neither codec; the caller retries.
		{"h264 non-idr slice", []byte{0, 0, 0, 1, 0x41, 0x9a, 0x00}, ""},
		{"no start code", []byte{0x67, 0x42, 0x00, 0x29}, ""},
		{"truncated after start code", []byte{0, 0, 1}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sniffCodec(tc.data); got != tc.want {
				t.Errorf("sniffCodec = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseSDP_PSIgnoresAudioClock uses the SDP a real 1080p camera sent: the
// video m-line advertises PCMA/8000, an audio clock. PS timestamps are 90kHz
// regardless, and taking 8000 literally reported a 25 fps stream as 2.22 fps.
func TestParseSDP_PSIgnoresAudioClock(t *testing.T) {
	sdp := "v=0\ns=hikvision\nm=video 0 RTP/AVP 8\na=rtpmap:8 PCMA/8000\n" +
		"a=Media_header:MEDIAINFO=494D4B48000000000200050011710110401F000000FA000000000000000000000000000000000000;\n"

	info := ParseSDP(sdp)
	if info.Container != "PS" || info.Codec != "H265" {
		t.Fatalf("container/codec = %q/%q, want PS/H265", info.Container, info.Codec)
	}
	if info.ClockRate != 90000 {
		t.Fatalf("clock = %d, want 90000 (PS is 90kHz, not the rtpmap audio clock)", info.ClockRate)
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

	w2, h2, _, ok := recoverResolution(au, "H265")
	if !ok {
		t.Fatal("recoverResolution returned ok=false")
	}
	if w2 != 1280 || h2 != 720 {
		t.Fatalf("dims = %dx%d, want 1280x720", w2, h2)
	}
}

// escapeNAL emulates an H.265 encoder: before writing a byte that would create
// a 00 00 0x (x<=3) sequence, insert 0x03 after the two zeros.
func escapeNAL(b []byte) []byte {
	out := make([]byte, 0, len(b)+4)
	for i := 0; i < len(b); i++ {
		if i >= 2 && out[len(out)-1] == 0 && out[len(out)-2] == 0 && b[i] <= 3 {
			out = append(out, 0x03)
		}
		out = append(out, b[i])
	}
	return out
}

// TestStripEmulationPrevention checks the byte-level EPB removal directly.
func TestStripEmulationPrevention(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{[]byte{0x00, 0x00, 0x03, 0x00}, []byte{0x00, 0x00, 0x00}},
		{[]byte{0x00, 0x00, 0x03, 0x01}, []byte{0x00, 0x00, 0x01}},
		{[]byte{0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x03, 0x03}, []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x03}},
		{[]byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}}, // no 00 00 prefix, unchanged
	}
	for _, c := range cases {
		got := stripEmulationPrevention(c.in)
		if !bytes.Equal(got, c.out) {
			t.Errorf("stripEmulationPrevention(%x) = %x, want %x", c.in, got, c.out)
		}
	}
}

// TestParseH265SPS_EPB verifies a valid SPS whose RBSP naturally contains
// 00 00 0x runs (the 32-bit profile-compatibility field is all zeros) still
// decodes to the right resolution once the on-wire emulation-prevention bytes
// are stripped. Without stripping, the 0x03 shifts every later field and the
// resolution becomes garbage (the live stream reported 2x1 instead of 1280x720).
func TestParseH265SPS_EPB(t *testing.T) {
	w := &testBitWriter{}
	w.putBits(0x42, 8)
	w.putBits(0x01, 8)
	w.putBits(0, 4)
	w.putBits(0, 3)
	w.putBits(1, 1)
	w.putBits(0, 2)
	w.putBits(0, 1)
	w.putBits(1, 5)
	w.putBits(0, 32) // general_profile_compatibility_flag: 4 zero bytes -> 00 00 00 00
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

	nal := w.bytes()          // valid 1280x720 SPS, no EPB yet
	escaped := escapeNAL(nal) // on-wire form with 0x03 escapes

	gotW, gotH, err := parseH265SPS(escaped)
	if err != nil {
		t.Fatalf("parseH265SPS with EPB: %v", err)
	}
	if gotW != 1280 || gotH != 720 {
		t.Fatalf("dims with EPB = %dx%d, want 1280x720 (EPB not stripped?)", gotW, gotH)
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
