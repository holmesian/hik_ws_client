package hikws

import "testing"

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
