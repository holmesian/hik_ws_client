package hikws

import (
	"bytes"
	"testing"
)

// The RTP headers here are written out byte by byte rather than built by a
// helper: a helper that shares the implementation's idea of the header layout
// would agree with a wrong implementation and pass while the real stream is
// corrupt, which is exactly how the PES header bug survived its first tests.
func TestRTPStrip(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{
			// V=2 P=0 X=0 CC=0, M=1 PT=96, seq, timestamp, SSRC.
			name: "fixed header",
			in: []byte{
				0x80, 0xe0, 0x18, 0x5c, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
				0x00, 0x00, 0x01, 0xba, 0x44,
			},
			want: []byte{0x00, 0x00, 0x01, 0xba, 0x44},
		},
		{
			// P=1: the last byte counts the padding and counts itself.
			name: "padding",
			in: []byte{
				0xa0, 0xe0, 0x18, 0x5d, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
				0x00, 0x00, 0x01, 0xe0, 0xff, 0xff, 0x03,
			},
			want: []byte{0x00, 0x00, 0x01, 0xe0},
		},
		{
			// CC=2: two 4-byte CSRC entries follow the fixed header.
			name: "csrc list",
			in: []byte{
				0x82, 0x60, 0x18, 0x5e, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
				0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
				0x00, 0x00, 0x01, 0xba,
			},
			want: []byte{0x00, 0x00, 0x01, 0xba},
		},
		{
			// X=1: 2 bytes profile + 2 bytes length in 32-bit words, then 1 word.
			name: "extension header",
			in: []byte{
				0x90, 0x60, 0x18, 0x5f, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
				0xbe, 0xde, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44,
				0x00, 0x00, 0x01, 0xba,
			},
			want: []byte{0x00, 0x00, 0x01, 0xba},
		},
		{
			name: "bare mpeg-ps is not rtp",
			in:   []byte{0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00, 0x03},
			want: []byte{0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00, 0x03},
		},
		{
			name: "bare annex-b is not rtp",
			in:   []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x29, 0x8d, 0x8d, 0x40, 0x28, 0x02},
			want: []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x29, 0x8d, 0x8d, 0x40, 0x28, 0x02},
		},
		{
			// A padding count larger than the payload cannot be honoured;
			// returning the message untouched beats returning nothing.
			name: "impossible padding count",
			in: []byte{
				0xa0, 0xe0, 0x18, 0x60, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
				0x00, 0x00, 0xff,
			},
			want: []byte{
				0xa0, 0xe0, 0x18, 0x60, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
				0x00, 0x00, 0xff,
			},
		},
		{
			name: "short message",
			in:   []byte{0x80, 0xe0, 0x18},
			want: []byte{0x80, 0xe0, 0x18},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rtpStrip(tc.in); !bytes.Equal(got, tc.want) {
				t.Errorf("rtpStrip = % x, want % x", got, tc.want)
			}
		})
	}
}

// TestRTPDetector covers the decision itself, which is where the damage is
// done: strip a bare stream and the container quietly loses bytes, skip a
// stripped one and the headers end up inside the bitstream.
func TestRTPDetector(t *testing.T) {
	// Two consecutive RTP packets: same SSRC 72 58 3c c8, seq 0x185c/0x185d.
	rtp1 := []byte{
		0x80, 0xe0, 0x18, 0x5c, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
		0x00, 0x00, 0x01, 0xba, 0x11,
	}
	rtp2 := []byte{
		0x80, 0xe0, 0x18, 0x5d, 0x00, 0x00, 0x2a, 0x64, 0x72, 0x58, 0x3c, 0xc8,
		0x22, 0x33, 0x44, 0x55, 0x66,
	}
	// A mid-stream MPEG-PS continuation that happens to open on 0b10xxxxxx.
	// One arbitrary byte in four does; this is the case that corrupted 39
	// live cameras when the check was made per message.
	cont1 := []byte{
		0x8c, 0x80, 0x08, 0x23, 0xc7, 0xdd, 0xc4, 0x69, 0xff, 0xff, 0xfc, 0x00,
		0x00, 0x00, 0x01, 0x40, 0x01,
	}
	cont2 := []byte{
		0xa5, 0x1f, 0x36, 0x26, 0xb1, 0x73, 0xbf, 0x6d, 0xc3, 0x46, 0x6f, 0x85,
		0xb3, 0x36, 0x4b, 0x56, 0x26,
	}

	tests := []struct {
		name  string
		feed  [][]byte
		want  [][]byte // payloads released, in order
		isRTP bool
	}{
		{
			name:  "rtp session strips every packet",
			feed:  [][]byte{rtp1, rtp2},
			want:  [][]byte{{0x00, 0x00, 0x01, 0xba, 0x11}, {0x22, 0x33, 0x44, 0x55, 0x66}},
			isRTP: true,
		},
		{
			// The first message settles it without holding anything back.
			name: "bare ps decides on the first message",
			feed: [][]byte{{0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00}, cont1},
			want: [][]byte{{0x00, 0x00, 0x01, 0xba, 0x44, 0x88, 0x2d, 0x42, 0x54, 0x01, 0x00, 0x00}, cont1},
		},
		{
			// Both messages have a plausible version field, but the SSRC
			// differs, so nothing may be stripped.
			name: "continuations that look like rtp are passed through",
			feed: [][]byte{cont1, cont2},
			want: [][]byte{cont1, cont2},
		},
		{
			// Same idea with matching SSRC but a sequence that does not
			// advance by one.
			name: "matching ssrc but wrong sequence is not rtp",
			feed: [][]byte{rtp1, append(append([]byte{}, rtp1[:2]...), append([]byte{0x99, 0x99}, rtp1[4:]...)...)},
			want: [][]byte{rtp1, append(append([]byte{}, rtp1[:2]...), append([]byte{0x99, 0x99}, rtp1[4:]...)...)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var d rtpDetector
			var got [][]byte
			for _, m := range tc.feed {
				got = append(got, d.feed(m)...)
			}
			got = append(got, d.flush()...)
			if len(got) != len(tc.want) {
				t.Fatalf("released %d payloads, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.want[i]) {
					t.Errorf("payload %d = % x, want % x", i, got[i], tc.want[i])
				}
			}
			if d.isRTP != tc.isRTP {
				t.Errorf("isRTP = %v, want %v", d.isRTP, tc.isRTP)
			}
		})
	}
}

// A WebSocket message boundary is not an RTP packet boundary. The HVAG camera
// family splits its first 8204-byte packet into 8192 bytes plus a 12-byte
// tail, so the second message is the middle of a packet, not a header. When
// the detector demanded two *adjacent* RTP messages this classified a live RTP
// session as bare and left every header inside the bitstream.
func TestRTPDetectorSurvivesFragmentedFirstPacket(t *testing.T) {
	head := []byte{
		0x80, 0x60, 0x2c, 0x25, 0x00, 0x00, 0x00, 0x00, 0x69, 0x54, 0xd8, 0x56,
		0x00, 0x00, 0x01, 0xba, 0x11,
	}
	// The remainder of that same packet, delivered as its own message. It is
	// payload, so it must reach the demuxer byte for byte.
	tail := []byte{0x4d, 0x2a, 0xf7, 0x5b, 0x5d, 0xf9, 0xcd, 0x32, 0x70, 0x85, 0x02, 0x6b}
	next := []byte{
		0x80, 0x60, 0x2c, 0x26, 0x00, 0x00, 0x00, 0x00, 0x69, 0x54, 0xd8, 0x56,
		0x22, 0x33, 0x44,
	}

	var d rtpDetector
	var got [][]byte
	for _, m := range [][]byte{head, tail, next} {
		got = append(got, d.feed(m)...)
	}
	got = append(got, d.flush()...)

	if !d.isRTP {
		t.Fatal("session with a fragmented first packet was not recognised as RTP")
	}
	want := [][]byte{{0x00, 0x00, 0x01, 0xba, 0x11}, tail, {0x22, 0x33, 0x44}}
	if len(got) != len(want) {
		t.Fatalf("released %d payloads, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("payload %d = % x, want % x", i, got[i], want[i])
		}
	}
}

// A session that ends after a single RTP-looking message must still deliver
// it: there is no second packet to confirm the sequence, and dropping the only
// payload is worse than passing it through.
func TestRTPDetectorFlushesHeldMessage(t *testing.T) {
	only := []byte{
		0x80, 0xe0, 0x18, 0x5c, 0x00, 0x00, 0x2a, 0x30, 0x72, 0x58, 0x3c, 0xc8,
		0x00, 0x00, 0x01, 0xba,
	}
	var d rtpDetector
	if got := d.feed(only); got != nil {
		t.Fatalf("first message released early: % x", got)
	}
	got := d.flush()
	if len(got) != 1 || !bytes.Equal(got[0], only) {
		t.Fatalf("flush = %v, want the held message verbatim", got)
	}
	if d.flush() != nil {
		t.Error("second flush released a payload again")
	}
}
