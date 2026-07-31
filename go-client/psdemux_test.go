package hikws

import (
	"bytes"
	"testing"
)

// psPack builds a minimal 14-byte MPEG-PS pack header (pack_stuffing_length=0).
func psPack() []byte {
	return []byte{0x00, 0x00, 0x01, psPackStart, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// psVideoPES builds a video PES packet (stream_id 0xE0) carrying payload,
// with the standard 3-byte MPEG-2 PES optional header. When pts>=0 a PTS is
// encoded; otherwise the optional header is empty. The returned slice is the
// whole PES packet including its start code.
func psVideoPES(payload []byte, pts int64) []byte {
	flags := byte(0x00)
	hdrLen := byte(0)
	head := []byte{}
	if pts >= 0 {
		flags = 0x80 // PTS_DTS_flags = 0b10
		hdrLen = 5
		head = encodePTS(uint64(pts))
	}
	body := append([]byte{0x80, flags, hdrLen}, head...)
	body = append(body, payload...)
	pes := []byte{0x00, 0x00, 0x01, pesVideoFirst}
	pes = append(pes, byte(len(body)>>8), byte(len(body)&0xff))
	pes = append(pes, body...)
	return pes
}

// encodePTS encodes a 33-bit PTS into the 5-byte MPEG PES timestamp field.
func encodePTS(pts uint64) []byte {
	return []byte{
		byte(0x20 | ((pts>>30)&0x07)<<1 | 0x01),
		byte((pts >> 22) & 0xFF),
		byte(((pts>>15)&0x7F)<<1 | 0x01),
		byte((pts >> 7) & 0xFF),
		byte((pts&0x7F)<<1 | 0x01),
	}
}

// TestPSDemux_SingleFrame feeds one pack + one video PES and a closing pack,
// and expects exactly one access unit with the PES payload preserved.
func TestPSDemux_SingleFrame(t *testing.T) {
	idr := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21} // H264 IDR
	d := &psDemuxer{}
	var got []psFrame
	got = append(got, d.Feed(append(psPack(), psVideoPES(idr, -1)...))...)
	got = append(got, d.Feed(psPack())...) // closing pack emits the buffered AU
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Data, idr) {
		t.Fatalf("payload = %x, want %x", got[0].Data, idr)
	}
	if got[0].HasPTS {
		t.Fatal("expected no PTS (none supplied)")
	}
}

// TestPSDemux_SplitNAL proves the demuxer is necessary: a NAL split across two
// PES packets is reassembled into a single contiguous access unit. Scanning
// the undemuxed PS bytes for start codes would instead see a bogus NAL header
// at the PES boundary.
func TestPSDemux_SplitNAL(t *testing.T) {
	nal := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21}
	d := &psDemuxer{}
	var got []psFrame
	// First PES carries the start code + first 2 bytes; second carries the rest.
	got = append(got, d.Feed(append(psPack(), psVideoPES(nal[:6], -1)...))...)
	got = append(got, d.Feed(psVideoPES(nal[6:], -1))...)
	got = append(got, d.Feed(psPack())...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1 (NAL merged across PES)", len(got))
	}
	if !bytes.Equal(got[0].Data, nal) {
		t.Fatalf("payload = %x, want %x", got[0].Data, nal)
	}
}

// TestPSDemux_PTS verifies the 33-bit PTS is recovered from the PES header and
// attached to the frame.
func TestPSDemux_PTS(t *testing.T) {
	idr := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x01}
	const want = int64(90000) // 1s @ 90kHz
	d := &psDemuxer{}
	var got []psFrame
	got = append(got, d.Feed(append(psPack(), psVideoPES(idr, want)...))...)
	got = append(got, d.Feed(psPack())...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	if !got[0].HasPTS {
		t.Fatal("expected PTS flag set")
	}
	if got[0].PTS != want {
		t.Fatalf("PTS = %d, want %d", got[0].PTS, want)
	}
}

// TestPSDemux_Resync confirms that garbage before a start code is skipped
// rather than corrupting the first access unit.
func TestPSDemux_Resync(t *testing.T) {
	idr := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x01}
	d := &psDemuxer{}
	var got []psFrame
	// Prefix with junk that is not a start code, then a valid pack.
	junk := []byte{0xAA, 0xBB, 0xCC}
	got = append(got, d.Feed(append(junk, append(psPack(), psVideoPES(idr, -1)...)...))...)
	got = append(got, d.Feed(psPack())...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Data, idr) {
		t.Fatalf("payload = %x, want %x", got[0].Data, idr)
	}
}

// TestPSDemux_StandardPESHeader pins the on-the-wire PES layout with bytes
// written out by hand, independently of psVideoPES. The MPEG-2 PES optional
// header is three bytes; reading PES_header_data_length from the second byte
// instead sees the 0x80 PTS flag as a 128-byte header, which chops the first
// 128 bytes off every payload and decodes the PTS one byte early. Both
// symptoms are invisible when the test helper shares the same mistake, so
// this test hard-codes the real layout.
func TestPSDemux_StandardPESHeader(t *testing.T) {
	// 200 bytes of payload: long enough that a 128-byte over-skip truncates
	// rather than dropping the packet outright.
	payload := make([]byte, 200)
	copy(payload, []byte{0x00, 0x00, 0x00, 0x01, 0x26, 0x01})
	for i := 6; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	const wantPTS = int64(3600)

	body := []byte{0x80, 0x80, 0x05} // marker/flags, PTS_DTS_flags=0b10, hdrLen=5
	body = append(body, encodePTS(uint64(wantPTS))...)
	body = append(body, payload...)
	pes := []byte{0x00, 0x00, 0x01, pesVideoFirst, byte(len(body) >> 8), byte(len(body))}
	pes = append(pes, body...)

	d := &psDemuxer{}
	var got []psFrame
	got = append(got, d.Feed(append(psPack(), pes...))...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Data, payload) {
		t.Fatalf("payload = %d bytes, want %d (PES header length misread)", len(got[0].Data), len(payload))
	}
	if !got[0].HasPTS || got[0].PTS != wantPTS {
		t.Fatalf("PTS = %d (has=%v), want %d", got[0].PTS, got[0].HasPTS, wantPTS)
	}
}

// TestPSDemux_PESWithDTS covers the PTS+DTS form (PTS_DTS_flags=0b11,
// hdrLen=10): the frame PTS must still be the PTS field, and the extra DTS
// bytes must not leak into the elementary stream.
func TestPSDemux_PESWithDTS(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xAB}
	const wantPTS = int64(7200)

	body := []byte{0x80, 0xC0, 0x0A}
	body = append(body, encodePTS(uint64(wantPTS))...)
	body = append(body, encodePTS(uint64(wantPTS-1800))...) // DTS
	body = append(body, payload...)
	pes := []byte{0x00, 0x00, 0x01, pesVideoFirst, byte(len(body) >> 8), byte(len(body))}
	pes = append(pes, body...)

	d := &psDemuxer{}
	var got []psFrame
	got = append(got, d.Feed(append(psPack(), pes...))...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Data, payload) {
		t.Fatalf("payload = %x, want %x (DTS leaked into the ES)", got[0].Data, payload)
	}
	if got[0].PTS != wantPTS {
		t.Fatalf("PTS = %d, want %d", got[0].PTS, wantPTS)
	}
}

// TestPSDemux_DropsPartialLeadingAU pins what happens when a live stream is
// joined mid-frame, which is the normal case: the session starts wherever the
// camera happens to be. The PES packets arriving before the first pack header
// are the tail of an access unit whose head was sent before we connected, so
// they must be dropped, not emitted as a frame. Measured on 42 cameras, 7
// begin this way — one with 151KiB of a key frame's tail.
func TestPSDemux_DropsPartialLeadingAU(t *testing.T) {
	tail := []byte{0x9A, 0x77, 0x01, 0x23} // mid-NAL bytes, no start code
	full := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x42}

	d := &psDemuxer{}
	var got []psFrame
	got = append(got, d.Feed(psVideoPES(tail, 3600))...) // joined mid-frame
	got = append(got, d.Feed(append(psPack(), psVideoPES(full, 7200)...))...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1 (the partial leading AU must be dropped)", len(got))
	}
	if !bytes.Equal(got[0].Data, full) {
		t.Fatalf("payload = %x, want %x", got[0].Data, full)
	}
	// The dropped tail carried a PTS of its own; taking it would date the
	// first real frame 40ms early.
	if got[0].PTS != 7200 {
		t.Fatalf("PTS = %d, want 7200 (PTS leaked from the dropped tail)", got[0].PTS)
	}
}

// A live stream is joined wherever the encoder happens to be, so the first
// message can open on any packet of the container, not only a pack header. One
// audio-heavy camera in the fleet opens on an audio PES: requiring 00 00 01 ba
// classified it as a non-PS stream and delivered raw transport chunks as
// frames for the whole session.
func TestIsPSData(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"pack header", []byte{0x00, 0x00, 0x01, 0xba, 0x44}, true},
		{"program end", []byte{0x00, 0x00, 0x01, 0xb9}, true},
		{"system header", []byte{0x00, 0x00, 0x01, 0xbb, 0x00, 0x06}, true},
		{"program stream map", []byte{0x00, 0x00, 0x01, 0xbc, 0x00, 0x12}, true},
		{"audio pes", []byte{0x00, 0x00, 0x01, 0xc0, 0x00, 0xad}, true},
		{"video pes", []byte{0x00, 0x00, 0x01, 0xe0, 0x00, 0x9c}, true},
		// An annex-b NAL header always has its top bit clear, so a bare
		// elementary stream can never be mistaken for the container.
		{"annex-b idr", []byte{0x00, 0x00, 0x01, 0x65, 0x88}, false},
		{"annex-b sps", []byte{0x00, 0x00, 0x01, 0x67, 0x64}, false},
		{"h265 vps", []byte{0x00, 0x00, 0x01, 0x40, 0x01}, false},
		{"not a start code", []byte{0x80, 0x60, 0x18, 0x5c}, false},
		{"too short", []byte{0x00, 0x00, 0x01}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPSData(tc.in); got != tc.want {
				t.Errorf("isPSData(% x) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// 82 of 94 cameras in the fleet interleave a private_stream_1 (0xBD) PES into
// the video program roughly once per second. Its payload is opaque (an 80-byte
// encrypted blob) and it carries a PTS of its own, so treating it as video
// both splices garbage into the bitstream and dates the frame wrong — and the
// frame/keyframe counts stay correct throughout, which is exactly the class of
// corruption that stays invisible in a summary.
//
// The packet below is a verbatim capture, not a helper-built one: a helper
// that shares the implementation's idea of a PES header cannot prove the
// implementation reads a real one correctly.
func TestPSDemux_SkipsPrivateStream(t *testing.T) {
	private := []byte{
		0x00, 0x00, 0x01, 0xbd, 0x00, 0x6a, // start code + length 106
		0x8c, 0x80, 0x07, 0x27, 0x9a, 0x07, 0xf7, 0x19, 0xff, 0xf8, // PES header, PTS present
		0x00, 0x02, 0x00, 0x17, 0x00, 0x01, 0x80, 0x00, 0x00, 0xff, 0x00, 0x00, 0xe0, 0xf1, 0xf0, 0x50,
		0x1d, 0x12, 0xf2, 0xf5, 0xee, 0xba, 0x71, 0xf3, 0xfc, 0xb6, 0x0f, 0x1b, 0x73, 0x66, 0x65, 0xd9,
		0x76, 0xb5, 0xff, 0xf7, 0x7a, 0xa5, 0xa1, 0xeb, 0xc7, 0xd4, 0x92, 0x7d, 0x14, 0x51, 0xba, 0x3b,
		0xfa, 0x5d, 0x69, 0x7f, 0xb6, 0x49, 0x3e, 0x9d, 0xae, 0x71, 0x02, 0x48, 0x5f, 0x57, 0xfb, 0x40,
		0xfa, 0x5d, 0x69, 0x7f, 0xb6, 0x49, 0x3e, 0x9d, 0xae, 0x71, 0x02, 0x48, 0x5f, 0x57, 0xfb, 0x40,
		0x79, 0x6f, 0xe1, 0xc9, 0xa9, 0x21, 0xc7, 0xfa, 0x04, 0x72, 0xf7, 0x26, 0xdc, 0x2e, 0x97, 0xcf,
	}
	idr := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21}

	d := &psDemuxer{}
	var got []psFrame
	got = append(got, d.Feed(psPack())...)
	got = append(got, d.Feed(private)...)
	got = append(got, d.Feed(psVideoPES(idr, 7200))...)
	got = append(got, d.Flush()...)

	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Data, idr) {
		t.Fatalf("payload = %x, want %x (private payload spliced into the ES)", got[0].Data, idr)
	}
	if got[0].PTS != 7200 {
		t.Fatalf("PTS = %d, want 7200 (PTS taken from the private packet)", got[0].PTS)
	}
}
