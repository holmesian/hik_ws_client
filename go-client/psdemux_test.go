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
