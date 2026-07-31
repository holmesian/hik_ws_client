package hikws

import (
	"bytes"
	"testing"
)

// psPack builds a minimal 14-byte MPEG-PS pack header (pack_stuffing_length=0).
func psPack() []byte {
	return []byte{0x00, 0x00, 0x01, psPackStart, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// psVideoPES builds a video PES packet (stream_id 0xE0) carrying payload.
// When pts>=0 a PTS is encoded into the PES header; otherwise the header is
// empty. The returned slice is the whole PES packet including its start code.
func psVideoPES(payload []byte, pts int64) []byte {
	flags := byte(0x00)
	hdrLen := byte(0)
	head := []byte{}
	if pts >= 0 {
		flags = 0x80 // PTS present
		hdrLen = 5
		head = encodePTS(uint64(pts))
	}
	body := append([]byte{flags, hdrLen}, head...)
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
