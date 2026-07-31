package hikws

import (
	"bytes"
	"encoding/binary"
)

// MPEG-PS start code IDs (the byte after the 00 00 01 prefix).
const (
	psPackStart   = 0xBA // pack header — starts a new access unit
	psSystemStart = 0xBB // system header; PSM/PES all sort above this
	pesVideoFirst = 0xE0
	pesVideoLast  = 0xEF
)

var startCode = []byte{0x00, 0x00, 0x01}

// psFrame is one video access unit recovered from the PS container.
type psFrame struct {
	Data   []byte
	PTS    int64 // 33-bit container PTS, 90kHz; valid only when HasPTS
	HasPTS bool
}

// psDemuxer reassembles the video elementary stream from the Hikvision
// MPEG-PS container.
//
// This is required, not cosmetic: the device splits a single NAL unit across
// PES packets (a PES header can land in the middle of a VPS), so the raw
// payload cannot be scanned as annex-b — start-code scanning over undemuxed
// PS both misses real NALs and matches PES stream IDs that merely look like
// NAL headers.
//
// One PS pack carries exactly one access unit, so a pack header closes the
// previous frame. That costs one frame of latency, which is inherent to the
// container: the frame is only known to be complete when the next one starts.
type psDemuxer struct {
	buf    []byte
	au     []byte
	pts    int64
	hasPTS bool
}

// Feed consumes a chunk of PS bytes and returns the access units it
// completed. Chunks may split a pack anywhere; the remainder is buffered
// until the next call. The buffer holds at most one incomplete unit
// (PES packets are length-delimited to 64KiB), so it cannot grow unbounded.
func (d *psDemuxer) Feed(data []byte) []psFrame {
	d.buf = append(d.buf, data...)

	var out []psFrame
	off := 0
	for off < len(d.buf) {
		n, frame, ok := d.step(d.buf[off:])
		if !ok {
			break
		}
		if frame != nil {
			out = append(out, *frame)
		}
		off += n
	}
	d.buf = append(d.buf[:0], d.buf[off:]...)
	return out
}

// step parses one container unit. It reports how many bytes were consumed,
// any access unit that unit completed, and ok=false when more data is needed.
func (d *psDemuxer) step(b []byte) (int, *psFrame, bool) {
	if len(b) < 4 {
		return 0, nil, false
	}

	if b[0]|b[1] != 0 || b[2] != 0x01 {
		// Not at a start code — resync. Keep the trailing 2 bytes, which may
		// be the head of a start code split across two chunks.
		if idx := bytes.Index(b, startCode); idx >= 0 {
			return idx, nil, true
		}
		return len(b) - 2, nil, true
	}

	switch sid := b[3]; {
	case sid == psPackStart:
		// 14-byte pack header + pack_stuffing_length (low 3 bits of byte 13).
		if len(b) < 14 {
			return 0, nil, false
		}
		n := 14 + int(b[13]&0x07)
		if len(b) < n {
			return 0, nil, false
		}
		return n, d.closeAU(), true

	case sid >= psSystemStart:
		// System header, program stream map and every PES packet share the
		// 6-byte length-delimited form.
		if len(b) < 6 {
			return 0, nil, false
		}
		n := 6 + int(binary.BigEndian.Uint16(b[4:6]))
		if len(b) < n {
			return 0, nil, false
		}
		if sid >= pesVideoFirst && sid <= pesVideoLast {
			d.appendPES(b[6:n])
		}
		return n, nil, true

	default:
		// Not a container start code (a stray NAL prefix) — step past it.
		return 3, nil, true
	}
}

// Flush emits the access unit still buffered, if any. It must be called when
// the stream ends: because one PS pack closes the previous frame, the last
// frame is only completed on Flush (one frame of latency is inherent to the
// container and unavoidably recovered here).
func (d *psDemuxer) Flush() []psFrame {
	if f := d.closeAU(); f != nil {
		return []psFrame{*f}
	}
	return nil
}

// closeAU emits the access unit accumulated so far, if any.
func (d *psDemuxer) closeAU() *psFrame {
	if len(d.au) == 0 {
		return nil
	}
	f := &psFrame{Data: d.au, PTS: d.pts, HasPTS: d.hasPTS}
	d.au, d.pts, d.hasPTS = nil, 0, false
	return f
}

// appendPES strips the PES header and appends the payload to the current
// access unit, taking the frame PTS from the first PES packet that carries one.
//
// b is the bytes after the 6-byte start-code/length prefix. The MPEG-2 PES
// optional header that follows is THREE bytes, not two:
//
//	b[0] '10' marker + scrambling/priority/alignment flags (0x80 typically)
//	b[1] PTS_DTS_flags (bits 7-6) + ESCR/ES_rate/DSM/copy/CRC/ext flags
//	b[2] PES_header_data_length, covering b[3:3+hlen] (PTS, DTS, ...)
//
// Reading the length from b[1] instead treats the 0x80 PTS flag as a
// 128-byte header, which silently chopped the first 128 bytes off every PES
// payload and decoded the PTS one byte early.
func (d *psDemuxer) appendPES(b []byte) {
	if len(b) < 3 || b[0]&0xC0 != 0x80 {
		return
	}
	hlen := int(b[2])
	if len(b) < 3+hlen {
		return
	}
	// PTS_DTS_flags occupy bits 7-6 of b[1]; 0b10 = PTS only, 0b11 = PTS+DTS.
	if b[1]&0x80 != 0 && hlen >= 5 && !d.hasPTS {
		d.pts, d.hasPTS = readPTS(b[3:8]), true
	}
	d.au = append(d.au, b[3+hlen:]...)
}

// readPTS decodes the 33-bit PTS from the 5-byte PES timestamp field.
func readPTS(b []byte) int64 {
	return int64((b[0]>>1)&0x07)<<30 |
		int64(b[1])<<22 |
		int64((b[2]>>1)&0x7F)<<15 |
		int64(b[3])<<7 |
		int64(b[4]>>1)
}
