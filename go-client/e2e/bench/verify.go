package main

import "encoding/binary"

// psWalker is a streaming version of the strict MPEG-PS structure walk the
// sample replay test does offline: every container element must begin exactly
// where the previous one ended, with no resyncing allowed.
//
// It exists because frame counts prove nothing. Every parser bug this library
// has hit — a misread PES header length, RTP headers left inside the payload —
// kept the frame count, the key frame count and the recovered resolution
// exactly right while corrupting the bitstream. Under concurrency the failure
// mode to rule out is bytes going missing or arriving interleaved, and only a
// non-resyncing walk can see that.
//
// It is incremental so a 64-way run does not have to hold 64 whole streams in
// memory: at most one container element (a PES packet is length-delimited to
// 64KiB) is buffered.
type psWalker struct {
	buf      []byte
	started  bool  // the first start code has been found
	Elements int   // container elements walked
	Offset   int64 // bytes consumed from the stream so far
	Derail   int64 // byte offset the walk derailed at, -1 while clean
	skipped  int64 // bytes dropped before the first start code
}

func newPSWalker() *psWalker { return &psWalker{Derail: -1} }

// Feed consumes the next chunk of raw container bytes. Once the walk has
// derailed it stops looking: the first derail is the finding, and everything
// after it is noise.
func (w *psWalker) Feed(b []byte) {
	if w.Derail >= 0 {
		return
	}
	w.buf = append(w.buf, b...)
	// A live stream is joined mid-container, so the walk starts at the first
	// start code rather than at byte 0 — the same rule the offline walk uses.
	if !w.started {
		for i := 0; i+3 < len(w.buf); i++ {
			if w.buf[i] == 0 && w.buf[i+1] == 0 && w.buf[i+2] == 1 && w.buf[i+3] >= 0xB9 {
				w.buf = w.buf[i:]
				w.skipped += int64(i)
				w.started = true
				break
			}
		}
		if !w.started {
			// Keep the last 3 bytes: a start code may straddle the chunk.
			if n := len(w.buf) - 3; n > 0 {
				w.skipped += int64(n)
				w.buf = append(w.buf[:0], w.buf[n:]...)
			}
			return
		}
	}
	off := 0
	for {
		n, ok, bad := w.step(w.buf[off:])
		if bad {
			w.Derail = w.Offset + int64(off)
			w.buf = nil
			return
		}
		if !ok {
			break
		}
		off += n
		w.Elements++
	}
	w.Offset += int64(off)
	w.buf = append(w.buf[:0], w.buf[off:]...)
}

// step sizes the element at the head of b. ok=false means more bytes are
// needed; bad=true means b does not start on a container element at all.
func (w *psWalker) step(b []byte) (n int, ok, bad bool) {
	if len(b) < 4 {
		return 0, false, false
	}
	if b[0] != 0 || b[1] != 0 || b[2] != 1 {
		return 0, false, true
	}
	switch id := b[3]; {
	case id == 0xBA: // pack header: 14 fixed bytes + stuffing
		if len(b) < 14 {
			return 0, false, false
		}
		n = 14 + int(b[13]&7)
	case id == 0xB9: // program end
		n = 4
	case id < 0xB9: // a NAL header, not a container start code
		return 0, false, true
	default: // system header, PSM and every PES packet are length-prefixed
		if len(b) < 6 {
			return 0, false, false
		}
		n = 6 + int(binary.BigEndian.Uint16(b[4:6]))
	}
	if len(b) < n {
		return 0, false, false
	}
	return n, true, false
}
