package hikws

import (
	"bytes"
	"encoding/binary"
)

// rtpFixedHeader is the size of the mandatory part of an RTP header.
const rtpFixedHeader = 12

// rtpStrip removes the RTP encapsulation from one packet and returns the media
// bytes. It assumes the caller has already established that the session is RTP
// — see rtpDetector for why that decision cannot be made packet by packet.
//
// Some proxies tunnel the container inside RTP instead of sending it bare: one
// RTP packet per WebSocket message, carrying a fragment of the MPEG-PS stream.
// Both parts of the encapsulation must be removed:
//
//   - the header, whose length is 12 bytes plus the CSRC list plus an optional
//     extension, and
//   - the trailing padding counted by the last byte when the P bit is set.
//
// Leaving either in place is silently destructive rather than obviously
// broken. A PES packet is consumed by its declared length, so injected bytes
// displace real payload instead of shifting it: the frame count, the key frame
// count, the NAL census and even the elementary stream length all stay exactly
// right while the slice data is corrupt. On the measured 1080p H.264 device
// that was 2031 headers and 1728 padding runs — 26,580 bytes of transport
// metadata spliced into the bitstream.
func rtpStrip(b []byte) []byte {
	if len(b) < rtpFixedHeader || b[0]>>6 != 2 {
		return b
	}
	n := rtpFixedHeader + 4*int(b[0]&0x0F) // CSRC list
	if b[0]&0x10 != 0 {                    // extension: 2 bytes profile, 2 bytes length in words
		if len(b) < n+4 {
			return b
		}
		n += 4 + 4*int(binary.BigEndian.Uint16(b[n+2:n+4]))
	}
	if n >= len(b) {
		return b
	}
	p := b[n:]
	if b[0]&0x20 != 0 { // padding, counted by the final byte and including it
		pad := int(p[len(p)-1])
		if pad == 0 || pad > len(p) {
			return b
		}
		p = p[:len(p)-pad]
	}
	return p
}

// rtpDetector decides once per session whether media messages are wrapped in
// RTP, and applies that one decision to every message.
//
// The check must not be made per message. Only the first payload of a bare
// MPEG-PS stream begins with a pack header; every later message is a
// mid-container continuation starting on an arbitrary byte, and one arbitrary
// byte in four has its top two bits set to 0b10 — a perfectly valid RTP
// version field. Deciding per message therefore cut 12 header bytes, plus
// whatever the last byte happened to claim as padding, out of a quarter of the
// messages on a bare-PS deployment. Measured on 39 live cameras: frame counts,
// key frame counts and recovered resolution were all still correct, and only a
// strict PS structure walk revealed the holes.
//
// So the decision comes from two consecutive messages instead. RTP carries a
// constant SSRC and a sequence number that advances by one; container bytes
// agree on all 48 of those bits only by an accident no real stream reaches.
// The first message is held until the second arrives, then both are released
// down whichever path was chosen.
type rtpDetector struct {
	decided bool
	isRTP   bool
	held    []byte
}

// feed returns the payloads ready for processing: none while the first message
// is held, then both once the session has been classified.
func (d *rtpDetector) feed(b []byte) [][]byte {
	if d.decided {
		return [][]byte{d.apply(b)}
	}
	if d.held == nil {
		// A first message that cannot be RTP settles it immediately, which is
		// the common case: bare PS opens on 0x00.
		if !rtpHeaderPlausible(b) {
			d.decided = true
			return [][]byte{b}
		}
		d.held = append([]byte(nil), b...)
		return nil
	}
	d.decided = true
	d.isRTP = rtpHeaderPlausible(b) && rtpConsecutive(d.held, b)
	first := d.held
	d.held = nil
	return [][]byte{d.apply(first), d.apply(b)}
}

// flush releases a held message when the session ends before a second one
// arrived. With only one message there is no sequence to check, so it is
// treated as not RTP: passing the bytes through leaves a recoverable stream,
// while stripping a header that was never there does not.
func (d *rtpDetector) flush() [][]byte {
	if d.held == nil {
		return nil
	}
	b := d.held
	d.held, d.decided = nil, true
	return [][]byte{b}
}

func (d *rtpDetector) apply(b []byte) []byte {
	if d.isRTP {
		return rtpStrip(b)
	}
	return b
}

// rtpHeaderPlausible reports whether b could be an RTP packet at all.
func rtpHeaderPlausible(b []byte) bool {
	return len(b) >= rtpFixedHeader && b[0]>>6 == 2
}

// rtpConsecutive reports whether b follows a as the next packet of one RTP
// stream: same SSRC, sequence number one higher (wrapping at 16 bits).
func rtpConsecutive(a, b []byte) bool {
	if !bytes.Equal(a[8:12], b[8:12]) {
		return false
	}
	seqA := binary.BigEndian.Uint16(a[2:4])
	seqB := binary.BigEndian.Uint16(b[2:4])
	return seqB == seqA+1
}
