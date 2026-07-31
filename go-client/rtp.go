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
// So the decision comes from a pair of messages instead. RTP carries a
// constant SSRC and a sequence number that advances by one; container bytes
// agree on all 48 of those bits only by an accident no real stream reaches.
//
// The pair must not be required to be adjacent. A WebSocket message boundary
// is not an RTP packet boundary: on the HVAG camera family the proxy delivers
// the first 8204-byte packet as 8192 bytes plus a 12-byte tail, so message two
// is the middle of a packet and fails the header check. Requiring adjacency
// therefore locked a genuinely RTP session onto the bare path for its whole
// lifetime, splicing every 12-byte header into the bitstream. The first few
// messages are held instead, and the pair is looked for among them.
type rtpDetector struct {
	decided bool
	isRTP   bool
	held    [][]byte
}

// rtpProbeMessages bounds the hold: after this many messages with no matching
// pair the session is bare, and the held bytes are released untouched.
const rtpProbeMessages = 4

// feed returns the payloads ready for processing: none while messages are
// held, then all of them at once when the session is classified.
func (d *rtpDetector) feed(b []byte) [][]byte {
	if d.decided {
		return [][]byte{d.apply(b)}
	}
	if len(d.held) == 0 && !rtpHeaderPlausible(b) {
		// A first message that cannot be RTP settles it immediately, which is
		// the common case: bare PS opens on 0x00.
		d.decided = true
		return [][]byte{b}
	}
	d.held = append(d.held, append([]byte(nil), b...))
	d.isRTP = rtpPairFound(d.held)
	if !d.isRTP && len(d.held) < rtpProbeMessages {
		return nil
	}
	d.decided = true
	return d.release()
}

// flush releases the held messages when the session ends before the detector
// reached a verdict. Without a confirming pair there is no sequence to check,
// so they are treated as not RTP: passing the bytes through leaves a
// recoverable stream, while stripping a header that was never there does not.
func (d *rtpDetector) flush() [][]byte {
	if len(d.held) == 0 {
		return nil
	}
	d.decided = true
	return d.release()
}

func (d *rtpDetector) release() [][]byte {
	out := make([][]byte, 0, len(d.held))
	for _, h := range d.held {
		out = append(out, d.apply(h))
	}
	d.held = nil
	return out
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

// rtpPairFound reports whether the held messages contain two RTP packets of
// one stream. Messages that are mid-packet fragments simply fail the header
// check and are skipped, so only the earlier of the two must be a packet
// start — the pair does not have to be adjacent in the message list.
func rtpPairFound(msgs [][]byte) bool {
	for i := range msgs {
		if !rtpHeaderPlausible(msgs[i]) {
			continue
		}
		for j := i + 1; j < len(msgs); j++ {
			if rtpHeaderPlausible(msgs[j]) && rtpConsecutive(msgs[i], msgs[j]) {
				return true
			}
		}
	}
	return false
}

// rtpConsecutive reports whether b is a later packet of the same RTP stream as
// a: same SSRC, and a sequence number ahead of it by at most the probe window.
// The gap allows for the packets that message fragmentation hid in between;
// bounding it keeps the 48-bit coincidence a container would need out of reach.
func rtpConsecutive(a, b []byte) bool {
	if !bytes.Equal(a[8:12], b[8:12]) {
		return false
	}
	seqA := binary.BigEndian.Uint16(a[2:4])
	seqB := binary.BigEndian.Uint16(b[2:4])
	gap := seqB - seqA // wraps at 16 bits, as the sequence number does
	return gap >= 1 && int(gap) <= rtpProbeMessages
}
