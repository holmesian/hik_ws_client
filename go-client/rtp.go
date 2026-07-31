package hikws

import "encoding/binary"

// rtpFixedHeader is the size of the mandatory part of an RTP header.
const rtpFixedHeader = 12

// rtpPayload strips the RTP encapsulation from one message and returns the
// media bytes. Messages that are not RTP are returned untouched.
//
// Some proxies tunnel the container inside RTP instead of sending it bare:
// one RTP packet per WebSocket message, carrying a fragment of the MPEG-PS
// stream. Both parts of the encapsulation must be removed:
//
//   - the header, whose length is 12 bytes plus the CSRC list plus an
//     optional extension, and
//   - the trailing padding counted by the last byte when the P bit is set.
//
// Leaving either in place is silently destructive rather than obviously
// broken. A PES packet is consumed by its declared length, so injected bytes
// displace real payload instead of shifting it: the frame count, the key
// frame count, the NAL census and even the elementary stream length all stay
// exactly right while the slice data is corrupt. On the measured 1080p H.264
// device that was 2031 headers and 1728 padding runs — 26,580 bytes of
// transport metadata spliced into the bitstream.
//
// Detecting RTP by the version field is unambiguous here: every container
// this client handles starts a message with 0x00 (an MPEG-PS pack header or
// an annex-b start code), so the two high bits can only read as version 2 on
// a real RTP packet.
func rtpPayload(b []byte) []byte {
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
