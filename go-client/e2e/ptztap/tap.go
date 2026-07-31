package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

// The five observation layers, in the order the bytes pass through them:
//
//  1. WebSocket text messages the client does not act on
//  2. binary protocol messages of a type the client discards
//  3. 0xBD private_stream_1 records inside the MPEG-PS container
//  4. SEI NALs inside the elementary stream
//  5. access-unit sizes and key-frame spacing
//
// Layers 1-2 are read off the library's Verbose log rather than through new
// callbacks: the messages are discarded by design (ADR-0002 / ADR-0004), and
// an experiment is not a reason to grow the library's surface. Layers 3-5 use
// the diagnostic callbacks that already exist.

// collector accumulates every observation on one clock. All sample times are
// milliseconds since t0, so a stream event and a PTZ request are directly
// comparable — without that the whole experiment is unfalsifiable.
type collector struct {
	mu sync.Mutex
	t0 time.Time

	frames  []frameSample
	private []privateSample
	seis    []seiSample
	wsMsgs  []wsSample

	// blobs maps a payload digest to its hex, so repeated private-stream
	// records cost one entry instead of one copy each.
	blobs map[string]string

	videoMsgs, audioMsgs int
	scanner              psScanner
	codec                string
}

type frameSample struct {
	T          float64 `json:"t_ms"`
	Size       int     `json:"size"`
	Key        bool    `json:"key"`
	PTS        int64   `json:"pts"`
	HasPTS     bool    `json:"has_pts"`
	FrameIndex int     `json:"i"`
}

type privateSample struct {
	T       float64 `json:"t_ms"`
	PESLen  int     `json:"pes_len"`  // bytes after the 6-byte start-code/length prefix
	HdrLen  int     `json:"hdr_len"`  // PES optional header length
	DataLen int     `json:"data_len"` // private payload after the PES header
	Digest  string  `json:"digest"`   // sha256/8 of the private payload
}

type seiSample struct {
	T           float64 `json:"t_ms"`
	NalType     int     `json:"nal_type"`
	PayloadType int     `json:"payload_type"`
	PayloadSize int     `json:"payload_size"`
	Digest      string  `json:"digest"`
	// Hex carries the payload itself when it is small enough to read by eye.
	// A digest can only say "these two differ"; telling a frame counter apart
	// from a pan/tilt status word needs the bytes.
	Hex string `json:"hex,omitempty"`
}

type wsSample struct {
	T      float64 `json:"t_ms"`
	Kind   string  `json:"kind"`
	Detail string  `json:"detail"`
}

func newCollector(t0 time.Time) *collector {
	c := &collector{t0: t0, blobs: map[string]string{}}
	c.scanner.onPrivate = c.onPrivateStream
	return c
}

func (c *collector) now() float64 {
	return float64(time.Since(c.t0).Microseconds()) / 1000
}

// onFrame records layers 4 and 5 from one demuxed access unit.
func (c *collector) onFrame(meta *hikws.FrameMeta, data []byte) {
	t := c.now()
	seis := scanSEI(data, meta.Codec)
	c.mu.Lock()
	defer c.mu.Unlock()
	if meta.Codec != "" {
		c.codec = meta.Codec
	}
	c.frames = append(c.frames, frameSample{
		T: t, Size: len(data), Key: meta.IsKeyFrame,
		PTS: meta.PTS, HasPTS: meta.HasPTS, FrameIndex: meta.FrameIndex,
	})
	for _, s := range seis {
		s.T = t
		c.seis = append(c.seis, s)
	}
}

// onRawVideo feeds layer 3: the container bytes before demux, which is the
// only place the 0xBD records still exist (the demuxer skips them).
func (c *collector) onRawVideo(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.videoMsgs++
	c.scanner.Feed(b)
}

func (c *collector) onAudio([]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.audioMsgs++
}

// onPrivateStream is called by the scanner with the bytes of one 0xBD packet
// after its 6-byte prefix. Caller holds c.mu.
func (c *collector) onPrivateStream(pes []byte) {
	hdrLen, data := splitPES(pes)
	digest := digest8(data)
	if _, seen := c.blobs[digest]; !seen && len(c.blobs) < 256 {
		c.blobs[digest] = hex.EncodeToString(data)
	}
	c.private = append(c.private, privateSample{
		T: c.now(), PESLen: len(pes), HdrLen: hdrLen, DataLen: len(data), Digest: digest,
	})
}

// digest8 fingerprints a payload: long enough to tell two records apart,
// short enough to print in a table.
func digest8(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// splitPES strips the PES optional header from a private_stream_1 packet and
// returns its length plus the payload. private_stream_1 uses the same
// three-byte optional header as a video PES; a record that does not look like
// one is returned whole rather than guessed at.
func splitPES(b []byte) (int, []byte) {
	if len(b) < 3 || b[0]&0xC0 != 0x80 {
		return 0, b
	}
	hlen := int(b[2])
	if len(b) < 3+hlen {
		return 0, b
	}
	return 3 + hlen, b[3+hlen:]
}

// ---------------------------------------------------------------- layer 3

// psScanner walks the MPEG-PS container looking for private_stream_1 records.
// It steps element by element exactly like the library's demuxer — the point
// of the exercise is to see what the demuxer skips, so scanning for 0x000001BD
// with a plain byte search would be wrong: that pattern occurs inside picture
// data too.
type psScanner struct {
	buf       []byte
	onPrivate func([]byte)
}

const (
	psPackStart   = 0xBA
	psSystemStart = 0xBB
	psPrivate1    = 0xBD
)

var startCode = []byte{0x00, 0x00, 0x01}

func (s *psScanner) Feed(data []byte) {
	s.buf = append(s.buf, data...)
	off := 0
	for off < len(s.buf) {
		n, ok := s.step(s.buf[off:])
		if !ok {
			break
		}
		off += n
	}
	s.buf = append(s.buf[:0], s.buf[off:]...)
}

func (s *psScanner) step(b []byte) (int, bool) {
	if len(b) < 4 {
		return 0, false
	}
	if b[0]|b[1] != 0 || b[2] != 0x01 {
		if idx := bytes.Index(b, startCode); idx >= 0 {
			return idx, true
		}
		return len(b) - 2, true
	}
	switch sid := b[3]; {
	case sid == psPackStart:
		if len(b) < 14 {
			return 0, false
		}
		n := 14 + int(b[13]&0x07)
		if len(b) < n {
			return 0, false
		}
		return n, true
	case sid >= psSystemStart:
		if len(b) < 6 {
			return 0, false
		}
		n := 6 + int(binary.BigEndian.Uint16(b[4:6]))
		if len(b) < n {
			return 0, false
		}
		if sid == psPrivate1 && s.onPrivate != nil {
			s.onPrivate(b[6:n])
		}
		return n, true
	default:
		return 3, true
	}
}

// ---------------------------------------------------------------- layer 4

// scanSEI pulls the SEI messages out of one annex-b access unit. H.264 carries
// them in nal_unit_type 6, H.265 in 39 (prefix) and 40 (suffix).
func scanSEI(au []byte, codec string) []seiSample {
	var out []seiSample
	for _, nal := range splitNALs(au) {
		if len(nal) == 0 {
			continue
		}
		var nalType, hdr int
		if codec == "H265" {
			if len(nal) < 2 {
				continue
			}
			nalType, hdr = int(nal[0]>>1)&0x3F, 2
			if nalType != 39 && nalType != 40 {
				continue
			}
		} else {
			nalType, hdr = int(nal[0]&0x1F), 1
			if nalType != 6 {
				continue
			}
		}
		out = append(out, parseSEI(stripEPB(nal[hdr:]), nalType)...)
	}
	return out
}

// splitNALs slices an annex-b access unit at its start codes. Both the 3-byte
// and 4-byte forms occur.
func splitNALs(au []byte) [][]byte {
	var out [][]byte
	i := 0
	for {
		idx := bytes.Index(au[i:], startCode)
		if idx < 0 {
			break
		}
		begin := i + idx + 3
		next := bytes.Index(au[begin:], startCode)
		end := len(au)
		if next >= 0 {
			end = begin + next
			if end > begin && au[end-1] == 0 {
				end--
			}
		}
		if begin < end {
			out = append(out, au[begin:end])
		}
		if next < 0 {
			break
		}
		i = begin + next
	}
	return out
}

// stripEPB removes emulation prevention bytes. The SEI payload is a sequence
// of length-prefixed messages, so a 00 00 03 left in place shifts every length
// after it.
func stripEPB(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if i >= 2 && b[i] == 3 && b[i-1] == 0 && b[i-2] == 0 && i+1 < len(b) && b[i+1] <= 3 {
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// parseSEI walks the payloadType/payloadSize pairs of an SEI RBSP. Both are
// coded as a run of 0xFF bytes plus a final byte.
func parseSEI(rbsp []byte, nalType int) []seiSample {
	var out []seiSample
	i := 0
	readVal := func() (int, bool) {
		v := 0
		for {
			if i >= len(rbsp) {
				return 0, false
			}
			b := rbsp[i]
			i++
			v += int(b)
			if b != 0xFF {
				return v, true
			}
		}
	}
	for i < len(rbsp) {
		if rbsp[i] == 0x80 { // rbsp_trailing_bits
			break
		}
		ptype, ok := readVal()
		if !ok {
			break
		}
		psize, ok := readVal()
		if !ok || i+psize > len(rbsp) {
			break
		}
		s := seiSample{
			NalType: nalType, PayloadType: ptype, PayloadSize: psize,
			Digest: digest8(rbsp[i : i+psize]),
		}
		if psize <= 64 {
			s.Hex = hex.EncodeToString(rbsp[i : i+psize])
		}
		out = append(out, s)
		i += psize
	}
	return out
}

// ------------------------------------------------------------- layers 1-2

var (
	reTextOther   = regexp.MustCompile(`Text msg \(no errorCode/sdp\): (\d+) bytes keys=(\S+)`)
	reTextNonJSON = regexp.MustCompile(`Text msg \(not JSON\): (\d+) bytes`)
	reProtoUnknwn = regexp.MustCompile(`Protocol msg (0x[0-9a-f]{2}): (\d+) bytes \(discarded\) head=(\S*)`)
	reKeepalive   = regexp.MustCompile(`Protocol msg 0x06 keepalive: (\d+) bytes`)
	reRawVideo    = regexp.MustCompile(`Raw video frame: (\d+) bytes`)
)

// logTap timestamps the library's Verbose log lines as they are written and
// keeps the ones that describe a discarded message. The library writes each
// line in a single Write from the socket read loop, so the timestamp taken
// here is the arrival time on the same clock as everything else — closer than
// the log's own second-resolution prefix.
type logTap struct {
	c    *collector
	pass io.Writer
}

func (t *logTap) Write(p []byte) (int, error) {
	line := string(p)
	var kind, detail string
	switch {
	case reTextOther.MatchString(line):
		m := reTextOther.FindStringSubmatch(line)
		kind, detail = "text-other", fmt.Sprintf("%s bytes keys=%s", m[1], m[2])
	case reTextNonJSON.MatchString(line):
		kind, detail = "text-nonjson", reTextNonJSON.FindStringSubmatch(line)[1]+" bytes"
	case reProtoUnknwn.MatchString(line):
		m := reProtoUnknwn.FindStringSubmatch(line)
		kind, detail = "proto-"+m[1], fmt.Sprintf("%s bytes head=%s", m[2], m[3])
	case reKeepalive.MatchString(line):
		kind, detail = "proto-0x06", reKeepalive.FindStringSubmatch(line)[1]+" bytes"
	case reRawVideo.MatchString(line):
		kind, detail = "no-envelope", reRawVideo.FindStringSubmatch(line)[1]+" bytes"
	}
	if kind != "" {
		t.c.mu.Lock()
		t.c.wsMsgs = append(t.c.wsMsgs, wsSample{T: t.c.now(), Kind: kind, Detail: detail})
		t.c.mu.Unlock()
	}
	return t.pass.Write(p)
}
