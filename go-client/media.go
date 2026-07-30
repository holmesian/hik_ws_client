package hikws

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MediaInfo is the SDP-like description of the stream, recovered from the
// SDP the server returns in the realplay success message. The h5player
// receives the same SDP and uses it to configure its decoder; callers of
// this library get the equivalent structured metadata here so they don't
// have to parse the raw SDP themselves.
type MediaInfo struct {
	// SDP is the original SDP string returned by the server.
	SDP string
	// Codec is the media codec, e.g. "H264" or "H265".
	Codec string
	// ClockRate is the RTP clock rate (typically 90000 for H.26x).
	ClockRate int
	// Width/Height are recovered from the SPS carried in
	// sprop-parameter-sets (H.264). They are 0 when not available
	// (e.g. H.265 SPS parsing is out of scope for this pass, or the
	// SDP omits sprop-parameter-sets).
	Width  int
	Height int
	// ParameterSets holds the base64 SPS/PPS from sprop-parameter-sets.
	ParameterSets []string
}

// ParseSDP extracts a MediaInfo from a realplay SDP string. It returns a
// non-nil MediaInfo even when fields cannot be determined, so callers can
// always read what is available.
func ParseSDP(sdp string) *MediaInfo {
	info := &MediaInfo{SDP: sdp}
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "a=rtpmap:"):
			// a=rtpmap:96 H264/90000
			fields := strings.SplitN(line, " ", 2)
			if len(fields) != 2 {
				continue
			}
			spec := fields[1]
			parts := strings.SplitN(spec, "/", 2)
			info.Codec = strings.ToUpper(parts[0])
			if len(parts) == 2 {
				if r, err := strconv.Atoi(parts[1]); err == nil {
					info.ClockRate = r
				}
			}
		case strings.HasPrefix(line, "a=fmtp:"):
			// a=fmtp:96 packetization-mode=1;profile-level-id=...;sprop-parameter-sets=Z0...,aM...
			idx := strings.Index(line, "sprop-parameter-sets=")
			if idx < 0 {
				continue
			}
			rest := line[idx+len("sprop-parameter-sets="):]
			if semi := strings.IndexByte(rest, ';'); semi >= 0 {
				rest = rest[:semi]
			}
			for _, ps := range strings.Split(rest, ",") {
				if ps = strings.TrimSpace(ps); ps != "" {
					info.ParameterSets = append(info.ParameterSets, ps)
				}
			}
			if info.Codec == "H264" && len(info.ParameterSets) > 0 {
				if w, h, err := parseH264SPS(info.ParameterSets[0]); err == nil {
					info.Width, info.Height = w, h
				}
			}
		}
	}
	return info
}

// bitReader is a minimal big-endian bit reader for SPS parsing.
type bitReader struct {
	data []byte
	pos  int // bit offset
}

func (b *bitReader) readBit() (int, error) {
	byteIdx := b.pos / 8
	if byteIdx >= len(b.data) {
		return 0, io.EOF
	}
	bit := int((b.data[byteIdx] >> (7 - (b.pos % 8))) & 1)
	b.pos++
	return bit, nil
}

func (b *bitReader) readBits(n int) (uint64, error) {
	var v uint64
	for i := 0; i < n; i++ {
		bit, err := b.readBit()
		if err != nil {
			return 0, err
		}
		v = (v << 1) | uint64(bit)
	}
	return v, nil
}

func (b *bitReader) readUE() (int, error) {
	leadingZeros := 0
	for {
		bit, err := b.readBit()
		if err != nil {
			return 0, err
		}
		if bit == 1 {
			break
		}
		leadingZeros++
		if leadingZeros > 31 {
			return 0, fmt.Errorf("ue(v) too long")
		}
	}
	if leadingZeros == 0 {
		return 0, nil
	}
	val, err := b.readBits(leadingZeros)
	if err != nil {
		return 0, err
	}
	return (1 << leadingZeros) - 1 + int(val), nil
}

func (b *bitReader) readSE() (int, error) {
	ue, err := b.readUE()
	if err != nil {
		return 0, err
	}
	if ue%2 == 0 {
		return -((ue + 1) / 2), nil
	}
	return (ue + 1) / 2, nil
}

// parseH264SPS decodes the width/height from a base64 SPS NAL unit
// (including its 1-byte NAL header), following the H.264 SPS syntax.
func parseH264SPS(b64 string) (int, int, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, 0, err
	}
	if len(raw) < 2 {
		return 0, 0, fmt.Errorf("sps too short")
	}
	// Skip the 1-byte NAL header (forbidden_zero | nal_ref_idc | nal_unit_type).
	br := &bitReader{data: raw[1:]}

	profileIdc, err := br.readBits(8)
	if err != nil {
		return 0, 0, err
	}
	if _, err = br.readBits(8); err != nil { // constraint flags + reserved
		return 0, 0, err
	}
	if _, err = br.readBits(8); err != nil { // level_idc
		return 0, 0, err
	}
	if _, err = br.readUE(); err != nil { // seq_parameter_set_id
		return 0, 0, err
	}

	chromaFormatIdc := 1
	switch profileIdc {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		cf, err := br.readUE()
		if err != nil {
			return 0, 0, err
		}
		chromaFormatIdc = cf
		if chromaFormatIdc == 3 {
			if _, err = br.readBit(); err != nil { // separate_colour_plane_flag
				return 0, 0, err
			}
		}
		if _, err = br.readUE(); err != nil { // bit_depth_luma_minus8
			return 0, 0, err
		}
		if _, err = br.readUE(); err != nil { // bit_depth_chroma_minus8
			return 0, 0, err
		}
		if _, err = br.readBit(); err != nil { // qpprime_y_zero_transform_bypass_flag
			return 0, 0, err
		}
		if smp, err := br.readBit(); err != nil {
			return 0, 0, err
		} else if smp == 1 {
			count := 8
			if chromaFormatIdc == 3 {
				count = 12
			}
			for i := 0; i < count; i++ {
				flag, err := br.readBit()
				if err != nil {
					return 0, 0, err
				}
				if flag == 1 {
					size := 16
					if i >= 6 {
						size = 64
					}
					for j := 0; j < size; j++ {
						if _, err = br.readSE(); err != nil {
							return 0, 0, err
						}
					}
				}
			}
		}
	}

	if _, err = br.readUE(); err != nil { // log2_max_frame_num_minus4
		return 0, 0, err
	}
	pocType, err := br.readUE()
	if err != nil {
		return 0, 0, err
	}
	switch pocType {
	case 0:
		if _, err = br.readUE(); err != nil { // log2_max_pic_order_cnt_lsb_minus4
			return 0, 0, err
		}
	case 1:
		if _, err = br.readBit(); err != nil { // delta_pic_order_always_zero_flag
			return 0, 0, err
		}
		if _, err = br.readSE(); err != nil { // offset_for_non_ref_pic
			return 0, 0, err
		}
		if _, err = br.readSE(); err != nil { // offset_for_top_to_bottom_field
			return 0, 0, err
		}
		num, err := br.readUE()
		if err != nil {
			return 0, 0, err
		}
		for i := 0; i < num; i++ {
			if _, err = br.readSE(); err != nil {
				return 0, 0, err
			}
		}
	}

	if _, err = br.readUE(); err != nil { // max_num_ref_frames
		return 0, 0, err
	}
	if _, err = br.readBit(); err != nil { // gaps_in_frame_num_value_allowed_flag
		return 0, 0, err
	}
	picWidthMbsMinus1, err := br.readUE()
	if err != nil {
		return 0, 0, err
	}
	picHeightMapUnitsMinus1, err := br.readUE()
	if err != nil {
		return 0, 0, err
	}
	frameMbsOnlyFlag, err := br.readBit()
	if err != nil {
		return 0, 0, err
	}
	if frameMbsOnlyFlag == 0 {
		if _, err = br.readBit(); err != nil { // mb_adaptive_frame_field_flag
			return 0, 0, err
		}
	}
	if _, err = br.readBit(); err != nil { // direct_8x8_inference_flag
		return 0, 0, err
	}
	cropFlag, err := br.readBit()
	if err != nil {
		return 0, 0, err
	}
	cropLeft, cropRight, cropTop, cropBottom := 0, 0, 0, 0
	if cropFlag == 1 {
		if cropLeft, err = br.readUE(); err != nil {
			return 0, 0, err
		}
		if cropRight, err = br.readUE(); err != nil {
			return 0, 0, err
		}
		if cropTop, err = br.readUE(); err != nil {
			return 0, 0, err
		}
		if cropBottom, err = br.readUE(); err != nil {
			return 0, 0, err
		}
	}

	width := (picWidthMbsMinus1 + 1) * 16
	height := (2 - frameMbsOnlyFlag) * (picHeightMapUnitsMinus1 + 1) * 16

	var subWC, subHC int
	switch chromaFormatIdc {
	case 1:
		subWC, subHC = 2, 2
	case 2:
		subWC, subHC = 2, 1
	default:
		subWC, subHC = 1, 1
	}
	width -= (cropLeft + cropRight) * subWC
	height -= (cropTop + cropBottom) * subHC

	if width <= 0 || height <= 0 || width > 8192 || height > 8192 {
		return 0, 0, fmt.Errorf("implausible dimensions %dx%d", width, height)
	}
	return width, height, nil
}

// FrameMeta describes a single recovered video frame. The elementary
// stream carries no DTS/PTS, so PTS/TimestampMs are synthesized from the
// arrival time and the SDP clock rate; they give callers a monotonic,
// order-preserving timestamp rather than the device capture timestamp.
type FrameMeta struct {
	FrameIndex  int
	IsKeyFrame  bool
	Codec       string
	Width       int
	Height      int
	PTS         int64 // clock-rate units, synthetic (arrival-based)
	TimestampMs int64 // wall-clock ms since stream start
}

// AnalyzeFrame scans an H.264/H.265 annex-b frame for NAL units and reports
// whether it contains an IDR/key NAL. The codec is required because H.264 and
// H.265 NAL type fields overlap (e.g. a H.264 SPS byte also decodes as a H.265
// VPS type), so the SDP-recovered codec is used to disambiguate: when codec is
// "H265" the H.265 IDR types (19/20) are checked, otherwise the H.264 IDR
// type (5) is used. It assumes the data begins with a NAL (optionally preceded
// by a 00 00 00 01 or 00 00 01 start code), which is the case for the raw
// elementary stream this client delivers.
func AnalyzeFrame(data []byte, codec string) bool {
	isH265 := codec == "H265"
	i := 0
	for i < len(data) {
		idx := bytes.Index(data[i:], []byte{0, 0, 1})
		if idx < 0 {
			break
		}
		pos := i + idx
		// The 01 of the start code is at pos+2, so the NAL header follows it.
		nalPos := pos + 3
		if nalPos >= len(data) {
			break
		}
		b := data[nalPos]
		if isH265 {
			t := int(b>>1) & 0x3F
			if t == 19 || t == 20 { // IDR_W_DLP / IDR_N_LP
				return true
			}
		} else {
			if int(b&0x1F) == 5 { // H.264 IDR
				return true
			}
		}
		i = nalPos + 1
	}
	return false
}
