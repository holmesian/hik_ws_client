package hikws

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
	// Container is the payload encapsulation, taken from the Hikvision
	// MEDIAINFO header: "PS" (MPEG program stream — what the cameras
	// actually send), "RTP", "GB", "HIK" or "RAW". Empty means the SDP
	// carried no MEDIAINFO header, and the payload is treated as a bare
	// elementary stream.
	Container string
	// Codec is the media codec, "H264" or "H265".
	Codec string
	// ClockRate is the timestamp clock rate (90000 for H.26x).
	ClockRate int
	// Width/Height are recovered from the SPS. The MEDIAINFO header
	// carries no resolution, so on a PS stream they stay 0 until the
	// first SPS has been seen in the bitstream.
	Width  int
	Height int
	// ParameterSets holds the base64 SPS/PPS from sprop-parameter-sets,
	// for the standard RTP-style SDP that carries them.
	ParameterSets []string
}

// ParseSDP extracts a MediaInfo from a realplay SDP string. It returns a
// non-nil MediaInfo even when fields cannot be determined, so callers can
// always read what is available.
func ParseSDP(sdp string) *MediaInfo {
	info := &MediaInfo{SDP: sdp}
	mediaHeader := ""
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "a=Media_header:MEDIAINFO="):
			mediaHeader = strings.TrimSuffix(
				strings.TrimPrefix(line, "a=Media_header:MEDIAINFO="), ";")
		case strings.HasPrefix(line, "a=rtpmap:"):
			// a=rtpmap:96 H264/90000 — the cameras send "a=rtpmap:0 /0",
			// which names no codec; only take fields that are present.
			fields := strings.SplitN(line, " ", 2)
			if len(fields) != 2 {
				continue
			}
			spec := fields[1]
			parts := strings.SplitN(spec, "/", 2)
			if parts[0] != "" {
				info.Codec = strings.ToUpper(parts[0])
			}
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
				if raw, err := base64.StdEncoding.DecodeString(info.ParameterSets[0]); err == nil {
					if w, h, err := parseH264SPSBytes(raw); err == nil {
						info.Width, info.Height = w, h
					}
				}
			}
		}
	}

	// The MEDIAINFO header is authoritative for container and codec and
	// overrides rtpmap, which the cameras leave blank.
	applyMediaHeader(info, mediaHeader)
	if info.Container == "PS" && info.ClockRate == 0 {
		info.ClockRate = 90000 // PS timestamps are 90kHz by definition
	}
	return info
}

// applyMediaHeader decodes the 40-byte Hikvision "IMKH" header carried in
// a=Media_header:MEDIAINFO=<hex>. Only the container and codec fields are
// read; the header carries no resolution (h5player takes that from the
// decoder), and the audio fields have no consumer here.
func applyMediaHeader(info *MediaInfo, hexStr string) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil || len(raw) < 12 || string(raw[:4]) != "IMKH" {
		return
	}
	switch [2]byte{raw[8], raw[9]} {
	case [2]byte{1, 0}:
		info.Container = "HIK"
	case [2]byte{2, 0}:
		info.Container = "PS"
	case [2]byte{4, 0}:
		info.Container = "RTP"
	case [2]byte{8, 0}:
		info.Container = "GB"
	case [2]byte{16, 0}:
		info.Container = "RAW"
	}
	switch [2]byte{raw[10], raw[11]} {
	case [2]byte{1, 0}, [2]byte{0, 1}:
		info.Codec = "H264"
	case [2]byte{5, 0}:
		info.Codec = "H265"
	}
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
	return parseH264SPSBytes(raw)
}

// parseH264SPSBytes decodes width/height from an already-decoded H.264 SPS
// NAL unit (including its 1-byte NAL header).
func parseH264SPSBytes(raw []byte) (int, int, error) {
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

// parseH265SPS decodes the width/height from an H.265 (HEVC) SPS NAL unit
// (including its 1-byte NAL header). Only the fields needed for resolution
// are read: pic_width/height_in_luma_samples plus the conformance window.
func parseH265SPS(raw []byte) (int, int, error) {
	if len(raw) < 3 {
		return 0, 0, fmt.Errorf("h265 sps too short")
	}
	br := &bitReader{data: raw[2:]} // skip the 2-byte HEVC NAL header

	// sps_video_parameter_set_id u(4), sps_max_sub_layers_minus1 u(3),
	// sps_temporal_id_nesting_flag u(1)
	if _, err := br.readBits(4); err != nil {
		return 0, 0, err
	}
	maxSubLayersMinus1, err := br.readBits(3)
	if err != nil {
		return 0, 0, err
	}
	if _, err = br.readBit(); err != nil { // temporal_id_nesting_flag
		return 0, 0, err
	}

	// profile_tier_level(1, maxSubLayersMinus1)
	if _, err = br.readBits(8); err != nil { // profile_space(2)+tier(1)+profile_idc(5)
		return 0, 0, err
	}
	if _, err = br.readBits(32); err != nil { // profile_compatibility flags
		return 0, 0, err
	}
	if _, err = br.readBits(48); err != nil { // constraint indicators
		return 0, 0, err
	}
	if _, err = br.readBits(8); err != nil { // general_level_idc
		return 0, 0, err
	}
	if maxSubLayersMinus1 > 0 {
		var subProfile, subLevel int
		for i := 0; i < int(maxSubLayersMinus1); i++ {
			p, err := br.readBit()
			if err != nil {
				return 0, 0, err
			}
			subProfile = (subProfile << 1) | p
			l, err := br.readBit()
			if err != nil {
				return 0, 0, err
			}
			subLevel = (subLevel << 1) | l
		}
		// reserved_zero_2bits for the remaining sub-layers
		if _, err = br.readBits(2 * (8 - int(maxSubLayersMinus1))); err != nil {
			return 0, 0, err
		}
		for i := 0; i < int(maxSubLayersMinus1); i++ {
			if (subProfile>>uint(int(maxSubLayersMinus1)-1-i))&1 == 1 {
				if _, err = br.readBits(8 + 32 + 48 + 8); err != nil {
					return 0, 0, err
				}
			}
			if (subLevel>>uint(int(maxSubLayersMinus1)-1-i))&1 == 1 {
				if _, err = br.readBits(8); err != nil {
					return 0, 0, err
				}
			}
		}
	}

	if _, err = br.readUE(); err != nil { // sps_seq_parameter_set_id
		return 0, 0, err
	}
	chromaFormatIdc, err := br.readUE()
	if err != nil {
		return 0, 0, err
	}
	if chromaFormatIdc == 3 {
		if _, err = br.readBit(); err != nil { // separate_colour_plane_flag
			return 0, 0, err
		}
	}
	picWidth, err := br.readUE()
	if err != nil {
		return 0, 0, err
	}
	picHeight, err := br.readUE()
	if err != nil {
		return 0, 0, err
	}
	confWinFlag, err := br.readBit()
	if err != nil {
		return 0, 0, err
	}
	cropLeft, cropRight, cropTop, cropBottom := 0, 0, 0, 0
	if confWinFlag == 1 {
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

	var subWC, subHC int
	switch chromaFormatIdc {
	case 1:
		subWC, subHC = 2, 2
	case 2:
		subWC, subHC = 2, 1
	default:
		subWC, subHC = 1, 1
	}
	width := picWidth - (cropLeft+cropRight)*subWC
	height := picHeight - (cropTop+cropBottom)*subHC
	if width <= 0 || height <= 0 || width > 8192 || height > 8192 {
		return 0, 0, fmt.Errorf("implausible h265 dimensions %dx%d", width, height)
	}
	return width, height, nil
}

// recoverResolution scans an annex-b elementary stream (one access unit) for
// the SPS NAL unit and decodes its width/height. It returns ok=false when no
// SPS is present or it cannot be parsed. The PS container delivers the stream
// in annex-b form, so this recovers the resolution the MEDIAINFO header lacks.
func recoverResolution(data []byte, codec string) (int, int, bool) {
	if codec == "" {
		return 0, 0, false
	}
	isH265 := codec == "H265"
	spsType := byte(7) // H.264 SPS
	if isH265 {
		spsType = 33 // H.265 SPS_NUT
	}
	i := 0
	for i < len(data) {
		idx := bytes.Index(data[i:], []byte{0, 0, 1})
		if idx < 0 {
			break
		}
		pos := i + idx
		nalPos := pos + 3
		if nalPos >= len(data) {
			break
		}
		b := data[nalPos]
		var t int
		if isH265 {
			t = int(b>>1) & 0x3F
		} else {
			t = int(b & 0x1F)
		}
		if t == int(spsType) {
			if isH265 {
				if w, h, err := parseH265SPS(data[nalPos:]); err == nil {
					return w, h, true
				}
			} else {
				if w, h, err := parseH264SPSBytes(data[nalPos:]); err == nil {
					return w, h, true
				}
			}
		}
		i = nalPos + 1
	}
	return 0, 0, false
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
	PTS         int64 // container PTS (90kHz) when HasPTS; else synthetic (arrival-based)
	HasPTS      bool  // true when PTS comes from the container, false for synthetic
	TimestampMs int64 // wall-clock ms since stream start
}

// AnalyzeFrame scans an H.264/H.265 annex-b frame for NAL units and reports
// whether it contains a key NAL. The codec is required because H.264 and
// H.265 NAL type fields overlap (e.g. a H.264 SPS byte also decodes as a H.265
// VPS type), so the SDP-recovered codec is used to disambiguate: when codec is
// "H265" any IRAP NAL (types 16-21) marks a key frame, otherwise the H.264 IDR
// type (5) is used. It assumes the data begins with a NAL (optionally preceded
// by a 00 00 00 01 or 00 00 01 start code), which is the case for the payload
// the PS demuxer and the raw elementary stream deliver.
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
			// IRAP NAL units (IDR/CRA) are decodable without prior frames.
			if t >= 16 && t <= 21 {
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
