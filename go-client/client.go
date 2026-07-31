package hikws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// keepaliveInterval is how often a WebSocket ping is sent to keep the
// session alive; keepaliveWriteWait bounds each control-frame write.
// They are vars so tests can shorten them.
var (
	keepaliveInterval  = 20 * time.Second
	keepaliveWriteWait = 5 * time.Second
)

type HikMediaClient struct {
	Config     *HikConfig
	conn       *websocket.Conn
	sessionID  string
	secretKey  string
	serverPKD  string
	serverRand string

	// mediaInfo is recovered from the SDP the server returns on realplay.
	mediaInfo *MediaInfo
	// ps demuxes the MPEG-PS container the cameras actually send. It is
	// allocated lazily on the first PS payload and stays nil for the raw
	// elementary stream (RTP/RAW container) paths.
	ps *psDemuxer
	// frameCount / startTime drive the synthetic per-frame timestamp.
	frameCount int
	startTime  time.Time

	// Callbacks
	OnVideoData  func([]byte)             // raw frame payload (backward compatible)
	OnAudioData  func([]byte)             // raw audio payload
	OnError      func(error)              // transport / session errors
	OnMediaInfo  func(*MediaInfo)         // SDP-like stream description (realplay)
	OnVideoFrame func(*FrameMeta, []byte) // per-frame metadata + payload
	OnRawVideo   func([]byte)             // raw container payload, before PS demux (diagnostics)

	mu sync.Mutex
}

func NewHikMediaClient(config *HikConfig) *HikMediaClient {
	return &HikMediaClient{
		Config: config,
	}
}

func (c *HikMediaClient) buildMediaURL() string {
	proxy := fmt.Sprintf("%s:%d", c.Config.DeviceIP, c.Config.DevicePort)
	return fmt.Sprintf("wss://%s:%d/media?version=%s&cipherSuites=%d&sessionID=&proxy=%s",
		c.Config.ProxyHost, c.Config.ProxyPort, c.Config.Version, c.Config.CipherSuites, proxy)
}

func (c *HikMediaClient) Connect(ctx context.Context) error {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	url := c.buildMediaURL()
	header := http.Header{}
	header.Add("Sec-WebSocket-Protocol", "v1.0.0")

	conn, _, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		return fmt.Errorf("websocket dial error: %w", err)
	}

	c.conn = conn
	return nil
}

func (c *HikMediaClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// Authenticate reads the first message expecting PKD and rand
func (c *HikMediaClient) Authenticate() error {
	msgType, msg, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}

	if msgType != websocket.TextMessage {
		return fmt.Errorf("expected text message for auth, got %d", msgType)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(msg, &resp); err != nil {
		return err
	}

	if code, ok := resp["errorCode"].(float64); ok && code != 0 {
		return fmt.Errorf("server error %v: %v", code, resp["errorMsg"])
	}

	if pkd, ok := resp["PKD"].(string); ok {
		c.serverPKD = pkd
	}
	if randStr, ok := resp["rand"].(string); ok {
		c.serverRand = randStr
	}

	return nil
}

func (c *HikMediaClient) Realplay() error {
	deviceURL := fmt.Sprintf("ws://%s:%d/openUrl/%s", c.Config.DeviceIP, c.Config.DevicePort, c.Config.Password)

	// Match the Python client: send empty key/authorization/token
	// to trigger the server to return the video stream directly.
	reqData := map[string]interface{}{
		"sequence":      0,
		"cmd":           "realplay",
		"url":           deviceURL,
		"key":           "",
		"authorization": "",
		"token":         "",
	}

	reqBytes, _ := json.Marshal(reqData)
	log.Printf("Sending realplay request to %s", deviceURL)
	return c.conn.WriteMessage(websocket.TextMessage, reqBytes)
}

// feedVideo routes a video payload to the caller. When the stream is an
// MPEG-PS container (recovered from the SDP MEDIAINFO header, or detected
// heuristically from a PS pack start), the payload is demuxed into access
// units first — the device splits a single NAL across PES packets, so the
// raw PS bytes cannot be scanned as annex-b. For every other container the
// payload is delivered verbatim.
func (c *HikMediaClient) feedVideo(data []byte) {
	if c.OnRawVideo != nil {
		c.OnRawVideo(data)
	}
	demux := false
	if c.mediaInfo != nil && c.mediaInfo.Container == "PS" {
		demux = true
	} else if c.mediaInfo == nil && isPSData(data) {
		demux = true
	}
	if !demux {
		c.deliverFrame(data, 0, false)
		return
	}
	if c.ps == nil {
		c.ps = &psDemuxer{}
	}
	for _, f := range c.ps.Feed(data) {
		c.deliverFrame(f.Data, f.PTS, f.HasPTS)
	}
}

// isPSData reports whether b begins with an MPEG-PS pack header
// (00 00 01 ba), used to demux streams whose SDP has not arrived yet.
func isPSData(b []byte) bool {
	return len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == psPackStart
}

// deliverFrame recovers the per-frame metadata and hands the payload to the
// caller. OnVideoFrame takes precedence over OnVideoData to avoid delivering
// the same payload twice; OnVideoData alone keeps working for existing
// callers. When hasPTS is true the container's real 90kHz PTS is used;
// otherwise a synthetic, order-preserving PTS is synthesized from arrival
// time. Resolution is recovered from an in-stream SPS when the MEDIAINFO
// header (which carries none) left it unknown.
func (c *HikMediaClient) deliverFrame(data []byte, pts int64, hasPTS bool) {
	if c.OnVideoFrame == nil && c.OnVideoData == nil {
		return
	}
	if c.startTime.IsZero() {
		c.startTime = time.Now()
	}
	c.frameCount++

	codec := ""
	if c.mediaInfo != nil {
		codec = c.mediaInfo.Codec
	}
	// Recover resolution from the in-stream SPS (the MEDIAINFO header has
	// none). This fills Width/Height for PS streams on the first key frame.
	if codec != "" && (c.mediaInfo == nil || c.mediaInfo.Width == 0) {
		if w, h, ok := recoverResolution(data, codec); ok {
			if c.mediaInfo != nil {
				c.mediaInfo.Width, c.mediaInfo.Height = w, h
			}
		}
	}

	elapsed := time.Since(c.startTime)
	meta := &FrameMeta{
		FrameIndex:  c.frameCount,
		IsKeyFrame:  AnalyzeFrame(data, codec),
		Codec:       codec,
		TimestampMs: elapsed.Milliseconds(),
	}
	if hasPTS {
		meta.PTS = pts
		meta.HasPTS = true
	} else if c.mediaInfo != nil && c.mediaInfo.ClockRate > 0 {
		meta.PTS = int64(elapsed.Seconds() * float64(c.mediaInfo.ClockRate))
	}
	if c.mediaInfo != nil {
		meta.Width, meta.Height = c.mediaInfo.Width, c.mediaInfo.Height
	}
	if c.Config.Verbose {
		log.Printf("Video frame #%d: %d bytes (key=%v, codec=%s)", meta.FrameIndex, len(data), meta.IsKeyFrame, codec)
	}

	if c.OnVideoFrame != nil {
		c.OnVideoFrame(meta, data)
		return
	}
	c.OnVideoData(data)
}

// flushPS delivers the last access unit still buffered in the demuxer,
// which closes on stream end (see psDemuxer.Flush).
func (c *HikMediaClient) flushPS() {
	if c.ps == nil {
		return
	}
	for _, f := range c.ps.Flush() {
		c.deliverFrame(f.Data, f.PTS, f.HasPTS)
	}
}

// Run processes incoming messages until context is cancelled or connection drops.
// This matches the Python client's receive_message + run loop behavior:
//   - Each binary WebSocket frame is unpacked and ALL protocol messages it
//     carries are dispatched (the server may batch several into one frame);
//     previously only the first was handled and the rest were dropped.
//   - If unpack succeeds with a known type → handle by type.
//   - If unpack succeeds with an unknown type → discard (matches Python).
//   - If unpack fails → treat the rest of the frame as raw video (matches Python).
//
// Per-frame logging is gated behind Config.Verbose to avoid log/alloc storms
// under multi-stream concurrency.
func (c *HikMediaClient) Run(ctx context.Context) {
	// Close the underlying connection when context is cancelled so that
	// ReadMessage unblocks immediately (the select+default pattern alone
	// cannot interrupt a blocking ReadMessage). The done channel makes the
	// watcher goroutine exit when Run returns, avoiding a goroutine leak.
	conn := c.conn
	done := make(chan struct{})
	defer close(done)
	// Flush the final buffered access unit when the stream ends.
	defer c.flushPS()
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	// Periodic WebSocket ping keepalive (WriteControl is safe for
	// concurrent use with other writes in gorilla/websocket).
	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				deadline := time.Now().Add(keepaliveWriteWait)
				if err := conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
					return
				}
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			// Context cancellation is not an error
			if ctx.Err() != nil {
				return
			}
			if c.OnError != nil {
				c.OnError(fmt.Errorf("read error: %w", err))
			}
			return
		}

		if msgType == websocket.TextMessage {
			var resp map[string]interface{}
			if err := json.Unmarshal(payload, &resp); err == nil {
				code, _ := resp["errorCode"].(float64)
				if code != 0 {
					msg, _ := resp["errorMsg"].(string)
					errMsg := fmt.Sprintf("server error code=%.0f msg=%s", code, msg)
					log.Print(errMsg)
					if c.OnError != nil {
						c.OnError(fmt.Errorf("%s", errMsg))
					}
				} else if sdp, ok := resp["sdp"].(string); ok && sdp != "" {
					if c.Config.Verbose {
						log.Printf("realplay OK, SDP length=%d", len(sdp))
					}
					// Recover the SDP-like stream description and expose it to
					// callers (codec, clock rate, width/height from SPS).
					c.mediaInfo = ParseSDP(sdp)
					if c.OnMediaInfo != nil {
						c.OnMediaInfo(c.mediaInfo)
					}
				}
			}

		} else if msgType == websocket.BinaryMessage {
			// ---- Match Python receive_message behaviour, but dispatch every
			// protocol message carried in this frame ----
			// Unpack until the frame is exhausted; a failed unpack means the
			// remaining bytes are raw video (matches Python WS_OP_BINARY path).
			buf := payload
			for len(buf) > 0 {
				msg, unpackErr := Unpack(buf)
				if unpackErr != nil {
					// Header incomplete / payload truncated → raw video data.
					if c.Config.Verbose {
						log.Printf("Raw video frame: %d bytes", len(buf))
					}
					c.feedVideo(buf)
					break
				}

				pType, pData := msg.Type, msg.Payload
				switch pType {
				case MsgTypeVideoData:
					c.feedVideo(pData)
				case MsgTypeAudioData:
					if c.OnAudioData != nil {
						c.OnAudioData(pData)
					}
				case MsgTypeSessionError:
					if c.OnError != nil {
						c.OnError(fmt.Errorf("session error: %s", string(pData)))
					}
					return
				case MsgTypeKeepAlive:
					// keepalive — discard
				default:
					// Unknown protocol type (e.g. 0x00 stream metadata) —
					// discard, matching Python which has no handler for
					// unmatched msg_types.
					if c.Config.Verbose {
						log.Printf("Protocol msg 0x%02x: %d bytes (discarded)", pType, len(pData))
					}
				}

				buf = msg.Remaining
			}
		}
	}
}
