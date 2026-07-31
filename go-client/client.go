package hikws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
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
	dialTimeout        = 10 * time.Second
)

// ServerError is an error the proxy reported in-band (expired openUrl token,
// bad credentials, device unreachable). It is terminal: retrying the same URL
// produces the same code, so Stream stops instead of reconnecting.
type ServerError struct {
	Code int
	Msg  string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error code=%d msg=%s", e.Code, e.Msg)
}

// ErrStalled is returned when no message arrived within Config.StallTimeout.
// The socket stays open when a camera stops publishing, so this watchdog is
// what turns a silent stream drop into a reconnect.
var ErrStalled = errors.New("stream stalled: no data within StallTimeout")

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
	// allocated on the first payload and stays nil for the bare elementary
	// stream paths; containerKnown records that the choice has been made.
	ps             *psDemuxer
	containerKnown bool
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
	OnSPS        func([]byte)             // first in-stream SPS NAL (start code + header), for archiving

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
		// Without this the handshake can hang forever on a black-holed
		// network, which would also hang the reconnect loop.
		HandshakeTimeout: dialTimeout,
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
	// Bound the handshake read: a proxy that accepts the socket but never
	// answers would otherwise block the session forever.
	if d := c.Config.StallTimeout; d > 0 {
		c.conn.SetReadDeadline(time.Now().Add(d))
		defer c.conn.SetReadDeadline(time.Time{})
	}
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
	c.conn.SetWriteDeadline(time.Now().Add(keepaliveWriteWait))
	defer c.conn.SetWriteDeadline(time.Time{})
	return c.conn.WriteMessage(websocket.TextMessage, reqBytes)
}

// streamEvent is one unit of work handed from the socket read loop to the
// delivery path. Routing media info through the same queue as the media
// itself keeps mediaInfo single-owner in async mode.
type streamEvent struct {
	kind byte
	data []byte
	info *MediaInfo
}

const (
	evVideo byte = 'v'
	evAudio byte = 'a'
	evInfo  byte = 'm'
)

func (c *HikMediaClient) dispatch(e streamEvent) {
	switch e.kind {
	case evVideo:
		c.feedVideo(e.data)
	case evAudio:
		if c.OnAudioData != nil {
			c.OnAudioData(e.data)
		}
	case evInfo:
		c.mediaInfo = e.info
		if c.OnMediaInfo != nil {
			c.OnMediaInfo(e.info)
		}
	}
}

// feedVideo routes a video payload to the caller. It first strips any RTP
// encapsulation, then, when the stream is an MPEG-PS container, demuxes the
// payload into access units — the device splits a single NAL across PES
// packets, so raw PS bytes cannot be scanned as annex-b. For every other
// container the payload is delivered verbatim.
func (c *HikMediaClient) feedVideo(data []byte) {
	data = rtpPayload(data)
	if c.OnRawVideo != nil {
		c.OnRawVideo(data)
	}
	// Decide the container once per session, from the first payload. The
	// MEDIAINFO header is a hint, not the truth: one camera family sends a
	// header this client cannot decode (magic "HVAG" rather than "IMKH"),
	// which leaves Container empty even though the payload is plainly
	// MPEG-PS. Sniffing settles it — but only on the first message, because
	// later ones carry PES continuations that start mid-pack.
	if !c.containerKnown {
		c.containerKnown = true
		if (c.mediaInfo != nil && c.mediaInfo.Container == "PS") ||
			((c.mediaInfo == nil || c.mediaInfo.Container == "") && isPSData(data)) {
			c.ps = &psDemuxer{}
		}
	}
	if c.ps == nil {
		c.deliverFrame(data, 0, false)
		return
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
	// Same reason as the container: a MEDIAINFO header this client cannot
	// decode leaves the codec blank, and without one there is no key frame
	// flag and no resolution. The bitstream says which codec it is.
	if codec == "" {
		if codec = sniffCodec(data); codec != "" && c.mediaInfo != nil {
			c.mediaInfo.Codec = codec
		}
	}
	// Recover resolution from the in-stream SPS (the MEDIAINFO header has
	// none). This fills Width/Height for PS streams on the first key frame.
	if codec != "" && (c.mediaInfo == nil || c.mediaInfo.Width == 0) {
		if w, h, sps, ok := recoverResolution(data, codec); ok {
			if c.mediaInfo != nil {
				c.mediaInfo.Width, c.mediaInfo.Height = w, h
			}
			if c.OnSPS != nil && sps != nil {
				c.OnSPS(sps)
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
	_ = c.run(ctx)
}

// Stream owns the whole session lifecycle — connect, authenticate, realplay,
// receive — and rebuilds it after a transport failure (dropped connection,
// stalled stream, dial error) up to Config.MaxReconnects times. It returns
// nil on a clean shutdown (context cancelled or stream ended) and the last
// error otherwise. A *ServerError is terminal and stops the loop immediately.
func (c *HikMediaClient) Stream(ctx context.Context) error {
	wait := c.Config.ReconnectWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	for attempt := 0; ; attempt++ {
		err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		var srv *ServerError
		if errors.As(err, &srv) || attempt >= c.Config.MaxReconnects {
			return err
		}
		backoff := time.Duration(attempt+1) * wait
		log.Printf("session failed (%v), reconnecting in %s", err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil
		}
	}
}

// session runs exactly one connect→receive cycle and always closes the socket.
func (c *HikMediaClient) session(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	defer c.Close()
	if err := c.Authenticate(); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	if err := c.Realplay(); err != nil {
		return fmt.Errorf("realplay: %w", err)
	}
	// A new session brings a new SDP and a fresh container; whatever the
	// dead connection left half-demuxed must not be spliced onto it.
	c.mediaInfo = nil
	c.ps, c.containerKnown = nil, false
	return c.run(ctx)
}

func (c *HikMediaClient) run(ctx context.Context) error {
	// Close the underlying connection when context is cancelled so that
	// ReadMessage unblocks immediately (the select+default pattern alone
	// cannot interrupt a blocking ReadMessage). The done channel makes the
	// watcher goroutine exit when Run returns, avoiding a goroutine leak.
	conn := c.conn
	done := make(chan struct{})
	defer close(done)
	// Flush the final buffered access unit when the stream ends.
	defer c.flushPS()

	// Delivery path: synchronous by default, pipelined through a worker when
	// AsyncDelivery is configured. Everything the caller observes goes
	// through the same channel, so ordering is identical in both modes and
	// mediaInfo is only ever touched by one goroutine.
	emit := c.dispatch
	if n := c.Config.AsyncDelivery; n > 0 {
		ch := make(chan streamEvent, n)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range ch {
				c.dispatch(e)
			}
		}()
		emit = func(e streamEvent) {
			select {
			case ch <- e:
			case <-ctx.Done():
			}
		}
		// Runs before the deferred flushPS above (LIFO), so the worker has
		// drained by the time the demuxer is flushed.
		defer func() {
			close(ch)
			wg.Wait()
		}()
	}

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
		// Re-armed before every read: any message resets the watchdog, so
		// this fires only when the proxy goes silent while holding the
		// socket open — the signature of a dropped camera stream.
		if d := c.Config.StallTimeout; d > 0 {
			conn.SetReadDeadline(time.Now().Add(d))
		}
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			// Context cancellation is not an error
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				err = ErrStalled
			} else {
				err = fmt.Errorf("read error: %w", err)
			}
			if c.OnError != nil {
				c.OnError(err)
			}
			return err
		}

		if msgType == websocket.TextMessage {
			var resp map[string]interface{}
			if err := json.Unmarshal(payload, &resp); err == nil {
				code, _ := resp["errorCode"].(float64)
				if code != 0 {
					msg, _ := resp["errorMsg"].(string)
					srv := &ServerError{Code: int(code), Msg: msg}
					log.Print(srv.Error())
					if c.OnError != nil {
						c.OnError(srv)
					}
					// The proxy tears the session down right after this;
					// keeping the loop alive only surfaced a confusing
					// "close 1005" a moment later.
					return srv
				} else if sdp, ok := resp["sdp"].(string); ok && sdp != "" {
					if c.Config.Verbose {
						log.Printf("realplay OK, SDP length=%d", len(sdp))
					}
					// Recover the SDP-like stream description and expose it to
					// callers (codec, clock rate, width/height from SPS).
					emit(streamEvent{kind: evInfo, info: ParseSDP(sdp)})
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
					emit(streamEvent{kind: evVideo, data: buf})
					break
				}

				pType, pData := msg.Type, msg.Payload
				switch pType {
				case MsgTypeVideoData:
					emit(streamEvent{kind: evVideo, data: pData})
				case MsgTypeAudioData:
					emit(streamEvent{kind: evAudio, data: pData})
				case MsgTypeSessionError:
					err := fmt.Errorf("session error: %s", string(pData))
					if c.OnError != nil {
						c.OnError(err)
					}
					return err
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
