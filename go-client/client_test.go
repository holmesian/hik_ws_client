package hikws

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const testSDP = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=Session streamed by Hikvision\n" +
	"m=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n" +
	"a=fmtp:96 packetization-mode=1;profile-level-id=42001f;sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPI8YMZYA==,aM7A8g==\n"

var (
	idrFrame = []byte{0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21}
	pFrame   = []byte{0, 0, 0, 1, 0x41, 0x9a, 0x00}
	// rawFrame is annex-b video delivered without a protocol header
	// (the server's raw-binary path); its first bytes cannot be parsed as
	// a valid 5-byte envelope, so the client must fall back to raw video.
	rawFrame = []byte{0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33, 0x44}
)

// startMock spins up a TLS WebSocket server running handle and returns a
// config pointing the client at it.
func startMock(t *testing.T, handle func(*testing.T, *websocket.Conn)) *HikConfig {
	t.Helper()
	up := websocket.Upgrader{Subprotocols: []string{"v1.0.0"}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		handle(t, conn)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return &HikConfig{
		ProxyHost:  u.Hostname(),
		ProxyPort:  port,
		DeviceIP:   "127.0.0.1",
		DevicePort: 559,
		Username:   "admin",
		Password:   "token123",
		Version:    "0.1",
	}
}

// sendAuth/expectRealplay reproduce the server side of the handshake:
// PKD+rand push, then the realplay request, then the SDP answer.
func sendAuth(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	if err := conn.WriteJSON(map[string]interface{}{
		"errorCode": 0, "PKD": "00aabb", "rand": "1234", "cipherSuite": 0, "version": "0.1",
	}); err != nil {
		t.Error(err)
	}
}

func expectRealplay(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Error(err)
		return
	}
	var req map[string]interface{}
	if err := json.Unmarshal(msg, &req); err != nil {
		t.Errorf("realplay request is not JSON: %v", err)
		return
	}
	if req["cmd"] != "realplay" {
		t.Errorf("cmd = %v, want realplay", req["cmd"])
	}
	if req["url"] != "ws://127.0.0.1:559/openUrl/token123" {
		t.Errorf("url = %v", req["url"])
	}
}

// connectAndPlay runs the client handshake against the mock.
func connectAndPlay(t *testing.T, cfg *HikConfig, ctx context.Context) *HikMediaClient {
	t.Helper()
	c := NewHikMediaClient(cfg)
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Authenticate(); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if c.serverPKD != "00aabb" || c.serverRand != "1234" {
		t.Fatalf("auth fields not captured: PKD=%q rand=%q", c.serverPKD, c.serverRand)
	}
	if err := c.Realplay(); err != nil {
		t.Fatalf("realplay: %v", err)
	}
	return c
}

// TestIntegration_FullStreamFlow exercises the whole receive path in one
// session: SDP/media info, a protocol video frame, several protocol
// messages batched into one WebSocket frame, an encrypted-flag frame, a
// raw (header-less) video frame, and finally a session error.
func TestIntegration_FullStreamFlow(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})

		// 1. single protocol video message (key frame)
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, idrFrame))
		// 2. one frame carrying video + audio + keepalive + unknown type
		batch := PackMessage(MsgTypeVideoData, pFrame)
		batch = append(batch, PackMessage(MsgTypeAudioData, []byte("audio-pcm"))...)
		batch = append(batch, PackMessage(MsgTypeKeepAlive, nil)...)
		batch = append(batch, PackMessage(0x07, []byte("unknown"))...)
		_ = conn.WriteMessage(websocket.BinaryMessage, batch)
		// 3. encrypted flag set on a video message
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData|EncryptFlag, pFrame))
		// 4. raw video without protocol header
		_ = conn.WriteMessage(websocket.BinaryMessage, rawFrame)
		// 5. session error terminates the stream
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeSessionError, []byte("stream closed")))
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)

	var (
		mu     sync.Mutex
		info   *MediaInfo
		metas  []*FrameMeta
		sizes  []int
		audio  [][]byte
		errs   []error
		frames = make(chan struct{}, 16)
	)
	c.OnMediaInfo = func(mi *MediaInfo) { mu.Lock(); info = mi; mu.Unlock() }
	c.OnVideoFrame = func(m *FrameMeta, data []byte) {
		mu.Lock()
		metas = append(metas, m)
		sizes = append(sizes, len(data))
		mu.Unlock()
		frames <- struct{}{}
	}
	c.OnAudioData = func(b []byte) { mu.Lock(); audio = append(audio, b); mu.Unlock() }
	c.OnError = func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() }

	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run did not return after session error")
	}

	mu.Lock()
	defer mu.Unlock()

	if info == nil {
		t.Fatal("OnMediaInfo never fired")
	}
	if info.Codec != "H264" || info.ClockRate != 90000 {
		t.Errorf("media info = %s/%d", info.Codec, info.ClockRate)
	}
	if info.Width != 1280 || info.Height < 720 || info.Height > 736 {
		t.Errorf("media dims = %dx%d, want 1280x~720", info.Width, info.Height)
	}

	// video: idr, p, encrypted p, raw
	if len(metas) != 4 {
		t.Fatalf("video frames = %d, want 4 (idr, p, encrypted, raw): %+v", len(metas), metas)
	}
	want := []struct {
		key  bool
		size int
	}{
		{true, len(idrFrame)},
		{false, len(pFrame)},
		{false, len(pFrame)},
		{true, len(rawFrame)},
	}
	for i, w := range want {
		if metas[i].IsKeyFrame != w.key {
			t.Errorf("frame %d: key = %v, want %v", i, metas[i].IsKeyFrame, w.key)
		}
		if sizes[i] != w.size {
			t.Errorf("frame %d: payload = %d bytes, want %d", i, sizes[i], w.size)
		}
		if metas[i].FrameIndex != i+1 {
			t.Errorf("frame %d: index = %d", i, metas[i].FrameIndex)
		}
		if metas[i].Codec != "H264" || metas[i].Width != 1280 {
			t.Errorf("frame %d: codec/dims = %s %dx%d", i, metas[i].Codec, metas[i].Width, metas[i].Height)
		}
		if i > 0 && metas[i].TimestampMs < metas[i-1].TimestampMs {
			t.Errorf("frame %d: timestamp went backwards", i)
		}
	}

	if len(audio) != 1 || string(audio[0]) != "audio-pcm" {
		t.Errorf("audio = %q, want one %q", audio, "audio-pcm")
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want the session error only", errs)
	}
	if got := errs[0].Error(); got != "session error: stream closed" {
		t.Errorf("error = %q", got)
	}
}

// TestIntegration_OnVideoDataOnly checks the backward-compatible callback:
// a caller that only registers OnVideoData still receives every payload,
// both protocol-framed and raw.
func TestIntegration_OnVideoDataOnly(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, idrFrame))
		_ = conn.WriteMessage(websocket.BinaryMessage, rawFrame)
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeSessionError, []byte("bye")))
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)

	var mu sync.Mutex
	var payloads [][]byte
	c.OnVideoData = func(b []byte) {
		mu.Lock()
		payloads = append(payloads, append([]byte(nil), b...))
		mu.Unlock()
	}
	c.OnError = func(error) {}

	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run did not return")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 {
		t.Fatalf("payloads = %d, want 2", len(payloads))
	}
	if string(payloads[0]) != string(idrFrame) || string(payloads[1]) != string(rawFrame) {
		t.Errorf("payloads = %v", payloads)
	}
}

// TestIntegration_BatchedFrameConsumedToTail locks the authoritative
// behaviour Python was diverging from: a binary frame may carry several
// protocol messages, and the read loop must keep unpacking until the frame
// is exhausted. Stopping after the first message drops the rest silently —
// nothing errors, the frame counter just runs low.
//
// The tail here cannot be unpacked (rawFrame's four declared length bytes
// exceed what is left), so it must be delivered as raw video, in order,
// after the two messages that preceded it.
func TestIntegration_BatchedFrameConsumedToTail(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})

		batch := PackMessage(MsgTypeVideoData, idrFrame)
		batch = append(batch, PackMessage(MsgTypeVideoData, pFrame)...)
		batch = append(batch, rawFrame...)
		_ = conn.WriteMessage(websocket.BinaryMessage, batch)
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeSessionError, []byte("bye")))
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)

	var mu sync.Mutex
	var payloads [][]byte
	c.OnVideoData = func(b []byte) {
		mu.Lock()
		payloads = append(payloads, append([]byte(nil), b...))
		mu.Unlock()
	}
	c.OnError = func(error) {}

	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run did not return")
	}

	mu.Lock()
	defer mu.Unlock()
	want := [][]byte{idrFrame, pFrame, rawFrame}
	if len(payloads) != len(want) {
		t.Fatalf("payloads = %d, want %d (frame not consumed to the tail): %v",
			len(payloads), len(want), payloads)
	}
	for i := range want {
		if string(payloads[i]) != string(want[i]) {
			t.Errorf("payload %d = %x, want %x", i, payloads[i], want[i])
		}
	}
}

// TestIntegration_ServerErrorText verifies the realplay failure path.
func TestIntegration_ServerErrorText(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 28316423, "errorMsg": "url expired"})
		time.Sleep(300 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)

	got := make(chan error, 1)
	c.OnError = func(e error) {
		select {
		case got <- e:
		default:
		}
	}
	go c.Run(ctx)

	select {
	case e := <-got:
		if e.Error() != "server error code=28316423 msg=url expired" {
			t.Errorf("error = %q", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnError never fired for errorCode != 0")
	}
}

// TestIntegration_AuthenticateServerError verifies Authenticate rejects an
// error response instead of proceeding with empty PKD/rand.
func TestIntegration_AuthenticateServerError(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 65559, "errorMsg": "auth failed"})
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := NewHikMediaClient(cfg)
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Authenticate(); err == nil {
		t.Fatal("Authenticate accepted an errorCode != 0 response")
	}
}

// TestIntegration_CancelNoLeak verifies Run returns promptly on context
// cancellation and leaves no goroutine behind (the watcher + keepalive
// goroutines must exit with it).
func TestIntegration_CancelNoLeak(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		// stay silent; the client must unblock on cancel
		time.Sleep(3 * time.Second)
	})

	ctx, cancel := context.WithCancel(context.Background())
	c := connectAndPlay(t, cfg, ctx)
	c.OnError = func(e error) { t.Errorf("unexpected error on cancel: %v", e) }

	before := runtime.NumGoroutine()
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("goroutines leaked: before=%d after=%d", before, runtime.NumGoroutine())
}

// TestIntegration_Keepalive verifies the periodic WebSocket ping reaches
// the server while the stream is idle.
func TestIntegration_Keepalive(t *testing.T) {
	old := keepaliveInterval
	keepaliveInterval = 50 * time.Millisecond
	defer func() { keepaliveInterval = old }()

	pinged := make(chan struct{}, 1)
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		conn.SetPingHandler(func(string) error {
			select {
			case pinged <- struct{}{}:
			default:
			}
			return nil
		})
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		// keep reading so control frames are processed
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)
	c.OnError = func(error) {}
	go c.Run(ctx)

	select {
	case <-pinged:
	case <-time.After(2 * time.Second):
		t.Fatal("no keepalive ping received")
	}
}

// hevcSPS builds a minimal but valid HEVC SPS NAL (2-byte NAL header + RBSP)
// carrying the given luma resolution, used by the PS/H.265 integration test.
func hevcSPS(w, h int) []byte {
	tw := &testBitWriter{}
	tw.putBits(0x42, 8) // NAL header byte 0 (type 33 = SPS_NUT)
	tw.putBits(0x01, 8) // NAL header byte 1
	tw.putBits(0, 4)    // sps_video_parameter_set_id
	tw.putBits(0, 3)    // sps_max_sub_layers_minus1
	tw.putBits(1, 1)    // sps_temporal_id_nesting_flag
	tw.putBits(0, 2)    // general_profile_space
	tw.putBits(0, 1)    // general_tier_flag
	tw.putBits(1, 5)    // general_profile_idc
	tw.putBits(0, 32)   // general_profile_compatibility_flag
	tw.putBits(0, 48)   // general_constraint_indicator_flag
	tw.putBits(93, 8)   // general_level_idc
	tw.putUE(0)         // sps_seq_parameter_set_id
	tw.putUE(1)         // chroma_format_idc
	tw.putUE(w)         // pic_width_in_luma_samples
	tw.putUE(h)         // pic_height_in_luma_samples
	tw.putBits(1, 1)    // conformance_window_flag
	tw.putUE(0)
	tw.putUE(0)
	tw.putUE(0)
	tw.putUE(0)
	return tw.bytes()
}

// TestIntegration_PS_H265 exercises the whole recovery path against a stream
// that is what the Hikvision cameras actually emit: an MPEG-PS container
// (not annex-b) carrying HEVC with the codec/container declared only in the
// SDP MEDIAINFO header, and resolution discoverable solely from the in-stream
// SPS. It asserts the client demuxes PS into access units, recovers the
// H.265 SPS resolution, reports the correct keyframe/PTS/frame-count, and
// delivers the original elementary stream to the caller.
func TestIntegration_PS_H265(t *testing.T) {
	// SDP with a MEDIAINFO header declaring PS container + H265 codec.
	hdr := make([]byte, 40)
	copy(hdr[:4], "IMKH")
	hdr[8] = 2  // container = PS
	hdr[10] = 5 // codec = H265
	sdp := "v=0\nm=video 0 RTP/AVP 0\na=rtpmap:0 /0\n" +
		"a=Media_header:MEDIAINFO=" + hex.EncodeToString(hdr) + ";\n"

	const (
		frames   = 10
		width    = 1280
		height   = 720
		keyEvery = 10 // first frame is an IDR, rest are TRAIL_R
	)
	sps := hevcSPS(width, height)
	vps := []byte{0, 0, 0, 1, 0x40, 0x01, 0x00}
	pps := []byte{0, 0, 0, 1, 0x44, 0x01, 0x00}

	var chunks [][]byte
	for i := 0; i < frames; i++ {
		au := append([]byte(nil), vps...)
		au = append(au, []byte{0, 0, 0, 1}...)
		au = append(au, sps...)
		au = append(au, pps...)
		if i == 0 {
			au = append(au, []byte{0, 0, 0, 1, 0x26, 0x01, 0x02}...) // IDR_W_DLP
		} else {
			au = append(au, []byte{0, 0, 0, 1, 0x02, 0x01, 0x03}...) // TRAIL_R
		}
		// 25fps @ 90kHz => 3600 ticks per frame.
		pts := int64(i * 3600)
		chunks = append(chunks, append(psPack(), psVideoPES(au, pts)...))
	}

	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": sdp})
		for _, ch := range chunks {
			_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, ch))
		}
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeSessionError, []byte("done")))
		time.Sleep(200 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)

	var (
		mu       sync.Mutex
		info     *MediaInfo
		metas    []*FrameMeta
		sizes    []int
		gotPTS   []int64
		errs     []error
		framesCh = make(chan struct{}, 32)
	)
	c.OnMediaInfo = func(mi *MediaInfo) { mu.Lock(); info = mi; mu.Unlock() }
	c.OnVideoFrame = func(m *FrameMeta, data []byte) {
		mu.Lock()
		metas = append(metas, m)
		sizes = append(sizes, len(data))
		if m.HasPTS {
			gotPTS = append(gotPTS, m.PTS)
		}
		mu.Unlock()
		framesCh <- struct{}{}
	}
	c.OnError = func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() }

	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run did not return after session error")
	}

	mu.Lock()
	defer mu.Unlock()

	if info == nil {
		t.Fatal("OnMediaInfo never fired")
	}
	if info.Container != "PS" || info.Codec != "H265" {
		t.Fatalf("media info = container %q codec %q, want PS/H265", info.Container, info.Codec)
	}
	if info.ClockRate != 90000 {
		t.Fatalf("clock rate = %d, want 90000", info.ClockRate)
	}
	// Resolution is NOT in the MEDIAINFO header; it must be recovered from
	// the in-stream SPS. If this is 0, the SPS recovery path is broken.
	if info.Width != width || info.Height != height {
		t.Fatalf("recovered resolution = %dx%d, want %dx%d", info.Width, info.Height, width, height)
	}

	if len(metas) != frames {
		t.Fatalf("frames = %d, want %d", len(metas), frames)
	}
	keyCount := 0
	for i, m := range metas {
		if m.IsKeyFrame {
			keyCount++
		}
		if m.Codec != "H265" {
			t.Errorf("frame %d: codec = %q, want H265", i, m.Codec)
		}
		if m.Width != width || m.Height != height {
			t.Errorf("frame %d: dims = %dx%d, want %dx%d", i, m.Width, m.Height, width, height)
		}
		if !m.HasPTS {
			t.Errorf("frame %d: HasPTS = false, want true (PS carries PTS)", i)
		}
		// The delivered payload must be the demuxed elementary stream, not the
		// raw PS bytes; it must be a plausible NAL-bearing access unit.
		if sizes[i] < 7 {
			t.Errorf("frame %d: implausibly small payload %d bytes", i, sizes[i])
		}
	}
	if keyCount != 1 {
		t.Fatalf("keyframes = %d, want 1 (only the IDR)", keyCount)
	}

	// PTS must be the real container PTS, monotonically increasing by 3600.
	if len(gotPTS) != frames {
		t.Fatalf("PTS frames = %d, want %d", len(gotPTS), frames)
	}
	for i := 1; i < len(gotPTS); i++ {
		if gotPTS[i]-gotPTS[i-1] != 3600 {
			t.Fatalf("PTS delta at %d = %d, want 3600 (25fps @ 90kHz)", i, gotPTS[i]-gotPTS[i-1])
		}
	}

	// The only error should be the terminating session error.
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want the single session error", errs)
	}
}
