package hikws

import (
	"context"
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
