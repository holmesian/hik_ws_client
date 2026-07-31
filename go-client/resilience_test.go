package hikws

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestStream_ReconnectsAfterDrop reproduces the common field failure: the
// proxy drops the socket mid-stream. Stream must rebuild the session and keep
// delivering frames without the caller doing anything.
func TestStream_ReconnectsAfterDrop(t *testing.T) {
	var conns int32
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		n := atomic.AddInt32(&conns, 1)
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		if n == 1 {
			// One frame, then vanish without a close handshake.
			_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, idrFrame))
			return
		}
		for i := 0; i < 50; i++ {
			if err := conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, pFrame)); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	cfg.MaxReconnects = 3
	cfg.ReconnectWait = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewHikMediaClient(cfg)
	var got int32
	enough := make(chan struct{})
	var once sync.Once
	c.OnVideoData = func([]byte) {
		if atomic.AddInt32(&got, 1) >= 3 {
			once.Do(func() { close(enough) })
		}
	}
	c.OnError = func(error) {}

	done := make(chan error, 1)
	go func() { done <- c.Stream(ctx) }()

	select {
	case <-enough:
	case <-ctx.Done():
		t.Fatalf("only %d frames after reconnect (connections=%d)", atomic.LoadInt32(&got), atomic.LoadInt32(&conns))
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stream returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stream did not return after cancel")
	}
	if n := atomic.LoadInt32(&conns); n < 2 {
		t.Errorf("connections = %d, want >= 2 (no reconnect happened)", n)
	}
}

// TestStream_ServerErrorNotRetried guards the expired-openUrl-token case:
// the token is single-use, so retrying burns time and produces the same
// code. Stream must give up after the first server error.
func TestStream_ServerErrorNotRetried(t *testing.T) {
	var conns int32
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		atomic.AddInt32(&conns, 1)
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 28316423, "errorMsg": "url expired"})
		time.Sleep(200 * time.Millisecond)
	})
	cfg.MaxReconnects = 3
	cfg.ReconnectWait = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewHikMediaClient(cfg)
	c.OnError = func(error) {}
	err := c.Stream(ctx)

	var srv *ServerError
	if !errors.As(err, &srv) {
		t.Fatalf("Stream returned %v, want *ServerError", err)
	}
	if srv.Code != 28316423 {
		t.Errorf("code = %d, want 28316423", srv.Code)
	}
	if n := atomic.LoadInt32(&conns); n != 1 {
		t.Errorf("connections = %d, want 1 (a server error must not be retried)", n)
	}
}

// TestStream_StallTimeout covers the silent stream drop: the socket stays
// healthy but the camera stops publishing. Without the watchdog the client
// would block on ReadMessage forever.
func TestStream_StallTimeout(t *testing.T) {
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		time.Sleep(3 * time.Second) // go silent
	})
	cfg.StallTimeout = 150 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewHikMediaClient(cfg)
	c.OnError = func(error) {}

	start := time.Now()
	err := c.Stream(ctx)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("Stream returned %v, want ErrStalled", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("stall detected after %s, want ~%s", elapsed, cfg.StallTimeout)
	}
}

// TestStream_StallTimeoutReconnects verifies a stalled stream is recovered,
// not just reported.
func TestStream_StallTimeoutReconnects(t *testing.T) {
	var conns int32
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		n := atomic.AddInt32(&conns, 1)
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		if n == 1 {
			time.Sleep(2 * time.Second) // stall
			return
		}
		for i := 0; i < 50; i++ {
			if err := conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, pFrame)); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	cfg.StallTimeout = 150 * time.Millisecond
	cfg.MaxReconnects = 2
	cfg.ReconnectWait = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewHikMediaClient(cfg)
	got := make(chan struct{}, 1)
	c.OnVideoData = func([]byte) {
		select {
		case got <- struct{}{}:
		default:
		}
	}
	c.OnError = func(error) {}
	go c.Stream(ctx)

	select {
	case <-got:
	case <-ctx.Done():
		t.Fatalf("no frame after stall recovery (connections=%d)", atomic.LoadInt32(&conns))
	}
}

// TestRun_AsyncDelivery checks the pipelined delivery path: with a slow
// consumer every frame still arrives, in order, and media info is still
// applied before the frames it describes. Run under -race this also proves
// mediaInfo is not shared across the read loop and the worker.
func TestRun_AsyncDelivery(t *testing.T) {
	const frames = 20
	cfg := startMock(t, func(t *testing.T, conn *websocket.Conn) {
		sendAuth(t, conn)
		expectRealplay(t, conn)
		_ = conn.WriteJSON(map[string]interface{}{"errorCode": 0, "sdp": testSDP})
		for i := 0; i < frames; i++ {
			_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeVideoData, pFrame))
		}
		_ = conn.WriteMessage(websocket.BinaryMessage, PackMessage(MsgTypeSessionError, []byte("done")))
		time.Sleep(300 * time.Millisecond)
	})
	cfg.AsyncDelivery = 4 // deliberately smaller than the burst

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := connectAndPlay(t, cfg, ctx)

	var mu sync.Mutex
	var indexes []int
	var codecs []string
	c.OnVideoFrame = func(m *FrameMeta, _ []byte) {
		time.Sleep(2 * time.Millisecond) // slow consumer
		mu.Lock()
		indexes = append(indexes, m.FrameIndex)
		codecs = append(codecs, m.Codec)
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
	if len(indexes) != frames {
		t.Fatalf("delivered %d frames, want %d (async delivery dropped media)", len(indexes), frames)
	}
	for i, idx := range indexes {
		if idx != i+1 {
			t.Fatalf("frame %d has index %d: async delivery reordered the stream", i, idx)
		}
		if codecs[i] != "H264" {
			t.Fatalf("frame %d codec = %q: media info was not applied before the frames", i, codecs[i])
		}
	}
}
