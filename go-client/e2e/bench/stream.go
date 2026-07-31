package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

// streamStat holds everything measured for one pull. The counters are atomic
// because the sampler reads them from another goroutine while the delivery
// worker writes them; taking a lock per frame would show up in the very
// numbers this tool exists to measure.
type streamStat struct {
	Index int `json:"index"`

	frames, keyframes atomic.Int64
	rawBytes, esBytes atomic.Int64

	mu        sync.Mutex
	started   time.Time
	tInfo     time.Duration
	tFirst    time.Duration
	container string
	codec     string
	width     int
	height    int
	// errKinds counts observed session failures by kind. Stream reconnects
	// after a stall or a read error, so these are the reconnect triggers;
	// a server error is terminal and ends the stream.
	errKinds map[string]int
	srvCodes map[int]int
	final    string
	walker   *psWalker
	archive  *os.File

	// Snapshot of the counters when the steady-state window opened.
	w0frames, w0keys, w0raw, w0es int64
	// Result of the window, filled in at the end.
	Result streamResult `json:"result"`
}

// streamResult is the per-stream row of the report. Everything rate-like is
// computed over the steady-state window only: including the ramp would blend
// connection setup into the per-stream cost, which is the number capacity
// planning actually needs.
type streamResult struct {
	OK            bool           `json:"ok"`
	Container     string         `json:"container"`
	Codec         string         `json:"codec"`
	Width         int            `json:"width"`
	Height        int            `json:"height"`
	FramesTotal   int64          `json:"frames_total"`
	FramesWindow  int64          `json:"frames_window"`
	KeysWindow    int64          `json:"keyframes_window"`
	FPS           float64        `json:"fps"`
	RawKbpsWindow float64        `json:"raw_kbps"`
	ESKbpsWindow  float64        `json:"es_kbps"`
	MediaInfoMs   int64          `json:"mediainfo_ms"`
	FirstFrameMs  int64          `json:"first_frame_ms"`
	Errors        map[string]int `json:"errors,omitempty"`
	ServerCodes   map[int]int    `json:"server_codes,omitempty"`
	Final         string         `json:"final,omitempty"`
	WalkElements  int            `json:"walk_elements,omitempty"`
	WalkDerail    int64          `json:"walk_derail,omitempty"`
}

func newStreamStat(idx int) *streamStat {
	return &streamStat{Index: idx, errKinds: map[string]int{}, srvCodes: map[int]int{}}
}

func (s *streamStat) snapshotWindowStart() {
	s.w0frames = s.frames.Load()
	s.w0keys = s.keyframes.Load()
	s.w0raw = s.rawBytes.Load()
	s.w0es = s.esBytes.Load()
}

func (s *streamStat) finish(window float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := streamResult{
		Container:    s.container,
		Codec:        s.codec,
		Width:        s.width,
		Height:       s.height,
		FramesTotal:  s.frames.Load(),
		FramesWindow: s.frames.Load() - s.w0frames,
		KeysWindow:   s.keyframes.Load() - s.w0keys,
		MediaInfoMs:  s.tInfo.Milliseconds(),
		FirstFrameMs: s.tFirst.Milliseconds(),
		Final:        s.final,
		WalkDerail:   -1,
	}
	if window > 0 {
		r.FPS = float64(r.FramesWindow) / window
		r.RawKbpsWindow = float64(s.rawBytes.Load()-s.w0raw) * 8 / 1000 / window
		r.ESKbpsWindow = float64(s.esBytes.Load()-s.w0es) * 8 / 1000 / window
	}
	r.OK = r.FramesWindow > 0
	if len(s.errKinds) > 0 {
		r.Errors = s.errKinds
	}
	if len(s.srvCodes) > 0 {
		r.ServerCodes = s.srvCodes
	}
	if s.walker != nil {
		r.WalkElements, r.WalkDerail = s.walker.Elements, s.walker.Derail
	}
	s.Result = r
}

// run drives one stream for the whole run and records what it cost.
func (s *streamStat) run(ctx context.Context, url string, o options) {
	config, err := hikws.ParseProxyURL(url)
	if err != nil {
		s.mu.Lock()
		s.final = "parse url: " + err.Error()
		s.mu.Unlock()
		return
	}
	config.MaxReconnects = o.reconnects
	config.ReconnectWait = 2 * time.Second
	config.StallTimeout = o.stall
	config.AsyncDelivery = o.async

	s.mu.Lock()
	s.started = time.Now()
	if o.verify {
		s.walker = newPSWalker()
	}
	if o.archiveDir != "" {
		f, ferr := os.Create(filepath.Join(o.archiveDir, fmt.Sprintf("stream%03d.ps", s.Index)))
		if ferr == nil {
			s.archive = f
		}
	}
	s.mu.Unlock()

	client := hikws.NewHikMediaClient(config)
	client.OnMediaInfo = func(mi *hikws.MediaInfo) {
		s.mu.Lock()
		if s.tInfo == 0 {
			s.tInfo = time.Since(s.started)
		}
		s.container, s.codec = mi.Container, mi.Codec
		s.mu.Unlock()
	}
	// OnRawVideo is the byte meter: it sees the container payload exactly as
	// the socket delivered it, before demux drops transport bytes.
	client.OnRawVideo = func(b []byte) {
		s.rawBytes.Add(int64(len(b)))
		if s.walker != nil {
			s.walker.Feed(b)
		}
		if s.archive != nil {
			s.archive.Write(b)
		}
	}
	// Every callback below runs on the one delivery goroutine of the session
	// in flight, so these two flags need no synchronisation of their own —
	// which keeps the hot path free of a lock the library itself does not take.
	var haveFirst, haveDims bool
	client.OnVideoFrame = func(meta *hikws.FrameMeta, data []byte) {
		s.frames.Add(1)
		s.esBytes.Add(int64(len(data)))
		if meta.IsKeyFrame {
			s.keyframes.Add(1)
		}
		if haveFirst && haveDims {
			return
		}
		s.mu.Lock()
		if !haveFirst {
			s.tFirst, haveFirst = time.Since(s.started), true
		}
		if meta.Codec != "" {
			s.codec = meta.Codec
		}
		if meta.Width > 0 {
			s.width, s.height, haveDims = meta.Width, meta.Height, true
		}
		s.mu.Unlock()
	}
	client.OnError = func(e error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var srv *hikws.ServerError
		switch {
		case errors.As(e, &srv):
			s.srvCodes[srv.Code]++
			s.errKinds["server"]++
		case errors.Is(e, hikws.ErrStalled):
			s.errKinds["stall"]++
		default:
			s.errKinds["read"]++
		}
	}

	err = client.Stream(ctx)
	s.mu.Lock()
	if err != nil {
		s.final = err.Error()
	}
	if s.archive != nil {
		s.archive.Close()
	}
	s.mu.Unlock()
}
