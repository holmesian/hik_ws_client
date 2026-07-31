// Command probe is the single live end-to-end tool: one connection, one
// token. It plays a stream, archives it under samples/<container>_<codec>/
// for offline research, and prints what the client actually recovered
// (container, codec, resolution, keyframes, PTS, fps).
//
// It is deliberately one tool rather than two. The openUrl tokens the proxy
// hands out are single-use and expire within about a minute, so a separate
// "analyze" run and "capture" run means the second one always fails with
// errorCode 28316423.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func main() {
	url := flag.String("url", "", "Hikvision proxy URL (wss://host:port/proxy/[ip]:port/openUrl/token)")
	dur := flag.Duration("dur", 15*time.Second, "how long to play")
	samples := flag.String("samples", "../samples", "sample archive root; the stream lands in <root>/<container>_<codec>/")
	name := flag.String("name", "", "override the archive sub-directory name")
	reconnects := flag.Int("reconnects", 2, "max reconnect attempts")
	stall := flag.Duration("stall", 10*time.Second, "abort a session after this long without data (0 disables)")
	async := flag.Int("async", 64, "async delivery queue depth (0 = deliver on the read loop)")
	flag.Parse()

	if *url == "" {
		log.Fatal("-url is required (tokens are single-use and short-lived; pass a fresh one)")
	}

	config, err := hikws.ParseProxyURL(*url)
	if err != nil {
		log.Fatalf("parse url: %v", err)
	}
	config.MaxReconnects = *reconnects
	config.ReconnectWait = 2 * time.Second
	config.StallTimeout = *stall
	config.AsyncDelivery = *async

	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; cancel() }()

	s := &stats{start: time.Now()}
	client := hikws.NewHikMediaClient(config)
	client.OnMediaInfo = func(mi *hikws.MediaInfo) {
		s.mu.Lock()
		s.info = mi
		s.mark(&s.tInfo)
		s.mu.Unlock()
		log.Printf("MEDIAINFO: container=%q codec=%q clock=%d paramsets=%d",
			mi.Container, mi.Codec, mi.ClockRate, len(mi.ParameterSets))
	}
	// Raw container bytes, verbatim and before demux: this is the artifact
	// worth archiving, because it is the only thing that reproduces a parser
	// bug offline.
	client.OnRawVideo = func(b []byte) {
		s.mu.Lock()
		s.mark(&s.tRaw)
		s.raw.Write(b)
		s.mu.Unlock()
	}
	client.OnSPS = func(b []byte) {
		s.mu.Lock()
		if s.sps == nil {
			s.sps = append([]byte(nil), b...)
		}
		s.mu.Unlock()
	}
	client.OnVideoFrame = s.frame
	client.OnError = func(e error) {
		s.mu.Lock()
		s.errs = append(s.errs, e.Error())
		s.mu.Unlock()
		log.Printf("ERROR: %v", e)
	}

	if err := client.Stream(ctx); err != nil {
		log.Printf("stream ended: %v", err)
	}

	summary := s.summarize()
	fmt.Print(summary)
	if err := s.archive(*samples, *name, summary); err != nil {
		log.Printf("archive: %v", err)
	}
}

type stats struct {
	mu      sync.Mutex
	info    *hikws.MediaInfo
	raw     bytes.Buffer // container bytes as received
	esBytes int          // size of the demuxed elementary stream
	sps     []byte

	frames, keyframes, ptsSeen int
	codec                      string
	minPTS, maxPTS             int64
	havePTS                    bool

	// Latency milestones, measured from the moment Stream is called: the
	// stream is only usable once a frame comes out, so "connected" is not
	// the number that matters to a caller.
	start               time.Time
	tInfo, tRaw, tFrame time.Duration
	errs                []string
}

// mark records a milestone the first time it happens. Caller holds s.mu.
func (s *stats) mark(d *time.Duration) {
	if *d == 0 {
		*d = time.Since(s.start)
	}
}

func (s *stats) frame(meta *hikws.FrameMeta, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mark(&s.tFrame)
	s.frames++
	s.esBytes += len(data)
	if meta.IsKeyFrame {
		s.keyframes++
	}
	if meta.Codec != "" {
		s.codec = meta.Codec
	}
	if meta.HasPTS {
		s.ptsSeen++
		if !s.havePTS {
			s.minPTS, s.maxPTS, s.havePTS = meta.PTS, meta.PTS, true
		}
		if meta.PTS < s.minPTS {
			s.minPTS = meta.PTS
		}
		if meta.PTS > s.maxPTS {
			s.maxPTS = meta.PTS
		}
	}
}

func (s *stats) summarize() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	container, clock, w, h := "", 0, 0, 0
	if s.info != nil {
		container, clock, w, h = s.info.Container, s.info.ClockRate, s.info.Width, s.info.Height
	}
	// The source URL is deliberately absent: host, internal proxy address and
	// openUrl token are all deployment secrets, and none of them says anything
	// about the bitstream. Samples are committed, so nothing identifying the
	// deployment may reach this file.
	fmt.Fprintln(&b, "==== probe summary ====")
	fmt.Fprintf(&b, "container   : %s\n", container)
	fmt.Fprintf(&b, "codec       : %s\n", s.codec)
	fmt.Fprintf(&b, "clockRate   : %d\n", clock)
	fmt.Fprintf(&b, "resolution  : %dx%d\n", w, h)
	fmt.Fprintf(&b, "frames      : %d\n", s.frames)
	fmt.Fprintf(&b, "keyframes   : %d\n", s.keyframes)
	fmt.Fprintf(&b, "rawBytes    : %d\n", s.raw.Len())
	fmt.Fprintf(&b, "esBytes     : %d\n", s.esBytes)
	fmt.Fprintf(&b, "latency     : mediainfo=%dms firstByte=%dms firstFrame=%dms\n",
		s.tInfo.Milliseconds(), s.tRaw.Milliseconds(), s.tFrame.Milliseconds())
	fmt.Fprintf(&b, "errors      : %d %v\n", len(s.errs), s.errs)
	if s.ptsSeen > 1 && clock > 0 && s.maxPTS > s.minPTS {
		span := s.maxPTS - s.minPTS
		fps := float64(s.ptsSeen-1) * float64(clock) / float64(span)
		fmt.Fprintf(&b, "pts         : %d frames, %d..%d (%d ticks @%dHz => %.2f fps)\n",
			s.ptsSeen, s.minPTS, s.maxPTS, span, clock, fps)
	} else {
		fmt.Fprintf(&b, "pts         : %d frames (no usable range)\n", s.ptsSeen)
	}
	fmt.Fprintln(&b, "=======================")
	return b.String()
}

// archive stores the sample under <root>/<container>_<codec>/ so different
// containers and codecs stay separated as more devices are tested.
func (s *stats) archive(root, name, summary string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.raw.Len() == 0 {
		return fmt.Errorf("nothing captured, not archiving")
	}
	container, sdp, height := "unknown", "", 0
	if s.info != nil {
		container, sdp, height = s.info.Container, s.info.SDP, s.info.Height
	}
	codec := s.codec
	if codec == "" {
		codec = "unknown"
	}
	if name == "" {
		// The resolution is part of the directory name so a second device
		// with the same container and codec lands beside the first instead
		// of overwriting it — different resolutions exercise different SPS.
		name = strings.ToLower(container + "_" + codec)
		if height > 0 {
			name = fmt.Sprintf("%s_%dp", name, height)
		}
	}
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Only the container bytes are archived. The elementary stream is fully
	// regenerable from them (that is what the library does), and MPEG-PS is a
	// standard container that ffprobe/ffplay read directly — keeping a second
	// multi-MB derived copy in the repo buys nothing.
	files := map[string][]byte{
		"stream" + containerExt(container): s.raw.Bytes(),
		"summary.txt":                      []byte(summary),
	}
	if sdp != "" {
		files["stream.sdp"] = []byte(sdp)
	}
	if s.sps != nil {
		files["sps.bin"] = s.sps
	}
	for fn, data := range files {
		if err := os.WriteFile(filepath.Join(dir, fn), data, 0644); err != nil {
			return err
		}
	}
	log.Printf("archived %d bytes to %s", s.raw.Len(), dir)
	return nil
}

func containerExt(c string) string {
	if c == "PS" {
		return ".ps"
	}
	return ".bin"
}
