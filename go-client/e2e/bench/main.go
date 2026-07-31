// Command bench measures what N concurrent streams cost: how many stay up,
// what they deliver, and what the process pays in CPU, memory, goroutines,
// garbage and bandwidth.
//
// It is a separate tool from e2e/probe on purpose. probe is a single-stream
// diagnostic that archives a sample and prints what the parser recovered;
// this one deliberately does not touch the disk (archiving would mix disk
// I/O into the resource numbers it exists to report) and says nothing about
// any individual stream's content beyond whether it kept flowing.
//
// URLs arrive on stdin, one per line, and a stream starts the instant a line
// is read. That is not a stylistic choice: the proxy's openUrl tokens are
// single-use and expire within about a minute, so collecting a batch of 64
// URLs and then connecting means the first ones are already dead — which
// produces a wall of errorCode 28316423 that reads exactly like a concurrency
// limit. Fetching and connecting have to be pipelined.
//
//	your-url-source -n 32 | go run ./e2e/bench -conc 32 -dur 60s -out /tmp/c32
//	go run ./e2e/bench -conc 32 -urls ./urls.txt -dur 60s -out /tmp/c32
//
// See README.md in this directory for the measured results.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type options struct {
	async      int
	stall      time.Duration
	reconnects int
	verify     bool
	archiveDir string
}

func main() {
	conc := flag.Int("conc", 0, "max concurrent streams (0 = start one per input line)")
	urls := flag.String("urls", "-", "URL source: a file, or - for stdin (read as a stream)")
	dur := flag.Duration("dur", 60*time.Second, "steady-state measurement window")
	settle := flag.Duration("settle", 10*time.Second, "delay between the last stream starting and the window opening")
	maxrun := flag.Duration("maxrun", 10*time.Minute, "hard cap on total run time")
	interval := flag.Duration("sample", time.Second, "resource sampling interval")
	async := flag.Int("async", 64, "AsyncDelivery queue depth (0 = deliver on the read loop)")
	stall := flag.Duration("stall", 10*time.Second, "abort a session after this long without data")
	reconnects := flag.Int("reconnects", 2, "max reconnect attempts per stream")
	verify := flag.Bool("verify", false, "strict PS structure walk on every stream (frame counts do not prove the bytes are intact)")
	archive := flag.String("archive", "", "archive raw container bytes into this directory (off by default: disk I/O pollutes the resource numbers)")
	out := flag.String("out", "", "write <out>.json and <out>.csv")
	label := flag.String("label", "", "label recorded in the report")
	cpuprofile := flag.String("cpuprofile", "", "write a CPU profile of the steady-state window here")
	memprofile := flag.String("memprofile", "", "write a heap profile at the end of the window here")
	quiet := flag.Bool("quiet", true, "silence the library's per-session log output")
	flag.Parse()

	if *quiet {
		// The library logs every realplay and every reconnect through the
		// standard logger. At 64 streams that is its own I/O workload.
		log.SetOutput(io.Discard)
	}
	o := options{async: *async, stall: *stall, reconnects: *reconnects, verify: *verify, archiveDir: *archive}
	if o.archiveDir != "" {
		if err := os.MkdirAll(o.archiveDir, 0755); err != nil {
			fatal("archive dir: %v", err)
		}
	}

	src, err := openSource(*urls)
	if err != nil {
		fatal("%v", err)
	}
	defer src.Close()

	r := &run{
		opts:   o,
		label:  *label,
		conc:   *conc,
		window: *dur,
		settle: *settle,
	}
	r.start(src, *maxrun, *interval, *cpuprofile)
	rep := r.report(*memprofile)

	fmt.Print(summary(rep))
	if *out != "" {
		if err := writeReport(*out, rep); err != nil {
			fatal("write report: %v", err)
		}
	}
}

func openSource(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

type run struct {
	opts   options
	label  string
	conc   int
	window time.Duration
	settle time.Duration

	startedAt      time.Time
	baseGoroutines int
	streams        []*streamStat
	live           atomic.Int64
	smp            *sampler
	winFrom        float64
	winTo          float64
}

// start reads URLs, launches a stream per URL as it arrives, then holds the
// fleet up long enough to measure it in steady state.
func (r *run) start(src io.Reader, maxrun, interval time.Duration, cpuprofile string) {
	r.baseGoroutines = runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(context.Background(), maxrun)
	defer cancel()

	r.startedAt = time.Now()
	r.smp = &sampler{start: r.startedAt, interval: interval, counts: r.counts}
	done := make(chan struct{})
	var smpWG sync.WaitGroup
	smpWG.Add(1)
	go func() { defer smpWG.Done(); r.smp.run(done) }()

	var wg sync.WaitGroup
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if r.conc > 0 && len(r.streams) >= r.conc {
			break
		}
		s := newStreamStat(len(r.streams))
		r.streams = append(r.streams, s)
		r.live.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer r.live.Add(-1)
			s.run(ctx, line, r.opts)
		}()
		fmt.Fprintf(os.Stderr, "\rstarted %d streams (%.0fs)", len(r.streams), time.Since(r.startedAt).Seconds())
	}
	fmt.Fprintf(os.Stderr, "\nramp done: %d streams in %.1fs; settling %s\n",
		len(r.streams), time.Since(r.startedAt).Seconds(), r.settle)

	sleepCtx(ctx, r.settle)
	// Counters are snapshotted, not reset: the window is a difference, so
	// nothing that happened during the ramp is attributed to it.
	for _, s := range r.streams {
		s.snapshotWindowStart()
	}
	r.winFrom = time.Since(r.startedAt).Seconds()
	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			fatal("cpuprofile: %v", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fatal("cpuprofile: %v", err)
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "window open at %.0fs for %s\n", r.winFrom, r.window)

	sleepCtx(ctx, r.window)
	r.winTo = time.Since(r.startedAt).Seconds()
	if cpuprofile != "" {
		pprof.StopCPUProfile()
	}

	cancel()
	wg.Wait()
	close(done)
	smpWG.Wait()
}

func (r *run) counts() (int, int64, int64) {
	var raw, frames int64
	for _, s := range r.streams {
		raw += s.rawBytes.Load()
		frames += s.frames.Load()
	}
	return int(r.live.Load()), raw, frames
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// report is the machine-readable result: one object per run, comparable
// across concurrency levels.
type report struct {
	Label      string  `json:"label"`
	Started    string  `json:"started"`
	Concurrent int     `json:"streams_started"`
	Streaming  int     `json:"streams_streaming"` // delivered frames inside the window
	WindowFrom float64 `json:"window_from"`
	WindowTo   float64 `json:"window_to"`
	Window     float64 `json:"window_seconds"`
	AsyncDepth int     `json:"async_depth"`
	NumCPU     int     `json:"num_cpu"`

	// Steady-state process cost.
	CPUCores      float64 `json:"cpu_cores"`      // CPU seconds burnt per wall second
	CPUPerStream  float64 `json:"cpu_per_stream"` // cores / streaming
	RSSBytes      int64   `json:"rss_bytes"`      // at window close
	RSSPerStream  int64   `json:"rss_per_stream"` // (RSS - baseline RSS) / streaming
	RSSBase       int64   `json:"rss_base"`       // RSS before any stream started
	Goroutines    int     `json:"goroutines"`
	GoroutinesPer float64 `json:"goroutines_per_stream"`
	HeapAlloc     uint64  `json:"heap_alloc"`
	AllocMBps     float64 `json:"alloc_mb_per_sec"` // TotalAlloc rate: the GC's actual input
	NumGC         uint32  `json:"gc_in_window"`
	GCPerSec      float64 `json:"gc_per_sec"`

	// Throughput.
	RawMbps       float64 `json:"raw_mbps"`    // OnRawVideo bytes
	NetRxMbps     float64 `json:"net_rx_mbps"` // /proc/net/dev, host-wide cross-check
	KbpsPerStream float64 `json:"kbps_per_stream"`
	FPSMean       float64 `json:"fps_mean"`
	FPSMin        float64 `json:"fps_min"`
	FirstFrameMs  []int64 `json:"first_frame_ms_percentiles"` // p50 p90 max

	Errors      map[string]int `json:"errors,omitempty"`
	ServerCodes map[int]int    `json:"server_codes,omitempty"`
	WalkDerails int            `json:"walk_derails"`
	WalkChecked int            `json:"walk_checked"`

	Streams []streamResult `json:"streams"`
	Samples []procSample   `json:"samples"`
}

func (r *run) report(memprofile string) *report {
	window := r.winTo - r.winFrom
	rep := &report{
		Label:       r.label,
		Started:     r.startedAt.Format(time.RFC3339),
		Concurrent:  len(r.streams),
		WindowFrom:  r.winFrom,
		WindowTo:    r.winTo,
		Window:      window,
		AsyncDepth:  r.opts.async,
		NumCPU:      runtime.NumCPU(),
		Errors:      map[string]int{},
		ServerCodes: map[int]int{},
	}

	var fpsSum float64
	var kbpsSum float64
	var firsts []int64
	rep.FPSMin = -1
	for _, s := range r.streams {
		s.finish(window)
		res := s.Result
		rep.Streams = append(rep.Streams, res)
		for k, v := range res.Errors {
			rep.Errors[k] += v
		}
		for k, v := range res.ServerCodes {
			rep.ServerCodes[k] += v
		}
		if s.walker != nil {
			rep.WalkChecked++
			if res.WalkDerail >= 0 {
				rep.WalkDerails++
			}
		}
		if !res.OK {
			continue
		}
		rep.Streaming++
		fpsSum += res.FPS
		kbpsSum += res.RawKbpsWindow
		if rep.FPSMin < 0 || res.FPS < rep.FPSMin {
			rep.FPSMin = res.FPS
		}
		if res.FirstFrameMs > 0 {
			firsts = append(firsts, res.FirstFrameMs)
		}
	}
	if rep.Streaming > 0 {
		rep.FPSMean = fpsSum / float64(rep.Streaming)
		rep.KbpsPerStream = kbpsSum / float64(rep.Streaming)
	}
	if rep.FPSMin < 0 {
		rep.FPSMin = 0
	}
	sort.Slice(firsts, func(i, j int) bool { return firsts[i] < firsts[j] })
	rep.FirstFrameMs = percentiles(firsts)

	if len(r.smp.samples) > 0 {
		rep.RSSBase = r.smp.samples[0].RSSBytes
	}
	if lo, hi, ok := r.smp.between(r.winFrom, r.winTo); ok {
		d := hi.T - lo.T
		rep.CPUCores = (hi.CPUSeconds - lo.CPUSeconds) / d
		rep.RSSBytes = hi.RSSBytes
		rep.Goroutines = hi.Goroutines - r.baseGoroutines
		rep.HeapAlloc = hi.HeapAlloc
		rep.AllocMBps = float64(hi.TotalAlloc-lo.TotalAlloc) / 1e6 / d
		rep.NumGC = hi.NumGC - lo.NumGC
		rep.GCPerSec = float64(rep.NumGC) / d
		rep.RawMbps = float64(hi.RawBytes-lo.RawBytes) * 8 / 1e6 / d
		rep.NetRxMbps = float64(hi.NetRxBytes-lo.NetRxBytes) * 8 / 1e6 / d
		if rep.Streaming > 0 {
			rep.CPUPerStream = rep.CPUCores / float64(rep.Streaming)
			rep.RSSPerStream = (rep.RSSBytes - rep.RSSBase) / int64(rep.Streaming)
			rep.GoroutinesPer = float64(rep.Goroutines) / float64(rep.Streaming)
		}
	}
	rep.Samples = r.smp.samples

	if memprofile != "" {
		if f, err := os.Create(memprofile); err == nil {
			runtime.GC()
			pprof.WriteHeapProfile(f)
			f.Close()
		}
	}
	return rep
}

func percentiles(sorted []int64) []int64 {
	if len(sorted) == 0 {
		return nil
	}
	at := func(p float64) int64 {
		i := int(p * float64(len(sorted)-1))
		return sorted[i]
	}
	return []int64{at(0.5), at(0.9), sorted[len(sorted)-1]}
}

func summary(r *report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "==== bench %s ====\n", r.Label)
	fmt.Fprintf(&b, "streams      : %d started, %d streaming in window\n", r.Concurrent, r.Streaming)
	fmt.Fprintf(&b, "window       : %.0fs..%.0fs (%.0fs), async=%d, cpus=%d\n", r.WindowFrom, r.WindowTo, r.Window, r.AsyncDepth, r.NumCPU)
	fmt.Fprintf(&b, "cpu          : %.3f cores total, %.4f cores/stream\n", r.CPUCores, r.CPUPerStream)
	fmt.Fprintf(&b, "rss          : %.1f MiB (base %.1f MiB, %.2f MiB/stream)\n",
		mib(r.RSSBytes), mib(r.RSSBase), mib(r.RSSPerStream))
	fmt.Fprintf(&b, "goroutines   : %d (%.1f/stream)\n", r.Goroutines, r.GoroutinesPer)
	fmt.Fprintf(&b, "heap         : %.1f MiB live, %.1f MB/s allocated, %d GC (%.2f/s)\n",
		mib(int64(r.HeapAlloc)), r.AllocMBps, r.NumGC, r.GCPerSec)
	fmt.Fprintf(&b, "bandwidth    : %.2f Mbit/s payload, %.2f Mbit/s on the wire, %.0f kbit/s per stream\n",
		r.RawMbps, r.NetRxMbps, r.KbpsPerStream)
	fmt.Fprintf(&b, "fps          : mean %.2f, min %.2f\n", r.FPSMean, r.FPSMin)
	if len(r.FirstFrameMs) == 3 {
		fmt.Fprintf(&b, "first frame  : p50 %dms p90 %dms max %dms\n", r.FirstFrameMs[0], r.FirstFrameMs[1], r.FirstFrameMs[2])
	}
	fmt.Fprintf(&b, "errors       : %v server=%v\n", r.Errors, r.ServerCodes)
	if r.WalkChecked > 0 {
		fmt.Fprintf(&b, "ps walk      : %d checked, %d derailed\n", r.WalkChecked, r.WalkDerails)
	}
	fmt.Fprintln(&b, "==========================")
	return b.String()
}

func mib(b int64) float64 { return float64(b) / (1 << 20) }

func writeReport(prefix string, r *report) error {
	jf, err := os.Create(prefix + ".json")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(jf)
	enc.SetIndent("", " ")
	if err := enc.Encode(r); err != nil {
		jf.Close()
		return err
	}
	if err := jf.Close(); err != nil {
		return err
	}

	cf, err := os.Create(prefix + ".csv")
	if err != nil {
		return err
	}
	defer cf.Close()
	w := csv.NewWriter(cf)
	defer w.Flush()
	head := []string{"index", "ok", "container", "codec", "res", "frames_window", "fps",
		"keyframes_window", "raw_kbps", "es_kbps", "mediainfo_ms", "first_frame_ms",
		"errors", "server_codes", "walk_elements", "walk_derail", "final"}
	if err := w.Write(head); err != nil {
		return err
	}
	for i, s := range r.Streams {
		row := []string{
			strconv.Itoa(i), strconv.FormatBool(s.OK), s.Container, s.Codec,
			fmt.Sprintf("%dx%d", s.Width, s.Height),
			strconv.FormatInt(s.FramesWindow, 10),
			strconv.FormatFloat(s.FPS, 'f', 2, 64),
			strconv.FormatInt(s.KeysWindow, 10),
			strconv.FormatFloat(s.RawKbpsWindow, 'f', 1, 64),
			strconv.FormatFloat(s.ESKbpsWindow, 'f', 1, 64),
			strconv.FormatInt(s.MediaInfoMs, 10),
			strconv.FormatInt(s.FirstFrameMs, 10),
			fmt.Sprint(s.Errors), fmt.Sprint(s.ServerCodes),
			strconv.Itoa(s.WalkElements), strconv.FormatInt(s.WalkDerail, 10),
			s.Final,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
