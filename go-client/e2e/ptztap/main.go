// Command ptztap answers one question with a controlled differential: while
// the camera is physically turning, does its video stream carry anything that
// says so?
//
// A passive census of 94 cameras already established what is in the stream
// when nothing moves (samples/README.md). That is the baseline, not the
// answer — nobody had ever looked at the same stream during a move. So this
// tool drives both sides itself, in one process: fetch the play URL, connect,
// record a quiet baseline, fire movePtzTimed at a recorded instant, keep
// recording, then move back. Every sample carries a timestamp from the same
// clock as the PTZ request, which is the only thing that lets an anomaly in
// the stream be attributed to the move.
//
// It is a separate tool on purpose. probe stays "one connection, one
// diagnosis" and bench stays "many connections, throughput"; neither should
// grow a camera-steering mode. The library is not modified to serve this
// experiment either: the messages it discards are read off its Verbose log.
//
// Nothing here loosens ADR-0004. If the answer had been "yes, layer N carries
// it", the next step is an ADR, not a parser.
//
// Usage:
//
//	HIK_OA_BASE=https://<host>/api.php HIK_OA_TOKEN=<bearer> \
//	  go run ./e2e/ptztap -ipc 306 -rounds 4 -out /tmp/ptztap-306.json
//	... -control     # same schedule, no PTZ request: the null experiment
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func main() {
	base := flag.String("base", os.Getenv("HIK_OA_BASE"), "device platform api.php endpoint (or HIK_OA_BASE)")
	token := flag.String("token", os.Getenv("HIK_OA_TOKEN"), "bearer token (or HIK_OA_TOKEN)")
	ipc := flag.Int("ipc", 0, "ipc_id of the camera to observe and move")
	protocol := flag.Int("protocol", 7, "getPlayUrl protocol")
	rounds := flag.Int("rounds", 4, "how many move/return rounds")
	baseline := flag.Duration("baseline", 10*time.Second, "quiet capture before each move")
	post := flag.Duration("post", 10*time.Second, "capture between the move and the return move")
	durMs := flag.Int("duration-ms", 240, "movePtzTimed duration_ms (the platform clamps to 999 and floors the actual motion at 50ms)")
	dirs := flag.String("dirs", "2,3,0,1", "direction codes to cycle through: 0 up, 1 down, 2 left, 3 right")
	control := flag.Bool("control", false, "control group: same schedule and same analysis, but no PTZ request is sent")
	guard := flag.Duration("guard", 1500*time.Millisecond, "frames this close to a move are neither motion nor baseline")
	out := flag.String("out", "", "write the full sample series to this JSON file")
	flag.Parse()

	if *ipc == 0 {
		log.Fatal("-ipc is required")
	}
	if *base == "" || *token == "" {
		log.Fatal("-base/-token (or HIK_OA_BASE/HIK_OA_TOKEN) are required; tokens are single-use, so the URL cannot be fetched by hand")
	}
	directions, err := parseDirs(*dirs)
	if err != nil {
		log.Fatal(err)
	}

	oa := newOAClient(*base, *token)
	// Fetch and connect back to back: the openUrl token expires within about
	// a minute, so anything between these two lines is a risk.
	playURL, err := oa.playURL(*ipc, *protocol)
	if err != nil {
		log.Fatalf("play url: %v", err)
	}
	config, err := hikws.ParseProxyURL(playURL)
	if err != nil {
		log.Fatalf("parse url: %v", err)
	}
	// Verbose is what makes layers 1-2 observable at all, and synchronous
	// delivery is what keeps the timestamps honest: with the async worker in
	// the way, a callback timestamp is a queue-drain time, not an arrival
	// time.
	config.Verbose = true
	config.AsyncDelivery = 0
	config.StallTimeout = 15 * time.Second
	config.MaxReconnects = 0

	run := &session{
		ipc: *ipc, control: *control, durationMs: *durMs, guardMs: float64(guard.Milliseconds()),
		Codec: "", started: time.Now(),
	}
	c := newCollector(run.started)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(&logTap{c: c, pass: os.Stderr})

	client := hikws.NewHikMediaClient(config)
	client.OnMediaInfo = func(mi *hikws.MediaInfo) { run.Codec, run.Container = mi.Codec, mi.Container }
	client.OnVideoFrame = c.onFrame
	client.OnRawVideo = c.onRawVideo
	client.OnAudioData = c.onAudio
	client.OnError = func(e error) { run.Errors = append(run.Errors, e.Error()) }

	total := time.Duration(*rounds)*(*baseline+*post) + time.Duration(*rounds)*6*time.Second + 30*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()

	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		if err := client.Stream(ctx); err != nil {
			log.Printf("stream ended: %v", err)
		}
	}()

	if !waitForFrames(c, 20*time.Second) {
		cancel()
		<-streamDone
		log.Fatalf("no video frames within 20s (ipc=%d); nothing to differentiate", *ipc)
	}

	run.Windows = runSchedule(oa, c, run, directions, *rounds, *baseline, *post)
	cancel()
	<-streamDone

	c.mu.Lock()
	run.Frames, run.Private, run.SEIs, run.WSMsgs = c.frames, c.private, c.seis, c.wsMsgs
	run.Blobs, run.VideoMsgs, run.AudioMsgs = c.blobs, c.videoMsgs, c.audioMsgs
	if run.Codec == "" {
		run.Codec = c.codec
	}
	c.mu.Unlock()

	fmt.Print(run.report())
	if *out != "" {
		blob, err := json.Marshal(run)
		if err != nil {
			log.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(*out, blob, 0644); err != nil {
			log.Fatalf("write %s: %v", *out, err)
		}
		log.Printf("wrote %s (%d frames, %d private records, %d SEI, %d ws msgs)",
			*out, len(run.Frames), len(run.Private), len(run.SEIs), len(run.WSMsgs))
	}
}

// waitForFrames blocks until the stream is actually producing, so the
// baseline window measures the stream rather than the connection setup.
func waitForFrames(c *collector, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.frames)
		c.mu.Unlock()
		if n >= 5 {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// ptzWindow is one move on the shared clock. SendT and ReturnT are measured
// locally; StartLatencyMs and AdjustedSleepMs come from the platform and
// narrow the window down to when the camera was really turning.
type ptzWindow struct {
	Round     int    `json:"round"`
	Direction int    `json:"direction"`
	Name      string `json:"name"`
	Reverse   bool   `json:"reverse"`
	Virtual   bool   `json:"virtual"` // control group: no request was sent

	SendT   float64 `json:"send_t_ms"`
	ReturnT float64 `json:"return_t_ms"`

	StartLatencyMs int    `json:"start_latency_ms"`
	AdjustedSleep  int    `json:"adjusted_sleep_ms"`
	StopSuccess    bool   `json:"stop_success"`
	Err            string `json:"error,omitempty"`
}

// motion is the interval the camera can actually have been moving in: it
// cannot start before the platform's start command lands, and the response
// only comes back after the stop command has.
// maxMotionMs caps how long a single move is allowed to be attributed to.
// The interval runs from the instant the platform reports the gimbal started
// to the instant the stop call came back, and that second edge is not always
// physical: one observed stop call took 12.5s to return while the gimbal had
// long since stopped. A <=900ms command plus acceleration, deceleration and
// the stop round-trip fits well inside 3s, so anything past that is the
// platform being slow, not the camera still turning.
const maxMotionMs = 3000

func (w ptzWindow) motion() (float64, float64) {
	lo := w.SendT + float64(w.StartLatencyMs)
	hi := w.ReturnT
	if hi > lo+maxMotionMs {
		hi = lo + maxMotionMs
	}
	return lo, hi
}

// runSchedule plays out the rounds. Each round is baseline → move → post →
// reverse move, so the camera is back where it started at the end of every
// round rather than only at the end of the run: if this process dies halfway
// through, a production camera is left at most one 240ms nudge off.
func runSchedule(oa *oaClient, c *collector, run *session, directions []int, rounds int, baseline, post time.Duration) []ptzWindow {
	var out []ptzWindow
	for r := 1; r <= rounds; r++ {
		dir := directions[(r-1)%len(directions)]
		log.Printf("=== round %d/%d: baseline %s, then direction %d ===", r, rounds, baseline, dir)
		time.Sleep(baseline)
		out = append(out, move(oa, c, run, r, dir, false))
		time.Sleep(post)
		out = append(out, move(oa, c, run, r, reverseOf(dir), true))
	}
	// A trailing quiet stretch: the last move needs somewhere to show up.
	time.Sleep(baseline)
	return out
}

func move(oa *oaClient, c *collector, run *session, round, dir int, reverse bool) ptzWindow {
	w := ptzWindow{Round: round, Direction: dir, Reverse: reverse, Virtual: run.control}
	w.SendT = c.now()
	if run.control {
		// The null experiment: burn the same wall clock the request would
		// have taken, mark the window virtual, send nothing.
		time.Sleep(time.Second)
		w.ReturnT, w.Name = c.now(), "virtual"
		return w
	}
	res, err := oa.movePtzTimed(run.ipc, dir, run.durationMs)
	w.ReturnT = c.now()
	if err != nil {
		w.Err = err.Error()
		log.Printf("PTZ %d failed: %v", dir, err)
		return w
	}
	w.Name, w.StartLatencyMs, w.AdjustedSleep, w.StopSuccess =
		res.DirectionName, res.StartLatencyMs, res.AdjustedSleep, res.StopSuccess
	log.Printf("PTZ direction=%d(%s) sent@%.0fms returned@%.0fms startLatency=%dms sleep=%dms stop=%v",
		dir, res.DirectionName, w.SendT, w.ReturnT, res.StartLatencyMs, res.AdjustedSleep, res.StopSuccess)
	return w
}

func parseDirs(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			return nil, fmt.Errorf("bad direction %q", f)
		}
		if reverseOf(v) < 0 {
			return nil, fmt.Errorf("direction %d has no reverse; only 0-3 may be used here", v)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no directions")
	}
	return out, nil
}

// session is the whole record of one run: every sample, every window, and
// enough context to interpret them. It is deliberately free of the play URL,
// the proxy host and the device name — the file is meant to be shareable.
type session struct {
	IpcID     int         `json:"ipc_id"`
	Control   bool        `json:"control"`
	Codec     string      `json:"codec"`
	Container string      `json:"container"`
	Windows   []ptzWindow `json:"windows"`
	Errors    []string    `json:"errors,omitempty"`

	Frames  []frameSample   `json:"frames"`
	Private []privateSample `json:"private_stream"`
	SEIs    []seiSample     `json:"sei"`
	WSMsgs  []wsSample      `json:"ws_messages"`
	Blobs   map[string]string

	VideoMsgs int `json:"video_msgs"`
	AudioMsgs int `json:"audio_msgs"`

	ipc        int
	control    bool
	durationMs int
	guardMs    float64
	started    time.Time
}

// MarshalJSON fills the exported mirrors of the private fields before
// encoding, so the JSON carries the run's parameters without exposing the
// unexported bookkeeping.
func (s *session) MarshalJSON() ([]byte, error) {
	type alias session
	s.IpcID, s.Control = s.ipc, s.control
	return json.Marshal((*alias)(s))
}

// classify says whether a sample time falls inside a move, inside the guard
// band around one, or in undisturbed stream. Guard exists because the
// encoder does not recover instantly and frames arrive a little after they
// are captured; counting those as baseline would understate the contrast,
// counting them as motion would overstate it.
func (s *session) classify(t float64) string {
	for _, w := range s.Windows {
		lo, hi := w.motion()
		if t >= lo && t <= hi {
			return "motion"
		}
		if t >= w.SendT-s.guardMs && t <= hi+s.guardMs {
			return "guard"
		}
	}
	return "quiet"
}

type sizeStats struct {
	N              int
	Mean, Median   float64
	P95, Max, Min  float64
	KeyFrames      int
	MaxNonKey      float64
	MeanNonKey     float64
	MedianNonKey   float64
	MaxNonKeyRatio float64
}

func statsOf(frames []frameSample) sizeStats {
	st := sizeStats{}
	if len(frames) == 0 {
		return st
	}
	var all, nonkey []float64
	for _, f := range frames {
		all = append(all, float64(f.Size))
		if f.Key {
			st.KeyFrames++
		} else {
			nonkey = append(nonkey, float64(f.Size))
		}
	}
	st.N = len(all)
	st.Mean, st.Median, st.P95, st.Max, st.Min = mean(all), pct(all, 0.5), pct(all, 0.95), pct(all, 1), pct(all, 0)
	if len(nonkey) > 0 {
		st.MeanNonKey, st.MedianNonKey, st.MaxNonKey = mean(nonkey), pct(nonkey, 0.5), pct(nonkey, 1)
	}
	return st
}

// The layer-5 statistic, and the only one of the five layers worth scoring:
// the largest non-key access unit in a short window over the median non-key
// access unit in the stretch immediately before it. Two properties matter.
// It is relative, because a busy 4 Mbps site and a static wall share no
// absolute scale — only a camera's own recent past is a fair reference. And
// it is causal: the baseline is strictly earlier than the window, so the
// number is one a live consumer could actually compute, unlike a ratio taken
// against the whole run's quiet median with hindsight.
const (
	detWindowMs   = 1800
	detStepMs     = 200
	detBaselineMs = 8000
	detAlarmGapMs = 2000 // consecutive over-threshold candidates are one alarm
)

type detCandidate struct {
	T     float64 // centre of the window
	Ratio float64
}

func detect(frames []frameSample) []detCandidate {
	var nk []frameSample
	for _, f := range frames {
		if !f.Key {
			nk = append(nk, f)
		}
	}
	if len(nk) == 0 {
		return nil
	}
	end := nk[len(nk)-1].T
	var out []detCandidate
	for t := float64(detBaselineMs); t+detWindowMs <= end; t += detStepMs {
		var base, win []float64
		for _, f := range nk {
			switch {
			case f.T >= t-detBaselineMs && f.T < t:
				base = append(base, float64(f.Size))
			case f.T >= t && f.T < t+detWindowMs:
				win = append(win, float64(f.Size))
			}
		}
		// Too few frames either side and the ratio is noise, not a measurement.
		if len(base) < 30 || len(win) < 10 {
			continue
		}
		med := pct(base, 0.5)
		if med <= 0 {
			continue
		}
		out = append(out, detCandidate{T: t + detWindowMs/2, Ratio: pct(win, 1) / med})
	}
	return out
}

// alarms counts distinct over-threshold events rather than over-threshold
// candidates: the windows overlap, so one spike lights up nine of them.
func alarms(cands []detCandidate, threshold float64) int {
	n := 0
	last := math.Inf(-1)
	for _, c := range cands {
		if c.Ratio >= threshold {
			if c.T-last > detAlarmGapMs {
				n++
			}
			last = c.T
		}
	}
	return n
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	i := int(p * float64(len(c)-1))
	return c[i]
}

// report prints the layer-by-layer verdict for this run.
func (s *session) report() string {
	var b strings.Builder
	mode := "PTZ"
	if s.control {
		mode = "CONTROL (no PTZ sent)"
	}
	fmt.Fprintf(&b, "\n==== ptztap ipc=%d %s ====\n", s.ipc, mode)
	fmt.Fprintf(&b, "container=%s codec=%s frames=%d windows=%d errors=%v\n",
		s.Container, s.Codec, len(s.Frames), len(s.Windows), s.Errors)

	var motion, quiet []frameSample
	for _, f := range s.Frames {
		switch s.classify(f.T) {
		case "motion":
			motion = append(motion, f)
		case "quiet":
			quiet = append(quiet, f)
		}
	}
	m, q := statsOf(motion), statsOf(quiet)

	fmt.Fprintf(&b, "\n-- layer 1/2: websocket messages --\n")
	byKind := map[string]map[string]int{}
	for _, w := range s.WSMsgs {
		cls := s.classify(w.T)
		if byKind[w.Kind] == nil {
			byKind[w.Kind] = map[string]int{}
		}
		byKind[w.Kind][cls]++
	}
	// OnRawVideo fires once per de-encapsulated payload, whatever envelope it
	// arrived in, so these two are the counts of media that reached the
	// caller; the log-derived kinds above account for how it was wrapped.
	byKind["video-payloads"] = map[string]int{"total": s.VideoMsgs}
	byKind["audio-payloads"] = map[string]int{"total": s.AudioMsgs}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(&b, "  %-22s %v\n", k, byKind[k])
	}

	fmt.Fprintf(&b, "\n-- layer 3: 0xBD private stream --\n")
	pm, pq := 0, 0
	lens := map[int]int{}
	digestsMotion, digestsQuiet := map[string]bool{}, map[string]bool{}
	for _, p := range s.Private {
		lens[p.DataLen]++
		switch s.classify(p.T) {
		case "motion":
			pm++
			digestsMotion[p.Digest] = true
		case "quiet":
			pq++
			digestsQuiet[p.Digest] = true
		}
	}
	fmt.Fprintf(&b, "  records=%d payloadLens=%v distinct=%d\n", len(s.Private), lens, len(s.Blobs))
	fmt.Fprintf(&b, "  in-motion=%d (distinct %d)  quiet=%d (distinct %d)\n",
		pm, len(digestsMotion), pq, len(digestsQuiet))
	onlyMotion := 0
	for d := range digestsMotion {
		if !digestsQuiet[d] {
			onlyMotion++
		}
	}
	fmt.Fprintf(&b, "  payloads seen only while moving: %d\n", onlyMotion)

	fmt.Fprintf(&b, "\n-- layer 4: SEI --\n")
	if len(s.SEIs) == 0 {
		fmt.Fprintf(&b, "  none in %d access units\n", len(s.Frames))
	} else {
		types := map[string]int{}
		payloads := map[string][]string{}
		for _, e := range s.SEIs {
			cls := s.classify(e.T)
			types[fmt.Sprintf("nal%d/type%d/%dB/%s", e.NalType, e.PayloadType, e.PayloadSize, cls)]++
			if e.Hex != "" && len(payloads[cls]) < 4 {
				payloads[cls] = append(payloads[cls], e.Hex)
			}
		}
		keys := make([]string, 0, len(types))
		for k := range types {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-40s %d\n", k, types[k])
		}
		// The bytes, not just the counts: a payload that only ever counts up
		// is not a PTZ signal no matter how reliably it appears.
		for _, cls := range []string{"quiet", "guard", "motion"} {
			if len(payloads[cls]) > 0 {
				fmt.Fprintf(&b, "  payload %-6s %s\n", cls, strings.Join(payloads[cls], " "))
			}
		}
	}

	fmt.Fprintf(&b, "\n-- layer 5: access unit sizes --\n")
	fmt.Fprintf(&b, "  quiet : n=%-5d mean=%-9.0f median=%-8.0f p95=%-9.0f max=%-9.0f keys=%d\n",
		q.N, q.Mean, q.Median, q.P95, q.Max, q.KeyFrames)
	fmt.Fprintf(&b, "  motion: n=%-5d mean=%-9.0f median=%-8.0f p95=%-9.0f max=%-9.0f keys=%d\n",
		m.N, m.Mean, m.Median, m.P95, m.Max, m.KeyFrames)
	if q.MedianNonKey > 0 {
		fmt.Fprintf(&b, "  non-key median: quiet=%.0f motion=%.0f  ratio=%.2fx\n",
			q.MedianNonKey, m.MedianNonKey, m.MedianNonKey/q.MedianNonKey)
		fmt.Fprintf(&b, "  non-key max   : quiet=%.0f motion=%.0f  ratio=%.2fx\n",
			q.MaxNonKey, m.MaxNonKey, m.MaxNonKey/q.MaxNonKey)
	}
	for _, w := range s.Windows {
		lo, hi := w.motion()
		fmt.Fprintf(&b, "  window r%d dir=%d%s %.0f..%.0fms (startLat=%dms sleep=%dms) -> %s\n",
			w.Round, w.Direction, map[bool]string{true: "(rev)"}[w.Reverse], lo, hi,
			w.StartLatencyMs, w.AdjustedSleep, windowPeak(s.Frames, lo, hi, q.MedianNonKey))
	}
	// The same layer-5 evidence, scored the way a live consumer would have to
	// score it, against the quiet stretches of this very run. A move that
	// only stands out next to a baseline computed with hindsight is not a
	// detection, and a threshold is worth nothing without its false alarms.
	cands := detect(s.Frames)
	var quietCands []detCandidate
	for _, c := range cands {
		if s.classify(c.T) == "quiet" {
			quietCands = append(quietCands, c)
		}
	}
	fmt.Fprintf(&b, "\n-- layer 5 detector: peak non-key AU / median of the previous %ds --\n", detBaselineMs/1000)
	peaks := make([]float64, 0, len(s.Windows))
	for _, w := range s.Windows {
		lo, hi := w.motion()
		best := 0.0
		for _, c := range cands {
			if c.T >= lo-300 && c.T <= hi+300 && c.Ratio > best {
				best = c.Ratio
			}
		}
		peaks = append(peaks, best)
	}
	fmt.Fprintf(&b, "  window ratios: %s\n", strings.Trim(fmt.Sprintf("%.1f", peaks), "[]"))
	quietSec := float64(len(quietCands)) * detStepMs / 1000
	fmt.Fprintf(&b, "  quiet candidates: %d (%.0fs), max %.1fx\n", len(quietCands), quietSec, maxRatio(quietCands))
	for _, T := range []float64{3, 5, 8} {
		hit := 0
		for _, p := range peaks {
			if p >= T {
				hit++
			}
		}
		fa := alarms(quietCands, T)
		perMin := 0.0
		if quietSec > 0 {
			perMin = float64(fa) / (quietSec / 60)
		}
		fmt.Fprintf(&b, "  T=%.0fx  detected %d/%d moves   false alarms %d (%.2f/min quiet)\n",
			T, hit, len(peaks), fa, perMin)
	}

	fmt.Fprintln(&b, "=======================================")
	return b.String()
}

func maxRatio(c []detCandidate) float64 {
	m := 0.0
	for _, x := range c {
		if x.Ratio > m {
			m = x.Ratio
		}
	}
	return m
}

// windowPeak describes what the access units did inside one move, relative to
// the run's quiet median. This is the number the whole layer-5 argument rests
// on, so it is printed per window rather than only in aggregate.
func windowPeak(frames []frameSample, lo, hi, quietMedian float64) string {
	var n int
	var maxSize float64
	keys := 0
	for _, f := range frames {
		if f.T < lo || f.T > hi {
			continue
		}
		n++
		if f.Key {
			keys++
			continue
		}
		if float64(f.Size) > maxSize {
			maxSize = float64(f.Size)
		}
	}
	if n == 0 {
		return "no frames"
	}
	ratio := 0.0
	if quietMedian > 0 {
		ratio = maxSize / quietMedian
	}
	return fmt.Sprintf("%d frames (%d key), peak non-key %.0fB = %.1fx quiet median", n, keys, maxSize, ratio)
}
