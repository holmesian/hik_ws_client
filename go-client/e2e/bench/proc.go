package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// userHZ is the unit /proc/<pid>/stat reports CPU time in. The kernel exports
// it to userspace as a fixed 100 regardless of the internal tick rate, so it
// is a constant here rather than a sysconf call.
const userHZ = 100.0

// procSample is one point of the process-level resource time series.
type procSample struct {
	T          float64 `json:"t"`           // seconds since run start
	CPUSeconds float64 `json:"cpu_seconds"` // cumulative utime+stime
	RSSBytes   int64   `json:"rss_bytes"`
	Goroutines int     `json:"goroutines"`
	HeapAlloc  uint64  `json:"heap_alloc"`
	TotalAlloc uint64  `json:"total_alloc"`
	NumGC      uint32  `json:"num_gc"`
	NetRxBytes int64   `json:"net_rx_bytes"` // host-wide, see readNetRx
	Streams    int     `json:"streams"`      // streams running at this point
	RawBytes   int64   `json:"raw_bytes"`    // cumulative OnRawVideo bytes
	Frames     int64   `json:"frames"`       // cumulative delivered frames
}

// readProcSelf returns cumulative CPU seconds and current RSS for this
// process. Both come from /proc, which is the only place the numbers the
// kernel actually charges us are visible; runtime alone cannot see CPU time
// spent in syscalls and TLS.
func readProcSelf() (cpu float64, rss int64) {
	if b, err := os.ReadFile("/proc/self/stat"); err == nil {
		// Fields after the comm field, which may itself contain spaces —
		// split at the last ')' so a process name never shifts the indices.
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 {
			f := strings.Fields(string(b)[i+1:])
			// f[0] is state; utime is field 14 and stime field 15 of the
			// original line, i.e. f[11] and f[12] here.
			if len(f) > 12 {
				ut, _ := strconv.ParseFloat(f[11], 64)
				st, _ := strconv.ParseFloat(f[12], 64)
				cpu = (ut + st) / userHZ
			}
		}
	}
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 1 {
			pages, _ := strconv.ParseInt(f[1], 10, 64)
			rss = pages * int64(os.Getpagesize())
		}
	}
	return cpu, rss
}

// readNetRx sums received bytes over every interface except loopback.
//
// This is the cross-check for the OnRawVideo byte count, not a replacement:
// it is network-namespace wide, so it includes anything else running here,
// and it counts the whole wire — TLS records, WebSocket headers, TCP/IP
// headers and the protocol envelopes — where OnRawVideo counts only the
// container payload the library hands out. The ratio between them is the
// interesting number: a large gap means the transport, not the media, is
// what the bandwidth is spent on.
func readNetRx() int64 {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0
	}
	var total int64
	for _, line := range strings.Split(string(b), "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if name := strings.TrimSpace(line[:i]); name == "lo" {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) > 0 {
			n, _ := strconv.ParseInt(f[0], 10, 64)
			total += n
		}
	}
	return total
}

// sampler collects the process time series until stopped.
type sampler struct {
	start    time.Time
	interval time.Duration
	samples  []procSample
	counts   func() (streams int, rawBytes, frames int64)
}

func (s *sampler) run(done <-chan struct{}) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.take()
	for {
		select {
		case <-t.C:
			s.take()
		case <-done:
			s.take()
			return
		}
	}
}

func (s *sampler) take() {
	cpu, rss := readProcSelf()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	streams, raw, frames := s.counts()
	s.samples = append(s.samples, procSample{
		T:          time.Since(s.start).Seconds(),
		CPUSeconds: cpu,
		RSSBytes:   rss,
		Goroutines: runtime.NumGoroutine(),
		HeapAlloc:  ms.HeapAlloc,
		TotalAlloc: ms.TotalAlloc,
		NumGC:      ms.NumGC,
		NetRxBytes: readNetRx(),
		Streams:    streams,
		RawBytes:   raw,
		Frames:     frames,
	})
}

// between returns the samples bracketing [from,to] seconds, or nil when the
// window holds fewer than two points (nothing can be differenced).
func (s *sampler) between(from, to float64) (procSample, procSample, bool) {
	var lo, hi procSample
	haveLo := false
	for _, p := range s.samples {
		if p.T < from {
			continue
		}
		if p.T > to {
			break
		}
		if !haveLo {
			lo, haveLo = p, true
		}
		hi = p
	}
	if !haveLo || hi.T <= lo.T {
		return lo, hi, false
	}
	return lo, hi, true
}
