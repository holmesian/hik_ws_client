// Command livetest connects to a Hikvision stream and reports what the
// go-client actually recovers: container, codec, resolution, frame count,
// keyframe count, real PTS range and the implied frame rate. It is the
// end-to-end check that the parser (PS demux + in-stream SPS) matches the
// device, rather than only the synthetic unit tests.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func main() {
	url := flag.String("url",
		"wss://ipcbasehkvideolj.coolmitech.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/EeHhP3i",
		"Hikvision proxy URL")
	dur := flag.Duration("dur", 10*time.Second, "how long to play")
	flag.Parse()

	config, err := hikws.ParseProxyURL(*url)
	if err != nil {
		log.Fatalf("parse url: %v", err)
	}
	config.Verbose = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; cancel() }()

	client := hikws.NewHikMediaClient(config)
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if err := client.Authenticate(); err != nil {
		log.Fatalf("authenticate: %v", err)
	}
	if err := client.Realplay(); err != nil {
		log.Fatalf("realplay: %v", err)
	}

	var (
		mu         sync.Mutex
		info       *hikws.MediaInfo
		frames     int64
		keyframes  int64
		bytesTotal int64
		ptsSeen    int64
		codecs     = map[string]int{}
		minPTS     int64 = -1
		maxPTS     int64 = -1
		firstPTS   int64
		resSeen    bool
	)

	client.OnMediaInfo = func(mi *hikws.MediaInfo) {
		mu.Lock()
		info = mi
		mu.Unlock()
		log.Printf("MEDIAINFO: container=%q codec=%q clock=%d paramsets=%d",
			mi.Container, mi.Codec, mi.ClockRate, len(mi.ParameterSets))
	}
	client.OnVideoFrame = func(meta *hikws.FrameMeta, data []byte) {
		atomic.AddInt64(&frames, 1)
		atomic.AddInt64(&bytesTotal, int64(len(data)))
		if meta.IsKeyFrame {
			atomic.AddInt64(&keyframes, 1)
		}
		if meta.Codec != "" {
			mu.Lock()
			codecs[meta.Codec]++
			mu.Unlock()
		}
		if meta.HasPTS {
			atomic.AddInt64(&ptsSeen, 1)
			p := meta.PTS
			mu.Lock()
			if minPTS < 0 {
				minPTS = p
				firstPTS = p
			}
			if p < minPTS {
				minPTS = p
			}
			if p > maxPTS {
				maxPTS = p
			}
			mu.Unlock()
		}
		mu.Lock()
		if meta.Width > 0 && meta.Height > 0 {
			resSeen = true
		}
		mu.Unlock()
	}
	client.OnError = func(e error) {
		log.Printf("ERROR: %v", e)
	}

	go func() { time.Sleep(*dur); cancel() }()

	client.Run(ctx)

	f := atomic.LoadInt64(&frames)
	kf := atomic.LoadInt64(&keyframes)
	bt := atomic.LoadInt64(&bytesTotal)
	ps := atomic.LoadInt64(&ptsSeen)

	mu.Lock()
	codec := ""
	for c := range codecs {
		codec = c
	}
	w, h := 0, 0
	cont := ""
	clk := 0
	if info != nil {
		w, h = info.Width, info.Height
		cont = info.Container
		clk = info.ClockRate
	}
	res := resSeen
	mu.Unlock()

	fmt.Println("==== livetest summary ====")
	fmt.Printf("url         : %s\n", *url)
	fmt.Printf("container   : %s\n", cont)
	fmt.Printf("codec       : %s\n", codec)
	fmt.Printf("clockRate   : %d\n", clk)
	fmt.Printf("resolution  : %dx%d (recovered from SPS: %v)\n", w, h, res)
	fmt.Printf("frames      : %d\n", f)
	fmt.Printf("keyframes   : %d\n", kf)
	fmt.Printf("bytes       : %d\n", bt)
	if ps > 0 {
		span := maxPTS - minPTS
		fps := 0.0
		if span > 0 && clk > 0 {
			fps = float64(ps-1) * float64(clk) / float64(span)
		}
		fmt.Printf("ptsSeen     : %d (first=%d last=%d range=%d @%dHz => %.2f fps)\n",
			ps, firstPTS, maxPTS, span, clk, fps)
	} else {
		fmt.Println("ptsSeen     : 0 (no real PTS; synthetic only)")
	}
	fmt.Println("============================")
}
