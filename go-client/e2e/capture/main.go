// Command capture connects to a Hikvision stream and dumps the raw video
// container to stream.ps plus the SDP to stream.ps.sdp, so the byte stream can
// be analyzed offline (e.g. with ffprobe) to confirm the container and codec
// the device actually sends.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func main() {
	url := flag.String("url",
		"wss://ipcbasehkvideolj.coolmitech.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/EeHhP3i",
		"Hikvision proxy URL")
	out := flag.String("out", "stream.ps", "raw payload output file")
	dur := flag.Duration("dur", 8*time.Second, "how long to capture")
	flag.Parse()

	config, err := hikws.ParseProxyURL(*url)
	if err != nil {
		log.Fatalf("parse url: %v", err)
	}

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

	f, err := os.Create(*out)
	if err != nil {
		log.Fatalf("create %s: %v", *out, err)
	}
	defer f.Close()

	var (
		mu     sync.Mutex
		wrote  int64
		frames int64
	)
	client.OnMediaInfo = func(mi *hikws.MediaInfo) {
		if err := os.WriteFile(*out+".sdp", []byte(mi.SDP), 0644); err == nil {
			log.Printf("wrote SDP to %s.sdp", *out)
		}
		log.Printf("MEDIAINFO: container=%q codec=%q clock=%d", mi.Container, mi.Codec, mi.ClockRate)
	}
	// Capture the raw PS container verbatim (before demux) for offline analysis.
	client.OnRawVideo = func(b []byte) {
		mu.Lock()
		n, _ := f.Write(b)
		wrote += int64(n)
		frames++
		mu.Unlock()
	}
	client.OnError = func(e error) { log.Printf("ERROR: %v", e) }

	go func() { time.Sleep(*dur); cancel() }()

	client.Run(ctx)

	log.Printf("captured %d bytes / %d frames to %s", wrote, frames, *out)
}
