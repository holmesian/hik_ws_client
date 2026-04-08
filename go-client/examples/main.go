package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"

	hikws "github.com/holmesian/hik_ws_client/go-client"
)

func fetchStream(ctx context.Context, proxyURL string, streamID string, saveScreenshots bool) {
	config, err := hikws.ParseProxyURL(proxyURL)
	if err != nil {
		log.Fatalf("Stream %s: URL Parse err: %v", streamID, err)
	}

	client := hikws.NewHikMediaClient(config)

	err = client.Connect(ctx)
	if err != nil {
		log.Printf("Stream %s: Connect err: %v\n", streamID, err)
		return
	}
	defer client.Close()

	if err := client.Authenticate(); err != nil {
		log.Printf("Stream %s: Auth err: %v\n", streamID, err)
		return
	}

	if err := client.Realplay(); err != nil {
		log.Printf("Stream %s: Realplay err: %v\n", streamID, err)
		return
	}

	log.Printf("Stream %s: Connected securely, playing video...\n", streamID)

	var saver *hikws.VideoSaver
	if saveScreenshots {
		// Launch saver that saves 1 frame every second
		saver, err = hikws.NewVideoSaver(ctx, "./output", streamID, 1)
		if err != nil {
			log.Printf("Stream %s: Warning failed to start video saver: %v\n", streamID, err)
		} else {
			defer saver.Close()
		}
	}

	videoFrames := 0
	videoBytes := 0
	client.OnVideoData = func(data []byte) {
		videoFrames++
		videoBytes += len(data)
		if videoFrames <= 5 {
			log.Printf("Stream %s: video frame #%d: %d bytes\n", streamID, videoFrames, len(data))
		} else if videoFrames == 6 {
			log.Printf("Stream %s: ... (suppressing further logs)\n", streamID)
		}
		if saver != nil {
			_, _ = saver.Write(data)
		}
	}

	client.OnError = func(e error) {
		log.Printf("Stream %s: Runtime error: %v\n", streamID, e)
	}

	// Blocks until ctx completes or session drops
	client.Run(ctx)
	log.Printf("Stream %s: ended. Total: %d frames, %d bytes\n", streamID, videoFrames, videoBytes)
}

func main() {
	targetUrl1 := flag.String("url1", "wss://example.com:6014/proxy/[1111::1111]:559/openUrl/dummy1", "First stream URL")
	targetUrl2 := flag.String("url2", "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/dummy2", "Second stream URL")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Capture interrupt signal to gracefully stop
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Println("Stopping via interrupt...")
		cancel()
	}()

	// Launch multiple streams concurrently!
	urls := []string{*targetUrl1, *targetUrl2}

	for i, u := range urls {
		if u == "" {
			continue
		}
		wg.Add(1)
		streamID := fmt.Sprintf("Cam%d", i+1)
		go func(url, id string) {
			defer wg.Done()
			fetchStream(ctx, url, id, true)
		}(u, streamID)
	}

	wg.Wait()
	log.Println("All streams ended gracefully.")
}
