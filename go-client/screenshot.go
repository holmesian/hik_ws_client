package hikws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// VideoSaver manages an ffmpeg process that decodes the video stream
// into an MJPEG pipe, then periodically saves JPEG frames to disk.
//
// Matches the Python play.py approach:
//   ffmpeg -hide_banner -sn -an -i pipe:0 -f image2pipe -vcodec mjpeg -v error pipe:1
type VideoSaver struct {
	pipeWriter *io.PipeWriter
	cmd        *exec.Cmd
	Prefix     string
	OutputDir  string
	Interval   time.Duration

	stopOnce sync.Once
	doneCh   chan struct{}

	// Callbacks
	OnJPEGFrame func(jpegData []byte) // called for every decoded JPEG frame

	// Diagnostics
	totalWritten int64
	mu           sync.Mutex
}

// NewVideoSaver starts an ffmpeg process to decode video and save screenshots.
func NewVideoSaver(ctx context.Context, outputDir, prefix string, intervalSeconds int) (*VideoSaver, error) {
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	reader, writer := io.Pipe()

	// Match Python play.py exactly — NO probesize/analyzeduration overrides
	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-hide_banner",
		"-sn", "-an",
		"-i", "pipe:0",
		"-f", "image2pipe",
		"-vcodec", "mjpeg",
		"-v", "error",
		"pipe:1",
	)

	cmd.Stdin = reader

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Read stderr in real-time to catch ffmpeg errors immediately
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start ffmpeg: %w", err)
	}

	log.Printf("VideoSaver [%s] ffmpeg started (pid=%d)", prefix, cmd.Process.Pid)

	doneCh := make(chan struct{})
	interval := time.Duration(intervalSeconds) * time.Second

	vs := &VideoSaver{
		pipeWriter: writer,
		cmd:        cmd,
		Prefix:     prefix,
		OutputDir:  outputDir,
		Interval:   interval,
		doneCh:     doneCh,
	}

	// Goroutine 1: read MJPEG frames from ffmpeg stdout and save periodically
	go vs.mjpegReader(ctx, stdoutPipe)

	// Goroutine 2: log ffmpeg stderr in real-time
	go vs.stderrLogger(stderrPipe)

	// Goroutine 3: wait for ffmpeg to exit
	go func() {
		defer close(doneCh)
		err := cmd.Wait()
		if ctx.Err() != nil {
			log.Printf("VideoSaver [%s] stopped (context cancelled). Total written: %d bytes", prefix, vs.totalWritten)
		} else if err != nil {
			log.Printf("VideoSaver [%s] ffmpeg exited with error: %v. Total written: %d bytes", prefix, err, vs.totalWritten)
		} else {
			log.Printf("VideoSaver [%s] stopped normally. Total written: %d bytes", prefix, vs.totalWritten)
		}
		_ = writer.Close()
	}()

	return vs, nil
}

// stderrLogger reads ffmpeg stderr and logs any output
func (vs *VideoSaver) stderrLogger(r io.Reader) {
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			log.Printf("VideoSaver [%s] ffmpeg stderr: %s", vs.Prefix, string(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}

// mjpegReader reads MJPEG data from ffmpeg stdout, parses JPEG frames,
// and saves them at the configured interval.
func (vs *VideoSaver) mjpegReader(ctx context.Context, r io.Reader) {
	var buf []byte
	frameCount := 0
	lastSave := time.Now()
	totalStdoutBytes := 0
	lastDiag := time.Now()

	for {
		// Check context before blocking read
		select {
		case <-ctx.Done():
			return
		default:
		}

		tmp := make([]byte, 8192)
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			totalStdoutBytes += n
		}
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				log.Printf("VideoSaver [%s] stdout read error: %v", vs.Prefix, err)
			}
			break
		}

		// Periodic diagnostic
		if time.Since(lastDiag) >= 3*time.Second {
			vs.mu.Lock()
			written := vs.totalWritten
			vs.mu.Unlock()
			log.Printf("VideoSaver [%s] diag: ffmpeg_out=%d bytes, jpeg_frames=%d, pipe_written=%d bytes",
				vs.Prefix, totalStdoutBytes, frameCount, written)
			lastDiag = time.Now()
		}

		// Extract all complete JPEG frames from the buffer
		for {
			start := bytes.Index(buf, []byte{0xFF, 0xD8})
			if start == -1 {
				buf = nil
				break
			}
			end := bytes.Index(buf[start:], []byte{0xFF, 0xD9})
			if end == -1 {
				break
			}
			end += start + 2

			jpegData := buf[start:end]
			buf = buf[end:]

			frameCount++
			if frameCount == 1 {
				log.Printf("VideoSaver [%s] first JPEG frame decoded: %d bytes", vs.Prefix, len(jpegData))
			}

			// Notify callback for every decoded JPEG frame
			if vs.OnJPEGFrame != nil {
				vs.OnJPEGFrame(jpegData)
			}

			// Save frame at configured interval
			if time.Since(lastSave) >= vs.Interval {
				filename := filepath.Join(vs.OutputDir,
					fmt.Sprintf("%s_%s_%04d.jpg", vs.Prefix,
						time.Now().Format("20060102_150405"), frameCount))
				if err := os.WriteFile(filename, jpegData, 0644); err != nil {
					log.Printf("VideoSaver [%s] save error: %v", vs.Prefix, err)
				} else {
					log.Printf("VideoSaver [%s] saved screenshot: %s (%d bytes)", vs.Prefix, filename, len(jpegData))
				}
				lastSave = time.Now()
			}
		}
	}
}

// Write video data directly to the ffmpeg pipe.
func (vs *VideoSaver) Write(data []byte) (int, error) {
	n, err := vs.pipeWriter.Write(data)
	vs.mu.Lock()
	vs.totalWritten += int64(n)
	vs.mu.Unlock()
	return n, err
}

// Close closes the pipe and stops ffmpeg.
func (vs *VideoSaver) Close() error {
	var err error
	vs.stopOnce.Do(func() {
		err = vs.pipeWriter.Close()
	})
	return err
}
