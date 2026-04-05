package hikws

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// VideoSaver manages an ffmpeg process to periodically snapshot screens from raw video bytes
type VideoSaver struct {
	pipeWriter *io.PipeWriter
	cmd        *exec.Cmd
	Prefix     string
	OutputDir  string
	Interval   int // Seconds between snapshots
}

// NewVideoSaver starts to listen to video stream and save frames to OutputDir periodically
// Notice: requires ffmpeg installed on host machine
func NewVideoSaver(ctx context.Context, outputDir, prefix string, intervalSeconds int) (*VideoSaver, error) {
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	reader, writer := io.Pipe()

	// Use ffmpeg to consume stdin and output images at specified rate
	fpsVal := fmt.Sprintf("1/%d", intervalSeconds)
	if intervalSeconds == 1 {
		fpsVal = "1"
	}
	outPattern := filepath.Join(outputDir, fmt.Sprintf("%s_%%04d.jpg", prefix))

	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-hide_banner", "-loglevel", "error", "-y",
		"-i", "pipe:0", // Read from stdin pipe
		"-vf", fmt.Sprintf("fps=%s", fpsVal),
		"-f", "image2",
		outPattern,
	)

	cmd.Stdin = reader

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start ffmpeg: %w", err)
	}

	vs := &VideoSaver{
		pipeWriter: writer,
		cmd:        cmd,
		Prefix:     prefix,
		OutputDir:  outputDir,
		Interval:   intervalSeconds,
	}

	go func() {
		_ = cmd.Wait() // wait until context cancels or video exits
		_ = writer.Close()
		log.Printf("VideoSaver [%s] stopped.", prefix)
	}()

	return vs, nil
}

// Write Video data directly to the ffmpeg pipe
func (vs *VideoSaver) Write(data []byte) (int, error) {
	return vs.pipeWriter.Write(data)
}

// Close closes the pipe and stops ffmpeg
func (vs *VideoSaver) Close() error {
	return vs.pipeWriter.Close()
}
