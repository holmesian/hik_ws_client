package hikws

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubFFmpeg installs a fake ffmpeg on PATH that emits two JPEG frames and
// then drains stdin, so the VideoSaver pipe/JPEG-framing/save logic can be
// tested without a real decoder.
func stubFFmpeg(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '\\377\\330JPEG-A\\377\\331\\377\\330JPEG-B\\377\\331'\ncat >/dev/null\n"
	path := filepath.Join(dir, "ffmpeg")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestVideoSaver_WritesJPEGFrames(t *testing.T) {
	stubFFmpeg(t)

	out := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// interval 0 → every decoded frame is saved
	saver, err := NewVideoSaver(ctx, out, "Cam1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := saver.Write(idrFrame); err != nil || n != len(idrFrame) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if err := saver.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var files []string
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(out, "Cam1_*.jpg"))
		if len(matches) >= 2 {
			files = matches
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(files) < 2 {
		t.Fatalf("saved %d screenshots, want 2", len(files))
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "JPEG-A") || data[0] != 0xFF || data[1] != 0xD8 {
		t.Errorf("first screenshot is not the expected JPEG: %q", data)
	}
}

func TestVideoSaver_CloseIsIdempotent(t *testing.T) {
	stubFFmpeg(t)

	saver, err := NewVideoSaver(context.Background(), t.TempDir(), "Cam2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := saver.Close(); err != nil {
		t.Fatal(err)
	}
	if err := saver.Close(); err != nil {
		t.Fatalf("second Close returned %v", err)
	}
}
