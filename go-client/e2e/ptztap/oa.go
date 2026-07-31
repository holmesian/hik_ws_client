package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// oaClient talks to the device platform that owns both the play URLs and the
// PTZ control endpoint. It lives in this tool rather than in the library:
// steering cameras is outside the component's scope (ADR-0004), and this is
// an experiment harness, not a feature.
type oaClient struct {
	base  string // .../api.php
	token string
	http  *http.Client
}

func newOAClient(base, token string) *oaClient {
	return &oaClient{base: base, token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

func (o *oaClient) do(req *http.Request, out interface{}) error {
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("authorization", "Bearer "+o.token)
	resp, err := o.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// playURL fetches a fresh openUrl address. The token in it is single-use and
// expires within about a minute, which is the whole reason this tool takes
// credentials instead of a URL: fetching and connecting have to happen in one
// process, back to back.
func (o *oaClient) playURL(ipcID, protocol int) (string, error) {
	q := url.Values{}
	q.Set("module", "ipc_device")
	q.Set("action", "getPlayUrl")
	q.Set("ipc_id", strconv.Itoa(ipcID))
	q.Set("protocol", strconv.Itoa(protocol))
	req, err := http.NewRequest(http.MethodGet, o.base+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			PlayURL string `json:"play_url"`
		} `json:"data"`
	}
	if err := o.do(req, &resp); err != nil {
		return "", err
	}
	if !resp.Success || resp.Data.PlayURL == "" {
		return "", fmt.Errorf("getPlayUrl failed: %s", resp.Message)
	}
	return resp.Data.PlayURL, nil
}

// ptzResult is what the platform reports about one timed move. The timing
// fields matter as much as the success flag: the platform issues start, sleeps
// and issues stop, so the camera is only actually moving from about
// StartLatencyMs after the request until the response comes back. Without
// those numbers a 240ms request looks like a 1s window.
type ptzResult struct {
	IpcID          int    `json:"ipc_id"`
	Direction      int    `json:"direction"`
	DirectionName  string `json:"direction_name"`
	DurationMs     int    `json:"duration_ms"`
	AdjustedSleep  int    `json:"adjusted_sleep_ms"`
	StartLatencyMs int    `json:"start_latency_ms"`
	StopSuccess    bool   `json:"stop_success"`
}

// movePtzTimed asks the platform to move the camera for duration_ms and stop.
// Direction codes are the platform's own: 0 up, 1 down, 2 left, 3 right
// (8/9 are zoom and are not used here).
func (o *oaClient) movePtzTimed(ipcID, direction, durationMs int) (*ptzResult, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"module":      "ipc_device",
		"action":      "movePtzTimed",
		"ipc_id":      ipcID,
		"direction":   direction,
		"duration_ms": durationMs,
	})
	req, err := http.NewRequest(http.MethodPost, o.base, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	var resp struct {
		Success bool       `json:"success"`
		Message string     `json:"message"`
		Data    *ptzResult `json:"data"`
	}
	if err := o.do(req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success || resp.Data == nil {
		return nil, fmt.Errorf("movePtzTimed failed: %s", resp.Message)
	}
	return resp.Data, nil
}

// reverseOf is the direction that undoes d. Production cameras must not be
// left pointing somewhere else because an experiment ran, so every move in
// this tool is paired with its opposite.
func reverseOf(d int) int {
	switch d {
	case 0:
		return 1
	case 1:
		return 0
	case 2:
		return 3
	case 3:
		return 2
	}
	return -1
}
