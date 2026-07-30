package hikws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// keepaliveInterval is how often a WebSocket ping is sent to keep the
// session alive; keepaliveWriteWait bounds each control-frame write.
const (
	keepaliveInterval  = 20 * time.Second
	keepaliveWriteWait = 5 * time.Second
)

type HikMediaClient struct {
	Config     *HikConfig
	conn       *websocket.Conn
	sessionID  string
	secretKey  string
	serverPKD  string
	serverRand string

	// Callbacks
	OnVideoData func([]byte)
	OnAudioData func([]byte)
	OnError     func(error)

	mu sync.Mutex
}

func NewHikMediaClient(config *HikConfig) *HikMediaClient {
	return &HikMediaClient{
		Config: config,
	}
}

func (c *HikMediaClient) buildMediaURL() string {
	proxy := fmt.Sprintf("%s:%d", c.Config.DeviceIP, c.Config.DevicePort)
	return fmt.Sprintf("wss://%s:%d/media?version=%s&cipherSuites=%d&sessionID=&proxy=%s",
		c.Config.ProxyHost, c.Config.ProxyPort, c.Config.Version, c.Config.CipherSuites, proxy)
}

func (c *HikMediaClient) Connect(ctx context.Context) error {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	url := c.buildMediaURL()
	header := http.Header{}
	header.Add("Sec-WebSocket-Protocol", "v1.0.0")

	conn, _, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		return fmt.Errorf("websocket dial error: %w", err)
	}

	c.conn = conn
	return nil
}

func (c *HikMediaClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// Authenticate reads the first message expecting PKD and rand
func (c *HikMediaClient) Authenticate() error {
	msgType, msg, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}

	if msgType != websocket.TextMessage {
		return fmt.Errorf("expected text message for auth, got %d", msgType)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(msg, &resp); err != nil {
		return err
	}

	if code, ok := resp["errorCode"].(float64); ok && code != 0 {
		return fmt.Errorf("server error %v: %v", code, resp["errorMsg"])
	}

	if pkd, ok := resp["PKD"].(string); ok {
		c.serverPKD = pkd
	}
	if randStr, ok := resp["rand"].(string); ok {
		c.serverRand = randStr
	}

	return nil
}

func (c *HikMediaClient) Realplay() error {
	deviceURL := fmt.Sprintf("ws://%s:%d/openUrl/%s", c.Config.DeviceIP, c.Config.DevicePort, c.Config.Password)

	// Match the Python client: send empty key/authorization/token
	// to trigger the server to return the video stream directly.
	reqData := map[string]interface{}{
		"sequence":      0,
		"cmd":           "realplay",
		"url":           deviceURL,
		"key":           "",
		"authorization": "",
		"token":         "",
	}

	reqBytes, _ := json.Marshal(reqData)
	log.Printf("Sending realplay request to %s", deviceURL)
	return c.conn.WriteMessage(websocket.TextMessage, reqBytes)
}

// Run processes incoming messages until context is cancelled or connection drops.
// This matches the Python client's receive_message + run loop behavior:
//   - Each binary WebSocket frame is unpacked and ALL protocol messages it
//     carries are dispatched (the server may batch several into one frame);
//     previously only the first was handled and the rest were dropped.
//   - If unpack succeeds with a known type → handle by type.
//   - If unpack succeeds with an unknown type → discard (matches Python).
//   - If unpack fails → treat the rest of the frame as raw video (matches Python).
// Per-frame logging is gated behind Config.Verbose to avoid log/alloc storms
// under multi-stream concurrency.
func (c *HikMediaClient) Run(ctx context.Context) {
	// Close the underlying connection when context is cancelled so that
	// ReadMessage unblocks immediately (the select+default pattern alone
	// cannot interrupt a blocking ReadMessage). The done channel makes the
	// watcher goroutine exit when Run returns, avoiding a goroutine leak.
	conn := c.conn
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	// Periodic WebSocket ping keepalive (WriteControl is safe for
	// concurrent use with other writes in gorilla/websocket).
	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				deadline := time.Now().Add(keepaliveWriteWait)
				if err := conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
					return
				}
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			// Context cancellation is not an error
			if ctx.Err() != nil {
				return
			}
			if c.OnError != nil {
				c.OnError(fmt.Errorf("read error: %w", err))
			}
			return
		}

		if msgType == websocket.TextMessage {
			var resp map[string]interface{}
			if err := json.Unmarshal(payload, &resp); err == nil {
				code, _ := resp["errorCode"].(float64)
				if code != 0 {
					msg, _ := resp["errorMsg"].(string)
					errMsg := fmt.Sprintf("server error code=%.0f msg=%s", code, msg)
					log.Print(errMsg)
					if c.OnError != nil {
						c.OnError(fmt.Errorf("%s", errMsg))
					}
				} else if sdp, ok := resp["sdp"].(string); ok && sdp != "" {
					log.Printf("realplay OK, SDP length=%d", len(sdp))
				}
			}

		} else if msgType == websocket.BinaryMessage {
			// ---- Match Python receive_message behaviour, but dispatch every
			// protocol message carried in this frame ----
			// Unpack until the frame is exhausted; a failed unpack means the
			// remaining bytes are raw video (matches Python WS_OP_BINARY path).
			buf := payload
			for len(buf) > 0 {
				pType, pData, remaining, unpackErr := UnpackMessage(buf)
				if unpackErr != nil {
					// Header incomplete / payload truncated → raw video data.
					if c.Config.Verbose {
						log.Printf("Raw video frame: %d bytes", len(buf))
					}
					if c.OnVideoData != nil {
						c.OnVideoData(buf)
					}
					break
				}

				switch pType {
				case MsgTypeVideoData:
					if c.Config.Verbose {
						log.Printf("Protocol video frame: %d bytes", len(pData))
					}
					if c.OnVideoData != nil {
						c.OnVideoData(pData)
					}
				case MsgTypeAudioData:
					if c.OnAudioData != nil {
						c.OnAudioData(pData)
					}
				case MsgTypeSessionError:
					if c.OnError != nil {
						c.OnError(fmt.Errorf("session error: %s", string(pData)))
					}
					return
				case MsgTypeKeepAlive:
					// keepalive — discard
				default:
					// Unknown protocol type (e.g. 0x00 stream metadata) —
					// discard, matching Python which has no handler for
					// unmatched msg_types.
					if c.Config.Verbose {
						log.Printf("Protocol msg 0x%02x: %d bytes (discarded)", pType, len(pData))
					}
				}

				buf = remaining
			}
		}
	}
}
