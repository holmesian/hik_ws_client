package hikws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
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

	buffer []byte
	mu     sync.Mutex
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
	return c.conn.WriteMessage(websocket.TextMessage, reqBytes)
}

func (c *HikMediaClient) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msgType, payload, err := c.conn.ReadMessage()
			if err != nil {
				if c.OnError != nil {
					c.OnError(fmt.Errorf("read error: %w", err))
				}
				return
			}

			if msgType == websocket.TextMessage {
				var resp map[string]interface{}
				if err := json.Unmarshal(payload, &resp); err == nil {
					if code, ok := resp["errorCode"].(float64); ok && code != 0 {
						if c.OnError != nil {
							c.OnError(fmt.Errorf("server message error: code=%v, msg=%v", code, resp["errorMsg"]))
						}
					}
				}
			} else if msgType == websocket.BinaryMessage {
				c.buffer = append(c.buffer, payload...)

				for len(c.buffer) >= 5 {
					// Peek at first byte — only known HikProtocol types should be parsed.
					// Raw video data (e.g. MPEG-PS starting with 0x00 0x00 0x01 0xBA)
					// will have a first byte that is NOT a valid protocol type.
					switch c.buffer[0] {
					case MsgTypeVideoData, MsgTypeAudioData, MsgTypeSessionError, MsgTypeKeepAlive:
						pType, data, remaining, err := UnpackMessage(c.buffer)
						if err != nil {
							// Not enough data for a complete packet, wait for more
							if err.Error() == "insufficient length for header" || err.Error() == "insufficient length for payload" {
								break
							}
							// Unexpected error, flush entire buffer as raw data
							if c.OnVideoData != nil {
								c.OnVideoData(c.buffer)
							}
							c.buffer = nil
							break
						}

						c.buffer = remaining

						switch pType {
						case MsgTypeVideoData:
							if c.OnVideoData != nil {
								c.OnVideoData(data)
							}
						case MsgTypeAudioData:
							if c.OnAudioData != nil {
								c.OnAudioData(data)
							}
						case MsgTypeSessionError:
							if c.OnError != nil {
								c.OnError(fmt.Errorf("session error: %s", string(data)))
							}
							return
						case MsgTypeKeepAlive:
							// keepalive, discard
						}

					default:
						// Unknown first byte (e.g. 0x00 from MPEG-PS header) — this is
						// raw video data, NOT a HikProtocol message. Forward entire
						// buffer contents to video pipeline without consuming any bytes.
						if c.OnVideoData != nil {
							c.OnVideoData(c.buffer)
						}
						c.buffer = nil
					}

					if len(c.buffer) == 0 {
						break
					}
				}
			}
		}
	}
}
