package hikws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
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
	iv, key, err := GenerateClientIVKey()
	if err != nil {
		return err
	}

	if c.serverPKD != "" {
		c.secretKey, err = GenerateRealplayKey(iv, key, c.serverPKD)
		if err != nil {
			return fmt.Errorf("failed to generate realplay key: %w", err)
		}
	}

	deviceURL := fmt.Sprintf("ws://%s:%d/openUrl/%s", c.Config.DeviceIP, c.Config.DevicePort, c.Config.Password)

	authorization, err := GenerateAuthorization(c.serverRand, c.Config.Password, key, iv)
	if err != nil {
		return err
	}

	token, err := GenerateToken(deviceURL, key, iv)
	if err != nil {
		return err
	}

	// For Hikvision backend empty keys usually trigger video
	// The Python client explicitly left key="" but generated authorization/token.
	// You can switch "key" to c.secretKey if it expects it.
	reqData := map[string]interface{}{
		"sequence":      0,
		"cmd":           "realplay",
		"url":           deviceURL,
		"key":           "",
		"authorization": authorization,
		"token":         token,
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
				// Process Binary frame which could be multiple Hik Protocol messages or raw
				c.buffer = append(c.buffer, payload...)

				for {
					pType, data, remaining, err := UnpackMessage(c.buffer)
					if err != nil {
						// Not enough data for a complete packet, wait for more
						if err.Error() == "insufficient length for header" || err.Error() == "insufficient length for payload" {
							break
						}
						// If unpacking fails totally, might be raw video data.
						if c.OnVideoData != nil {
							c.OnVideoData(payload)
						}
						c.buffer = []byte{}
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
						// Keepalive pinged
					default:
						log.Printf("Received unhandled protocol message byte: 0x%02x\n", pType)
					}
					
					// Break if empty buffer
					if len(c.buffer) == 0 {
					    break
					}
				}
			}
		}
	}
}
