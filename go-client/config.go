package hikws

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HikConfig represents the connection configuration for the Hikvision device.
type HikConfig struct {
	ProxyHost    string
	ProxyPort    int
	ProxyPath    string
	DeviceIP     string
	DevicePort   int
	Username     string
	Password     string
	Version      string
	CipherSuites int
	// Verbose enables per-frame debug logging. Leave false in production:
	// every video/audio frame would otherwise emit a log line, which
	// dominates I/O and allocates under multi-stream concurrency.
	Verbose bool

	// MaxReconnects is how many extra session attempts Stream makes after a
	// transport failure (dropped connection, stall, dial error). 0 disables
	// reconnection. Server-reported errors (expired token, bad credentials)
	// are never retried — reconnecting with the same URL cannot fix them.
	MaxReconnects int
	// ReconnectWait is the base backoff between attempts; the Nth retry waits
	// N*ReconnectWait. Defaults to 2s when zero.
	ReconnectWait time.Duration
	// StallTimeout aborts a session when no WebSocket message arrives within
	// this window. This is the only way to detect a silently dropped stream:
	// the proxy keeps the TCP connection open and simply stops sending media.
	// 0 disables the watchdog.
	StallTimeout time.Duration
	// AsyncDelivery, when > 0, moves demuxing and the user callbacks off the
	// socket read loop onto a worker fed by a buffered channel of this
	// capacity. It pipelines parsing with reading, so a slow consumer no
	// longer throttles the socket. Sends block when the buffer is full, so
	// no media is ever silently dropped.
	AsyncDelivery int

	// UserAgent overrides the User-Agent header sent on the wss dial.
	// Empty keeps the Go default ("Go-http-client/1.1", injected by
	// net/http when the handshake request carries none). Callers that
	// need to present a browser UA (e.g. HolmesAIEye's hikws ingest,
	// EAS-7537) set it explicitly; gorilla's Dialer writes the header
	// verbatim into the handshake request.
	UserAgent string

	// TLSConfig is the optional *tls.Config used for the wss handshake.
	// When nil, Connect verifies the server certificate with a secure
	// default (InsecureSkipVerify=false) — the previous hardcoded
	// InsecureSkipVerify:true was removed (issue #33). Set TLSConfig to:
	//   - supply a private CA (RootCAs) so wss to the Hikvision proxy does
	//     normal certificate validation;
	//   - attach client certificates;
	//   - or, only for test/self-signed setups, opt out of verification by
	//     setting InsecureSkipVerify:true.
	// The config is cloned before each dial, so a shared instance is never
	// mutated by the client.
	TLSConfig *tls.Config
}

// ParseProxyURL parses a Hikvision proxy URL to extract the configuration.
// Example: wss://example.com:6014/proxy/[fd00::10c]:559/openUrl/<token>
func ParseProxyURL(proxyURL string) (*HikConfig, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	host := u.Hostname()
	portStr := u.Port()
	port := 443
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}

	pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")

	if len(pathParts) < 2 || pathParts[0] != "proxy" {
		return nil, fmt.Errorf("invalid proxy path structure")
	}

	deviceInfo := pathParts[1]
	var deviceIP string
	var devicePort int = 554 // Default RTSP port

	if strings.Contains(deviceInfo, "]:") {
		// IPv6 with port
		parts := strings.SplitN(deviceInfo[1:], "]:", 2)
		deviceIP = "[" + parts[0] + "]"
		devicePort, _ = strconv.Atoi(parts[1])
	} else if strings.Count(deviceInfo, ":") == 1 {
		// IPv4 with port
		parts := strings.SplitN(deviceInfo, ":", 2)
		deviceIP = parts[0]
		devicePort, _ = strconv.Atoi(parts[1])
	} else {
		// Just IP
		deviceIP = deviceInfo
	}

	// Default credentials
	username := "admin"
	password := ""

	if len(pathParts) > 3 && pathParts[2] == "openUrl" {
		authPart := pathParts[3]
		// Try to base64 decode, if fails or doesn't have ":", use as password
		decoded, err := base64.StdEncoding.DecodeString(authPart)
		if err == nil && strings.Contains(string(decoded), ":") {
			parts := strings.SplitN(string(decoded), ":", 2)
			username = parts[0]
			password = parts[1]
		} else if err == nil {
			password = string(decoded)
		} else {
			password = authPart
		}
	}

	return &HikConfig{
		ProxyHost:    host,
		ProxyPort:    port,
		ProxyPath:    "/proxy/" + deviceInfo,
		DeviceIP:     deviceIP,
		DevicePort:   devicePort,
		Username:     username,
		Password:     password,
		Version:      "0.1",
		CipherSuites: 0,
	}, nil
}
