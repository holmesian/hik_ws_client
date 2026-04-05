package hikws

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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
}

// ParseProxyURL parses a Hikvision proxy URL to extract the configuration.
// Example: wss://example.com:6014/proxy/[fd00:0:2c0:9::10c]:559/openUrl/mYqWpMI
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
