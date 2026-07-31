package hikws

import "testing"

func TestParseProxyURL(t *testing.T) {
	cases := []struct {
		name           string
		url            string
		host           string
		port           int
		deviceIP       string
		devicePort     int
		user, password string
	}{
		{
			name: "ipv6 with port and base64 password",
			// base64("auth_token") has no ':' → whole value is the password
			url:        "wss://example.com:6014/proxy/[1111::2222]:559/openUrl/YXV0aF90b2tlbg==",
			host:       "example.com",
			port:       6014,
			deviceIP:   "[1111::2222]",
			devicePort: 559,
			user:       "admin",
			password:   "auth_token",
		},
		{
			name:       "ipv4 with port and user:pass",
			url:        "wss://10.0.0.1/proxy/192.168.1.64:554/openUrl/YWRtaW46c2VjcmV0", // admin:secret
			host:       "10.0.0.1",
			port:       443,
			deviceIP:   "192.168.1.64",
			devicePort: 554,
			user:       "admin",
			password:   "secret",
		},
		{
			name:       "plain token, default rtsp port",
			url:        "wss://example.com:6014/proxy/192.168.1.64/openUrl/token!!",
			host:       "example.com",
			port:       6014,
			deviceIP:   "192.168.1.64",
			devicePort: 554,
			user:       "admin",
			password:   "token!!",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseProxyURL(tc.url)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ProxyHost != tc.host || cfg.ProxyPort != tc.port {
				t.Errorf("proxy = %s:%d, want %s:%d", cfg.ProxyHost, cfg.ProxyPort, tc.host, tc.port)
			}
			if cfg.DeviceIP != tc.deviceIP || cfg.DevicePort != tc.devicePort {
				t.Errorf("device = %s:%d, want %s:%d", cfg.DeviceIP, cfg.DevicePort, tc.deviceIP, tc.devicePort)
			}
			if cfg.Username != tc.user || cfg.Password != tc.password {
				t.Errorf("auth = %s/%s, want %s/%s", cfg.Username, cfg.Password, tc.user, tc.password)
			}
		})
	}
}

func TestParseProxyURL_Invalid(t *testing.T) {
	if _, err := ParseProxyURL("wss://example.com:6014/media?version=0.1"); err == nil {
		t.Fatal("expected error for a non-proxy path")
	}
}

func TestBuildMediaURL(t *testing.T) {
	cfg, err := ParseProxyURL("wss://example.com:6014/proxy/[fd00::10c]:559/openUrl/tok")
	if err != nil {
		t.Fatal(err)
	}
	got := NewHikMediaClient(cfg).buildMediaURL()
	want := "wss://example.com:6014/media?version=0.1&cipherSuites=0&sessionID=&proxy=[fd00::10c]:559"
	if got != want {
		t.Errorf("media url =\n%s\nwant\n%s", got, want)
	}
}
