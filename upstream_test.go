package mihomo

import (
	"testing"

	pub "github.com/goose-network/goose-plugin-api"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in   string
		want *upstreamConfig
		err  bool
	}{
		{"", nil, false},
		{"   ", nil, false},
		{"127.0.0.1:7890", &upstreamConfig{server: "127.0.0.1", port: 7890}, false},
		{"127.0.0.1", &upstreamConfig{server: "127.0.0.1", port: 1080}, false},
		{"socks5://127.0.0.1:7890", &upstreamConfig{server: "127.0.0.1", port: 7890}, false},
		{"socks5h://127.0.0.1:7890", &upstreamConfig{server: "127.0.0.1", port: 7890}, false},
		{
			"socks5://user:pass@10.0.0.1:1080",
			&upstreamConfig{server: "10.0.0.1", port: 1080, username: "user", password: "pass"},
			false,
		},
		{
			"user:pass@proxy.example.com:7890",
			&upstreamConfig{server: "proxy.example.com", port: 7890, username: "user", password: "pass"},
			false,
		},
		{
			"socks5://u%20ser:p%40ss@10.0.0.2:1080",
			&upstreamConfig{server: "10.0.0.2", port: 1080, username: "u ser", password: "p@ss"},
			false,
		},
		// IPv6 literal with port.
		{"[::1]:7890", &upstreamConfig{server: "::1", port: 7890}, false},
		{"[2001:db8::1]:7890", &upstreamConfig{server: "2001:db8::1", port: 7890}, false},
		// Bare IPv6: colons don't parse as one port — the whole thing stays
		// the host with the default port.
		{"::1", &upstreamConfig{server: "::1", port: 1080}, false},
		{"http://127.0.0.1:7890", nil, true},
		{":7890", nil, true},
		{"socks5://", nil, true},
	}
	for _, tc := range cases {
		got, err := parseUpstream(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("parseUpstream(%q) = %+v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUpstream(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if (got == nil) != (tc.want == nil) {
			t.Errorf("parseUpstream(%q) = %+v, want %+v", tc.in, got, tc.want)
			continue
		}
		if got == nil {
			continue
		}
		if got.server != tc.want.server || got.port != tc.want.port ||
			got.username != tc.want.username || got.password != tc.want.password {
			t.Errorf("parseUpstream(%q) = %+v, want %+v", tc.in, *got, *tc.want)
		}
	}
}

func TestUpstreamDialerNoUpstream(t *testing.T) {
	d, err := upstreamDialer("")
	if err != nil {
		t.Fatalf("upstreamDialer(\"\") error: %v", err)
	}
	if d != nil {
		t.Fatalf("upstreamDialer(\"\") = %v, want nil", d)
	}
}

func TestUpstreamDialerBuilds(t *testing.T) {
	d, err := upstreamDialer("127.0.0.1:7890")
	if err != nil {
		t.Fatalf("upstreamDialer error: %v", err)
	}
	if d == nil {
		t.Fatal("upstreamDialer returned nil dialer")
	}
}

func TestOutboundFactoryUpstreamWiring(t *testing.T) {
	factory, ok := pub.Lookup("mihomo-vless")
	if !ok {
		t.Fatal("mihomo-vless not registered")
	}
	o, err := factory(map[string]any{
		"id": "test-1",
		"proxy": map[string]any{
			"type":               "vless",
			"name":               "test",
			"server":             "relay.example.com",
			"port":               443,
			"uuid":               "00000000-0000-0000-0000-000000000001",
			"flow":               "xtls-rprx-vision",
			"tls":                true,
			"servername":         "www.microsoft.com",
			"client-fingerprint": "chrome",
			"reality-opts": map[string]any{
				// Any valid 32-byte x25519 public key (base64url, unpadded):
				// the build only parses it, never contacts the server.
				"public-key": "VDMPp33PahoMKyaUbZhfSCrGbFN246nKaz5_0x3yNUg",
				"short-id":   "0123",
			},
		},
		"upstream_proxy": "socks5://127.0.0.1:7890",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	out := o.(*Outbound)
	if out.upstream != "socks5://127.0.0.1:7890" {
		t.Fatalf("out.upstream = %q", out.upstream)
	}
	// Building with the upstream must succeed (the socks5 upstream proxy and
	// the vless proxy both parse), even though the upstream is not actually
	// listening — ensure only builds, it never connects.
	if err := out.ensure(); err != nil {
		t.Fatalf("ensure with upstream: %v", err)
	}
	if out.proxy == nil {
		t.Fatal("ensure did not set proxy")
	}
}

func TestOutboundFactoryRejectsBadUpstream(t *testing.T) {
	factory, ok := pub.Lookup("mihomo-vless")
	if !ok {
		t.Fatal("mihomo-vless not registered")
	}
	_, err := factory(map[string]any{
		"id": "test-2",
		"proxy": map[string]any{
			"type":   "vless",
			"name":   "test",
			"server": "relay.example.com",
			"port":   443,
			"uuid":   "00000000-0000-0000-0000-000000000001",
		},
		"upstream_proxy": "http://127.0.0.1:7890",
	})
	if err == nil {
		t.Fatal("factory accepted http:// upstream")
	}
}
