package mihomo

import (
	"context"
	"encoding/base64"

	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"

	pub "github.com/goose-network/goose-plugin-api"
)

// TestParseSubscriptionClashYAML verifies the Clash YAML path: a `proxies:`
// list is parsed into mappings with the expected goose protocol names.
func TestParseSubscriptionClashYAML(t *testing.T) {
	body := []byte(`
proxies:
  - name: "socks-one"
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: "vmess-one"
    type: vmess
    server: 127.0.0.1
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    alterId: 0
    cipher: auto
`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("want 2 mappings, got %d: %+v", len(mappings), mappings)
	}
	if p, ok := ProtocolOf(mappings[0]); !ok || p != "mihomo-socks5" {
		t.Fatalf("first mapping protocol = %q ok=%v", p, ok)
	}
	if p, ok := ProtocolOf(mappings[1]); !ok || p != "mihomo-vmess" {
		t.Fatalf("second mapping protocol = %q ok=%v", p, ok)
	}
}

// TestParseSubscriptionV2RayLinks verifies the V2Ray-link-list path, both
// plain and base64-encoded.
func TestParseSubscriptionV2RayLinks(t *testing.T) {
	lines := []string{
		"socks5://127.0.0.1:1080#sock-a",
		"trojan://pass@example.com:443?sni=example.com#tro-a",
	}
	for name, body := range map[string][]byte{
		"plain":  []byte(strings.Join(lines, "\n")),
		"base64": []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))),
	} {
		mappings, err := ParseSubscription(body)
		if err != nil {
			t.Fatalf("%s: ParseSubscription: %v", name, err)
		}
		if len(mappings) != 2 {
			t.Fatalf("%s: want 2 mappings, got %d: %+v", name, len(mappings), mappings)
		}
		if p, ok := ProtocolOf(mappings[0]); !ok || p != "mihomo-socks5" {
			t.Fatalf("%s: first mapping protocol = %q ok=%v", name, p, ok)
		}
		if p, ok := ProtocolOf(mappings[1]); !ok || p != "mihomo-trojan" {
			t.Fatalf("%s: second mapping protocol = %q ok=%v", name, p, ok)
		}
	}
}

// TestParseSubscriptionSkipsGroups verifies group/special types are skipped.
func TestParseSubscriptionSkipsGroups(t *testing.T) {
	body := []byte(`
proxies:
  - name: "a"
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-groups:
  - name: "g"
    type: select
    proxies: ["a"]
`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	for _, m := range mappings {
		if p, ok := ProtocolOf(m); ok && strings.Contains(p, "select") {
			t.Fatalf("group leaked into outbounds: %+v", m)
		}
	}
}

// TestProviderOutboundsEndToEnd runs the full provider flow against a local
// subscription server: fetch + parse + emit goose outbound configs whose
// protocol factories can actually build a dialable mihomo proxy.
func TestProviderOutboundsEndToEnd(t *testing.T) {
	// A socks5 echo server the outbound will dial through.
	socksAddr, stopSocks := startMihomoTestSocks5(t)
	defer stopSocks()

	subBody := []byte(fmt.Sprintf("proxies:\n  - name: \"one\"\n    type: socks5\n    server: %s\n    port: %d\n",
		"127.0.0.1", mustPort(t, socksAddr)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(subBody)
	}))
	defer srv.Close()

	// The provider registered itself in init() as "mihomo"; build it the
	// way the engine's manager would.
	factory, ok := pub.LookupProvider("mihomo")
	if !ok {
		t.Fatal("provider mihomo not registered")
	}
	prov, err := factory(map[string]any{"url": srv.URL})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if prov.Name() != "mihomo" {
		t.Fatalf("Name = %q", prov.Name())
	}
	if prov.Watch() != nil {
		t.Fatal("Watch should be nil")
	}

	cfgs, err := prov.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("want 1 outbound config, got %d: %+v", len(cfgs), cfgs)
	}
	oc := cfgs[0]
	if oc.Protocol != "mihomo-socks5" {
		t.Fatalf("protocol = %q", oc.Protocol)
	}
	if !strings.HasPrefix(oc.ID, "mihomo-socks5-127.0.0.1:") {
		t.Fatalf("id = %q", oc.ID)
	}

	// The emitted config must be buildable by the registered outbound
	// factory and dialable through the socks5 server.
	build, ok := pub.Lookup(oc.Protocol)
	if !ok {
		t.Fatalf("outbound protocol %q not registered", oc.Protocol)
	}
	out, err := build(oc.Config)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if out.Protocol() != "mihomo-socks5" {
		t.Fatalf("out.Protocol = %q", out.Protocol())
	}
	if out.Address() == "" {
		t.Fatal("Address should carry the proxy server addr")
	}

	// Real dial through the mihomo-built socks5 proxy to the echo upstream.
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()
	conn, err := out.DialContext(context.Background(), pub.NetworkTCP, echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
}

// TestParseProxyRoundTrip sanity-checks that a mapping parsed from a
// subscription still round-trips through adapter.ParseProxy (the same call
// the outbound factory makes on first dial).
func TestParseProxyRoundTrip(t *testing.T) {
	mappings, err := ParseSubscription([]byte("socks5://127.0.0.1:1080#x\n"))
	if err != nil || len(mappings) != 1 {
		t.Fatalf("ParseSubscription: %v mappings=%d", err, len(mappings))
	}
	p, err := adapter.ParseProxy(mappings[0])
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if p.Addr() != "127.0.0.1:1080" {
		t.Fatalf("Addr = %q", p.Addr())
	}
}

// --- test servers ---

// startEchoServer runs a TCP server echoing what it reads.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// startMihomoTestSocks5 runs a minimal RFC1928 socks5 server (no-auth) that
// relays CONNECT targets to a plain echo... simplified: it accepts the
// handshake and then just echoes bytes, which is enough to prove the mihomo
// outbound completed a socks5 CONNECT.
func startMihomoTestSocks5(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSocks5(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// serveTestSocks5 performs the socks5 greeting + CONNECT handshake and then
// echoes (enough for the dial assertion).
func serveTestSocks5(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// request: VER CMD RSV ATYP ...
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var addrLen int
	switch req[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		addrLen = int(l[0])
	}
	if addrLen > 0 {
		if _, err := io.ReadFull(c, make([]byte, addrLen+2)); err != nil {
			return
		}
	}
	// success reply with a zero bound address.
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(c, c)
}

// mustPort extracts the port from a host:port string for building YAML.
func mustPort(t *testing.T, hostPort string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split %s: %v", hostPort, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port %s: %v", portStr, err)
	}
	return port
}
