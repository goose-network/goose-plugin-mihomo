package mihomo

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"
)

// fakeStackDialer is a pub.StackDialer that records dials and returns a
// net.Pipe connection, so a test can observe the bytes a mihomo proxy pushes
// through the engine stack without any real socket. onConn, when set, runs
// on the pipe's peer end and plays the server on the other side.
type fakeStackDialer struct {
	mu       sync.Mutex
	dials    []string
	networks []string
	fail     bool
	onConn   func(net.Conn)
}

func (f *fakeStackDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	f.networks = append(f.networks, network)
	f.mu.Unlock()
	if f.fail {
		return nil, &net.OpError{Op: "dial", Err: errStackRefused}
	}
	c1, c2 := net.Pipe()
	if f.onConn != nil {
		go f.onConn(c2)
	} else {
		// Keep the pipe's read side from blocking the dialer when the test
		// does not drain it: close the peer when the dial's context is done.
		go func() {
			<-ctx.Done()
			c2.Close()
		}()
	}
	return c1, nil
}

// serveSocks5NoAuth completes a no-auth SOCKS5 handshake on conn's server
// side (greeting → method 0, CONNECT → success) and then parks until the
// peer closes. It lets a mihomo socks5 outbound finish its dial over a pipe
// the engine stack handed back.
func serveSocks5NoAuth(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, head[1])); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil { // no-auth
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		return
	}
	var addrLen int
	switch req[3] {
	case 1:
		addrLen = 4
	case 4:
		addrLen = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		addrLen = int(l[0])
	default:
		return
	}
	if _, err := io.ReadFull(br, make([]byte, addrLen+2)); err != nil {
		return
	}
	// Success reply, BND.ADDR 0.0.0.0:0.
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, conn)
}

type stackRefusedError struct{}

func (stackRefusedError) Error() string { return "fake stack: dial refused" }

var errStackRefused = stackRefusedError{}

// TestEngineStackDialerNormalizesNetwork verifies mihomo's family-specific
// network names collapse to the stack dialer's "tcp"/"udp" contract.
func TestEngineStackDialerNormalizesNetwork(t *testing.T) {
	fs := &fakeStackDialer{}
	d := engineStackDialer{fs}
	ctx := context.Background()

	for _, in := range []string{"tcp", "tcp4", "tcp6"} {
		fs.dials = nil
		fs.networks = nil
		// The dial returns a pipe nobody drains; only the recorded call
		// matters here. Close it right away.
		c, err := d.DialContext(ctx, in, "10.0.0.1:443")
		if err != nil {
			t.Fatalf("DialContext(%q): %v", in, err)
		}
		c.Close()
		if fs.networks[0] != "tcp" {
			t.Errorf("DialContext(%q) dialed network %q, want %q", in, fs.networks[0], "tcp")
		}
	}
	for _, in := range []string{"udp", "udp4", "udp6"} {
		fs.dials = nil
		fs.networks = nil
		c, err := d.DialContext(ctx, in, "10.0.0.1:443")
		if err != nil {
			t.Fatalf("DialContext(%q): %v", in, err)
		}
		c.Close()
		if fs.networks[0] != "udp" {
			t.Errorf("DialContext(%q) dialed network %q, want %q", in, fs.networks[0], "udp")
		}
	}
}

// TestEngineStackDialerListenPacketRefused verifies the packet-socket
// refusal: the engine stack exposes streams, not bound UDP sockets.
func TestEngineStackDialerListenPacketRefused(t *testing.T) {
	d := engineStackDialer{&fakeStackDialer{}}
	if _, err := d.ListenPacket(context.Background(), "udp", "0.0.0.0:0", netip.MustParseAddrPort("0.0.0.0:0")); err == nil {
		t.Fatal("ListenPacket through the engine stack unexpectedly succeeded")
	}
}

// TestProxyOptionsForPrecedence verifies the five composition branches.
func TestProxyOptionsForPrecedence(t *testing.T) {
	// Neither upstream nor stack: no options at all.
	opts, err := proxyOptionsFor("", nil, nil)
	if err != nil {
		t.Fatalf("proxyOptionsFor(neither): %v", err)
	}
	if len(opts) != 0 {
		t.Fatalf("proxyOptionsFor(neither) = %d options, want 0", len(opts))
	}

	fs := &fakeStackDialer{}

	// Stack only.
	opts, err = proxyOptionsFor("", fs, nil)
	if err != nil {
		t.Fatalf("proxyOptionsFor(stack): %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("proxyOptionsFor(stack) = %d options, want 1", len(opts))
	}

	// Upstream only.
	opts, err = proxyOptionsFor("127.0.0.1:7890", nil, nil)
	if err != nil {
		t.Fatalf("proxyOptionsFor(upstream): %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("proxyOptionsFor(upstream) = %d options, want 1", len(opts))
	}

	// Upstream composed over the stack.
	opts, err = proxyOptionsFor("127.0.0.1:7890", fs, nil)
	if err != nil {
		t.Fatalf("proxyOptionsFor(upstream+stack): %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("proxyOptionsFor(upstream+stack) = %d options, want 1", len(opts))
	}

	// An engine route outranks both the raw upstream form and the stack —
	// exactly one option, the route dialer.
	opts, err = proxyOptionsFor("127.0.0.1:7890", fs, &fakeUpstreamDialer{})
	if err != nil {
		t.Fatalf("proxyOptionsFor(route): %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("proxyOptionsFor(route) = %d options, want 1", len(opts))
	}

	// Bad upstream is an error in both upstream branches.
	if _, err := proxyOptionsFor("http://127.0.0.1:7890", nil, nil); err == nil {
		t.Fatal("proxyOptionsFor accepted http:// upstream")
	}
	if _, err := proxyOptionsFor("http://127.0.0.1:7890", fs, nil); err == nil {
		t.Fatal("proxyOptionsFor accepted http:// upstream with stack")
	}
}

// fakeUpstreamDialer is a pub.UpstreamDialer that records dials and returns
// a net.Pipe connection, so a test can observe the bytes a mihomo proxy
// pushes through the engine route. onConn, when set, runs on the pipe's
// peer end and plays the server on the other side.
type fakeUpstreamDialer struct {
	mu       sync.Mutex
	dials    []string
	networks []string
	fail     bool
	onConn   func(net.Conn)
}

func (f *fakeUpstreamDialer) DialUpstream(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	f.networks = append(f.networks, network)
	f.mu.Unlock()
	if f.fail {
		return nil, &net.OpError{Op: "dial", Err: errStackRefused}
	}
	c1, c2 := net.Pipe()
	if f.onConn != nil {
		go f.onConn(c2)
	} else {
		go func() {
			<-ctx.Done()
			c2.Close()
		}()
	}
	return c1, nil
}

// TestEngineUpstreamDialerNormalizesNetwork verifies mihomo's
// family-specific network names collapse to the route dialer's
// "tcp"/"udp" contract.
func TestEngineUpstreamDialerNormalizesNetwork(t *testing.T) {
	fu := &fakeUpstreamDialer{}
	d := engineUpstreamDialer{fu}
	ctx := context.Background()

	for _, in := range []string{"tcp", "tcp4", "tcp6"} {
		fu.dials = nil
		fu.networks = nil
		c, err := d.DialContext(ctx, in, "10.0.0.1:443")
		if err != nil {
			t.Fatalf("DialContext(%q): %v", in, err)
		}
		c.Close()
		if fu.networks[0] != "tcp" {
			t.Errorf("DialContext(%q) dialed network %q, want %q", in, fu.networks[0], "tcp")
		}
	}
	for _, in := range []string{"udp", "udp4", "udp6"} {
		fu.dials = nil
		fu.networks = nil
		c, err := d.DialContext(ctx, in, "10.0.0.1:443")
		if err != nil {
			t.Fatalf("DialContext(%q): %v", in, err)
		}
		c.Close()
		if fu.networks[0] != "udp" {
			t.Errorf("DialContext(%q) dialed network %q, want %q", in, fu.networks[0], "udp")
		}
	}
}

// TestEngineUpstreamDialerListenPacketRefused verifies the packet-socket
// refusal: an engine route exposes tunnels, not bound UDP sockets.
func TestEngineUpstreamDialerListenPacketRefused(t *testing.T) {
	d := engineUpstreamDialer{&fakeUpstreamDialer{}}
	if _, err := d.ListenPacket(context.Background(), "udp", "0.0.0.0:0", netip.MustParseAddrPort("0.0.0.0:0")); err == nil {
		t.Fatal("ListenPacket through an engine route unexpectedly succeeded")
	}
}

// TestOutboundFactoryConsumesRouteDialer verifies the factory type-asserts
// the engine-injected upstream-route dialer out of the config map.
func TestOutboundFactoryConsumesRouteDialer(t *testing.T) {
	factory, ok := pub.Lookup("mihomo-socks5")
	if !ok {
		t.Fatal("mihomo-socks5 not registered")
	}
	base := map[string]any{
		"id": "route-1",
		"proxy": map[string]any{
			"type":   "socks5",
			"name":   "route-test",
			"server": "10.9.8.7",
			"port":   1080,
		},
	}
	o, err := factory(base)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if o.(*Outbound).route != nil {
		t.Fatal("route dialer present without injection")
	}

	withRoute := map[string]any{
		"id":                  "route-2",
		"proxy":               base["proxy"],
		pub.UpstreamDialerKey: &fakeUpstreamDialer{},
	}
	o, err = factory(withRoute)
	if err != nil {
		t.Fatalf("factory (with route): %v", err)
	}
	if o.(*Outbound).route == nil {
		t.Fatal("injected route dialer not consumed")
	}
}

// TestOutboundDialsThroughEngineRoute is the behavioral proof: a dial
// through a mihomo-socks5 outbound must reach the proxy's server via the
// engine-injected route dialer, with the raw upstream form superseded. The
// fake route hands back a pipe whose peer completes the SOCKS5 handshake, so
// the dial succeeding at all proves the proxy's greeting and CONNECT bytes
// traversed the engine route — no real socket is ever opened.
func TestOutboundDialsThroughEngineRoute(t *testing.T) {
	fu := &fakeUpstreamDialer{onConn: serveSocks5NoAuth}
	factory, ok := pub.Lookup("mihomo-socks5")
	if !ok {
		t.Fatal("mihomo-socks5 not registered")
	}
	o, err := factory(map[string]any{
		"id": "route-dial",
		"proxy": map[string]any{
			"type":   "socks5",
			"name":   "route-dial-test",
			"server": "10.9.8.7",
			"port":   1080,
		},
		// Both injections present: the route must win.
		pub.UpstreamDialerKey: fu,
		"_dialer":             &fakeStackDialer{},
		"upstream_proxy":      "127.0.0.1:7890",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, pub.NetworkTCP, "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// The route must have been consulted exactly once, for the proxy's own
	// server address, over TCP.
	fu.mu.Lock()
	dials, networks := append([]string{}, fu.dials...), append([]string{}, fu.networks...)
	fu.mu.Unlock()
	if len(dials) != 1 {
		t.Fatalf("engine route dialed %d times, want 1", len(dials))
	}
	if dials[0] != "10.9.8.7:1080" {
		t.Fatalf("engine route dialed %q, want the proxy server 10.9.8.7:1080", dials[0])
	}
	if networks[0] != "tcp" {
		t.Fatalf("engine route network = %q, want tcp", networks[0])
	}
}

// TestOutboundFactoryConsumesStackDialer verifies the factory type-asserts
// the engine-injected stack dialer out of the config map.
func TestOutboundFactoryConsumesStackDialer(t *testing.T) {
	factory, ok := pub.Lookup("mihomo-socks5")
	if !ok {
		t.Fatal("mihomo-socks5 not registered")
	}
	base := map[string]any{
		"id": "stack-1",
		"proxy": map[string]any{
			"type":   "socks5",
			"name":   "stack-test",
			"server": "10.9.8.7",
			"port":   1080,
		},
	}
	o, err := factory(base)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if o.(*Outbound).stack != nil {
		t.Fatal("stack dialer present without injection")
	}

	withStack := map[string]any{
		"id":      "stack-2",
		"proxy":   base["proxy"],
		"_dialer": &fakeStackDialer{},
	}
	o, err = factory(withStack)
	if err != nil {
		t.Fatalf("factory (with stack): %v", err)
	}
	if o.(*Outbound).stack == nil {
		t.Fatal("injected stack dialer not consumed")
	}
}

// TestOutboundDialsThroughEngineStack is the behavioral proof: a dial
// through a mihomo-socks5 outbound must reach the proxy's server via the
// engine-injected stack dialer. The fake stack hands back a pipe whose peer
// completes the SOCKS5 handshake, so the dial succeeding at all proves the
// proxy's greeting and CONNECT bytes traversed the engine stack — no real
// socket is ever opened.
func TestOutboundDialsThroughEngineStack(t *testing.T) {
	fs := &fakeStackDialer{onConn: serveSocks5NoAuth}
	factory, ok := pub.Lookup("mihomo-socks5")
	if !ok {
		t.Fatal("mihomo-socks5 not registered")
	}
	o, err := factory(map[string]any{
		"id": "stack-dial",
		"proxy": map[string]any{
			"type":   "socks5",
			"name":   "stack-dial-test",
			"server": "10.9.8.7",
			"port":   1080,
		},
		"_dialer": fs,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, pub.NetworkTCP, "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// The stack must have been consulted exactly once, for the proxy's own
	// server address, over TCP.
	fs.mu.Lock()
	dials, networks := append([]string{}, fs.dials...), append([]string{}, fs.networks...)
	fs.mu.Unlock()
	if len(dials) != 1 {
		t.Fatalf("engine stack dialed %d times, want 1", len(dials))
	}
	if dials[0] != "10.9.8.7:1080" {
		t.Fatalf("engine stack dialed %q, want the proxy server 10.9.8.7:1080", dials[0])
	}
	if networks[0] != "tcp" {
		t.Fatalf("engine stack network = %q, want tcp", networks[0])
	}
}

// TestOutboundDialFailsWhenStackRefuses proves the stack is not optional at
// dial time: a refusing stack fails the dial rather than falling back to a
// bare system socket.
func TestOutboundDialFailsWhenStackRefuses(t *testing.T) {
	fs := &fakeStackDialer{fail: true}
	factory, ok := pub.Lookup("mihomo-socks5")
	if !ok {
		t.Fatal("mihomo-socks5 not registered")
	}
	o, err := factory(map[string]any{
		"id": "stack-fail",
		"proxy": map[string]any{
			"type":   "socks5",
			"name":   "stack-fail-test",
			"server": "10.9.8.7",
			"port":   1080,
		},
		"_dialer": fs,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := o.DialContext(ctx, pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("dial through a refusing engine stack unexpectedly succeeded")
	}
}
