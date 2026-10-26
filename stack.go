// stack.go wires the engine's layer-3/4 stack dialer into mihomo's dial
// path.
//
// The engine injects its network stack (goose-plugin-api's StackDialer — the
// host kernel's system stack or the userspace gvisor netstack) into every
// outbound's config map under the reserved "_dialer" key. An outbound that
// consumes it routes its connection to its own server through the engine
// stack instead of opening a bare socket, so the engine governs the
// transport — the same ability the psiphon/tor/geph plugins consume through
// their providers.
//
// adapter.WithDialerForAPI is the injection point: it outranks every
// in-mapping dialer option inside mihomo (see upstream.go), and it takes
// mihomo's C.Dialer — a two-method interface the engine stack adapts to
// trivially. When the outbound also carries an upstream_proxy, the two
// COMPOSE: the socks5 upstream proxy is built with its own dialer set to the
// engine stack, so the hop to the upstream rides the engine stack and the
// SOCKS5 tunnel to the server runs on top — the same precedence the tor
// plugin implements for its upstream.
package mihomo

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"

	pub "github.com/goose-network/goose-plugin-api"
)

// engineStackDialer adapts pub.StackDialer to mihomo's C.Dialer. mihomo
// passes specific network names ("tcp", "tcp4", "udp6", ...); the stack
// dialer's contract is the family-agnostic "tcp"/"udp", so the name is
// normalized before passing through.
type engineStackDialer struct{ d pub.StackDialer }

func (s engineStackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if strings.Contains(network, "udp") {
		return s.d.Dial(ctx, "udp", address)
	}
	return s.d.Dial(ctx, "tcp", address)
}

// ListenPacket binds a local UDP socket — used by some mihomo outbounds
// (wireguard, hysteria, tuic) as their own data path. The engine stack
// exposes connected streams, not bound packet sockets, so this is refused;
// those outbound types fall back to... nothing, meaning UDP-transport
// outbounds need their server's UDP dials to go out some other way (an
// upstream socks5 with UDP ASSOCIATE, or the system stack when no engine
// stack dialer is injected).
func (s engineStackDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("mihomo: binding a UDP socket through the engine stack is not supported")
}

// proxyOptionsFor composes the adapter.ProxyOption list for one outbound:
//
//   - upstream only: the current behavior — the server connection transits
//     the socks5 upstream (dialed by the system dialer inside the upstream
//     proxy).
//   - upstream + stack: the socks5 upstream proxy is built with its own
//     dialer set to the engine stack, then wrapped as the outbound's dialer.
//     The hop to the upstream rides the engine stack; the SOCKS5 tunnel runs
//     on top.
//   - stack only: the server connection is dialed by the engine stack
//     directly.
//   - neither: nil — mihomo dials with its own defaults, exactly as before.
func proxyOptionsFor(upstream string, stack pub.StackDialer) ([]adapter.ProxyOption, error) {
	switch {
	case upstream != "" && stack != nil:
		d, err := upstreamDialerViaStack(upstream, stack)
		if err != nil {
			return nil, err
		}
		return []adapter.ProxyOption{adapter.WithDialerForAPI(d)}, nil
	case upstream != "":
		d, err := upstreamDialer(upstream)
		if err != nil {
			return nil, err
		}
		return []adapter.ProxyOption{adapter.WithDialerForAPI(d)}, nil
	case stack != nil:
		return []adapter.ProxyOption{adapter.WithDialerForAPI(engineStackDialer{stack})}, nil
	default:
		return nil, nil
	}
}

// upstreamDialerViaStack builds the upstream socks5 proxy whose own
// connection to the upstream server is dialed through the engine stack, then
// wraps it as a C.Dialer. The returned dialer, injected via
// WithDialerForAPI, carries the outbound's server traffic through
// stack → upstream socks5 → server.
func upstreamDialerViaStack(addr string, stack pub.StackDialer) (C.Dialer, error) {
	uc, err := parseUpstream(addr)
	if err != nil {
		return nil, err
	}
	if uc == nil {
		return nil, nil
	}
	p, err := adapter.ParseProxy(upstreamSocks5Mapping(uc), adapter.WithDialerForAPI(engineStackDialer{stack}))
	if err != nil {
		return nil, err
	}
	return proxydialer.New(p, false), nil
}
