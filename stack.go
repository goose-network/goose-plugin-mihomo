// stack.go wires the engine's layer-3/4 stack dialer and upstream-route
// dialer into mihomo's dial path.
//
// The engine injects its network stack (goose-plugin-api's StackDialer — the
// host kernel's system stack or the userspace gvisor netstack) into every
// outbound's config map under the reserved "_dialer" key. An outbound that
// consumes it routes its connection to its own server through the engine
// stack instead of opening a bare socket, so the engine governs the
// transport — the same ability the psiphon/tor/geph plugins consume through
// their providers.
//
// When the outbound spec carries an upstream_proxy NAMING AN ENGINE ROUTE
// (outbound:/pool:/chain:), the engine instead injects an UpstreamDialer
// under the reserved "_upstream_dialer" key. That route outranks everything
// else: the server connection tunnels through the route's own members, and
// the raw socks5 "upstream_proxy" address form (upstream.go) is ignored.
//
// adapter.WithDialerForAPI is the injection point: it outranks every
// in-mapping dialer option inside mihomo (see upstream.go), and it takes
// mihomo's C.Dialer — a two-method interface both engine dialers adapt to
// trivially. When the outbound carries a raw upstream_proxy instead, the two
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

// engineUpstreamDialer adapts the engine's injected upstream-route dialer
// (goose-plugin-api's UpstreamDialer) to mihomo's C.Dialer. Every dial this
// proxy's server connection makes tunnels through the engine route the
// outbound spec names; the route's handshake is already done, so mihomo
// speaks its own protocol straight over the tunnel.
type engineUpstreamDialer struct{ d pub.UpstreamDialer }

func (u engineUpstreamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if strings.Contains(network, "udp") {
		return u.d.DialUpstream(ctx, "udp", address)
	}
	return u.d.DialUpstream(ctx, "tcp", address)
}

// ListenPacket is refused for the same reason as engineStackDialer's: the
// route exposes connected tunnels, not bound packet sockets, and the
// UDP-transport outbound types that need one are excluded from engine
// detours anyway (they dial unbound kernel sockets by design).
func (u engineUpstreamDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("mihomo: binding a UDP socket through an engine upstream route is not supported")
}

// proxyOptionsFor composes the adapter.ProxyOption list for one outbound:
//
//   - engine route: the server connection tunnels through the route the
//     spec's upstream_proxy names (resolved by the engine against live
//     config per dial) — the raw socks5 upstream form and the stack are
//     both superseded.
//   - raw upstream only: the server connection transits the socks5 upstream
//     (dialed by the system dialer inside the upstream proxy).
//   - raw upstream + stack: the socks5 upstream proxy is built with its own
//     dialer set to the engine stack, then wrapped as the outbound's
//     dialer. The hop to the upstream rides the engine stack; the SOCKS5
//     tunnel runs on top.
//   - stack only: the server connection is dialed by the engine stack
//     directly.
//   - none: nil — mihomo dials with its own defaults, exactly as before.
func proxyOptionsFor(upstream string, stack pub.StackDialer, route pub.UpstreamDialer) ([]adapter.ProxyOption, error) {
	switch {
	case route != nil:
		return []adapter.ProxyOption{adapter.WithDialerForAPI(engineUpstreamDialer{route})}, nil
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
