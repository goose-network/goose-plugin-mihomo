// outbound.go implements the goose outbound protocol "mihomo-<type>" for
// every mihomo proxy type. The factory is shared: the provider registers the
// proxy mapping under cfg["proxy"], and each protocol name dispatches through
// the same builder.
package mihomo

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	pub "github.com/goose-network/goose-plugin-api"
)

// registeredTypes are the mihomo proxy types this plugin exposes as goose
// outbound protocols. Kept explicit (rather than wildcard) so the protocol
// surface is visible where the rest of goose lists protocols, and so an
// unknown type in a subscription is a visible skip rather than a silent
// runtime factory miss.
var registeredTypes = []string{
	"ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan",
	"hysteria", "hysteria2", "wireguard", "tuic", "ssh", "anytls", "mieru",
	"shadowquic", "gost-relay", "sudoku", "masque", "trusttunnel",
	"openvpn", "tailscale", "zerotier", "easytier",
}

func init() {
	for _, typ := range registeredTypes {
		pub.Register("mihomo-"+typ, newOutboundFactory(typ))
	}
}

// newOutboundFactory returns an OutboundFactory for one mihomo proxy type.
func newOutboundFactory(typ string) pub.OutboundFactory {
	return func(cfg map[string]any) (pub.Outbound, error) {
		raw, ok := cfg["proxy"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mihomo %s outbound: missing proxy mapping", typ)
		}
		id, _ := cfg["id"].(string)
		return &Outbound{id: id, proto: "mihomo-" + typ, mapping: raw}, nil
	}
}

// Outbound is a goose outbound backed by one mihomo proxy. The mihomo proxy
// object is built lazily on first dial: constructing a pool of hundreds of
// subscription proxies then costs no connections up front, and a mapping
// that fails to build is reported at dial time instead of pool-build time
// (matching how the engine tolerates broken outbounds).
type Outbound struct {
	id      string
	proto   string
	mapping map[string]any

	once   sync.Once
	proxy  C.Proxy
	buildE error
}

// ensure builds the mihomo proxy exactly once.
func (o *Outbound) ensure() error {
	o.once.Do(func() {
		// Copy the mapping so mihomo's decoder can't mutate our config.
		m := make(map[string]any, len(o.mapping))
		for k, v := range o.mapping {
			m[k] = v
		}
		// The provider already validated ParseProxy succeeds when it emitted
		// the config, so a failure here is unexpected but non-fatal: surface
		// it on every dial.
		p, err := adapter.ParseProxy(m)
		if err != nil {
			o.buildE = fmt.Errorf("mihomo outbound: build %s: %w", o.proto, err)
			return
		}
		o.proxy = p
	})
	return o.buildE
}

func (o *Outbound) ID() string       { return o.id }
func (o *Outbound) Protocol() string { return o.proto }

// Address returns the proxy's server address (mihomo's Base.Addr), used for
// geo-location and metrics. Empty when the proxy is not yet built.
func (o *Outbound) Address() string {
	if err := o.ensure(); err != nil || o.proxy == nil {
		return ""
	}
	return o.proxy.Addr()
}

func (o *Outbound) Location() *pub.Location { return nil }

func (o *Outbound) Stats() pub.OutboundStats { return pub.OutboundStats{} }

// DialContext dials the target through the mihomo proxy. The target is
// passed to the remote server as-is (INNER metadata with Host set), so a
// domain target is resolved by the proxy server, not locally — exactly the
// semantics a proxied client expects.
func (o *Outbound) DialContext(ctx context.Context, network pub.Network, target string) (net.Conn, error) {
	if err := o.ensure(); err != nil {
		return nil, err
	}
	meta := &C.Metadata{
		Type:    C.INNER,
		NetWork: C.TCP,
	}
	if err := meta.SetRemoteAddress(target); err != nil {
		return nil, fmt.Errorf("mihomo outbound: bad target %q: %w", target, err)
	}
	if network == pub.NetworkUDP {
		meta.NetWork = C.UDP
	}
	conn, err := o.proxy.DialContext(ctx, meta)
	if err != nil {
		return nil, fmt.Errorf("mihomo outbound: dial %s via %s: %w", target, o.proto, err)
	}
	return conn, nil
}

// outboundDialTimeout bounds a stuck mihomo dial so the engine's bridge
// cannot hang forever. (The router applies its own deadlines upstream.)
const outboundDialTimeout = 30 * time.Second
