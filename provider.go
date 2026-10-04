// Package mihomo is the mihomo subscription provider plugin for the goose
// proxy-pool engine.
//
// It embeds github.com/metacubex/mihomo as a Go library and gives goose two
// things:
//
//   - a Provider ("mihomo") that fetches a subscription URL and parses the
//     body with mihomo's own converters — Clash YAML `proxies:` lists and
//     V2Ray-style link lists (vmess://, vless://, trojan://, ss://, ssr://,
//     hysteria://, hysteria2://, tuic://, socks5://, http://, anytls://,
//     mieru:// ...), plain or base64-encoded — into outbound configs, one per
//     proxy server;
//   - an outbound protocol for every mihomo proxy type, registered under its
//     mihomo name prefixed "mihomo-" (e.g. "mihomo-vmess", "mihomo-trojan"),
//     which dials by building the mihomo proxy from the proxy mapping and
//     calling its DialContext. All of mihomo's dialer/DNS machinery is
//     auto-initialized by its package inits.
//
// # Outbound config shape
//
// The provider puts the FULL parsed proxy mapping under cfg["proxy"], and the
// outbound factory rebuilds the mihomo proxy from it lazily (on first dial,
// under a lock) so constructing a pool of hundreds of proxies costs no
// connections up front:
//
//	{
//	  "id":   "mihomo-vmess-1.2.3.4:443",
//	  "proxy": {"type":"vmess","name":"...","server":"1.2.3.4","port":443,...}
//	}
//
// # Provider config
//
//	{
//	  "url":    "https://example.com/sub",  // required
//	  "prefix": "mihomo"                     // optional, outbound-id prefix
//	}
package mihomo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/yaml"

	pub "github.com/goose-network/goose-plugin-api"
)

func init() {
	pub.RegisterProvider("mihomo", NewProvider)
}

const (
	// fetchTimeout bounds one subscription download.
	fetchTimeout = 30 * time.Second
	// maxBodyBytes caps the subscription body so a hostile link cannot
	// exhaust engine memory.
	maxBodyBytes = 8 << 20
	// defaultPrefix is the outbound-id prefix when the config omits one.
	defaultPrefix = "mihomo"
)

// Provider is a goose outbound provider backed by a mihomo subscription.
type Provider struct {
	url    string
	prefix string
	client *http.Client
}

// NewProvider builds a mihomo provider from config:
//
//	{"url":"https://...","prefix":"mihomo"}
func NewProvider(cfg map[string]any) (pub.Provider, error) {
	u, _ := cfg["url"].(string)
	if u == "" {
		return nil, fmt.Errorf("mihomo provider: missing url")
	}
	prefix, _ := cfg["prefix"].(string)
	if prefix == "" {
		prefix = defaultPrefix
	}
	return &Provider{
		url:    u,
		prefix: prefix,
		client: &http.Client{Timeout: fetchTimeout},
	}, nil
}

// Name identifies the plugin.
func (p *Provider) Name() string { return "mihomo" }

// Watch is nil: the provider has no change signal of its own, so the engine
// falls back to periodic polling of Outbounds.
func (p *Provider) Watch() <-chan struct{} { return nil }

// Outbounds fetches the subscription and parses it into outbound configs.
func (p *Provider) Outbounds(ctx context.Context) ([]pub.OutboundConfig, error) {
	body, err := p.fetch(ctx)
	if err != nil {
		return nil, err
	}
	mappings, err := ParseSubscription(body)
	if err != nil {
		return nil, fmt.Errorf("mihomo provider: parse %s: %w", p.url, err)
	}
	out := make([]pub.OutboundConfig, 0, len(mappings))
	seen := map[string]int{}
	for _, m := range mappings {
		proto, ok := ProtocolOf(m)
		if !ok {
			continue // type not dialable (e.g. group-only entries)
		}
		id := fmt.Sprintf("%s-%s-%s", p.prefix, m["type"], ServerKey(m))
		seen[id]++
		if n := seen[id]; n > 1 {
			id = fmt.Sprintf("%s-%d", id, n)
		}
		out = append(out, pub.OutboundConfig{
			ID:       id,
			Protocol: proto,
			Config:   map[string]any{"id": id, "proxy": m},
		})
	}
	return out, nil
}

// fetch downloads the subscription body.
func (p *Provider) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("mihomo provider: bad url: %w", err)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mihomo provider: fetch %s: %w", p.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mihomo provider: %s: status %s", p.url, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("mihomo provider: read %s: %w", p.url, err)
	}
	return body, nil
}

// ParseSubscription turns a subscription body into mihomo proxy mappings.
// Clash YAML is tried first (detected by the body parsing as a YAML map with
// a `proxies:` list); anything else falls through to mihomo's V2Ray-style
// link converter (which handles the classic base64-encoded link list too).
func ParseSubscription(body []byte) ([]map[string]any, error) {
	if mappings, ok := parseClashYAML(body); ok {
		return mappings, nil
	}
	return convert.ConvertsV2Ray(body)
}

// parseClashYAML extracts a Clash `proxies:` list. It returns ok=false when
// the body is not a Clash YAML config (no proxies key or a non-list value),
// letting the caller fall back to the link-list format.
func parseClashYAML(body []byte) ([]map[string]any, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	raw, ok := doc["proxies"]
	if !ok {
		return nil, false
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out, len(out) > 0
}

// ProtocolOf maps a mihomo proxy mapping to its goose outbound protocol name
// ("mihomo-<type>"). It returns ok=false for types goose cannot dial
// (groups, special adapters).
func ProtocolOf(m map[string]any) (string, bool) {
	typ, _ := m["type"].(string)
	if typ == "" {
		return "", false
	}
	switch typ {
	case "direct", "reject", "reject-drop", "pass", "dns", "rematch",
		"selector", "url-test", "fallback", "load-balance", "relay":
		return "", false
	}
	if _, err := adapter.ParseProxy(m); err != nil {
		return "", false
	}
	return "mihomo-" + typ, true
}

// ServerKey derives a stable per-proxy key from the mapping's server+port so
// pool IDs stay stable across refreshes that reorder the list.
func ServerKey(m map[string]any) string {
	server, _ := m["server"].(string)
	port := fmt.Sprint(m["port"])
	if server == "" {
		// Fallback: some types (wireguard ...) have no single server field.
		if name, _ := m["name"].(string); name != "" {
			return name
		}
		return "unknown"
	}
	return server + ":" + port
}
