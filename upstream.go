// upstream.go adds optional upstream-proxy support to mihomo outbounds.
//
// When a config carries "upstream_proxy", the mihomo proxy is built with
// adapter.WithDialerForAPI over a plain socks5 mihomo proxy parsed from the
// upstream address, so the outbound's connection to its server transits the
// upstream instead of going direct. DialerForAPI has higher priority than
// every dialer option inside mihomo (BasicOption.NewDialer), which is exactly
// the programmatic injection point needed — there is no mapping key for it.
//
// The upstream is a single address shared by every outbound built from the
// same provider run (e.g. a local sing-box/clash listening on
// 127.0.0.1:7890), so each Outbound parses its own throwaway socks5 proxy:
// adapter.ParseProxy is stateless and cheap, and the resulting proxy is only
// a dialer, never registered anywhere.
package mihomo

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
)

// defaultUpstreamPort is the conventional SOCKS5 port, used when the
// upstream address omits one ("127.0.0.1" → "127.0.0.1:1080").
const defaultUpstreamPort = 1080

// upstreamConfig is one parsed upstream proxy address.
type upstreamConfig struct {
	server   string
	port     int
	username string
	password string
}

// parseUpstream parses an upstream proxy address. Accepted forms:
//
//	socks5://user:pass@host:port   (scheme optional, socks5 assumed)
//	user:pass@host:port
//	host:port
//	host                            (default port appended)
//
// An empty string returns (nil, nil): no upstream configured.
func parseUpstream(s string) (*upstreamConfig, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	rest := s
	var user, pass string
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme := strings.ToLower(rest[:i])
		if scheme != "socks5" && scheme != "socks5h" {
			return nil, fmt.Errorf("mihomo upstream: unsupported scheme %q (only socks5)", scheme)
		}
		rest = rest[i+3:]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo := rest[:i]
		rest = rest[i+1:]
		if j := strings.Index(userinfo, ":"); j >= 0 {
			user, pass = userinfo[:j], userinfo[j+1:]
		} else {
			user = userinfo
		}
		if u, err := url.QueryUnescape(user); err == nil {
			user = u
		}
		if p, err := url.QueryUnescape(pass); err == nil {
			pass = p
		}
	}

	host := rest
	port := defaultUpstreamPort
	if strings.HasPrefix(rest, "[") {
		// Bracketed IPv6 literal, optionally [addr]:port.
		end := strings.Index(rest, "]")
		if end < 0 {
			return nil, fmt.Errorf("mihomo upstream: unterminated bracket in %q", s)
		}
		host = rest[1:end]
		if tail := rest[end+1:]; tail != "" {
			p, err := parsePort(strings.TrimPrefix(tail, ":"))
			if err != nil {
				return nil, fmt.Errorf("mihomo upstream: %w", err)
			}
			port = p
		}
	} else {
		// Exactly one colon means host:port. More than one is ambiguous
		// (bare IPv6): only accept it as a whole-host literal, and require
		// brackets for IPv6-plus-port.
		switch strings.Count(rest, ":") {
		case 1:
			i := strings.Index(rest, ":")
			p, err := parsePort(rest[i+1:])
			if err != nil {
				return nil, fmt.Errorf("mihomo upstream: %w", err)
			}
			host, port = rest[:i], p
		case 0:
			// host alone; default port.
		default:
			if net.ParseIP(rest) == nil {
				return nil, fmt.Errorf("mihomo upstream: ambiguous address %q (bracket IPv6 as [addr]:port)", s)
			}
		}
	}
	if host == "" {
		return nil, fmt.Errorf("mihomo upstream: missing host in %q", s)
	}

	return &upstreamConfig{server: host, port: port, username: user, password: pass}, nil
}

// parsePort validates a port string for the address forms above.
func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return p, nil
}

// upstreamSocks5Mapping builds the throwaway socks5 proxy mapping for one
// parsed upstream address (shared by the plain and via-stack dialer
// builders).
func upstreamSocks5Mapping(uc *upstreamConfig) map[string]any {
	mapping := map[string]any{
		"type":   "socks5",
		"name":   "goose-upstream",
		"server": uc.server,
		"port":   uc.port,
	}
	if uc.username != "" {
		mapping["username"] = uc.username
		mapping["password"] = uc.password
	}
	return mapping
}

// upstreamDialer builds the upstream socks5 proxy and wraps it as a C.Dialer
// to inject via adapter.WithDialerForAPI. A nil address returns a nil dialer
// (no upstream: dial direct).
func upstreamDialer(addr string) (C.Dialer, error) {
	uc, err := parseUpstream(addr)
	if err != nil {
		return nil, err
	}
	if uc == nil {
		return nil, nil
	}
	p, err := adapter.ParseProxy(upstreamSocks5Mapping(uc))
	if err != nil {
		return nil, fmt.Errorf("mihomo upstream: build socks5 proxy for %s:%d: %w", uc.server, uc.port, err)
	}
	return proxydialer.New(p, false), nil
}
