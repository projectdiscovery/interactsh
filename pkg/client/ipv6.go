package client

import (
	"context"
	"errors"
	"net"

	iputil "github.com/projectdiscovery/utils/ip"
)

// errServerNotResolvable is returned when the IPv6 capability of the server
// cannot be determined because it is addressed by a literal IP rather than a
// resolvable hostname.
var errServerNotResolvable = errors.New("server is not a resolvable hostname")

// ipResolver resolves a host to its IP addresses. *net.Resolver satisfies it.
type ipResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// hostHasIPv6 reports whether host resolves to at least one IPv6 address. A
// false result with a nil error means the host resolves but publishes no AAAA
// records; a non-nil error means resolution failed and the result is unknown.
func hostHasIPv6(ctx context.Context, resolver ipResolver, host string) (bool, error) {
	addrs, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.To4() == nil && addr.To16() != nil {
			return true, nil
		}
	}
	return false, nil
}

// ServerSupportsIPv6 reports whether the interactsh server in use publishes
// IPv6 (AAAA) records. A false result means interactions reaching the target
// over IPv6 are silently dropped by the server. The boolean is meaningful only
// when the returned error is nil.
func (c *Client) ServerSupportsIPv6(ctx context.Context) (bool, error) {
	if c.serverURL == nil {
		return false, errServerNotResolvable
	}
	host := c.serverURL.Hostname()
	if host == "" || iputil.IsIP(host) {
		return false, errServerNotResolvable
	}
	return hostHasIPv6(ctx, net.DefaultResolver, host)
}

// ServerURL returns the interactsh server the client registered to.
func (c *Client) ServerURL() string {
	if c.serverURL == nil {
		return ""
	}
	return c.serverURL.String()
}
