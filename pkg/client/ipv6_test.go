package client

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubResolver struct {
	addrs []net.IP
	err   error
}

func (s stubResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return s.addrs, s.err
}

func TestHostHasIPv6(t *testing.T) {
	t.Run("ipv4 only reports no ipv6", func(t *testing.T) {
		ok, err := hostHasIPv6(context.Background(), stubResolver{addrs: []net.IP{net.ParseIP("178.128.212.209")}}, "oast.pro")
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("dual stack reports ipv6", func(t *testing.T) {
		ok, err := hostHasIPv6(context.Background(), stubResolver{addrs: []net.IP{net.ParseIP("178.128.212.209"), net.ParseIP("2001:db8::1")}}, "oast.pro")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("resolution failure surfaces error", func(t *testing.T) {
		ok, err := hostHasIPv6(context.Background(), stubResolver{err: errors.New("no such host")}, "oast.pro")
		require.Error(t, err)
		require.False(t, ok)
	})
}
