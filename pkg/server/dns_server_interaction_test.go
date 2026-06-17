package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/stretchr/testify/require"
)

// Regression suite for https://github.com/projectdiscovery/interactsh/issues/1362.
// Each row exercises a different shape of correlation id and parent domain to
// guard against false-positive matches in ordinary domain labels overwriting
// legitimate ones, and against alphabet mismatches.
func TestDNSInteractionStored(t *testing.T) {
	cases := []struct {
		name          string
		cidl, cidn    int
		correlationID string
		nonce         string
		parentDomain  string
		queryName     func(preamble, parent string) string
		expectStored  int
	}{
		{
			name: "short ids with parent label rejected by alphabet (example.com)",
			cidl: 3, cidn: 3,
			correlationID: "d82", nonce: "yyy",
			parentDomain: "example.com",
			expectStored: 1,
		},
		{
			name: "short ids with alphabet-compatible parent label (oast.online)",
			cidl: 3, cidn: 3,
			correlationID: "d82", nonce: "yyy",
			parentDomain: "oast.online",
			expectStored: 1,
		},
		{
			name: "readme example cidl=4 cidn=6",
			cidl: 4, cidn: 6,
			correlationID: "abcd", nonce: "ybndrf",
			parentDomain: "hackwithautomation.com",
			expectStored: 1,
		},
		{
			name: "default lengths",
			cidl: 20, cidn: 13,
			correlationID: "c6rj61aciaeutn2ae680", nonce: "cg5ugboyyyyyn",
			parentDomain: "example.com",
			expectStored: 1,
		},
		{
			name: "uppercase query is normalized",
			cidl: 3, cidn: 3,
			correlationID: "d82", nonce: "yyy",
			parentDomain: "example.com",
			queryName: func(preamble, parent string) string {
				return strings.ToUpper(preamble) + "." + parent + "."
			},
			expectStored: 1,
		},
		{
			name: "multi-level subdomain prefix",
			cidl: 3, cidn: 3,
			correlationID: "d82", nonce: "yyy",
			parentDomain: "example.com",
			queryName: func(preamble, parent string) string {
				return "extra." + preamble + "." + parent + "."
			},
			expectStored: 1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStorage(t)
			registerTestKey(t, store, tc.correlationID)

			port := freeUDPPort(t)
			startTestDNSServer(t, &Options{
				Domains:                  []string{tc.parentDomain},
				IPAddresses:              []net.IP{net.ParseIP("127.0.0.1")},
				ListenIP:                 "127.0.0.1",
				DnsPort:                  port,
				Storage:                  store,
				CorrelationIdLength:      tc.cidl,
				CorrelationIdNonceLength: tc.cidn,
				Stats:                    &Metrics{},
			})

			query := defaultQueryName(tc.correlationID+tc.nonce, tc.parentDomain)
			if tc.queryName != nil {
				query = tc.queryName(tc.correlationID+tc.nonce, tc.parentDomain)
			}
			sendDNSQuery(t, port, query)

			interactions, _, err := store.GetInteractions(tc.correlationID, "secret")
			require.NoError(t, err)
			require.Len(t, interactions, tc.expectStored)
		})
	}
}

// Unregistered preambles must not produce stored interactions, even though
// they pass the alphabet check.
func TestDNSInteractionNotStored_UnregisteredPreamble(t *testing.T) {
	store := newTestStorage(t)
	registerTestKey(t, store, "d82")

	port := freeUDPPort(t)
	startTestDNSServer(t, &Options{
		Domains:                  []string{"example.com"},
		IPAddresses:              []net.IP{net.ParseIP("127.0.0.1")},
		ListenIP:                 "127.0.0.1",
		DnsPort:                  port,
		Storage:                  store,
		CorrelationIdLength:      3,
		CorrelationIdNonceLength: 3,
		Stats:                    &Metrics{},
	})

	sendDNSQuery(t, port, "abcybn.example.com.")

	interactions, _, err := store.GetInteractions("d82", "secret")
	require.NoError(t, err)
	require.Empty(t, interactions, "queries that do not target a registered preamble must not be stored under another id")
}

func defaultQueryName(preamble, parent string) string {
	return preamble + "." + parent + "."
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, conn.Close())
	return port
}

func newTestStorage(t *testing.T) storage.Storage {
	t.Helper()
	s, err := storage.New(&storage.Options{EvictionTTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func registerTestKey(t *testing.T, store storage.Storage, correlationID string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
	require.NoError(t, store.SetIDPublicKey(correlationID, "secret", base64.StdEncoding.EncodeToString(pemEncoded)))
}

func startTestDNSServer(t *testing.T, opts *Options) {
	t.Helper()
	server := NewDNSServer("udp", opts)
	alive := make(chan bool, 2)
	go server.ListenAndServe(alive)
	<-alive
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", opts.DnsPort), 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, time.Second, 20*time.Millisecond)
	t.Cleanup(func() { _ = server.server.Shutdown() })
}

func sendDNSQuery(t *testing.T, port int, name string) {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	_, _, err := client.Exchange(msg, fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
}
