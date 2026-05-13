package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/stretchr/testify/require"
)

// Regression for https://github.com/projectdiscovery/interactsh/issues/1362:
// short --cidl / --cidn must still record DNS callbacks. A parent label
// longer than cidl+cidn (e.g. "example") historically caused the legitimate
// correlation id to be overwritten by a false-positive slide window.
func TestDNSInteractionStored_ShortCorrelationIDs(t *testing.T) {
	const cidl, cidn = 3, 3
	const correlationID, nonce = "d82", "yyy"
	const parentDomain = "example.com"

	store := newTestStorage(t)
	registerTestKey(t, store, correlationID)

	port := freeUDPPort(t)
	startTestDNSServer(t, &Options{
		Domains:                  []string{parentDomain},
		IPAddresses:              []net.IP{net.ParseIP("127.0.0.1")},
		ListenIP:                 "127.0.0.1",
		DnsPort:                  port,
		Storage:                  store,
		CorrelationIdLength:      cidl,
		CorrelationIdNonceLength: cidn,
		Stats:                    &Metrics{},
	})

	sendDNSQuery(t, port, fmt.Sprintf("%s%s.%s.", correlationID, nonce, parentDomain))

	interactions, _, err := store.GetInteractions(correlationID, "secret")
	require.NoError(t, err)
	require.Len(t, interactions, 1, "DNS interaction should be recorded when cidl+cidn is shorter than the parent label")
}

func TestDNSInteractionStored_DefaultCorrelationIDs(t *testing.T) {
	const cidl, cidn = 20, 13
	const correlationID = "abcdefghijklmnopqrst"
	const nonce = "uvwxyz0123456"
	const parentDomain = "example.com"

	store := newTestStorage(t)
	registerTestKey(t, store, correlationID)

	port := freeUDPPort(t)
	startTestDNSServer(t, &Options{
		Domains:                  []string{parentDomain},
		IPAddresses:              []net.IP{net.ParseIP("127.0.0.1")},
		ListenIP:                 "127.0.0.1",
		DnsPort:                  port,
		Storage:                  store,
		CorrelationIdLength:      cidl,
		CorrelationIdNonceLength: cidn,
		Stats:                    &Metrics{},
	})

	sendDNSQuery(t, port, fmt.Sprintf("%s%s.%s.", correlationID, nonce, parentDomain))

	interactions, _, err := store.GetInteractions(correlationID, "secret")
	require.NoError(t, err)
	require.Len(t, interactions, 1)
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
