package server

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression suite for https://github.com/projectdiscovery/interactsh/issues/1362
// covering the SMTP path. Each row exercises a different shape of correlation
// id and parent domain to guard against false-positive matches in ordinary
// domain labels overwriting legitimate ones, and against alphabet mismatches.
func TestSMTPInteractionStored(t *testing.T) {
	cases := []struct {
		name          string
		cidl, cidn    int
		correlationID string
		nonce         string
		parentDomain  string
		toAddress     func(preamble, parent string) string
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
			name: "default lengths",
			cidl: 20, cidn: 13,
			correlationID: "c6rj61aciaeutn2ae680", nonce: "cg5ugboyyyyyn",
			parentDomain: "example.com",
			expectStored: 1,
		},
		{
			name: "uppercase recipient is normalized",
			cidl: 3, cidn: 3,
			correlationID: "d82", nonce: "yyy",
			parentDomain: "example.com",
			toAddress: func(preamble, parent string) string {
				return "victim@" + strings.ToUpper(preamble) + "." + parent
			},
			expectStored: 1,
		},
		{
			name: "multi-level subdomain prefix",
			cidl: 3, cidn: 3,
			correlationID: "d82", nonce: "yyy",
			parentDomain: "example.com",
			toAddress: func(preamble, parent string) string {
				return "victim@extra." + preamble + "." + parent
			},
			expectStored: 1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStorage(t)
			registerTestKey(t, store, tc.correlationID)

			opts := &Options{
				Domains:                  []string{tc.parentDomain},
				ListenIP:                 "127.0.0.1",
				Storage:                  store,
				CorrelationIdLength:      tc.cidl,
				CorrelationIdNonceLength: tc.cidn,
				Stats:                    &Metrics{},
			}
			srv := &SMTPServer{options: opts}

			addr := defaultRecipient(tc.correlationID+tc.nonce, tc.parentDomain)
			if tc.toAddress != nil {
				addr = tc.toAddress(tc.correlationID+tc.nonce, tc.parentDomain)
			}
			remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
			require.NoError(t, srv.defaultHandler(remote, "attacker@example.org", []string{addr}, []byte("DATA")))

			interactions, _, err := store.GetInteractions(tc.correlationID, "secret")
			require.NoError(t, err)
			require.Len(t, interactions, tc.expectStored)
		})
	}
}

// Unregistered preambles must not produce stored interactions, even though
// they pass the alphabet check. This is the structural defense against the
// previous "last match wins" overwrite bug.
func TestSMTPInteractionNotStored_UnregisteredPreamble(t *testing.T) {
	store := newTestStorage(t)
	registerTestKey(t, store, "d82")

	opts := &Options{
		Domains:                  []string{"example.com"},
		ListenIP:                 "127.0.0.1",
		Storage:                  store,
		CorrelationIdLength:      3,
		CorrelationIdNonceLength: 3,
		Stats:                    &Metrics{},
	}
	srv := &SMTPServer{options: opts}

	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	require.NoError(t, srv.defaultHandler(remote, "attacker@example.org", []string{"victim@abcybn.example.com"}, []byte("DATA")))

	interactions, _, err := store.GetInteractions("d82", "secret")
	require.NoError(t, err)
	require.Empty(t, interactions, "recipients that do not target a registered preamble must not be stored under another id")
}

func defaultRecipient(preamble, parent string) string {
	return "victim@" + preamble + "." + parent
}
