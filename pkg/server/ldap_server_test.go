package server

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestLDAPServer(t *testing.T) (*LDAPServer, func() int) {
	t.Helper()
	store := newTestStorage(t)
	registerTestKey(t, store, "d82")
	server := &LDAPServer{options: &Options{
		Storage:                  store,
		CorrelationIdLength:      3,
		CorrelationIdNonceLength: 3,
		Stats:                    &Metrics{},
	}}
	stored := func() int {
		interactions, _, err := store.GetInteractions("d82", "secret")
		require.NoError(t, err)
		return len(interactions)
	}
	return server, stored
}

func TestLDAPSearchStoresInteraction(t *testing.T) {
	server, stored := newTestLDAPServer(t)
	server.handleSearchInteractions("cn=d82ybn,dc=example,dc=com", "Type=Search\n", "127.0.0.1:1")
	require.Equal(t, 1, stored())
}

// One search with many correlation ids must not record an interaction per id.
func TestLDAPSearchInteractionsBounded(t *testing.T) {
	server, stored := newTestLDAPServer(t)

	var ids []string
	for i := 0; i < 100; i++ {
		ids = append(ids, "cn=d82y"+string(zbase32Alphabet[i/32])+string(zbase32Alphabet[i%32]))
	}
	server.handleSearchInteractions(strings.Join(ids, ","), "Type=Search\n", "127.0.0.1:1")
	require.Equal(t, maxLDAPSearchInteractions, stored())
}

// A correlation id repeated in one search is recorded once.
func TestLDAPSearchRepeatedIDStoredOnce(t *testing.T) {
	server, stored := newTestLDAPServer(t)
	server.handleSearchInteractions(strings.Repeat("cn=d82ybn,", 100), "Type=Search\n", "127.0.0.1:1")
	require.Equal(t, 1, stored())
}
