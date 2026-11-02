package server

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/require"
)

func rootTLDInteractions(t *testing.T, store interface {
	GetInteractionsWithIdForConsumer(id, consumer string) ([]string, error)
}, id string) []Interaction {
	t.Helper()
	raw, err := store.GetInteractionsWithIdForConsumer(id, "consumer")
	require.NoError(t, err)
	out := make([]Interaction, 0, len(raw))
	for _, r := range raw {
		var interaction Interaction
		require.NoError(t, json.Unmarshal([]byte(r), &interaction))
		out = append(out, interaction)
	}
	return out
}

// TestHTTPBodyIsTruncated checks that an HTTP body larger than MaxBodySize
// is not read past the limit, and the interaction is still stored.
func TestHTTPBodyIsTruncated(t *testing.T) {
	store := newTestStorage(t)
	require.NoError(t, store.SetID("example.com"))

	h, err := NewHTTPServer(&Options{
		Domains:                  []string{"example.com"},
		Storage:                  store,
		RootTLD:                  true,
		OriginURL:                "*",
		CorrelationIdLength:      3,
		CorrelationIdNonceLength: 3,
		MaxBodySize:              1024,
		Stats:                    &Metrics{},
	})
	require.NoError(t, err)

	body := bytes.Repeat([]byte("<"), 64*1024)
	req := httptest.NewRequest(http.MethodPost, "http://abc123.example.com/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.nontlsserver.Handler.ServeHTTP(w, req)

	interactions := rootTLDInteractions(t, store, "example.com")
	require.Len(t, interactions, 1)
	require.Equal(t, 1024, strings.Count(interactions[0].RawRequest, "<"))
}

func TestDefaultMaxBodySize(t *testing.T) {
	require.EqualValues(t, DefaultMaxBodySize, (&Options{}).GetMaxBodySize())
	require.EqualValues(t, 10, (&Options{MaxBodySize: 10}).GetMaxBodySize())
}

// TestSMTPDataIsTruncated checks that the SMTP message kept is capped.
func TestSMTPDataIsTruncated(t *testing.T) {
	store := newTestStorage(t)
	require.NoError(t, store.SetID("example.com"))
	srv := &SMTPServer{options: &Options{
		Domains:                  []string{"example.com"},
		Storage:                  store,
		RootTLD:                  true,
		CorrelationIdLength:      3,
		CorrelationIdNonceLength: 3,
		MaxBodySize:              1024,
		Stats:                    &Metrics{},
	}}
	session := &interactshSession{
		srv:    srv,
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		from:   "sender@example.org",
		to:     []string{"a@example.com"},
	}
	require.NoError(t, session.Data(bytes.NewReader(bytes.Repeat([]byte("~"), 64*1024))))

	interactions := rootTLDInteractions(t, store, "example.com")
	require.Len(t, interactions, 1)
	require.Equal(t, 1024, strings.Count(interactions[0].RawRequest, "~"))
}

// TestSMTPMessageStoredOncePerBucket checks that repeated RCPT lines do not
// multiply the stored message.
func TestSMTPMessageStoredOncePerBucket(t *testing.T) {
	store := newTestStorage(t)
	require.NoError(t, store.SetID("example.com"))
	correlationID := "d82"
	registerTestKey(t, store, correlationID)

	srv := &SMTPServer{options: &Options{
		Domains:                  []string{"example.com"},
		Storage:                  store,
		RootTLD:                  true,
		CorrelationIdLength:      3,
		CorrelationIdNonceLength: 3,
		Stats:                    &Metrics{},
	}}
	recipient := defaultRecipient(correlationID+"yyy", "example.com")
	other := defaultRecipient(correlationID+"zzz", "example.com")
	recipients := []string{recipient, recipient, recipient, recipient, other}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	require.NoError(t, srv.defaultHandler(remote, "sender@example.org", recipients, []byte("BODY")))

	// one item per distinct unique id; the body is in only one of them
	interactions, _, err := store.GetInteractions(correlationID, "secret")
	require.NoError(t, err)
	require.Len(t, interactions, 2)

	// one root-tld item per domain
	require.Len(t, rootTLDInteractions(t, store, "example.com"), 1)
}

func TestSMTPServerLimits(t *testing.T) {
	srv, err := NewSMTPServer(&Options{Domains: []string{"example.com"}, ListenIP: "127.0.0.1"})
	require.NoError(t, err)
	for _, s := range []*smtp.Server{srv.smtpServer, srv.smtpsServer, srv.smtpAutoTLSServer} {
		require.Equal(t, smtpMaxRecipients, s.MaxRecipients)
		require.Equal(t, smtpTimeout, s.ReadTimeout)
		require.Equal(t, smtpTimeout, s.WriteTimeout)
	}
}
