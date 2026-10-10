package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterRejectsUnusableCorrelationID(t *testing.T) {
	publicKey := testPublicKey(t)
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"too short", strings.Repeat("a", 19)},
		{"too long", strings.Repeat("a", 21)},
		{"unsupported letter", strings.Repeat("w", 20)},
		{"uppercase storage key", strings.Repeat("A", 20)},
		{"punctuation", strings.Repeat("a", 19) + "-"},
		{"non ASCII", strings.Repeat("a", 18) + "é"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStorage(t)
			stats := &Metrics{}
			h, err := NewHTTPServer(&Options{
				Domains: []string{"example.com"}, Storage: store, Stats: stats,
				CorrelationIdLength: 20, CorrelationIdNonceLength: 13,
			})
			require.NoError(t, err)
			body, err := json.Marshal(RegisterRequest{
				PublicKey: publicKey, SecretKey: "test-secret", CorrelationID: tc.id,
			})
			require.NoError(t, err)
			w := httptest.NewRecorder()
			h.nontlsserver.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
			require.Equal(t, http.StatusBadRequest, w.Code)
			var response map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.Contains(t, response["error"], "correlation-id")
			_, err = store.GetCacheItem(tc.id)
			require.Error(t, err, "a rejected registration must not create storage")
			require.Zero(t, atomic.LoadInt64(&stats.Sessions))
			require.Zero(t, atomic.LoadInt64(&stats.SessionsTotal))
		})
	}
}

func TestRegisteredCorrelationIDReceivesCallbacks(t *testing.T) {
	publicKey := testPublicKey(t)
	for _, tc := range []struct {
		name        string
		id          string
		nonceLength int
	}{
		{"default", strings.Repeat("a", 20), 13},
		{"short", "0av", 3},
		{"all prefix characters", "0123456789abcdefghijklmnopqrstuv", 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStorage(t)
			stats := &Metrics{}
			h, err := NewHTTPServer(&Options{
				Domains: []string{"example.com"}, Storage: store, Stats: stats,
				CorrelationIdLength: len(tc.id), CorrelationIdNonceLength: tc.nonceLength,
			})
			require.NoError(t, err)
			body, err := json.Marshal(RegisterRequest{
				PublicKey: publicKey, SecretKey: "test-secret", CorrelationID: tc.id,
			})
			require.NoError(t, err)
			w := httptest.NewRecorder()
			h.nontlsserver.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
			require.Equal(t, http.StatusOK, w.Code)
			require.EqualValues(t, 1, atomic.LoadInt64(&stats.Sessions))
			require.EqualValues(t, 1, atomic.LoadInt64(&stats.SessionsTotal))

			for _, scheme := range []string{"http", "https"} {
				for _, c := range "ybndrfg8ejkmcpqxot1uwisza345h769" {
					// DNS names are case-insensitive; the registered storage key stays lowercase.
					host := strings.ToUpper(tc.id+strings.Repeat(string(c), tc.nonceLength)) + ".example.com"
					req := httptest.NewRequest(http.MethodGet, scheme+"://"+host+"/callback", nil)
					w := httptest.NewRecorder()
					if scheme == "https" {
						h.tlsserver.Handler.ServeHTTP(w, req)
					} else {
						h.nontlsserver.Handler.ServeHTTP(w, req)
					}
					require.Equal(t, http.StatusOK, w.Code)
					interactions, _, err := store.GetInteractions(tc.id, "test-secret")
					require.NoError(t, err)
					require.Len(t, interactions, 1, "accepted registrations must receive recognized callbacks")
				}
			}

			// Registration cannot validate future nonces; existing callback matching stays strict.
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.id+strings.Repeat("0", tc.nonceLength)+".example.com/", nil)
			h.nontlsserver.Handler.ServeHTTP(httptest.NewRecorder(), req)
			interactions, _, err := store.GetInteractions(tc.id, "test-secret")
			require.NoError(t, err)
			require.Empty(t, interactions)
		})
	}
}
