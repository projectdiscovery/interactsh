package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestHttpProtocol(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.com/", nil)
		require.Equal(t, "http", httpProtocol(r))
	})
	t.Run("tls", func(t *testing.T) {
		r := httptest.NewRequest("GET", "https://example.com/", nil)
		r.TLS = &tls.ConnectionState{}
		require.Equal(t, "https", httpProtocol(r))
	})
}

func TestWriteResponseFromDynamicRequest(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/?status=404", nil)
		w := httptest.NewRecorder()
		writeResponseFromDynamicRequest(w, req)

		resp := w.Result()
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "could not get correct result")
	})
	t.Run("delay", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/?delay=1", nil)
		w := httptest.NewRecorder()
		now := time.Now()
		writeResponseFromDynamicRequest(w, req)
		took := time.Since(now)

		require.Greater(t, took, 1*time.Second, "could not get correct delay")
	})
	t.Run("body", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/?body=this+is+example+body", nil)
		w := httptest.NewRecorder()
		writeResponseFromDynamicRequest(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, "this is example body", string(body), "could not get correct result")
	})

        t.Run("b64_body", func(t *testing.T) {
                req := httptest.NewRequest("GET", "http://example.com/?b64_body=dGhpcyBpcyBleGFtcGxlIGJvZHk=", nil)
                w := httptest.NewRecorder()
                writeResponseFromDynamicRequest(w, req)

                resp := w.Result()
                body, _ := io.ReadAll(resp.Body)
                require.Equal(t, "this is example body", string(body), "could not get correct result")
        })
	t.Run("header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/?header=Key:value&header=Test:Another", nil)
		w := httptest.NewRecorder()
		writeResponseFromDynamicRequest(w, req)

		resp := w.Result()
		require.Equal(t, resp.Header.Get("Key"), "value", "could not get correct result")
		require.Equal(t, resp.Header.Get("Test"), "Another", "could not get correct result")
	})
}

func TestSessionTotalMetric(t *testing.T) {
	stats := &Metrics{}
	removed := make(chan struct{})
	closeOnce := sync.Once{}

	store, err := storage.New(&storage.Options{
		EvictionTTL: 5 * time.Minute,
		OnRemoval: func() {
			atomic.AddInt64(&stats.Sessions, -1)
			closeOnce.Do(func() { close(removed) })
		},
	})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	h := &HTTPServer{
		options: &Options{
			Storage: store,
			Stats:   stats,
		},
	}

	// Generate a client key pair and registration payload.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	pubB64 := base64.StdEncoding.EncodeToString(pubPem)

	correlationID := xid.New().String()
	secretKey := uuid.New().String()

	// --- Register ---
	regBody, err := jsoniter.Marshal(&RegisterRequest{
		PublicKey:     pubB64,
		SecretKey:     secretKey,
		CorrelationID: correlationID,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(regBody))
	w := httptest.NewRecorder()
	h.registerHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	require.Equal(t, int64(1), atomic.LoadInt64(&stats.Sessions), "sessions should be 1 after register")
	require.Equal(t, int64(1), atomic.LoadInt64(&stats.SessionsTotal), "sessions_total should be 1 after register")

	// --- Deregister ---
	deregBody, err := jsoniter.Marshal(&DeregisterRequest{
		SecretKey:     secretKey,
		CorrelationID: correlationID,
	})
	require.NoError(t, err)
	req = httptest.NewRequest("POST", "/deregister", bytes.NewReader(deregBody))
	w = httptest.NewRecorder()
	h.deregisterHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	select {
	case <-removed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnRemoval callback")
	}

	require.Equal(t, int64(0), atomic.LoadInt64(&stats.Sessions), "sessions should be 0 after deregister")
	require.Equal(t, int64(1), atomic.LoadInt64(&stats.SessionsTotal), "sessions_total should remain 1 after deregister")
}
