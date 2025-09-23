package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

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

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestHTTPServer_NoLeak_WhenClosed(t *testing.T) {
	t.Parallel()

	opts := &Options{
		Domains:                  []string{"example.com"},
		ListenIP:                 "127.0.0.1",
		HttpPort:                 0,
		HttpsPort:                0,
		CorrelationIdLength:      8,
		CorrelationIdNonceLength: 6,
	}
	s, err := NewHTTPServer(opts)
	require.NoError(t, err)

	httpAlive := make(chan bool, 1)
	httpsAlive := make(chan bool, 1)
	go s.ListenAndServe(nil, httpAlive, httpsAlive)
	select {
	case <-httpAlive:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("server did not start")
	}

	_ = s.Close(context.Background())

	time.Sleep(200 * time.Millisecond)
}
