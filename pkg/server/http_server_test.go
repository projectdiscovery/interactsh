package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
