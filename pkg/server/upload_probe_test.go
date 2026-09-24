package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// payloadHost builds a host of the shape a client payload URL would use.
func payloadHost(correlationID string) string {
	return correlationID + strings.Repeat("a", 13) + ".oast.test"
}

// probeUpload issues an upload request the way a target would: against a payload
// host, with whatever token the caller supplies.
func probeUpload(t *testing.T, h *HTTPServer, host, token, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = "203.0.113.9:4444"
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	w := httptest.NewRecorder()
	h.uploadHandler(w, req)
	return w.Result()
}

// storedInteractions returns the interaction records held for a correlation id.
func storedInteractions(t *testing.T, h *HTTPServer, correlationID string) []string {
	t.Helper()
	item, err := h.options.Storage.GetCacheItem(correlationID)
	require.NoError(t, err)
	return item.Data
}

// A legitimate client never reaches /upload unauthenticated, nor at all on a
// server whose advertised capabilities say uploads are off. So anything arriving
// there is a target probing the endpoint, and the operator should see it.
func TestUploadProbeRecording(t *testing.T) {
	payload := `{"correlation-id":"probe","secret-key":"x","files":[{"name":"a.dtd","data":"QUFBQUFB"}]}`

	t.Run("unauthenticated probe is recorded and refused", func(t *testing.T) {
		h, id, _ := uploadTestServer(t, true)
		h.options.Auth = true
		h.options.Token = "server-token"

		resp := probeUpload(t, h, payloadHost(id), "", payload)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		data := storedInteractions(t, h, id)
		require.Len(t, data, 1, "a probe of /upload must reach the operator's stream")

		record := &Interaction{}
		require.NoError(t, json.Unmarshal([]byte(data[0]), record))
		// UniqueID carries the nonce as well; the record is filed under the id.
		require.True(t, strings.HasPrefix(record.UniqueID, id), "got %q", record.UniqueID)
		require.Contains(t, record.RawRequest, "POST /upload")
		require.Contains(t, record.RawResponse, "401 Unauthorized",
			"the record must state the status the target actually received")
		require.Equal(t, uint64(1), h.options.Stats.Http)
	})

	t.Run("probe against a server without uploads is recorded", func(t *testing.T) {
		h, id, _ := uploadTestServer(t, false)

		resp := probeUpload(t, h, payloadHost(id), "", payload)
		require.Equal(t, http.StatusNotImplemented, resp.StatusCode)

		data := storedInteractions(t, h, id)
		require.Len(t, data, 1)
		record := &Interaction{}
		require.NoError(t, json.Unmarshal([]byte(data[0]), record))
		require.Contains(t, record.RawResponse, "501 Not Implemented")
		require.Contains(t, record.RawResponse, "file upload is not enabled on this server")
	})

	t.Run("the request body is summarised, never stored", func(t *testing.T) {
		h, id, _ := uploadTestServer(t, false)
		big := strings.Repeat("Q", 200000)
		body := `{"files":[{"name":"a.dtd","data":"` + big + `"}]}`

		resp := probeUpload(t, h, payloadHost(id), "", body)
		require.Equal(t, http.StatusNotImplemented, resp.StatusCode)

		record := &Interaction{}
		require.NoError(t, json.Unmarshal([]byte(storedInteractions(t, h, id)[0]), record))
		require.NotContains(t, record.RawRequest, big,
			"an attacker-controlled body must not be persisted")
		require.Contains(t, record.RawRequest, fmt.Sprintf("[request body elided: %d bytes]", len(body)))
		require.Less(t, len(record.RawRequest), 1000, "the record must not scale with the body")
	})

	t.Run("an authenticated upload is not recorded as an interaction", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		h.options.Auth = true
		h.options.Token = "server-token"

		resp := probeUpload(t, h, payloadHost(id), "server-token",
			uploadBody(t, id, secret, map[string][]byte{"evil.dtd": []byte("payload")}))
		require.Equal(t, http.StatusOK, resp.StatusCode)

		require.Empty(t, storedInteractions(t, h, id),
			"the operator's own upload must not be attributed to the target")
		require.Zero(t, h.options.Stats.Http)
	})

	t.Run("a probe with no correlation id is dropped, not recorded", func(t *testing.T) {
		h, id, _ := uploadTestServer(t, false)

		// No panic: handleInteraction slices a correlation id out of uniqueID.
		resp := probeUpload(t, h, "example.com", "", payload)
		require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
		require.Empty(t, storedInteractions(t, h, id))
		require.Zero(t, h.options.Stats.Http)
	})
}
