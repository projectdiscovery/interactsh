package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

// serveRequestWithHeaders is serveRequest with request headers, for the
// conditional and ranged cases ServeContent handles on its own.
func serveRequestWithHeaders(t *testing.T, h *HTTPServer, host, path string, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	req.RemoteAddr = "203.0.113.7:5555"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.serveUploadedFile(w, req)
	return w.Result()
}

// records returns the interaction records stored for a session, newest last.
func records(t *testing.T, h *HTTPServer, correlationID string) []*Interaction {
	t.Helper()
	item, err := h.options.Storage.GetCacheItem(correlationID)
	require.NoError(t, err)
	out := make([]*Interaction, 0, len(item.Data))
	for _, raw := range item.Data {
		record := &Interaction{}
		require.NoError(t, jsoniter.Unmarshal([]byte(raw), record))
		out = append(out, record)
	}
	return out
}

// A fetch that misses is evidence too: it separates "the target never came" from
// "the target asked for a name I am not hosting".
func TestServeUploadedFileRecordsMisses(t *testing.T) {
	setup := func(t *testing.T) (*HTTPServer, string) {
		t.Helper()
		h, id, secret := uploadTestServer(t, true)
		require.Equal(t, http.StatusOK,
			doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": []byte("payload")})).StatusCode)
		return h, id
	}

	t.Run("a name that is not hosted", func(t *testing.T) {
		h, id := setup(t)
		resp := serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd.txt", nil)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)

		got := records(t, h, id)
		require.Len(t, got, 1, "a miss must reach the operator")
		require.Contains(t, got[0].RawRequest, "GET /f/evil.dtd.txt")
		require.Contains(t, got[0].RawResponse, "404 Not Found")
		require.Contains(t, got[0].RawResponse, `[no hosted file for "/f/evil.dtd.txt" on this session]`)
		require.NotContains(t, got[0].RawResponse, "body elided", "nothing was served")
	})

	t.Run("a rejected file name", func(t *testing.T) {
		h, id := setup(t)
		require.Equal(t, http.StatusNotFound,
			serveRequestWithHeaders(t, h, payloadHost(id), "/f/../../etc/passwd", nil).StatusCode)
		require.Len(t, records(t, h, id), 1)
	})

	t.Run("a server with uploads disabled", func(t *testing.T) {
		h, id, _ := uploadTestServer(t, false)
		require.Equal(t, http.StatusNotFound,
			serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd", nil).StatusCode)

		got := records(t, h, id)
		require.Len(t, got, 1, "a probe of /f/ is worth recording even with uploads off")
		require.Contains(t, got[0].RawResponse, "404 Not Found")
	})

	t.Run("a host carrying no correlation id is dropped", func(t *testing.T) {
		h, id := setup(t)
		require.Equal(t, http.StatusNotFound,
			serveRequestWithHeaders(t, h, "example.com", "/f/evil.dtd", nil).StatusCode)
		require.Empty(t, records(t, h, id))
		require.Zero(t, h.options.Stats.Http, "nothing recorded, so nothing counted")
	})
}

// The stored record must state what ServeContent actually sent. Claiming a full
// 200 for a 304 is evidence of a delivery that never happened.
func TestServeUploadedFileRecordsActualResponse(t *testing.T) {
	content := []byte("PAYLOAD")
	setup := func(t *testing.T) (*HTTPServer, string) {
		t.Helper()
		h, id, secret := uploadTestServer(t, true)
		require.Equal(t, http.StatusOK,
			doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": content})).StatusCode)
		return h, id
	}

	t.Run("a conditional request answered 304 records zero bytes", func(t *testing.T) {
		h, id := setup(t)
		first := serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd", nil)
		lastMod := first.Header.Get("Last-Modified")
		require.NotEmpty(t, lastMod)

		resp := serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd",
			map[string]string{"If-Modified-Since": lastMod})
		require.Equal(t, http.StatusNotModified, resp.StatusCode)

		got := records(t, h, id)
		require.Len(t, got, 2)
		require.Contains(t, got[1].RawResponse, "304 Not Modified")
		require.Contains(t, got[1].RawResponse, fmt.Sprintf("[body elided: 0 of %d bytes", len(content)))
		require.NotContains(t, got[1].RawResponse, "200 OK")
	})

	t.Run("a ranged request answered 206 records the range size", func(t *testing.T) {
		h, id := setup(t)
		resp := serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd",
			map[string]string{"Range": "bytes=0-1"})
		require.Equal(t, http.StatusPartialContent, resp.StatusCode)

		got := records(t, h, id)
		require.Len(t, got, 1)
		require.Contains(t, got[0].RawResponse, "206 Partial Content")
		require.Contains(t, got[0].RawResponse, fmt.Sprintf("[body elided: 2 of %d bytes", len(content)))
	})

	t.Run("a plain fetch still records the full length", func(t *testing.T) {
		h, id := setup(t)
		require.Equal(t, http.StatusOK,
			serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd", nil).StatusCode)

		got := records(t, h, id)
		require.Len(t, got, 1)
		require.Contains(t, got[0].RawResponse, "200 OK")
		require.Contains(t, got[0].RawResponse, fmt.Sprintf("Content-Length: %d", len(content)))
		require.Contains(t, got[0].RawResponse, fmt.Sprintf("[body elided: %d of %d bytes", len(content), len(content)))
	})
}

// /metrics and the interaction stream must not disagree about what arrived.
func TestServeUploadedFileMetricsMatchRecords(t *testing.T) {
	h, id, secret := uploadTestServer(t, true)
	require.Equal(t, http.StatusOK,
		doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": []byte("payload")})).StatusCode)

	// two hits, two misses, and one request that cannot be attributed
	serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd", nil)
	serveRequestWithHeaders(t, h, payloadHost(id), "/f/evil.dtd", nil)
	serveRequestWithHeaders(t, h, payloadHost(id), "/f/absent.dtd", nil)
	serveRequestWithHeaders(t, h, payloadHost(id), "/f/also-absent.dtd", nil)
	serveRequestWithHeaders(t, h, "example.com", "/f/evil.dtd", nil)

	require.Len(t, records(t, h, id), 4)
	require.Equal(t, uint64(4), h.options.Stats.Http,
		"the http counter must equal the interactions actually recorded")
}
