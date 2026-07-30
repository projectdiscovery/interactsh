package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

// testPublicKey returns a base64-encoded PEM RSA public key accepted by
// Storage.SetIDPublicKey.
func testPublicKey(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "could not generate rsa key")

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	require.NoError(t, err, "could not marshal public key")

	pubkeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubkeyBytes})
	return base64.StdEncoding.EncodeToString(pubkeyPem)
}

// uploadTestServer returns an HTTPServer with uploads enabled and a registered
// session, plus that session's correlation ID and secret.
func uploadTestServer(t *testing.T, enableUploads bool) (*HTTPServer, string, string) {
	t.Helper()

	store, err := storage.New(&storage.Options{EvictionTTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	options := &Options{
		Storage:                  store,
		Stats:                    &Metrics{},
		CorrelationIdLength:      settings.CorrelationIdLengthDefault,
		CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
		UploadDirectory:          t.TempDir(),
		UploadMaxFileSize:        1024,
		UploadMaxFiles:           3,
		UploadMaxTotalSize:       1 << 20,
		UploadTTL:                time.Hour,
	}
	if enableUploads {
		us, err := NewUploadStore(options)
		require.NoError(t, err)
		t.Cleanup(func() { _ = us.Close() })
		options.Upload = true
		options.UploadStore = us
	}

	h := &HTTPServer{options: options}

	secret := uuid.New().String()
	correlationID := xid.New().String()
	require.NoError(t, store.SetIDPublicKey(correlationID, secret, testPublicKey(t)))

	return h, correlationID, secret
}

func uploadBody(t *testing.T, correlationID, secret string, files map[string][]byte) string {
	t.Helper()

	req := UploadRequest{CorrelationID: correlationID, SecretKey: secret}
	for name, data := range files {
		req.Files = append(req.Files, UploadFileRequest{
			Name: name,
			Data: base64.StdEncoding.EncodeToString(data),
		})
	}
	encoded, err := json.Marshal(req)
	require.NoError(t, err)
	return string(encoded)
}

func doUpload(t *testing.T, h *HTTPServer, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.uploadHandler(w, req)
	return w.Result()
}

func TestUploadHandler(t *testing.T) {
	t.Run("stores a file", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		content := []byte("<!ENTITY % x SYSTEM \"file:///etc/passwd\">")

		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": content}))
		require.Equal(t, http.StatusOK, resp.StatusCode)

		out := &UploadResponse{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
		require.Len(t, out.Files, 1)
		require.Equal(t, "evil.dtd", out.Files[0].Name)
		require.EqualValues(t, len(content), out.Files[0].Size)
		require.Equal(t, "/f/evil.dtd", out.Files[0].HTTPPath)
		require.Equal(t, "/"+uploadsDirName+"/"+id+"/evil.dtd", out.Files[0].FTPPath)

		files, ok := h.options.UploadStorage().ListUploads(id)
		require.True(t, ok)
		require.Len(t, files, 1, "metadata should be recorded against the session")
	})

	t.Run("501 when uploads disabled", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, false)
		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"a.dtd": []byte("x")}))
		require.Equal(t, http.StatusNotImplemented, resp.StatusCode,
			"the client uses 501 as the capability signal")
	})

	t.Run("404 for unknown correlation id", func(t *testing.T) {
		h, _, secret := uploadTestServer(t, true)
		resp := doUpload(t, h, uploadBody(t, xid.New().String(), secret, map[string][]byte{"a.dtd": []byte("x")}))
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("403 for wrong secret", func(t *testing.T) {
		h, id, _ := uploadTestServer(t, true)
		resp := doUpload(t, h, uploadBody(t, id, uuid.New().String(), map[string][]byte{"a.dtd": []byte("x")}))
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("413 for oversize file", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"big.bin": make([]byte, 2048)}))
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	t.Run("413 for too many files in one request", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		files := map[string][]byte{}
		for i := 0; i < 5; i++ {
			files[fmt.Sprintf("f%d.dtd", i)] = []byte("x")
		}
		resp := doUpload(t, h, uploadBody(t, id, secret, files))
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	t.Run("413 when session quota is reached across requests", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		for i := 0; i < 3; i++ {
			resp := doUpload(t, h, uploadBody(t, id, secret,
				map[string][]byte{fmt.Sprintf("f%d.dtd", i): []byte("x")}))
			require.Equal(t, http.StatusOK, resp.StatusCode)
		}
		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"overflow.dtd": []byte("x")}))
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	t.Run("replacing a name does not consume a new slot", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		for i := 0; i < 3; i++ {
			resp := doUpload(t, h, uploadBody(t, id, secret,
				map[string][]byte{fmt.Sprintf("f%d.dtd", i): []byte("x")}))
			require.Equal(t, http.StatusOK, resp.StatusCode)
		}
		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"f0.dtd": []byte("replaced")}))
		require.Equal(t, http.StatusOK, resp.StatusCode, "overwriting an existing name must be allowed at quota")

		files, _ := h.options.UploadStorage().ListUploads(id)
		require.Len(t, files, 3)
	})

	t.Run("400 for traversal name", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		for _, name := range []string{"../evil", "a/b", "/etc/passwd", `..\evil`, ""} {
			resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{name: []byte("x")}))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, "name %q must be rejected", name)
		}
	})

	t.Run("400 for malformed base64", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		body := fmt.Sprintf(`{"correlation-id":%q,"secret-key":%q,"files":[{"name":"a.dtd","data":"!!!not base64!!!"}]}`, id, secret)
		resp := doUpload(t, h, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("400 for duplicate names in one request", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		body := fmt.Sprintf(
			`{"correlation-id":%q,"secret-key":%q,"files":[{"name":"a.dtd","data":"eA=="},{"name":"a.dtd","data":"eQ=="}]}`,
			id, secret)
		resp := doUpload(t, h, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("400 for empty file list", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		resp := doUpload(t, h, uploadBody(t, id, secret, nil))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("405 for non-POST", func(t *testing.T) {
		h, _, _ := uploadTestServer(t, true)
		req := httptest.NewRequest(http.MethodGet, "http://example.com/upload", nil)
		w := httptest.NewRecorder()
		h.uploadHandler(w, req)
		require.Equal(t, http.StatusMethodNotAllowed, w.Result().StatusCode)
	})

	// A failure partway through must not leave the session holding some files.
	t.Run("rejects the whole request if any file is invalid", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		body := fmt.Sprintf(
			`{"correlation-id":%q,"secret-key":%q,"files":[{"name":"good.dtd","data":"eA=="},{"name":"../bad","data":"eQ=="}]}`,
			id, secret)
		resp := doUpload(t, h, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		files, _ := h.options.UploadStorage().ListUploads(id)
		require.Empty(t, files, "no file should have been stored")
	})
}

func TestRegisterAdvertisesCapabilities(t *testing.T) {
	t.Run("uploads enabled", func(t *testing.T) {
		h, _, _ := uploadTestServer(t, true)
		h.options.Ftp = true
		// Set at startup once the FTP and upload roots are known to be the same
		// directory; without it FTP is not advertised for hosted files.
		h.options.FTPServesUploads = true

		body := fmt.Sprintf(`{"public-key":%q,"secret-key":%q,"correlation-id":%q}`,
			testPublicKey(t), uuid.New().String(), xid.New().String())
		w := httptest.NewRecorder()
		h.registerHandler(w, httptest.NewRequest(http.MethodPost, "http://example.com/register", strings.NewReader(body)))

		resp := w.Result()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		out := &RegisterResponse{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
		require.Equal(t, "registration successful", out.Message,
			"legacy clients match on this exact string")
		require.NotNil(t, out.Capabilities)
		require.True(t, out.Capabilities.Upload)
		require.True(t, out.Capabilities.FTP)
		require.EqualValues(t, 1024, out.Capabilities.UploadMaxFileSize)
		require.Equal(t, 3, out.Capabilities.UploadMaxFiles)
	})

	// An ftp:// URL that resolves to nothing is worse than no URL: the target
	// follows it, gets a 550, and the operator reads the silence as "not
	// vulnerable". So a split root must not be advertised.
	t.Run("ftp not advertised when it cannot reach the uploads", func(t *testing.T) {
		h, _, _ := uploadTestServer(t, true)
		h.options.Ftp = true
		h.options.FTPServesUploads = false

		body := fmt.Sprintf(`{"public-key":%q,"secret-key":%q,"correlation-id":%q}`,
			testPublicKey(t), uuid.New().String(), xid.New().String())
		w := httptest.NewRecorder()
		h.registerHandler(w, httptest.NewRequest(http.MethodPost, "http://example.com/register", strings.NewReader(body)))

		out := &RegisterResponse{}
		require.NoError(t, json.NewDecoder(w.Result().Body).Decode(out))
		require.NotNil(t, out.Capabilities)
		require.True(t, out.Capabilities.Upload, "http hosting still works")
		require.False(t, out.Capabilities.FTP, "a split root must not be advertised as ftp-capable")
	})

	t.Run("uploads disabled", func(t *testing.T) {
		h, _, _ := uploadTestServer(t, false)

		body := fmt.Sprintf(`{"public-key":%q,"secret-key":%q,"correlation-id":%q}`,
			testPublicKey(t), uuid.New().String(), xid.New().String())
		w := httptest.NewRecorder()
		h.registerHandler(w, httptest.NewRequest(http.MethodPost, "http://example.com/register", strings.NewReader(body)))

		out := &RegisterResponse{}
		require.NoError(t, json.NewDecoder(w.Result().Body).Decode(out))
		require.NotNil(t, out.Capabilities)
		require.False(t, out.Capabilities.Upload)
	})
}
