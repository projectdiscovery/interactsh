package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// newUploadClient returns a client pointed at handler, already "registered".
func newUploadClient(t *testing.T, handler http.HandlerFunc, caps *server.Capabilities) *Client {
	t.Helper()

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	parsed, err := url.Parse(ts.URL)
	require.NoError(t, err)

	c := &Client{
		correlationID:            "c6rj61aciaeutn2ae680",
		secretKey:                "6a1b0e5c-3f2d-4a7b-8c9d-0e1f2a3b4c5d",
		serverURL:                parsed,
		httpClient:               retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle),
		correlationIdLength:      20,
		CorrelationIdNonceLength: 13,
	}
	c.State.Store(Idle)
	if caps != nil {
		c.capabilities.Store(caps)
	}
	return c
}

func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, content, 0o600))
	return p
}

func TestUploadFiles(t *testing.T) {
	caps := &server.Capabilities{Upload: true, UploadMaxFileSize: 1024, UploadMaxFiles: 5, FTP: true}

	t.Run("posts the expected request and decodes the response", func(t *testing.T) {
		var (
			gotAuth   string
			gotPath   string
			gotMethod string
			gotBody   server.UploadRequest
		)
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
			require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))

			_ = json.NewEncoder(w).Encode(&server.UploadResponse{
				Message: "upload successful",
				Files: []server.UploadedFileResponse{{
					Name: "evil.dtd", Size: 7, SHA256: "abc",
					HTTPPath: "/f/evil.dtd", FTPPath: "/.interactsh-user-uploads/c6rj61aciaeutn2ae680/evil.dtd",
				}},
			})
		}, caps)
		c.token = "sekrit"

		files, err := c.UploadFiles([]string{writeTempFile(t, "evil.dtd", []byte("payload"))})
		require.NoError(t, err)

		require.Equal(t, http.MethodPost, gotMethod)
		require.Equal(t, "/upload", gotPath)
		require.Equal(t, "sekrit", gotAuth)
		require.Equal(t, "c6rj61aciaeutn2ae680", gotBody.CorrelationID)
		require.Equal(t, c.secretKey, gotBody.SecretKey)
		require.Len(t, gotBody.Files, 1)
		require.Equal(t, "evil.dtd", gotBody.Files[0].Name)
		require.Equal(t, "cGF5bG9hZA==", gotBody.Files[0].Data, "content should be base64 encoded")

		require.Len(t, files, 1)
		require.Equal(t, "/f/evil.dtd", files[0].HTTPPath)
	})

	t.Run("501 reports unsupported", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
		}, nil)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.ErrorIs(t, err, ErrUploadUnsupported)
	})

	t.Run("404 and 405 report unsupported", func(t *testing.T) {
		for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
			c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}, nil)
			_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
			require.ErrorIs(t, err, ErrUploadUnsupported, "status %d", code)
		}
	})

	t.Run("server error message is surfaced", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write([]byte(`{"error":"file is too big"}`))
		}, caps)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.Error(t, err)
		require.Contains(t, err.Error(), "file is too big")
	})

	t.Run("advertised absence of upload fails without a request", func(t *testing.T) {
		var called atomic.Bool
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
		}, &server.Capabilities{Upload: false})

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.ErrorIs(t, err, ErrUploadUnsupported)
		require.False(t, called.Load(), "must not contact a server known not to support uploads")
	})

	t.Run("local validation happens before any request", func(t *testing.T) {
		cases := []struct {
			name  string
			paths func(t *testing.T) []string
			want  string
		}{
			{"missing file", func(t *testing.T) []string {
				return []string{filepath.Join(t.TempDir(), "absent.dtd")}
			}, "could not read file"},
			{"directory", func(t *testing.T) []string {
				return []string{t.TempDir()}
			}, "not a regular file"},
			{"empty file", func(t *testing.T) []string {
				return []string{writeTempFile(t, "empty.dtd", nil)}
			}, "is empty"},
			{"oversize", func(t *testing.T) []string {
				return []string{writeTempFile(t, "big.dtd", make([]byte, 4096))}
			}, "accepts at most"},
			{"unusable name", func(t *testing.T) []string {
				return []string{writeTempFile(t, ".hidden", []byte("x"))}
			}, "will not accept"},
			{"too many files", func(t *testing.T) []string {
				var paths []string
				for i := 0; i < 6; i++ {
					paths = append(paths, writeTempFile(t, "f.dtd", []byte("x")))
				}
				return paths
			}, "accepts at most"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var called atomic.Bool
				c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
					called.Store(true)
				}, caps)

				_, err := c.UploadFiles(tc.paths(t))
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.want)
				require.False(t, called.Load(), "must fail before contacting the server")
			})
		}
	})

	t.Run("duplicate basenames are rejected", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {}, caps)

		a := writeTempFile(t, "evil.dtd", []byte("one"))
		b := writeTempFile(t, "evil.dtd", []byte("two"))
		_, err := c.UploadFiles([]string{a, b})
		require.Error(t, err)
		require.Contains(t, err.Error(), "would both be hosted as")
	})

	t.Run("refuses plaintext http to a remote server", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {}, caps)
		c.serverURL = &url.URL{Scheme: "http", Host: "oast.example.com"}

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refusing to upload over plaintext http",
			"the file and the secret key must not go over the wire in clear")
	})

	t.Run("closed client", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {}, caps)
		c.State.Store(Closed)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.Error(t, err)
		require.False(t, errors.Is(err, ErrUploadUnsupported))
	})
}

func TestFileURLComposition(t *testing.T) {
	file := UploadedFile{Name: "evil.dtd", HTTPPath: "/f/evil.dtd", FTPPath: "/.interactsh-user-uploads/c6rj61aciaeutn2ae680/evil.dtd"}
	// 20-char correlation id plus a 13-char nonce, as URL() composes it.
	host := "c6rj61aciaeutn2ae680xk4tqy8pqhwmi.oast.test"

	t.Run("https server", func(t *testing.T) {
		c := &Client{serverURL: &url.URL{Scheme: "https", Host: "oast.test"}}
		require.Equal(t, "https://"+host+"/f/evil.dtd", c.FileURL(host, file))
		require.Equal(t, "ftp://"+host+"/.interactsh-user-uploads/c6rj61aciaeutn2ae680/evil.dtd", c.FTPFileURL(host, file))
	})

	t.Run("http server", func(t *testing.T) {
		c := &Client{serverURL: &url.URL{Scheme: "http", Host: "127.0.0.1:8080"}}
		require.Equal(t, "http://"+host+"/f/evil.dtd", c.FileURL(host, file))
	})
}

func TestIsLoopbackURL(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		require.True(t, isLoopbackURL(host), "expected %q to be loopback", host)
	}
	for _, host := range []string{"oast.test", "example.com:8080", "10.0.0.1"} {
		require.False(t, isLoopbackURL(host), "expected %q not to be loopback", host)
	}
}
