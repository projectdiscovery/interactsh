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
	// A registration happened, so whatever it said -- including nothing -- is
	// authoritative. newResumedUploadClient covers the other case.
	c.capabilitiesKnown.Store(true)
	return c
}

// newResumedUploadClient models a session resumed from -sf whose re-registration
// was refused because the session is still alive: no capabilities were ever
// received, so nothing is known about what the server offers.
func newResumedUploadClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	c := newUploadClient(t, handler, nil)
	c.capabilitiesKnown.Store(false)
	return c
}

func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, content, 0o600))
	return p
}

// errkit compares errors by message, so building ErrUploadNotAdvertised on an
// errkit sentinel made errors.Is match in both directions -- and the CLI checks the
// specific error first, so a server with -upload merely switched off was told to
// upgrade. The direction has to stay one-way.
func TestUploadSentinelsAreDirectional(t *testing.T) {
	require.True(t, errors.Is(ErrUploadNotAdvertised, ErrUploadUnsupported),
		"a server that advertised nothing cannot host files either")
	require.False(t, errors.Is(ErrUploadUnsupported, ErrUploadNotAdvertised),
		"a server that answered 501 is not a server that failed to advertise")
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

	// Capabilities are advertised here, so the request is actually made: a server
	// that says it can host files and then refuses is the case 501 is left for.
	t.Run("501 reports unsupported", func(t *testing.T) {
		var called atomic.Bool
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
			w.WriteHeader(http.StatusNotImplemented)
		}, caps)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.ErrorIs(t, err, ErrUploadUnsupported)
		require.True(t, called.Load(), "the 501 path is only reachable by sending the request")
	})

	// 404 is what the server answers for an unknown correlation id -- a session
	// problem needing a re-register, not a server missing a flag. Reporting it as
	// "does not accept file uploads" sent the operator after the wrong remedy.
	t.Run("404 surfaces the server's reason rather than claiming unsupported", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"unknown correlation-id"}`))
		}, caps)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown correlation-id")
		require.Contains(t, err.Error(), "404")
		require.False(t, errors.Is(err, ErrUploadUnsupported),
			"an unknown session must not be reported as a server without -upload")
	})

	t.Run("405 is surfaced rather than claiming unsupported", func(t *testing.T) {
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}, caps)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.Error(t, err)
		require.False(t, errors.Is(err, ErrUploadUnsupported))
	})

	// A server advertising no capabilities predates file hosting. Its catch-all
	// answers 200 with HTML, so without this the failure was an opaque
	// "invalid character '<'" decode error.
	t.Run("a server that advertised nothing is refused before any request", func(t *testing.T) {
		var called atomic.Bool
		c := newUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head></head><body></body></html>"))
		}, nil)

		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.ErrorIs(t, err, ErrUploadNotAdvertised)
		require.ErrorIs(t, err, ErrUploadUnsupported,
			"callers asking only whether hosting is possible need no change")
		require.False(t, called.Load(), "no point asking a server that cannot answer")
		require.NotContains(t, err.Error(), "invalid character")
	})

	// Regression: a resumed session knows nothing about the server's capabilities,
	// and treating that as "the server offers nothing" made every -sf resume
	// refuse to upload, blaming a server that hosts files perfectly well.
	t.Run("a resumed session attempts the upload rather than assuming", func(t *testing.T) {
		var called atomic.Bool
		c := newResumedUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			called.Store(true)
			_ = json.NewEncoder(w).Encode(&server.UploadResponse{
				Message: "upload successful",
				Files: []server.UploadedFileResponse{{
					Name: "a.dtd", Size: 1, SHA256: "abc", HTTPPath: "/f/a.dtd",
				}},
			})
		})

		files, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.NoError(t, err, "an unknown capability set must not be read as unsupported")
		require.True(t, called.Load(), "the request has to be made to find out")
		require.Len(t, files, 1)
	})

	t.Run("a resumed session still reports a genuine 501", func(t *testing.T) {
		c := newResumedUploadClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
		})
		_, err := c.UploadFiles([]string{writeTempFile(t, "a.dtd", []byte("x"))})
		require.ErrorIs(t, err, ErrUploadUnsupported)
		require.False(t, errors.Is(err, ErrUploadNotAdvertised),
			"the server answered, so this is not version skew")
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

	// The payload host carries the HTTP listener's port, which tells us nothing
	// about where FTP is bound, so it must not leak into the ftp:// URL.
	t.Run("ftp url drops the http port", func(t *testing.T) {
		c := &Client{serverURL: &url.URL{Scheme: "http", Host: "127.0.0.1:8080"}}
		require.Equal(t, "ftp://"+host+"/.interactsh-user-uploads/c6rj61aciaeutn2ae680/evil.dtd",
			c.FTPFileURL(host+":8080", file))
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
