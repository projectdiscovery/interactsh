package client

import (
	"bytes"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestNewAcceptsServerURLWithOptionalTrailingSlash(t *testing.T) {
	var registrationCount atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "//register":
			// Some deployments canonicalize this path with a redirect that drops the POST body.
			http.Redirect(w, r, "/register", http.StatusMovedPermanently)
		case "/register", "/base%2F/register":
			request := &server.RegisterRequest{}
			if err := json.NewDecoder(r.Body).Decode(request); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"could not decode json body: %s"}`, err), http.StatusBadRequest)
				return
			}
			registrationCount.Add(1)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/poll":
			_, _ = w.Write([]byte(`{"data":[],"extra":[],"aes_key":""}`))
		case "/deregister", "/base%2F/deregister":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})

	testServer := httptest.NewTLSServer(handler)
	t.Cleanup(testServer.Close)

	httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	httpClient.HTTPClient = testServer.Client()

	for _, test := range []struct {
		name   string
		suffix string
	}{
		{name: "without trailing slash"},
		{name: "with trailing slash", suffix: "/"},
		{name: "with percent-encoded slash", suffix: "/base%2F/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			interactshClient, err := New(&Options{
				ServerURL:           testServer.URL + test.suffix,
				DisableHTTPFallback: true,
				HTTPClient:          httpClient,
			})
			require.NoError(t, err)
			require.NoError(t, interactshClient.Close())
		})
	}

	t.Run("resumed session with trailing slash", func(t *testing.T) {
		originalClient, err := New(&Options{
			ServerURL:           testServer.URL,
			DisableHTTPFallback: true,
			HTTPClient:          httpClient,
		})
		require.NoError(t, err)

		publicKey, err := encodePublicKey(originalClient.pubKey)
		require.NoError(t, err)
		sessionInfo := &options.SessionInfo{
			ServerURL:     testServer.URL + "/",
			PrivateKey:    string(x509.MarshalPKCS1PrivateKey(originalClient.privKey)),
			CorrelationID: originalClient.correlationID,
			SecretKey:     originalClient.secretKey,
			PublicKey:     publicKey,
		}
		require.NoError(t, originalClient.Close())

		registrationsBeforeResume := registrationCount.Load()
		resumedClient, err := New(&Options{
			SessionInfo: sessionInfo,
			HTTPClient:  httpClient,
		})
		require.NoError(t, err)
		require.Equal(t, registrationsBeforeResume+1, registrationCount.Load())
		require.NoError(t, resumedClient.getInteractions(func(*server.Interaction) {}))
		require.NoError(t, resumedClient.Close())
	})
}

type testBufferWriter struct {
	buf bytes.Buffer
}

func (w *testBufferWriter) Write(data []byte, level levels.Level) {
	w.buf.Write(data)
}

func TestClient_CustomLogger(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/deregister":
			w.WriteHeader(http.StatusOK)
		case "/poll":
			// Return invalid JSON to trigger a poll decode error
			_, _ = w.Write([]byte(`invalid json`))
		default:
			http.NotFound(w, r)
		}
	})

	testServer := httptest.NewTLSServer(handler)
	t.Cleanup(testServer.Close)

	httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	httpClient.HTTPClient = testServer.Client()

	t.Run("defaults to gologger.DefaultLogger when nil", func(t *testing.T) {
		c, err := New(&Options{
			ServerURL:           testServer.URL,
			DisableHTTPFallback: true,
			HTTPClient:          httpClient,
		})
		require.NoError(t, err)
		require.Equal(t, gologger.DefaultLogger, c.logger)
		require.NoError(t, c.Close())
	})

	t.Run("uses custom caller logger when specified", func(t *testing.T) {
		bw := &testBufferWriter{}
		customLogger := &gologger.Logger{}
		customLogger.SetFormatter(formatter.NewCLI(false))
		customLogger.SetWriter(bw)
		customLogger.SetMaxLevel(levels.LevelVerbose)

		c, err := New(&Options{
			ServerURL:           testServer.URL,
			DisableHTTPFallback: true,
			HTTPClient:          httpClient,
			Logger:              customLogger,
		})
		require.NoError(t, err)
		require.Equal(t, customLogger, c.logger)

		// Poll returns invalid JSON, which should log to customLogger
		err = c.getInteractions(func(*server.Interaction) {})
		require.Error(t, err)
		require.Contains(t, bw.buf.String(), "Could not decode interactions")

		require.NoError(t, c.Close())
	})
}
