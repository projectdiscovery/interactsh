package client

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestNewTLSVerifyEnv(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/register":
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)

	t.Run("default accepts self-signed certificate", func(t *testing.T) {
		c, err := New(&Options{ServerURL: srv.URL, Token: "test-token"})
		require.NoError(t, err)
		_ = c.Close()
	})

	t.Setenv("INTERACTSH_TLS_VERIFY", "true")

	t.Run("untrusted certificate is refused", func(t *testing.T) {
		requests.Store(0)
		_, err := New(&Options{ServerURL: srv.URL, Token: "test-token"})
		require.ErrorContains(t, err, "certificate")
		require.Zero(t, requests.Load(), "a request reached the untrusted server")
	})

	t.Run("trusted certificate is accepted", func(t *testing.T) {
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())
		httpClient.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots

		c, err := New(&Options{ServerURL: srv.URL, Token: "test-token", HTTPClient: httpClient})
		require.NoError(t, err)
		tr := httpClient.HTTPClient2.Transport.(*http.Transport)
		require.Nil(t, tr.DialTLSContext)
		require.Nil(t, tr.DialTLS) //nolint:staticcheck // DialTLS is deprecated but still used
		require.False(t, tr.TLSClientConfig.InsecureSkipVerify)
		require.Same(t, roots, tr.TLSClientConfig.RootCAs, "the fallback client must trust the primary roots")
		require.True(t, c.disableHTTPFallback, "the cleartext fallback must be off")
		require.Equal(t, []string{"h2", "http/1.1"}, tr.TLSClientConfig.NextProtos, "the fallback client must keep its HTTP/2 ALPN offer")
		_ = c.Close()
	})

	t.Run("cleartext session URL is refused", func(t *testing.T) {
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())
		httpClient.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots

		_, err := New(&Options{ServerURL: srv.URL, Token: "test-token", HTTPClient: httpClient, SessionInfo: &options.SessionInfo{
			ServerURL: "http://" + srv.Listener.Addr().String(),
			PublicKey: "unused",
		}})
		require.ErrorContains(t, err, "session server URL is not https")
	})
}
