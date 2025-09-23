package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryablehttp-go"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestClient_NoLeak_AfterNew(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&server.PollResponse{Data: []string{}, Extra: []string{}, AESKey: "", TLDData: []string{}})
	})
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "deregistration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{
		ServerURL:         ts.URL,
		HTTPClient:        httpClient,
		KeepAliveInterval: 10 * time.Millisecond,
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	_ = c
	time.Sleep(50 * time.Millisecond)
}

func TestClient_NoLeaks_WhenStoppedAndClosed(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&server.PollResponse{Data: []string{}, Extra: []string{}, AESKey: "", TLDData: []string{}})
	})
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "deregistration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{
		ServerURL:  ts.URL,
		HTTPClient: httpClient,
		// disable keepalive here to avoid race clobbering Polling -> Idle during re-register
		KeepAliveInterval: 0,
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	if err := c.StartPolling(10*time.Millisecond, func(_ *server.Interaction) {}); err != nil {
		t.Fatalf("unexpected error starting polling: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	if err := c.StopPolling(); err != nil {
		t.Fatalf("unexpected error stopping polling: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("unexpected error closing client: %v", err)
	}

	time.Sleep(30 * time.Millisecond)
}

func TestClient_StartPolling_StateErrors(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{ServerURL: ts.URL, HTTPClient: httpClient, KeepAliveInterval: 0}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	c.State.Store(Polling)
	if err := c.StartPolling(5*time.Millisecond, func(_ *server.Interaction) {}); err == nil {
		t.Fatalf("expected error when already polling")
	}

	c.State.Store(Closed)
	if err := c.StartPolling(5*time.Millisecond, func(_ *server.Interaction) {}); err == nil {
		t.Fatalf("expected error when client is closed")
	}
}

func TestClient_StopPolling_NotPolling(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{ServerURL: ts.URL, HTTPClient: httpClient, KeepAliveInterval: 0}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	if err := c.StopPolling(); err == nil {
		t.Fatalf("expected error when not polling")
	}
}

func TestClient_Close_ErrorsAndDeregister(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&server.PollResponse{Data: []string{}, Extra: []string{}, AESKey: "", TLDData: []string{}})
	})
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "deregistration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{ServerURL: ts.URL, HTTPClient: httpClient, KeepAliveInterval: 0}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	if err := c.StartPolling(5*time.Millisecond, func(_ *server.Interaction) {}); err != nil {
		t.Fatalf("unexpected error starting polling: %v", err)
	}
	if err := c.Close(); err == nil {
		_ = c.StopPolling()
		t.Fatalf("expected error when closing while polling")
	}

	if err := c.StopPolling(); err != nil {
		t.Fatalf("unexpected error stopping polling: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("unexpected error closing client: %v", err)
	}
	if err := c.Close(); err == nil {
		t.Fatalf("expected error when closing already closed client")
	}
}

func TestClient_URL_Builds_And_EmptyOnClosed(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{ServerURL: ts.URL, HTTPClient: httpClient, KeepAliveInterval: 0}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	u := c.URL()
	if u == "" {
		t.Fatalf("expected non-empty URL")
	}

	c.State.Store(Closed)
	if got := c.URL(); got != "" {
		t.Fatalf("expected empty URL when closed, got %q", got)
	}
}

func TestClient_SaveSessionTo_WritesYAML(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = 2 * time.Second
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := &Options{ServerURL: ts.URL, HTTPClient: httpClient, KeepAliveInterval: 0}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	tmp := t.TempDir() + "/sess.yaml"
	if err := c.SaveSessionTo(tmp); err != nil {
		t.Fatalf("unexpected error saving session: %v", err)
	}
}
