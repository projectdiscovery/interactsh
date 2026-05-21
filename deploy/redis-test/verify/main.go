// verify is a small smoke harness for issue #1267: it registers a client
// against interactsh-server "A", triggers an HTTP interaction directly on
// interactsh-server "B", and verifies that the polling client (still talking
// to "A") receives the interaction thanks to the shared Redis state.
//
//	go run ./deploy/redis-test/verify
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "verify FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("verify OK")
}

func run() error {
	urlA := envOr("ISH_A_URL", "http://localhost:8080")
	urlB := envOr("ISH_B_URL", "http://localhost:8081")
	token := envOr("ISH_TOKEN", "testtoken-7e2c")

	c, err := client.New(&client.Options{
		ServerURL:                urlA,
		Token:                    token,
		DisableHTTPFallback:      false,
		CorrelationIdLength:      20,
		CorrelationIdNonceLength: 13,
	})
	if err != nil {
		return fmt.Errorf("client.New: %w", err)
	}
	defer c.Close()

	callbackURL := c.URL()
	if callbackURL == "" {
		return fmt.Errorf("client did not return a callback URL")
	}
	fmt.Printf("registered against A, callback URL = %s\n", callbackURL)

	got := make(chan *server.Interaction, 1)
	var once sync.Once
	if err := c.StartPolling(500*time.Millisecond, func(ix *server.Interaction) {
		once.Do(func() { got <- ix })
	}); err != nil {
		return fmt.Errorf("StartPolling: %w", err)
	}

	// Give the poller one tick to enter its loop before we trigger.
	time.Sleep(750 * time.Millisecond)

	// Trigger an HTTP interaction on instance B by curling its HTTP port
	// with a Host header matching the registered subdomain. Instance B
	// resolves the correlation id from the host, encrypts the request
	// payload with the AES key that lives in shared Redis, and pushes the
	// ciphertext to the data list. Instance A serves the poll.
	probe := fmt.Sprintf("hello-from-instance-b-%d", time.Now().UnixNano())
	if err := triggerHTTP(urlB, callbackURL, probe); err != nil {
		return fmt.Errorf("trigger interaction on B: %w", err)
	}
	fmt.Printf("triggered HTTP interaction on B with probe %q\n", probe)

	select {
	case ix := <-got:
		if ix == nil {
			return fmt.Errorf("nil interaction received")
		}
		if !strings.Contains(ix.RawRequest, probe) {
			return fmt.Errorf("interaction received but probe %q not present in RawRequest: %q",
				probe, ix.RawRequest)
		}
		fmt.Printf("polled from A, captured B's interaction (protocol=%s, remote=%s)\n",
			ix.Protocol, ix.RemoteAddress)
		return nil
	case <-time.After(15 * time.Second):
		return fmt.Errorf("timed out waiting for interaction to propagate via Redis")
	}
}

func triggerHTTP(serverURL, callbackURL, probe string) error {
	host := strings.Split(strings.TrimPrefix(strings.TrimPrefix(callbackURL,
		"http://"), "https://"), "/")[0]

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		serverURL+"/"+probe, nil)
	if err != nil {
		return err
	}
	req.Host = host
	req.Header.Set("X-Probe", probe)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
