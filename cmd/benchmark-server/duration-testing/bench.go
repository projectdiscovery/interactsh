package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryabledns"
	"go.uber.org/ratelimit"
)

var defaultDuration time.Duration

func init() {
	defaultDuration, _ = time.ParseDuration("30s")
}

var (
	serverURL             = flag.String("url", "http://192.168.1.86", "URL of the interactsh server")
	serverIP              = flag.String("ip", "192.168.1.86", "IP of benchmarked server")
	n                     = flag.Int("n", 1000, "Number of interactsh clients to register")
	pollintInterval       = flag.Duration("d", defaultDuration, "Polling interval")
	interactionsRateLimit = flag.Int("rl", 10, "Max interactions per second per session")
)

var (
	errors int64
)

func main() {
	flag.Parse()

	if err := process(); err != nil {
		log.Fatalf("Could not process: %s\n", err)
	}
}

func process() error {
	var swg sync.WaitGroup
	for i := 0; i < *n; i++ {
		swg.Add(1)

		go func(idx int) {
			defer swg.Done()

			startClient(idx)
		}(i)
	}
	swg.Wait()

	return nil
}

func startClient(idx int) {
	client, err := client.New(&client.Options{
		ServerURL: *serverURL,
	})
	if err != nil {
		errors++
		log.Printf("Unexpected register response: %v\n", err)
		return
	}

	log.Printf("client %d registered, sample url: %s\n", idx, client.URL())
	client.StartPolling(defaultDuration, func(interaction *server.Interaction) {
		log.Printf("Client %d polled interaction: %s interactions:", idx, interaction.FullId)
	})

	dnsClient := retryabledns.New([]string{*serverIP + ":53"}, 1)

	// simulate continous interactions
	rateLimiter := ratelimit.New(*interactionsRateLimit)
	for {
		rateLimiter.Take()
		req, _ := http.NewRequest(http.MethodGet, *serverURL, nil)
		req.Host = client.URL()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("client %d failed to send http request\n", idx)
		} else if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			log.Printf("Client %d sent HTTP request: %d\n", idx, resp.StatusCode)
		}

		data, err := dnsClient.Query(client.URL(), dns.TypeA)
		if err != nil {
			log.Printf("client %d failed to send dns request\n", idx)
		}
		log.Printf("Client %d sent DNS request: %s\n", idx, data.StatusCode)
	}
}
