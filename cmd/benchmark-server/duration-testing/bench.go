package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryabledns"
	"go.uber.org/ratelimit"
)

var (
	serverURL             = flag.String("url", "http://192.168.1.86", "URL of the interactsh server")
	serverIP              = flag.String("ip", "192.168.1.86", "IP of benchmarked server")
	n                     = flag.Int("n", 100, "Number of interactsh clients to register")
	pollintInterval       = flag.Int("d", 30, "Polling interval in seconds")
	interactionsRateLimit = flag.Int("rl", 10, "Max interactions per second per session")
)

var (
	clients   []*client.Client
	ctx       context.Context
	ctxCancel context.CancelFunc
)

func main() {
	flag.Parse()

	ctx, ctxCancel = context.WithCancel(context.Background())
	clients = make([]*client.Client, *n)

	if err := process(); err != nil {
		log.Fatalf("Could not process: %s\n", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		ctxCancel()
		for _, client := range clients {
			_ = client.StopPolling()
			_ = client.Close()
		}
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
		log.Printf("Unexpected register response: %v\n", err)
		return
	}

	clients[idx] = client

	log.Printf("client %d registered, sample url: %s\n", idx, client.URL())
	_ = client.StartPolling(time.Duration(*pollintInterval)*time.Second, func(interaction *server.Interaction) {
		log.Printf("Client %d polled interaction: %s\n", idx, interaction.FullId)
	})

	dnsClient, err := retryabledns.New([]string{*serverIP + ":53"}, 1)
	if err != nil {
		log.Fatal(err)
	}

	// simulate continuous interactions
	rateLimiter := ratelimit.New(*interactionsRateLimit)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			rateLimiter.Take()
			req, err := http.NewRequest(http.MethodGet, *serverURL, nil)
			if err != nil {
				log.Printf("%s\n", err)
				continue
			}
			req.Host = client.URL()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("client %d failed to send http request\n", idx)
			} else if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
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
}
