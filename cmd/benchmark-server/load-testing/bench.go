package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/retryabledns"
	"github.com/remeh/sizedwaitgroup"
)

var (
	serverURL   = flag.String("url", "https://hackwithautomation.com", "URL of the interactsh server")
	serverIP    = flag.String("ip", "138.68.140.25", "IP of benchmarked server")
	pollCount   = flag.Int("poll-count", 10, "Number of poll interactions per registered URL")
	n           = flag.Int("n", 1000, "Number of interactsh sessions to register")
	concurrency = flag.Int("c", 300, "Number of concurrent requests to send")
	token       = flag.String("token", "gg", "Authentication token for the server")
)

var (
	errors   = int64(0)
	requests = int64(0)
	polls    = int64(0)
)

func main() {
	flag.Parse()

	if err := process(); err != nil {
		log.Fatalf("Could not process: %s\n", err)
	}
}

func process() error {
	swg := sizedwaitgroup.New(*concurrency)
	for i := 0; i < *n; i++ {
		swg.Add()

		go func() {
			benchmarkServer()
			swg.Done()
		}()
	}
	swg.Wait()

	fmt.Printf("Send: errors=%v requests=%v polls=%v\n", errors, requests, polls)
	return nil
}

func benchmarkServer() {
	client, err := client.New(&client.Options{
		ServerURL: *serverURL,
		Token:     *token,
	})
	if err != nil {
		errors++
		log.Printf("Unexpected register response: %v\n", err)
		return
	}

	dnsClient, err := retryabledns.New([]string{*serverIP + ":53"}, 1)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < *pollCount; i++ {
		client.URL()

		polls++
		data, err := dnsClient.Query(client.URL(), dns.TypeA)
		if err != nil {
			errors++
			log.Printf("Unexpected resolve response: %v\n", err)
			continue
		}
		_ = data
	}
	requests++
}
