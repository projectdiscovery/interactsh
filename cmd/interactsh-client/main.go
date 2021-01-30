package main

import (
	"flag"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

var (
	serverURL    = flag.String("url", "https://interact.sh", "URL of the interactsh server")
	n            = flag.Int("n", 1, "Number of interactable URLs to generate")
	pollInterval = flag.Int("poll-interval", 5, "Number of seconds between each poll request")
	persistent   = flag.Bool("persistent", false, "Enables persistent interactsh sessions")
)

func main() {
	flag.Parse()

	client, err := client.New(&client.Options{
		ServerURL:         *serverURL,
		PersistentSession: *persistent,
	})
	if err != nil {
		gologger.Fatal().Msgf("Could not create client: %s\n", err)
	}

	gologger.Info().Msgf("Listing %d URLs\n", *n)
	for i := 0; i < *n; i++ {
		gologger.Silent().Msgf("%s\n", client.URL())
	}

	client.StartPolling(time.Duration(*pollInterval)*time.Second, func(interaction *server.Interaction) {
		gologger.Silent().Msgf(
			"[%s] %s interaction from %s",
			interaction.UniqueID, strings.ToUpper(interaction.Protocol), interaction.RemoteAddress,
		)
		if interaction.QType != "" {
			gologger.Silent().Msgf("DNS Request Type: %s", interaction.QType)
		}
		if interaction.SMTPFrom != "" {
			gologger.Silent().Msgf("SMTP Request From: %s", interaction.SMTPFrom)
		}
		gologger.Silent().Msgf("\nRequest:\n%s\n", interaction.RawRequest)
		gologger.Silent().Msgf("\nResponse:\n%s\n", interaction.RawResponse)
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		client.StopPolling()
		client.Close()
		os.Exit(1)
	}
}
