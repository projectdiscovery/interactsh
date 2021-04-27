package main

import (
	"bytes"
	jsonpkg "encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

var (
	serverURL    = flag.String("url", "https://interact.sh", "URL of the interactsh server")
	n            = flag.Int("n", 1, "Number of interactable URLs to generate")
	output       = flag.String("o", "", "File to write output to")
	json         = flag.Bool("json", false, "Show JSON output")
	verbose      = flag.Bool("v", false, "Show verbose output")
	pollInterval = flag.Int("poll-interval", 5, "Number of seconds between each poll request")
	persistent   = flag.Bool("persist", false, "Enables persistent interactsh sessions")
)

const banner = `
    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.1
`

const Version = `0.0.1`

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Warning().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Warning().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

func main() {
	flag.Parse()

	showBanner()

	var outputFile *os.File
	var err error
	if *output != "" {
		if outputFile, err = os.Create(*output); err != nil {
			gologger.Fatal().Msgf("Could not create output file: %s\n", err)
		}
		defer outputFile.Close()
	}

	client, err := client.New(&client.Options{
		ServerURL:         *serverURL,
		PersistentSession: *persistent,
	})
	if err != nil {
		gologger.Fatal().Msgf("Could not create client: %s\n", err)
	}

	gologger.Info().Msgf("Listing %d URL for OOB Testing\n", *n)
	for i := 0; i < *n; i++ {
		gologger.Info().Msgf("%s\n", client.URL())
	}

	client.StartPolling(time.Duration(*pollInterval)*time.Second, func(interaction *server.Interaction) {
		if !*json {
			builder := &bytes.Buffer{}

			switch interaction.Protocol {
			case "dns":
				builder.WriteString(fmt.Sprintf("[%s] Recieved DNS interaction (%s) from %s at %s", interaction.UniqueID, interaction.QType, interaction.RemoteAddress, interaction.Timestamp.Format("2006-02-02 15:04")))
				if *verbose {
					builder.WriteString(fmt.Sprintf("\n-----------\nDNS Request\n-----------\n\n%s\n\n------------\nDNS Response\n------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
				}
			case "http":
				builder.WriteString(fmt.Sprintf("[%s] Recieved HTTP interaction from %s at %s", interaction.UniqueID, interaction.RemoteAddress, interaction.Timestamp.Format("2006-02-02 15:04")))
				if *verbose {
					builder.WriteString(fmt.Sprintf("\n------------\nHTTP Request\n------------\n\n%s\n\n-------------\nHTTP Response\n-------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
				}
			case "smtp":
				builder.WriteString(fmt.Sprintf("[%s] Recieved SMTP interaction from %s at %s", interaction.UniqueID, interaction.RemoteAddress, interaction.Timestamp.Format("2006-02-02 15:04")))
				if *verbose {
					builder.WriteString(fmt.Sprintf("\n------------\nSMTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
				}
			}
			if outputFile != nil {
				outputFile.Write(builder.Bytes())
				outputFile.Write([]byte("\n"))
			}
			gologger.Silent().Msgf("%s", builder.String())
		} else {
			b, err := jsonpkg.MarshalIndent(interaction, "", "\t")
			if err != nil {
				gologger.Error().Msgf("Could not marshal json output: %s\n", err)
			} else {
				os.Stdout.Write(b)
				os.Stdout.Write([]byte("\n"))
			}
			if outputFile != nil {
				outputFile.Write(b)
				outputFile.Write([]byte("\n"))
			}
		}
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		client.StopPolling()
		client.Close()
		os.Exit(1)
	}
}
