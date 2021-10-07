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

const banner = `
    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.6
`

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Warning().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Warning().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

func main() {

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	serverURL := flag.String("server", "https://interactsh.com", "Interactsh server to use")
	n := flag.Int("n", 1, "Interactsh payload count to generate")
	output := flag.String("o", "", "Output file to write interaction")
	json := flag.Bool("json", false, "Write output in JSONL(ines) format")
	verbose := flag.Bool("v", false, "Display verbose interaction")
	pollInterval := flag.Int("poll-interval", 5, "Interaction poll interval in seconds")
	persistent := flag.Bool("persist", false, "Enables persistent interactsh sessions")
	dnsOnly := flag.Bool("dns-only", false, "Display only dns interaction in CLI output")
	httpOnly := flag.Bool("http-only", false, "Display only http interaction in CLI output")
	smtpOnly := flag.Bool("smtp-only", false, "Display only smtp interactions in CLI output")
	token := flag.String("token", "", "Authentication token to connect interactsh server")

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
		Token:             *token,
	})
	if err != nil {
		gologger.Fatal().Msgf("Could not create client: %s\n", err)
	}

	gologger.Info().Msgf("Listing %d payload for OOB Testing\n", *n)
	for i := 0; i < *n; i++ {
		gologger.Info().Msgf("%s\n", client.URL())
	}

	// show all interactions
	noFilter := !*dnsOnly && !*httpOnly && !*smtpOnly

	client.StartPolling(time.Duration(*pollInterval)*time.Second, func(interaction *server.Interaction) {
		if !*json {
			builder := &bytes.Buffer{}

			switch interaction.Protocol {
			case "dns":
				if noFilter || *dnsOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received DNS interaction (%s) from %s at %s", interaction.FullId, interaction.QType, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if *verbose {
						builder.WriteString(fmt.Sprintf("\n-----------\nDNS Request\n-----------\n\n%s\n\n------------\nDNS Response\n------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "http":
				if noFilter || *httpOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received HTTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if *verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nHTTP Request\n------------\n\n%s\n\n-------------\nHTTP Response\n-------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "smtp":
				if noFilter || *smtpOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received SMTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if *verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nSMTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "responder", "smb":
				if noFilter {
					builder.WriteString(fmt.Sprintf("Received Responder/Smb interaction at %s", interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if *verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nResponder/SMB Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			}
		} else {
			b, err := jsonpkg.MarshalIndent(interaction, "", "\t")
			if err != nil {
				gologger.Error().Msgf("Could not marshal json output: %s\n", err)
			} else {
				os.Stdout.Write(b)
				os.Stdout.Write([]byte("\n"))
			}
			if outputFile != nil {
				_, _ = outputFile.Write(b)
				_, _ = outputFile.Write([]byte("\n"))
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

func writeOutput(outputFile *os.File, builder *bytes.Buffer) {
	if outputFile != nil {
		_, _ = outputFile.Write(builder.Bytes())
		_, _ = outputFile.Write([]byte("\n"))
	}
	gologger.Silent().Msgf("%s", builder.String())
}
