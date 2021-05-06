package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

func main() {
	var eviction int
	var debug bool

	options := &server.Options{}
	flag.BoolVar(&debug, "debug", false, "Use interactsh in debug mode")
	flag.StringVar(&options.Domain, "domain", "", "Domain to use for interactsh server")
	flag.StringVar(&options.IPAddress, "ip", "", "IP Address to use for interactsh server")
	flag.StringVar(&options.ListenIP, "listen-ip", "0.0.0.0", "IP Address to listen on")
	flag.StringVar(&options.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server")
	flag.IntVar(&eviction, "eviction", 7, "Number of days to persist interactions for")
	flag.Parse()

	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetWriter(&noopWriter{})
	}

	store := storage.New(time.Duration(eviction) * time.Hour * 24)
	options.Storage = store

	dnsServer, err := server.NewDNSServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create DNS server")
	}
	go dnsServer.ListenAndServe()

	trimmedDomain := strings.TrimSuffix(options.Domain, ".")
	autoTLS, err := acme.NewAutomaticTLS(options.Hostmaster, fmt.Sprintf("*.%s,%s", trimmedDomain, trimmedDomain), func(txt string) {
		dnsServer.TxtRecord = txt
	})
	if err != nil {
		gologger.Fatal().Msgf("Could not generate certs for auto TLS")
	}
	httpServer, err := server.NewHTTPServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create HTTP server")
	}
	go httpServer.ListenAndServe(autoTLS)

	smtpServer, err := server.NewSMTPServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create SMTP server")
	}
	go smtpServer.ListenAndServe(autoTLS)

	log.Printf("Listening on DNS, SMTP and HTTP ports\n")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		os.Exit(1)
	}
}

type noopWriter struct{}

func (n *noopWriter) Write(data []byte, level levels.Level) {}
