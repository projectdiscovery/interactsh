package main

import (
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

func main() {
	var eviction int
	var debug bool

	options := &server.Options{}
	flag.BoolVar(&debug, "debug", false, "Use interactsh in debug mode")
	flag.StringVar(&options.Domain, "domain", "", "Domain to use for interactsh server")
	flag.StringVar(&options.IPAddress, "ip", "", "IP Address to use for interactsh server")
	flag.StringVar(&options.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server")
	flag.StringVar(&options.CACert, "cacert", "", "CA Certificate to use for interactsh server")
	flag.StringVar(&options.CAKey, "cakey", "", "CA Key to use for interactsh server")
	flag.IntVar(&eviction, "eviction", 7, "Number of days to persist interactions for")
	flag.Parse()

	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}

	store := storage.New(time.Duration(eviction) * time.Hour * 24)
	options.Storage = store

	dnsServer, err := server.NewDNSServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create DNS server")
	}
	go dnsServer.ListenAndServe()

	httpServer, err := server.NewHTTPServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create HTTP server")
	}
	go httpServer.ListenAndServe()

	smtpServer, err := server.NewSMTPServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create SMTP server")
	}
	go smtpServer.ListenAndServe()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		os.Exit(1)
	}
}
