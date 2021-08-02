package main

import (
	"crypto/rand"
	"encoding/hex"
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
	"github.com/projectdiscovery/nebula"
)

func main() {
	var eviction int
	var debug, skipacme bool

	options := &server.Options{}
	flag.BoolVar(&debug, "debug", false, "Use interactsh in debug mode")
	flag.StringVar(&options.Domain, "domain", "", "Domain to use for interactsh server")
	flag.StringVar(&options.IPAddress, "ip", "", "IP Address to use for interactsh server")
	flag.StringVar(&options.ListenIP, "listen-ip", "0.0.0.0", "IP Address to listen on")
	flag.StringVar(&options.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server")
	flag.IntVar(&eviction, "eviction", 7, "Number of days to persist interactions for")
	flag.BoolVar(&options.Auth, "auth", false, "Require a token from the client to retrieve interactions")
	flag.StringVar(&options.Token, "token", "", "Generate a token that the client must provide to retrieve interactions")
	flag.BoolVar(&options.Template, "template", false, "Enable client's template upload")
	flag.BoolVar(&skipacme, "skip-acme", false, "Skip acme registration")
	flag.BoolVar(&nebula.Unsafe, "unsafe", false, "Enable nebula's unsafe scripts")
	flag.Parse()

	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetWriter(&noopWriter{})
	}

	if options.Token != "" {
		options.Auth = true
	}
	if options.Auth && options.Token == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			gologger.Fatal().Msgf("Could not generate token\n")
		}
		options.Token = hex.EncodeToString(b)
		log.Printf("Client Token: %s\n", options.Token)
	}

	store := storage.New(time.Duration(eviction) * time.Hour * 24)
	options.Storage = store

	// we set a global instance for nebula interactions
	server.Storage = store
	// ensure we have the global set
	nebula.Refresh()
	_ = nebula.AddFunc("store_info", store.SetInternalById)
	_ = nebula.AddFunc("cleanup_info", store.CleanupInternalById)

	dnsServer, err := server.NewDNSServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create DNS server")
	}
	go dnsServer.ListenAndServe()

	trimmedDomain := strings.TrimSuffix(options.Domain, ".")

	var autoTLS *acme.AutoTLS
	if !skipacme {
		var err error
		autoTLS, err = acme.NewAutomaticTLS(options.Hostmaster, fmt.Sprintf("*.%s,%s", trimmedDomain, trimmedDomain), func(txt string) {
			dnsServer.TxtRecord = txt
		})
		if err != nil {
			gologger.Warning().Msgf("An error occurred while applying for an certificate, error: %v", err)
			gologger.Warning().Msgf("Could not generate certs for auto TLS, https will be disabled")
		}
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
