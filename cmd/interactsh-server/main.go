package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/folderutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"gopkg.in/yaml.v2"
)

type Template struct {
	Callbacks []server.Callback `yaml:"callbacks"`
}

func main() {
	var eviction int
	var debug bool
	var templatesPath string

	options := &server.Options{}
	flag.BoolVar(&debug, "debug", false, "Use interactsh in debug mode")
	flag.StringVar(&options.Domain, "domain", "", "Domain to use for interactsh server")
	flag.StringVar(&options.IPAddress, "ip", "", "IP Address to use for interactsh server")
	flag.StringVar(&options.ListenIP, "listen-ip", "0.0.0.0", "IP Address to listen on")
	flag.StringVar(&options.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server")
	flag.IntVar(&eviction, "eviction", 7, "Number of days to persist interactions for")
	flag.StringVar(&templatesPath, "templates-path", "", "Template(s) Path")
	flag.Parse()

	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetWriter(&noopWriter{})
	}

	// unmarshal the template
	// load all templates
	if fileutil.FolderExists(templatesPath) {
		tplFiles, err := folderutil.GetFiles(templatesPath)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		for _, tplfile := range tplFiles {
			gologger.Info().Msgf("Loading template: %s\n", tplfile)
			callbacks, err := readCallbacksFromFile(tplfile)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}

			options.Callbacks = append(options.Callbacks, callbacks...)
		}
	} else if fileutil.FileExists(templatesPath) {
		callbacks, err := readCallbacksFromFile(templatesPath)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}

		options.Callbacks = append(options.Callbacks, callbacks...)
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
		gologger.Warning().Msgf("An error occurred while applying for an certificate, error: %v", err)
		gologger.Warning().Msgf("Could not generate certs for auto TLS, https will be disabled")
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

func readCallbacksFromFile(filename string) ([]server.Callback, error) {
	tpldata, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var callbacks []server.Callback
	err = yaml.Unmarshal(tpldata, &callbacks)
	if err != nil {
		return nil, err
	}

	return callbacks, nil
}

type noopWriter struct{}

func (n *noopWriter) Write(data []byte, level levels.Level) {}
