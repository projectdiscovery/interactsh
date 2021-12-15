package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
	var debug, smb, responder bool

	options := &server.Options{}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.BoolVar(&debug, "debug", false, "Run interactsh in debug mode")
	flag.StringVar(&options.Domain, "domain", "", "Domain to use for interactsh server")
	flag.IntVar(&options.DomainPort, "domain-port", 53, "Port to use by DNS server for interactsh server")
	flag.StringVar(&options.IPAddress, "ip", "", "Public IP Address to use for interactsh server")
	flag.StringVar(&options.ListenIP, "listen-ip", "0.0.0.0", "Public IP Address to listen on")
	flag.IntVar(&options.HttpPort, "http-port", 80, "HTTP port to listen on")
	flag.IntVar(&options.HttpsPort, "https-port", 443, "HTTPS port to listen on")
	flag.StringVar(&options.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server")
	flag.IntVar(&eviction, "eviction", 30, "Number of days to persist interactions for")
	flag.BoolVar(&responder, "responder", false, "Start a responder agent - docker must be installed")
	flag.BoolVar(&smb, "smb", false, "Start a smb agent - impacket and python 3 must be installed")
	flag.IntVar(&options.SmbPort, "smb-port", 445, "SMB port to listen on")
	flag.IntVar(&options.SmtpPort, "smtp-port", 25, "SMTP port to listen on")
	flag.IntVar(&options.SmtpsPort, "smtps-port", 587, "SMTPS port to listen on")
	flag.IntVar(&options.SmtpAutoTLSPort, "smtp-autotls-port", 465, "SMTP autoTLS port to listen on")
	flag.BoolVar(&options.Auth, "auth", false, "Enable authentication to server using random generated token")
	flag.StringVar(&options.Token, "token", "", "Enable authentication to server using given token")
	flag.StringVar(&options.OriginURL, "origin-url", "https://app.interactsh.com", "Origin URL to send in ACAO Header")
	flag.BoolVar(&options.RootTLD, "root-tld", false, "Enable wildcard/global interaction for *.domain.com")
	flag.Parse()

	if options.IPAddress == "" && options.ListenIP == "0.0.0.0" {
		ip := getPublicIP()
		options.IPAddress = ip
		options.ListenIP = ip
	}
	if options.Hostmaster == "" {
		options.Hostmaster = fmt.Sprintf("admin@%s", options.Domain)
	}
	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetWriter(&noopWriter{})
	}

	// responder and smb can't be active at the same time
	if responder && smb {
		fmt.Printf("responder and smb can't be active at the same time\n")
		os.Exit(1)
	}

	// Requires auth if token is specified or enables it automatically for responder and smb options
	if options.Token != "" || responder || smb {
		options.Auth = true
	}

	// if root-tld is enabled we enable auth - This ensure that any client has the token
	if options.RootTLD {
		options.Auth = true
	}

	// of in case a custom token is specified
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

	if options.Auth {
		_ = options.Storage.SetID(options.Token)
	}

	// If riit-tld is enabled create a singleton unencrypted record in the store
	if options.RootTLD {
		_ = store.SetID(options.Domain)
	}

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

	if responder {
		responderServer, err := server.NewResponderServer(options)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server")
		}
		go responderServer.ListenAndServe() //nolint
		defer responderServer.Close()
	}

	if smb {
		smbServer, err := server.NewSMBServer(options)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server")
		}
		go smbServer.ListenAndServe() //nolint
		defer smbServer.Close()
	}

	log.Printf("Listening on DNS, SMTP and HTTP ports\n")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		os.Exit(1)
	}
}

type noopWriter struct{}

func (n *noopWriter) Write(data []byte, level levels.Level) {}

func getPublicIP() string {
	url := "https://api.ipify.org?format=text" // we are using a pulib IP API, we're using ipify here, below are some others

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(ip)
}
