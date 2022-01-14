package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
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
	var debug, smb, responder, ftp, skipacme, ldapWithFullLogger bool

	options := &server.Options{}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.BoolVar(&debug, "debug", false, "Run interactsh in debug mode")
	flag.StringVar(&options.Domain, "domain", "", "Domain to use for interactsh server")
	flag.IntVar(&options.DnsPort, "dns-port", 53, "Port to use by DNS server for interactsh server")
	flag.StringVar(&options.IPAddress, "ip", "", "Public IP Address to use for interactsh server")
	flag.StringVar(&options.ListenIP, "listen-ip", "0.0.0.0", "Public IP Address to listen on")
	flag.IntVar(&options.HttpPort, "http-port", 80, "HTTP port to listen on")
	flag.IntVar(&options.HttpsPort, "https-port", 443, "HTTPS port to listen on")
	flag.StringVar(&options.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server")
	flag.BoolVar(&ldapWithFullLogger, "ldap", false, "Enable full logging LDAP server - if false only ldap search query with correlation will be enabled")
	flag.IntVar(&eviction, "eviction", 30, "Number of days to persist interactions for")
	flag.BoolVar(&responder, "responder", false, "Start a responder agent - docker must be installed")
	flag.BoolVar(&smb, "smb", false, "Start a smb agent - impacket and python 3 must be installed")
	flag.IntVar(&options.SmbPort, "smb-port", 445, "SMB port to listen on")
	flag.IntVar(&options.SmtpPort, "smtp-port", 25, "SMTP port to listen on")
	flag.IntVar(&options.SmtpsPort, "smtps-port", 587, "SMTPS port to listen on")
	flag.IntVar(&options.SmtpAutoTLSPort, "smtp-autotls-port", 465, "SMTP autoTLS port to listen on")
	flag.IntVar(&options.FtpPort, "ftp-port", 21, "FTP port to listen on")
	flag.IntVar(&options.LdapPort, "ldap-port", 389, "LDAP port to listen on")
	flag.BoolVar(&ftp, "ftp", false, "Start a ftp agent")
	flag.BoolVar(&options.Auth, "auth", false, "Enable authentication to server using random generated token")
	flag.StringVar(&options.Token, "token", "", "Enable authentication to server using given token")
	flag.StringVar(&options.OriginURL, "origin-url", "https://app.interactsh.com", "Origin URL to send in ACAO Header")
	flag.BoolVar(&options.RootTLD, "root-tld", false, "Enable wildcard/global interaction for *.domain.com")
	flag.StringVar(&options.FTPDirectory, "ftp-dir", "", "Ftp directory - temporary if not specified")
	flag.BoolVar(&skipacme, "skip-acme", false, "Skip acme registration (certificate checks/handshake + TLS protocols will be disabled)")
	flag.BoolVar(&options.AppCnameDNSRecord, "app-cname", false, "Enable DNS CNAME record (eg. app.interactsh.domain) for web app")
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
	}

	// responder and smb can't be active at the same time
	if responder && smb {
		gologger.Fatal().Msgf("responder and smb can't be active at the same time\n")
	}

	// Requires auth if token is specified or enables it automatically for responder and smb options
	if options.Token != "" || responder || smb || ftp || ldapWithFullLogger {
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
		gologger.Info().Msgf("Client Token: %s\n", options.Token)
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

	acmeStore := acme.NewProvider()
	options.ACMEStore = acmeStore

	dnsTcpServer := server.NewDNSServer("tcp", options)
	dnsUdpServer := server.NewDNSServer("udp", options)
	dnsTcpAlive := make(chan bool, 1)
	dnsUdpAlive := make(chan bool, 1)
	go dnsTcpServer.ListenAndServe(dnsTcpAlive)
	go dnsUdpServer.ListenAndServe(dnsUdpAlive)

	trimmedDomain := strings.TrimSuffix(options.Domain, ".")

	var tlsConfig *tls.Config
	if !skipacme {
		acmeManagerTLS, acmeErr := acme.HandleWildcardCertificates(fmt.Sprintf("*.%s", trimmedDomain), options.Hostmaster, acmeStore)
		if acmeErr != nil {
			gologger.Warning().Msgf("An error occurred while applying for an certificate, error: %v", acmeErr)
			gologger.Warning().Msgf("Could not generate certs for auto TLS, https will be disabled")
		}
		tlsConfig = acmeManagerTLS
	}

	httpServer, err := server.NewHTTPServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create HTTP server")
	}
	httpAlive := make(chan bool)
	httpsAlive := make(chan bool)
	go httpServer.ListenAndServe(tlsConfig, httpAlive, httpsAlive)

	smtpServer, err := server.NewSMTPServer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create SMTP server")
	}
	smtpAlive := make(chan bool)
	smtpsAlive := make(chan bool)
	go smtpServer.ListenAndServe(tlsConfig, smtpAlive, smtpsAlive)

	ldapAlive := make(chan bool)
	ldapServer, err := server.NewLDAPServer(options, ldapWithFullLogger)
	if err != nil {
		gologger.Fatal().Msgf("Could not create LDAP server")
	}
	go ldapServer.ListenAndServe(tlsConfig, ldapAlive)
	defer ldapServer.Close()

	ftpAlive := make(chan bool)
	if ftp {
		ftpServer, err := server.NewFTPServer(options)
		if err != nil {
			gologger.Fatal().Msgf("Could not create FTP server")
		}
		go ftpServer.ListenAndServe(tlsConfig, ftpAlive) //nolint
	}

	responderAlive := make(chan bool)
	if responder {
		responderServer, err := server.NewResponderServer(options)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server")
		}
		go responderServer.ListenAndServe(responderAlive) //nolint
		defer responderServer.Close()
	}

	smbAlive := make(chan bool)
	if smb {
		smbServer, err := server.NewSMBServer(options)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server")
		}
		go smbServer.ListenAndServe(smbAlive) //nolint
		defer smbServer.Close()
	}

	gologger.Info().Msgf("Listening with the following services:\n")
	go func() {
		for {
			service := ""
			network := ""
			port := 0
			status := true
			fatal := false
			select {
			case status = <-dnsUdpAlive:
				service = "DNS"
				network = "UDP"
				port = options.DnsPort
				fatal = true
			case status = <-dnsTcpAlive:
				service = "DNS"
				network = "TCP"
				port = options.DnsPort
			case status = <-httpAlive:
				service = "HTTP"
				network = "TCP"
				port = options.HttpPort
				fatal = true
			case status = <-httpsAlive:
				service = "HTTPS"
				network = "TCP"
				port = options.HttpsPort
			case status = <-smtpAlive:
				service = "SMTP"
				network = "TCP"
				port = options.SmtpPort
			case status = <-smtpsAlive:
				service = "SMTPS"
				network = "TCP"
				port = options.SmtpsPort
			case status = <-ftpAlive:
				service = "FTP"
				network = "TCP"
				port = options.FtpPort
			case status = <-responderAlive:
				service = "Responder"
				network = "TCP"
				port = 445
			case status = <-smbAlive:
				service = "SMB"
				network = "TCP"
				port = options.SmbPort
			case status = <-ldapAlive:
				service = "LDAP"
				network = "TCP"
				port = options.LdapPort
			}
			if status {
				gologger.Silent().Msgf("[%s] Listening on %s %s:%d", service, network, options.ListenIP, port)
			} else if fatal {
				gologger.Fatal().Msgf("The %s %s service has unexpectedly stopped", network, service)
			} else {
				gologger.Warning().Msgf("The %s %s service has unexpectedly stopped", network, service)
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		os.Exit(1)
	}
}

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
