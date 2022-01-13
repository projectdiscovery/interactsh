package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

func main() {
	cliOptions := &options.CLIServerOptions{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Interactsh Server.`)

	options.CreateGroup(flagSet, "server", "Server",
		flagSet.StringVar(&cliOptions.Domain, "domain", "", "Domain to use for interactsh server"),
		flagSet.StringVar(&cliOptions.IPAddress, "ip", "", "Public IP Address to use for interactsh server"),
		flagSet.StringVar(&cliOptions.ListenIP, "listen-ip", "0.0.0.0", "Public IP Address to listen on"),
		flagSet.StringVar(&cliOptions.Hostmaster, "hostmaster", "", "Hostmaster email to use for interactsh server"),
		flagSet.IntVar(&cliOptions.Eviction, "eviction", 30, "Number of days to persist interactions for"),
		flagSet.BoolVar(&cliOptions.Auth, "auth", false, "Enable authentication to server using random generated token"),
		flagSet.StringVar(&cliOptions.Token, "token", "", "Enable authentication to server using given token"),
		flagSet.StringVar(&cliOptions.OriginURL, "origin-url", "https://app.interactsh.com", "Origin URL to send in ACAO Header"),
		flagSet.BoolVar(&cliOptions.SkipAcme, "skip-acme", false, "Skip acme registration (certificate checks/handshake + TLS protocols will be disabled)"),
		flagSet.BoolVar(&cliOptions.AppCnameDNSRecord, "app-cname", false, "Enable DNS CNAME record (eg. app.interactsh.domain) for web app"),
	)
	options.CreateGroup(flagSet, "services", "Services",
		flagSet.IntVar(&cliOptions.DnsPort, "dns-port", 53, "Port to use by DNS server for interactsh server"),
		flagSet.IntVar(&cliOptions.HttpPort, "http-port", 80, "HTTP port to listen on"),
		flagSet.IntVar(&cliOptions.HttpsPort, "https-port", 443, "HTTPS port to listen on"),
		flagSet.BoolVar(&cliOptions.LdapWithFullLogger, "ldap", false, "Enable full logging LDAP server - if false only ldap search query with correlation will be enabled"),
		flagSet.BoolVar(&cliOptions.Responder, "responder", false, "Start a responder agent - docker must be installed"),
		flagSet.BoolVar(&cliOptions.Smb, "smb", false, "Start a smb agent - impacket and python 3 must be installed"),
		flagSet.IntVar(&cliOptions.SmbPort, "smb-port", 445, "SMB port to listen on"),
		flagSet.IntVar(&cliOptions.SmtpPort, "smtp-port", 25, "SMTP port to listen on"),
		flagSet.IntVar(&cliOptions.SmtpsPort, "smtps-port", 587, "SMTPS port to listen on"),
		flagSet.IntVar(&cliOptions.SmtpAutoTLSPort, "smtp-autotls-port", 465, "SMTP autoTLS port to listen on"),
		flagSet.IntVar(&cliOptions.FtpPort, "ftp-port", 21, "FTP port to listen on"),
		flagSet.IntVar(&cliOptions.LdapPort, "ldap-port", 389, "LDAP port to listen on"),
		flagSet.BoolVar(&cliOptions.Ftp, "ftp", false, "Start a ftp agent"),
		flagSet.BoolVar(&cliOptions.RootTLD, "root-tld", false, "Enable wildcard/global interaction for *.domain.com"),
		flagSet.StringVar(&cliOptions.FTPDirectory, "ftp-dir", "", "Ftp directory - temporary if not specified"),
	)
	options.CreateGroup(flagSet, "output", "Output",
		flagSet.BoolVar(&cliOptions.Debug, "debug", false, "Run interactsh in debug mode"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}

	serverOptions := cliOptions.AsServerOptions()

	if serverOptions.IPAddress == "" && serverOptions.ListenIP == "0.0.0.0" {
		ip := getPublicIP()
		serverOptions.IPAddress = ip
		serverOptions.ListenIP = ip
	}
	if serverOptions.Hostmaster == "" {
		serverOptions.Hostmaster = fmt.Sprintf("admin@%s", serverOptions.Domain)
	}

	if cliOptions.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}

	// responder and smb can't be active at the same time
	if cliOptions.Responder && cliOptions.Smb {
		gologger.Fatal().Msgf("responder and smb can't be active at the same time\n")
	}

	// Requires auth if token is specified or enables it automatically for responder and smb options
	if serverOptions.Token != "" || cliOptions.Responder || cliOptions.Smb || cliOptions.Ftp || cliOptions.LdapWithFullLogger {
		serverOptions.Auth = true
	}

	// if root-tld is enabled we enable auth - This ensure that any client has the token
	if serverOptions.RootTLD {
		serverOptions.Auth = true
	}

	// of in case a custom token is specified
	if serverOptions.Token != "" {
		serverOptions.Auth = true
	}

	if serverOptions.Auth && serverOptions.Token == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			gologger.Fatal().Msgf("Could not generate token\n")
		}
		serverOptions.Token = hex.EncodeToString(b)
		gologger.Info().Msgf("Client Token: %s\n", serverOptions.Token)
	}

	store := storage.New(time.Duration(cliOptions.Eviction) * time.Hour * 24)
	serverOptions.Storage = store

	if serverOptions.Auth {
		_ = serverOptions.Storage.SetID(serverOptions.Token)
	}

	// If riit-tld is enabled create a singleton unencrypted record in the store
	if serverOptions.RootTLD {
		_ = store.SetID(serverOptions.Domain)
	}

	acmeStore := acme.NewProvider()
	serverOptions.ACMEStore = acmeStore

	dnsServer, err := server.NewDNSServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create DNS server")
	}
	dnsAlive := make(chan bool, 1)
	go dnsServer.ListenAndServe(dnsAlive)

	trimmedDomain := strings.TrimSuffix(serverOptions.Domain, ".")

	var tlsConfig *tls.Config
	if !cliOptions.SkipAcme {
		acmeManagerTLS, acmeErr := acme.HandleWildcardCertificates(fmt.Sprintf("*.%s", trimmedDomain), serverOptions.Hostmaster, acmeStore)
		if acmeErr != nil {
			gologger.Warning().Msgf("An error occurred while applying for an certificate, error: %v", err)
			gologger.Warning().Msgf("Could not generate certs for auto TLS, https will be disabled")
		}
		tlsConfig = acmeManagerTLS
	}

	httpServer, err := server.NewHTTPServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create HTTP server")
	}
	httpAlive := make(chan bool)
	httpsAlive := make(chan bool)
	go httpServer.ListenAndServe(tlsConfig, httpAlive, httpsAlive)

	smtpServer, err := server.NewSMTPServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create SMTP server")
	}
	smtpAlive := make(chan bool)
	smtpsAlive := make(chan bool)
	go smtpServer.ListenAndServe(tlsConfig, smtpAlive, smtpsAlive)

	ldapAlive := make(chan bool)
	ldapServer, err := server.NewLDAPServer(serverOptions, cliOptions.LdapWithFullLogger)
	if err != nil {
		gologger.Fatal().Msgf("Could not create LDAP server")
	}
	go ldapServer.ListenAndServe(tlsConfig, ldapAlive)
	defer ldapServer.Close()

	ftpAlive := make(chan bool)
	if cliOptions.Ftp {
		ftpServer, err := server.NewFTPServer(serverOptions)
		if err != nil {
			gologger.Fatal().Msgf("Could not create FTP server")
		}
		go ftpServer.ListenAndServe(tlsConfig, ftpAlive) //nolint
	}

	responderAlive := make(chan bool)
	if cliOptions.Responder {
		responderServer, err := server.NewResponderServer(serverOptions)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server")
		}
		go responderServer.ListenAndServe(responderAlive) //nolint
		defer responderServer.Close()
	}

	smbAlive := make(chan bool)
	if cliOptions.Smb {
		smbServer, err := server.NewSMBServer(serverOptions)
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
			port := 0
			status := true
			fatal := false
			select {
			case status = <-dnsAlive:
				service = "DNS"
				port = serverOptions.DnsPort
				fatal = true
			case status = <-httpAlive:
				service = "HTTP"
				port = serverOptions.HttpPort
				fatal = true
			case status = <-httpsAlive:
				service = "HTTPS"
				port = serverOptions.HttpsPort
			case status = <-smtpAlive:
				service = "SMTP"
				port = serverOptions.SmtpPort
			case status = <-smtpsAlive:
				service = "SMTPS"
				port = serverOptions.SmtpsPort
			case status = <-ftpAlive:
				service = "FTP"
				port = serverOptions.FtpPort
			case status = <-responderAlive:
				service = "Responder"
				port = 445
			case status = <-smbAlive:
				service = "SMB"
				port = serverOptions.SmbPort
			case status = <-ldapAlive:
				service = "LDAP"
				port = serverOptions.LdapPort
			}
			if status {
				gologger.Silent().Msgf("[%s] Listening on %s:%d", service, serverOptions.ListenIP, port)
			} else if fatal {
				gologger.Fatal().Msgf("The %s service has unexpectedly stopped", service)
			} else {
				gologger.Warning().Msgf("The %s service has unexpectedly stopped", service)
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
