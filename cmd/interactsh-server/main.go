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
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

func main() {
	cliOptions := &options.CLIServerOptions{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Interactsh server - Go client to configure and host interactsh server.`)

	options.CreateGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&cliOptions.Domain, "domain", "d", "", "configured domain to use with interactsh server"),
		flagSet.StringVar(&cliOptions.IPAddress, "ip", "", "public ip address to use for interactsh server"),
		flagSet.StringVarP(&cliOptions.ListenIP, "listen-ip", "lip", "0.0.0.0", "public ip address to listen on"),
		flagSet.IntVarP(&cliOptions.Eviction, "eviction", "e", 30, "number of days to persist interaction data in memory"),
		flagSet.BoolVarP(&cliOptions.Auth, "auth", "a", false, "enable authentication to server using random generated token"),
		flagSet.StringVarP(&cliOptions.Token, "token", "t", "", "enable authentication to server using given token"),
		flagSet.StringVar(&cliOptions.OriginURL, "acao-url", "https://app.interactsh.com", "origin url to send in acao header (required to use web-client)"),
		flagSet.BoolVarP(&cliOptions.SkipAcme, "skip-acme", "sa", false, "skip acme registration (certificate checks/handshake + TLS protocols will be disabled)"),
		flagSet.BoolVarP(&cliOptions.ScanEverywhere, "scan-everywhere", "se", false, "scan canary token everywhere"),
		flagSet.IntVarP(&cliOptions.CorrelationIdLength, "correlation-id-length", "cidl", settings.CorrelationIdLengthDefault, "length of the correlation id preamble"),
		flagSet.IntVarP(&cliOptions.CorrelationIdNonceLength, "correlation-id-nonce-length", "cidn", settings.CorrelationIdNonceLengthDefault, "length of the correlation id nonce"),
		flagSet.StringVar(&cliOptions.CertificatePath, "cert", "", "custom certificate path"),
		flagSet.StringVar(&cliOptions.PrivateKeyPath, "privkey", "", "custom private key path"),
	)
	options.CreateGroup(flagSet, "services", "Services",
		flagSet.IntVar(&cliOptions.DnsPort, "dns-port", 53, "port to use for dns service"),
		flagSet.IntVar(&cliOptions.HttpPort, "http-port", 80, "port to use for http service"),
		flagSet.IntVar(&cliOptions.HttpsPort, "https-port", 443, "port to use for https service"),
		flagSet.IntVar(&cliOptions.SmtpPort, "smtp-port", 25, "port to use for smtp service"),
		flagSet.IntVar(&cliOptions.SmtpsPort, "smtps-port", 587, "port to use for smtps service"),
		flagSet.IntVar(&cliOptions.SmtpAutoTLSPort, "smtp-autotls-port", 465, "port to use for smtps autotls service"),
		flagSet.IntVar(&cliOptions.LdapPort, "ldap-port", 389, "port to use for ldap service"),
		flagSet.BoolVar(&cliOptions.LdapWithFullLogger, "ldap", false, "enable ldap server with full logging (authenticated)"),
		flagSet.BoolVarP(&cliOptions.RootTLD, "wildcard", "wc", false, "enable wildcard interaction for interactsh domain (authenticated)"),
		flagSet.BoolVar(&cliOptions.Smb, "smb", false, "start smb agent - impacket and python 3 must be installed (authenticated)"),
		flagSet.BoolVar(&cliOptions.Responder, "responder", false, "start responder agent - docker must be installed (authenticated)"),
		flagSet.BoolVar(&cliOptions.Ftp, "ftp", false, "start ftp agent (authenticated)"),
		flagSet.IntVar(&cliOptions.SmbPort, "smb-port", 445, "port to use for smb service"),
		flagSet.IntVar(&cliOptions.FtpPort, "ftp-port", 21, "port to use for ftp service"),
		flagSet.StringVar(&cliOptions.FTPDirectory, "ftp-dir", "", "ftp directory - temporary if not specified"),
	)
	options.CreateGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&cliOptions.Debug, "debug", false, "start interactsh server in debug mode"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}

	options.ShowBanner()

	if cliOptions.IPAddress == "" && cliOptions.ListenIP == "0.0.0.0" {
		ip := getPublicIP()
		cliOptions.IPAddress = ip
		cliOptions.ListenIP = ip
	}
	cliOptions.Hostmaster = fmt.Sprintf("admin@%s", cliOptions.Domain)

	serverOptions := cliOptions.AsServerOptions()
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

	dnsTcpServer := server.NewDNSServer("tcp", serverOptions)
	dnsUdpServer := server.NewDNSServer("udp", serverOptions)
	dnsTcpAlive := make(chan bool, 1)
	dnsUdpAlive := make(chan bool, 1)
	go dnsTcpServer.ListenAndServe(dnsTcpAlive)
	go dnsUdpServer.ListenAndServe(dnsUdpAlive)

	trimmedDomain := strings.TrimSuffix(serverOptions.Domain, ".")

	var tlsConfig *tls.Config
	switch {
	case cliOptions.CertificatePath != "" && cliOptions.PrivateKeyPath != "":
		cert, err := tls.LoadX509KeyPair(cliOptions.CertificatePath, cliOptions.PrivateKeyPath)
		if err != nil {
			gologger.Error().Msgf("Could not load certs and private key for auto TLS, https will be disabled")
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
			ServerName:         cliOptions.Domain,
		}
	case !cliOptions.SkipAcme && cliOptions.Domain != "":
		acmeManagerTLS, acmeErr := acme.HandleWildcardCertificates(fmt.Sprintf("*.%s", trimmedDomain), serverOptions.Hostmaster, acmeStore, cliOptions.Debug)
		if acmeErr != nil {
			gologger.Error().Msgf("An error occurred while applying for an certificate, error: %v", acmeErr)
			gologger.Error().Msgf("Could not generate certs for auto TLS, https will be disabled")
		} else {
			tlsConfig = acmeManagerTLS
		}
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
			network := ""
			port := 0
			status := true
			fatal := false
			select {
			case status = <-dnsUdpAlive:
				service = "DNS"
				network = "UDP"
				port = serverOptions.DnsPort
				fatal = true
			case status = <-dnsTcpAlive:
				service = "DNS"
				network = "TCP"
				port = serverOptions.DnsPort
			case status = <-httpAlive:
				service = "HTTP"
				network = "TCP"
				port = serverOptions.HttpPort
				fatal = true
			case status = <-httpsAlive:
				service = "HTTPS"
				network = "TCP"
				port = serverOptions.HttpsPort
			case status = <-smtpAlive:
				service = "SMTP"
				network = "TCP"
				port = serverOptions.SmtpPort
			case status = <-smtpsAlive:
				service = "SMTPS"
				network = "TCP"
				port = serverOptions.SmtpsPort
			case status = <-ftpAlive:
				service = "FTP"
				network = "TCP"
				port = serverOptions.FtpPort
			case status = <-responderAlive:
				service = "Responder"
				network = "TCP"
				port = 445
			case status = <-smbAlive:
				service = "SMB"
				network = "TCP"
				port = serverOptions.SmbPort
			case status = <-ldapAlive:
				service = "LDAP"
				network = "TCP"
				port = serverOptions.LdapPort
			}
			if status {
				gologger.Silent().Msgf("[%s] Listening on %s %s:%d", service, network, serverOptions.ListenIP, port)
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
