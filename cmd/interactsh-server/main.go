package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	_ "net/http/pprof"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/internal/runner"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	folderutil "github.com/projectdiscovery/utils/folder"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	healthcheck           bool
	defaultConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/interactsh-server/config.yaml")
	pprofServerAddress    = "127.0.0.1:8086"
)

func main() {
	cliOptions := &options.CLIServerOptions{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Interactsh server - Go client to configure and host interactsh server.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&cliOptions.Domains, "domain", "d", []string{}, "single/multiple configured domain to use for server", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVar(&cliOptions.IPAddress, "ip", "", "public ip address to use for interactsh server"),
		flagSet.StringVarP(&cliOptions.ListenIP, "listen-ip", "lip", "0.0.0.0", "public ip address to listen on"),
		flagSet.IntVarP(&cliOptions.Eviction, "eviction", "e", 30, "number of days to persist interaction data in memory"),
		flagSet.BoolVarP(&cliOptions.NoEviction, "no-eviction", "ne", false, "disable periodic data eviction from memory"),
		flagSet.BoolVarP(&cliOptions.Auth, "auth", "a", false, "enable authentication to server using random generated token"),
		flagSet.StringVarP(&cliOptions.Token, "token", "t", "", "enable authentication to server using given token"),
		flagSet.StringVar(&cliOptions.OriginURL, "acao-url", "*", "origin url to send in acao header to use web-client)"), // cli flag set to deprecate
		flagSet.BoolVarP(&cliOptions.SkipAcme, "skip-acme", "sa", false, "skip acme registration (certificate checks/handshake + TLS protocols will be disabled)"),
		flagSet.BoolVarP(&cliOptions.ScanEverywhere, "scan-everywhere", "se", false, "scan canary token everywhere"),
		flagSet.IntVarP(&cliOptions.CorrelationIdLength, "correlation-id-length", "cidl", settings.CorrelationIdLengthDefault, "length of the correlation id preamble"),
		flagSet.IntVarP(&cliOptions.CorrelationIdNonceLength, "correlation-id-nonce-length", "cidn", settings.CorrelationIdNonceLengthDefault, "length of the correlation id nonce"),
		flagSet.StringVar(&cliOptions.CertificatePath, "cert", "", "custom certificate path"),
		flagSet.StringVar(&cliOptions.PrivateKeyPath, "privkey", "", "custom private key path"),
		flagSet.StringVarP(&cliOptions.OriginIPHeader, "origin-ip-header", "oih", "", "HTTP header containing origin ip (interactsh behind a reverse proxy)"),
	)

	flagSet.CreateGroup("config", "config",
		flagSet.StringVar(&cliOptions.Config, "config", defaultConfigLocation, "flag configuration file"),
		flagSet.BoolVarP(&cliOptions.DynamicResp, "dynamic-resp", "dr", false, "enable setting up arbitrary response data"),
		flagSet.StringVarP(&cliOptions.CustomRecords, "custom-records", "cr", "", "custom dns records YAML file for DNS server"),
		flagSet.StringVarP(&cliOptions.HTTPIndex, "http-index", "hi", "", "custom index file for http server"),
		flagSet.StringVarP(&cliOptions.HTTPDirectory, "http-directory", "hd", "", "directory with files to serve with http server"),
		flagSet.BoolVarP(&cliOptions.DiskStorage, "disk", "ds", false, "disk based storage"),
		flagSet.StringVarP(&cliOptions.DiskStoragePath, "disk-path", "dsp", "", "disk storage path"),
		flagSet.StringVarP(&cliOptions.HeaderServer, "server-header", "csh", "", "custom value of Server header in response"),
		flagSet.BoolVarP(&cliOptions.NoVersionHeader, "disable-version", "dv", false, "disable publishing interactsh version in response header"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(options.GetUpdateCallback("interactsh-server"), "update", "up", "update interactsh-server to latest version"),
		flagSet.BoolVarP(&cliOptions.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic interactsh-server update check"),
	)

	flagSet.CreateGroup("services", "Services",
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

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&cliOptions.Version, "version", false, "show version of the project"),
		flagSet.BoolVar(&cliOptions.Debug, "debug", false, "start interactsh server in debug mode"),
		flagSet.BoolVarP(&cliOptions.EnablePprof, "enable-pprof", "ep", false, "enable pprof debugging server"),
		flagSet.BoolVarP(&healthcheck, "hc", "health-check", false, "run diagnostic check up"),
		flagSet.BoolVar(&cliOptions.EnableMetrics, "metrics", false, "enable metrics endpoint"),
		flagSet.BoolVarP(&cliOptions.Verbose, "verbose", "v", false, "display verbose interaction"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}
	options.ShowBanner()

	if healthcheck {
		cfgFilePath, _ := flagSet.GetConfigFilePath()
		gologger.Print().Msgf("%s\n", runner.DoHealthCheck(cfgFilePath))
		os.Exit(0)
	}
	if cliOptions.Version {
		gologger.Info().Msgf("Current Version: %s\n", options.Version)
		os.Exit(0)
	}

	if !cliOptions.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("interactsh-server", options.Version)()
		if err != nil {
			if cliOptions.Verbose {
				gologger.Error().Msgf("interactsh version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current interactsh version %v %v", options.Version, updateutils.GetVersionDescription(options.Version, latestVersion))
		}
	}

	if cliOptions.Config != defaultConfigLocation {
		if err := flagSet.MergeConfigFile(cliOptions.Config); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	if len(cliOptions.Domains) == 0 {
		gologger.Fatal().Msgf("No domains specified\n")
	}

	if cliOptions.IPAddress == "" && cliOptions.ListenIP == "0.0.0.0" {
		publicIP, _ := getPublicIP()
		outboundIP, _ := iputil.GetSourceIP("scanme.sh")

		if publicIP == "" && outboundIP == nil {
			gologger.Fatal().Msgf("Could not determine public IP address\n")
		}
		if publicIP == "" && outboundIP != nil {
			publicIP = outboundIP.String()
		}
		gologger.Info().Msgf("Public IP: %s\n", publicIP)
		gologger.Info().Msgf("Outbound IP: %s\n", outboundIP)
		// it's essential to be able to bind to cliOptions.DnsPort on any of the two ips
		bindableIP, err := iputil.GetBindableAddress(cliOptions.DnsPort, publicIP, outboundIP.String())
		if bindableIP == "" && err != nil {
			var addressesBuilder strings.Builder
			networkInterfaces, _ := net.Interfaces()
			for _, networkInterface := range networkInterfaces {
				addresses, _ := networkInterface.Addrs()
				var addressesStr []string
				for _, address := range addresses {
					addressesStr = append(addressesStr, address.String())
				}
				if len(addressesStr) > 0 {
					addressesBuilder.WriteString(fmt.Sprintf("%s: %s\n", networkInterface.Name, strings.Join(addressesStr, ",")))
				}
			}
			gologger.Fatal().Msgf("%s\nNo bindable address could be found for port %d\nPlease ensure to have proper privileges and/or choose the correct ip:\n%s\n", err, cliOptions.DnsPort, addressesBuilder.String())
		}
		cliOptions.ListenIP = bindableIP
		cliOptions.IPAddress = publicIP
	}

	for _, domain := range cliOptions.Domains {
		hostmaster := fmt.Sprintf("admin@%s", domain)
		cliOptions.Hostmasters = append(cliOptions.Hostmasters, hostmaster)
	}

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

	// if root-tld is enabled we enable auth - This ensures that any client has the token
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

	evictionTTL := time.Duration(cliOptions.Eviction) * time.Hour * 24
	if cliOptions.NoEviction {
		evictionTTL = -1
	}
	var store storage.Storage
	storeOptions := storage.DefaultOptions
	storeOptions.EvictionTTL = evictionTTL
	if cliOptions.DiskStorage {
		if cliOptions.DiskStoragePath == "" {
			gologger.Fatal().Msgf("disk storage path must be specified\n")
		}
		storeOptions.DbPath = cliOptions.DiskStoragePath
	}

	var err error
	store, err = storage.New(&storeOptions)
	if err != nil {
		gologger.Fatal().Msgf("couldn't create storage: %s\n", err)
	}

	serverOptions.Storage = store

	if serverOptions.Auth {
		_ = serverOptions.Storage.SetID(serverOptions.Token)
	}

	serverOptions.Stats = &server.Metrics{}

	// If root-tld is enabled create a singleton unencrypted record in the store
	if serverOptions.RootTLD {
		for _, domain := range serverOptions.Domains {
			_ = store.SetID(domain)
		}
	}

	acmeStore := acme.NewProvider()
	serverOptions.ACMEStore = acmeStore

	dnsTcpServer := server.NewDNSServer("tcp", serverOptions)
	dnsUdpServer := server.NewDNSServer("udp", serverOptions)
	dnsTcpAlive := make(chan bool, 1)
	dnsUdpAlive := make(chan bool, 1)
	go dnsTcpServer.ListenAndServe(dnsTcpAlive)
	go dnsUdpServer.ListenAndServe(dnsUdpAlive)

	var tlsConfig *tls.Config
	switch {
	case cliOptions.CertificatePath != "" && cliOptions.PrivateKeyPath != "":
		var domain string
		if len(cliOptions.Domains) > 0 {
			domain = cliOptions.Domains[0]
		}
		acmeManagerTLS, acmeErr := acme.BuildTlsConfigWithCertAndKeyPaths(cliOptions.CertificatePath, cliOptions.PrivateKeyPath, domain)
		if acmeErr != nil {
			gologger.Error().Msgf("https will be disabled: %s", acmeErr)
		} else {
			tlsConfig = acmeManagerTLS
		}
	case !cliOptions.SkipAcme && len(cliOptions.Domains) > 0:
		var certs []tls.Certificate
		for idx, domain := range cliOptions.Domains {
			trimmedDomain := strings.TrimSuffix(domain, ".")
			hostmaster := serverOptions.Hostmasters[idx]
			domainCerts, acmeErr := acme.HandleWildcardCertificates(fmt.Sprintf("*.%s", trimmedDomain), hostmaster, acmeStore, cliOptions.Debug)
			if acmeErr != nil {
				gologger.Error().Msgf("An error occurred while applying for a certificate, error: %v", acmeErr)
				gologger.Error().Msgf("Could not generate certs for auto TLS, https will be disabled")
			} else {
				certs = append(certs, domainCerts...)
			}
		}
		var tlsErr error
		tlsConfig, tlsErr = acme.BuildTlsConfigWithCerts("", certs...)
		if tlsErr != nil {
			gologger.Error().Msgf("An error occurred while preparing tls configuration, error: %v", tlsErr)
		}
	}

	// manually cleans up stale OCSP from storage
	acme.CleanupStorage()

	httpServer, err := server.NewHTTPServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create HTTP server: %s", err)
	}
	httpAlive := make(chan bool)
	httpsAlive := make(chan bool)
	go httpServer.ListenAndServe(tlsConfig, httpAlive, httpsAlive)

	smtpServer, err := server.NewSMTPServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create SMTP server: %s", err)
	}
	smtpAlive := make(chan bool)
	smtpsAlive := make(chan bool)
	go smtpServer.ListenAndServe(tlsConfig, smtpAlive, smtpsAlive)

	ldapAlive := make(chan bool)
	ldapServer, err := server.NewLDAPServer(serverOptions, cliOptions.LdapWithFullLogger)
	if err != nil {
		gologger.Fatal().Msgf("Could not create LDAP server: %s", err)
	}
	go ldapServer.ListenAndServe(tlsConfig, ldapAlive)
	defer ldapServer.Close()

	ftpAlive := make(chan bool)
	if cliOptions.Ftp {
		ftpServer, err := server.NewFTPServer(serverOptions)
		if err != nil {
			gologger.Fatal().Msgf("Could not create FTP server: %s", err)
		}
		go ftpServer.ListenAndServe(tlsConfig, ftpAlive) //nolint
	}

	responderAlive := make(chan bool)
	if cliOptions.Responder {
		responderServer, err := server.NewResponderServer(serverOptions)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server: %s", err)
		}
		go responderServer.ListenAndServe(responderAlive) //nolint
		defer responderServer.Close()
	}

	smbAlive := make(chan bool)
	if cliOptions.Smb {
		smbServer, err := server.NewSMBServer(serverOptions)
		if err != nil {
			gologger.Fatal().Msgf("Could not create SMB server: %s", err)
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

	var pprofServer *http.Server
	if cliOptions.EnablePprof {
		pprofServer = &http.Server{
			Addr:    pprofServerAddress,
			Handler: http.DefaultServeMux,
		}
		gologger.Info().Msgf("Listening pprof debug server on: %s", pprofServerAddress)
		go func() {
			_ = pprofServer.ListenAndServe()
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		if err := store.Close(); err != nil {
			gologger.Warning().Msgf("Couldn't close the storage: %s\n", err)
		}
		if pprofServer != nil {
			pprofServer.Close()
		}
		os.Exit(1)
	}
}

func getPublicIP() (string, error) {
	ip, err := iputil.WhatsMyIP()
	if err != nil {
		return "", err
	}

	// public ip should match one of the configured interfaces
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	externalIP := ip
	for _, address := range addresses {
		if stringsutil.EqualFoldAny(externalIP, address.String()) {
			return externalIP, nil
		}
	}

	return externalIP, errors.New("couldn't find an interface configured with external ip")
}
