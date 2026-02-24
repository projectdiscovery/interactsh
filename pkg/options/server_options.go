package options

import (
	"net"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

type CLIServerOptions struct {
	Resolvers                goflags.StringSlice
	Config                   string
	Version                  bool
	Debug                    bool
	Domains                  goflags.StringSlice
	DnsPort                  int
	IPAddresses              goflags.StringSlice
	ListenIP                 string
	HttpPort                 int
	HttpsPort                int
	Hostmasters              []string
	LdapWithFullLogger       bool
	Eviction                 int
	NoEviction               bool
	EvictionStrategy         string
	Responder                bool
	Smb                      bool
	SmbPort                  int
	SmtpPort                 int
	SmtpsPort                int
	SmtpAutoTLSPort          int
	FtpPort                  int
	FtpsPort                 int
	LdapPort                 int
	Ftp                      bool
	Auth                     bool
	HTTPIndex                string
	HTTPDirectory            string
	Token                    string
	OriginURL                string
	RootTLD                  bool
	FTPDirectory             string
	SkipAcme                 bool
	DynamicResp              bool
	CorrelationIdLength      int
	CorrelationIdNonceLength int
	ScanEverywhere           bool
	CertificatePath          string
	CustomRecords            string
	PrivateKeyPath           string
	OriginIPHeader           string
	DiskStorage              bool
	DiskStoragePath          string
	EnablePprof              bool
	EnableMetrics            bool
	Verbose                  bool
	DisableUpdateCheck       bool
	NoVersionHeader          bool
	HeaderServer             string
	DefaultHTTPResponseFile  string
}

func (cliServerOptions *CLIServerOptions) AsServerOptions() *server.Options {
	var ipAddresses []net.IP

	for _, ipAddress := range cliServerOptions.IPAddresses {
		parsedIP := net.ParseIP(ipAddress)
		if parsedIP != nil {
			ipAddresses = append(ipAddresses, parsedIP)
		} else {
			if cliServerOptions.Debug {
				gologger.Warning().Msgf("Invalid IP address '%s' will be ignored\n", ipAddress)
			}
		}
	}

	ipAddresses = uniqueIPs(ipAddresses)

	return &server.Options{
		Domains:                  cliServerOptions.Domains,
		DnsPort:                  cliServerOptions.DnsPort,
		IPAddresses:              ipAddresses,
		ListenIP:                 cliServerOptions.ListenIP,
		HttpPort:                 cliServerOptions.HttpPort,
		HttpsPort:                cliServerOptions.HttpsPort,
		Hostmasters:              cliServerOptions.Hostmasters,
		SmbPort:                  cliServerOptions.SmbPort,
		SmtpPort:                 cliServerOptions.SmtpPort,
		SmtpsPort:                cliServerOptions.SmtpsPort,
		SmtpAutoTLSPort:          cliServerOptions.SmtpAutoTLSPort,
		FtpPort:                  cliServerOptions.FtpPort,
		FtpsPort:                 cliServerOptions.FtpsPort,
		LdapPort:                 cliServerOptions.LdapPort,
		Auth:                     cliServerOptions.Auth,
		HTTPIndex:                cliServerOptions.HTTPIndex,
		HTTPDirectory:            cliServerOptions.HTTPDirectory,
		Token:                    cliServerOptions.Token,
		Version:                  Version,
		DynamicResp:              cliServerOptions.DynamicResp,
		OriginURL:                cliServerOptions.OriginURL,
		RootTLD:                  cliServerOptions.RootTLD,
		FTPDirectory:             cliServerOptions.FTPDirectory,
		CorrelationIdLength:      cliServerOptions.CorrelationIdLength,
		CorrelationIdNonceLength: cliServerOptions.CorrelationIdNonceLength,
		ScanEverywhere:           cliServerOptions.ScanEverywhere,
		CertificatePath:          cliServerOptions.CertificatePath,
		CustomRecords:            cliServerOptions.CustomRecords,
		PrivateKeyPath:           cliServerOptions.PrivateKeyPath,
		OriginIPHeader:           cliServerOptions.OriginIPHeader,
		DiskStorage:              cliServerOptions.DiskStorage,
		DiskStoragePath:          cliServerOptions.DiskStoragePath,
		EnableMetrics:            cliServerOptions.EnableMetrics,
		NoVersionHeader:          cliServerOptions.NoVersionHeader,
		HeaderServer:             cliServerOptions.HeaderServer,
		DefaultHTTPResponseFile:  cliServerOptions.DefaultHTTPResponseFile,
	}
}

// uniqueIPs removes duplicate IP addresses from a slice
func uniqueIPs(ips []net.IP) []net.IP {
	seen := make(map[string]bool)
	result := []net.IP{}

	for _, ip := range ips {
		key := ip.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, ip)
		}
	}

	return result
}
