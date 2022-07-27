package options

import "github.com/projectdiscovery/goflags"

type CLIClientOptions struct {
	Match                    goflags.FileCommaSeparatedStringSlice
	Filter                   goflags.FileCommaSeparatedStringSlice
	Config                   string
	Version                  bool
	ServerURL                string
	NumberOfPayloads         int
	Output                   string
	JSON                     bool
	Verbose                  bool
	PollInterval             int
	DNSOnly                  bool
	HTTPOnly                 bool
	SmtpOnly                 bool
	Token                    string
	DisableHTTPFallback      bool
	CorrelationIdLength      int
	CorrelationIdNonceLength int
	SessionFile              string
}
