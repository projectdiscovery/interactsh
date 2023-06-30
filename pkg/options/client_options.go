package options

import (
	"time"

	"github.com/projectdiscovery/goflags"
)

type CLIClientOptions struct {
	Match                    goflags.StringSlice
	Filter                   goflags.StringSlice
	Config                   string
	Version                  bool
	ServerURL                string
	NumberOfPayloads         int
	Output                   string
	JSON                     bool
	StorePayload             bool
	StorePayloadFile         string
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
	Asn                      bool
	DisableUpdateCheck       bool
	KeepAliveInterval        time.Duration
}
