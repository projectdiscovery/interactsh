package options

type CLIClientOptions struct {
	ServerURL           string
	NumberOfPayloads    int
	Output              string
	JSON                bool
	Verbose             bool
	PollInterval        int
	Persistent          bool
	DNSOnly             bool
	HTTPOnly            bool
	SmtpOnly            bool
	Token               string
	DisableHTTPFallback bool
}
