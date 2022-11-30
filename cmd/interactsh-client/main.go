package main

import (
	"bytes"
	jsonpkg "encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/internal/runner"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
)

var (
	healthcheck           bool
	defaultConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/interactsh-client/config.yaml")
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	defaultOpts := client.DefaultOptions
	cliOptions := &options.CLIClientOptions{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Interactsh client - Go client to generate interactsh payloads and display interaction data.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&cliOptions.ServerURL, "server", "s", defaultOpts.ServerURL, "interactsh server(s) to use"),
	)

	flagSet.CreateGroup("config", "config",
		flagSet.StringVar(&cliOptions.Config, "config", defaultConfigLocation, "flag configuration file"),
		flagSet.IntVarP(&cliOptions.NumberOfPayloads, "number", "n", 1, "number of interactsh payload to generate"),
		flagSet.StringVarP(&cliOptions.Token, "token", "t", "", "authentication token to connect protected interactsh server"),
		flagSet.IntVarP(&cliOptions.PollInterval, "poll-interval", "pi", 5, "poll interval in seconds to pull interaction data"),
		flagSet.BoolVarP(&cliOptions.DisableHTTPFallback, "no-http-fallback", "nf", false, "disable http fallback registration"),
		flagSet.IntVarP(&cliOptions.CorrelationIdLength, "correlation-id-length", "cidl", settings.CorrelationIdLengthDefault, "length of the correlation id preamble"),
		flagSet.IntVarP(&cliOptions.CorrelationIdNonceLength, "correlation-id-nonce-length", "cidn", settings.CorrelationIdNonceLengthDefault, "length of the correlation id nonce"),
		flagSet.StringVarP(&cliOptions.SessionFile, "session-file", "sf", "", "store/read from session file"),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.StringSliceVarP(&cliOptions.Match, "match", "m", nil, "match interaction based on the specified pattern", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&cliOptions.Filter, "filter", "f", nil, "filter interaction based on the specified pattern", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&cliOptions.DNSOnly, "dns-only", false, "display only dns interaction in CLI output"),
		flagSet.BoolVar(&cliOptions.HTTPOnly, "http-only", false, "display only http interaction in CLI output"),
		flagSet.BoolVar(&cliOptions.SmtpOnly, "smtp-only", false, "display only smtp interactions in CLI output"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVar(&cliOptions.Output, "o", "", "output file to write interaction data"),
		flagSet.BoolVar(&cliOptions.JSON, "json", false, "write output in JSONL(ines) format"),
		flagSet.BoolVar(&cliOptions.Verbose, "v", false, "display verbose interaction"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&cliOptions.Version, "version", false, "show version of the project"),
		flagSet.BoolVarP(&healthcheck, "hc", "health-check", false, "run diagnostic check up"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}

	options.ShowBanner()

	if healthcheck {
		cfgFilePath, _ := goflags.GetConfigFilePath()
		gologger.Print().Msgf("%s\n", runner.DoHealthCheck(cfgFilePath))
		os.Exit(0)
	}
	if cliOptions.Version {
		gologger.Info().Msgf("Current Version: %s\n", options.Version)
		os.Exit(0)
	}

	if cliOptions.Config != defaultConfigLocation {
		if err := flagSet.MergeConfigFile(cliOptions.Config); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	var outputFile *os.File
	var err error
	if cliOptions.Output != "" {
		if outputFile, err = os.Create(cliOptions.Output); err != nil {
			gologger.Fatal().Msgf("Could not create output file: %s\n", err)
		}
		defer outputFile.Close()
	}

	var sessionInfo *options.SessionInfo
	if fileutil.FileExists(cliOptions.SessionFile) {
		// attempt to load session info - silently ignore on failure
		_ = fileutil.Unmarshal(fileutil.YAML, []byte(cliOptions.SessionFile), &sessionInfo)
	}

	client, err := client.New(&client.Options{
		ServerURL:                cliOptions.ServerURL,
		Token:                    cliOptions.Token,
		DisableHTTPFallback:      cliOptions.DisableHTTPFallback,
		CorrelationIdLength:      cliOptions.CorrelationIdLength,
		CorrelationIdNonceLength: cliOptions.CorrelationIdNonceLength,
		SessionInfo:              sessionInfo,
	})
	if err != nil {
		gologger.Fatal().Msgf("Could not create client: %s\n", err)
	}

	gologger.Info().Msgf("Listing %d payload for OOB Testing\n", cliOptions.NumberOfPayloads)
	for i := 0; i < cliOptions.NumberOfPayloads; i++ {
		gologger.Info().Msgf("%s\n", client.URL())
	}

	// show all interactions
	noFilter := !cliOptions.DNSOnly && !cliOptions.HTTPOnly && !cliOptions.SmtpOnly

	var matcher *regexMatcher
	var filter *regexMatcher
	if len(cliOptions.Match) > 0 {
		if matcher, err = newRegexMatcher(cliOptions.Match); err != nil {
			gologger.Fatal().Msgf("Could not compile matchers: %s\n", err)
		}
	}
	if len(cliOptions.Filter) > 0 {
		if filter, err = newRegexMatcher(cliOptions.Filter); err != nil {
			gologger.Fatal().Msgf("Could not compile filter: %s\n", err)
		}
	}

	client.StartPolling(time.Duration(cliOptions.PollInterval)*time.Second, func(interaction *server.Interaction) {
		if matcher != nil && !matcher.match(interaction.FullId) {
			return
		}
		if filter != nil && filter.match(interaction.FullId) {
			return
		}
		if !cliOptions.JSON {
			builder := &bytes.Buffer{}

			switch interaction.Protocol {
			case "dns":
				if noFilter || cliOptions.DNSOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received DNS interaction (%s) from %s at %s", interaction.FullId, interaction.QType, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n-----------\nDNS Request\n-----------\n\n%s\n\n------------\nDNS Response\n------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "http":
				if noFilter || cliOptions.HTTPOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received HTTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nHTTP Request\n------------\n\n%s\n\n-------------\nHTTP Response\n-------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "smtp":
				if noFilter || cliOptions.SmtpOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received SMTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nSMTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "ftp":
				if noFilter {
					builder.WriteString(fmt.Sprintf("Received FTP interaction from %s at %s", interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nFTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "responder", "smb":
				if noFilter {
					builder.WriteString(fmt.Sprintf("Received Responder/Smb interaction at %s", interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nResponder/SMB Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "ldap":
				if noFilter {
					builder.WriteString(fmt.Sprintf("[%s] Received LDAP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nLDAP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			}
		} else {
			b, err := jsonpkg.Marshal(interaction)
			if err != nil {
				gologger.Error().Msgf("Could not marshal json output: %s\n", err)
			} else {
				os.Stdout.Write(b)
				os.Stdout.Write([]byte("\n"))
			}
			if outputFile != nil {
				_, _ = outputFile.Write(b)
				_, _ = outputFile.Write([]byte("\n"))
			}
		}
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		if cliOptions.SessionFile != "" {
			_ = client.SaveSessionTo(cliOptions.SessionFile)
		}
		client.StopPolling()
		// whether the session is saved/loaded it shouldn't be destroyed {
		if cliOptions.SessionFile == "" {
			client.Close()
		}
		os.Exit(1)
	}
}

func writeOutput(outputFile *os.File, builder *bytes.Buffer) {
	if outputFile != nil {
		_, _ = outputFile.Write(builder.Bytes())
		_, _ = outputFile.Write([]byte("\n"))
	}
	gologger.Silent().Msgf("%s", builder.String())
}

type regexMatcher struct {
	items []*regexp.Regexp
}

func newRegexMatcher(items []string) (*regexMatcher, error) {
	matcher := &regexMatcher{}
	for _, item := range items {
		if compiled, err := regexp.Compile(item); err != nil {
			return nil, err
		} else {
			matcher.items = append(matcher.items, compiled)
		}
	}
	return matcher, nil
}

func (m *regexMatcher) match(item string) bool {
	for _, regex := range m.items {
		if regex.MatchString(item) {
			return true
		}
	}
	return false
}
