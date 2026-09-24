package server

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Correlation ids are produced from xid (cidl prefix) and zbase32 (cidn suffix),
// so detection is restricted to those alphabets to avoid false-positive matches
// inside ordinary domain labels (see issue #1362).
const (
	xidAlphabet     = "0123456789abcdefghijklmnopqrstuv"
	zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
)

var (
	xidAlphabetTable     = newAlphabetTable(xidAlphabet)
	zbase32AlphabetTable = newAlphabetTable(zbase32Alphabet)
)

func newAlphabetTable(alphabet string) [256]bool {
	var table [256]bool
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		table[c] = true
		if c >= 'a' && c <= 'z' {
			table[c-32] = true
		}
	}
	return table
}

func inAlphabet(table [256]bool, s string) bool {
	for i := 0; i < len(s); i++ {
		if !table[s[i]] {
			return false
		}
	}
	return true
}

func (options *Options) isCorrelationID(s string) bool {
	if len(s) != options.GetIdLength() {
		return false
	}
	if !inAlphabet(xidAlphabetTable, s[:options.CorrelationIdLength]) {
		return false
	}
	return inAlphabet(zbase32AlphabetTable, s[options.CorrelationIdLength:])
}

func formatAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// storeInteraction marshals interaction and persists it under correlationID via Storage.AddInteraction.
// Each protocol handler builds its own protocol-specific Interaction and delegates the marshal/log/store
// step here so every match is stored independently (see issue #1362).
func (options *Options) storeInteraction(interaction *Interaction, correlationID string) {
	data, err := json.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode %s interaction: %s\n", interaction.Protocol, err)
		return
	}
	gologger.Debug().Msgf("%s Interaction: \n%s\n", strings.ToUpper(interaction.Protocol), string(data))
	if err := options.Storage.AddInteraction(correlationID, data); err != nil {
		gologger.Warning().Msgf("Could not store %s interaction: %s\n", interaction.Protocol, err)
	}
}

// storeRootTLDInteraction marshals interaction and persists it under id via Storage.AddInteractionWithId.
// Used when RootTLD is enabled and the request targets a configured parent domain directly.
func (options *Options) storeRootTLDInteraction(interaction *Interaction, id string) {
	data, err := json.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode root tld %s interaction: %s\n", interaction.Protocol, err)
		return
	}
	gologger.Debug().Msgf("Root TLD %s Interaction: \n%s\n", strings.ToUpper(interaction.Protocol), string(data))
	if err := options.Storage.AddInteractionWithId(id, data); err != nil {
		gologger.Warning().Msgf("Could not store root tld %s interaction: %s\n", interaction.Protocol, err)
	}
}

// extractCorrelationID finds the first correlation id embedded in a host,
// returning the full unique id (correlation id plus nonce) and the host label
// prefix it was found in.
//
// This mirrors the extraction the logger middleware performs, so that a request
// served from the file route is attributed to the same session the logger would
// have attributed it to. TestExtractCorrelationIDMatchesLogger keeps the two in
// step.
func (options *Options) extractCorrelationID(host string) (uniqueID, fullID string) {
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}
	parts := strings.Split(host, ".")
	for i, part := range parts {
		for chunk := range stringsutil.SlideWithLength(part, options.GetIdLength()) {
			normalized := strings.ToLower(chunk)
			if !options.isCorrelationID(normalized) {
				continue
			}
			fullID := part
			if i+1 <= len(parts) {
				fullID = strings.Join(parts[:i+1], ".")
			}
			return normalized, fullID
		}
	}
	return "", ""
}
