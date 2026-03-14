package server

import (
	"net"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/rs/xid"
)

// getMinIdLength returns the minimum length of a correlation ID + nonce combined in a single label.
func (options *Options) getMinIdLength() int {
	return options.CorrelationIdLength + settings.CorrelationIdNonceLengthMinimum
}

// isCorrelationID reports whether s could be a correlation ID, optionally followed by a nonce.
// Accepts bare correlation IDs (len == CorrelationIdLength) and IDs with nonce (len >= CorrelationIdLength).
func (options *Options) isCorrelationID(s string) bool {
	if len(s) < options.CorrelationIdLength || !govalidator.IsAlphanumeric(s) {
		return false
	}
	// xid encodes 12 bytes as a 20-char base32hex string; validate the prefix when possible
	const xidStringLength = 20
	if options.CorrelationIdLength >= xidStringLength {
		_, err := xid.FromString(strings.ToLower(s[:xidStringLength]))
		return err == nil
	}
	return true
}

func formatAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
