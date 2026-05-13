package server

import (
	"net"
	"strconv"
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
