package server

import (
	"net"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/rs/xid"
)

func (options *Options) isCorrelationID(s string) bool {
	if len(s) == options.GetIdLength() && govalidator.IsAlphanumeric(s) {
		// xid should be 12
		if options.CorrelationIdLength != 12 {
			return true
		} else if _, err := xid.FromString(strings.ToLower(s[:options.CorrelationIdLength])); err == nil {
			return true
		}
	}
	return false
}

func formatAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
