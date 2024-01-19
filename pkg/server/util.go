package server

import (
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/rs/xid"
)

func (options *Options) isCorrelationID(s string) bool {
	if ok, _ := regexp.MatchString("^[a-f0-9]{8}$", s); ok {
		return false
	}

	if options.getBurpCorrelationID(s) != "" {
		return true
	}

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
