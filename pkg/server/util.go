package server

import (
	"github.com/asaskevich/govalidator"
	"github.com/rs/xid"
)

func (options *Options) isCorrelationID(s string) bool {
	if len(s) == options.GetIdLength() && govalidator.IsAlphanumeric(s) {
		if _, err := xid.FromString(s[:options.CorrelationIdLength]); err == nil {
			return true
		}
	}
	return false
}
