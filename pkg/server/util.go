package server

import (
	"github.com/asaskevich/govalidator"
	"github.com/rs/xid"
)

func isCorrelationID(s string) bool {
	if len(s) == 33 && govalidator.IsAlphanumeric(s) {
		if _, err := xid.FromString(s[:20]); err == nil {
			return true
		}
	}
	return false
}
