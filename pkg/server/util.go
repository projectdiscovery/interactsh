package server

import (
	"github.com/asaskevich/govalidator"
)

func isCorrelationID(s string) bool {
	return len(s) == 33 && govalidator.IsAlphanumeric(s)
}
