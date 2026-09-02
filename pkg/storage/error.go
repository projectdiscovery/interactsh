package storage

import "github.com/projectdiscovery/utils/errkit"

var ErrCorrelationIdNotFound = errkit.New("could not get correlation-id from cache")

// ErrInvalidSecretKey is returned when the secret key presented for a
// correlation-id does not match the one stored at registration. It is
// distinguishable from ErrCorrelationIdNotFound so callers can tell "wrong
// session" apart from "no such session".
var ErrInvalidSecretKey = errkit.New("invalid secret key passed for correlation-id")
