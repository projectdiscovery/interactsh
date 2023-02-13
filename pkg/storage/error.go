package storage

import "errors"

var ErrCorrelationIdNotFound = errors.New("could not get correlation-id from cache")
