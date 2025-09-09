package storage

import "github.com/projectdiscovery/utils/errkit"

var ErrCorrelationIdNotFound = errkit.New("could not get correlation-id from cache")
