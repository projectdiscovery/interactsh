package storage

import "time"

type EvictionStrategy int

const (
	EvictionStrategySliding EvictionStrategy = iota // expire-after-access
	EvictionStrategyFixed                           // expire-after-write
)

type Options struct {
	DbPath                string
	EvictionTTL           time.Duration
	MaxSize               int
	MaxSharedInteractions int
	EvictionStrategy      EvictionStrategy
	// OnRemoval is called for each client session removed from cache
	// (deregistration, TTL expiry, size eviction, or cache close).
	OnRemoval func()
	// OnEviction is invoked when a correlation-id leaves the cache for any
	// reason: explicit removal, TTL expiry, capacity eviction or Close.
	// Unlike OnRemoval it fires for every entry, not just client sessions, and
	// receives the evicted data so callers can release resources keyed off it.
	// It runs on the cache's single event goroutine and must not block.
	OnEviction func(correlationID string, data *CorrelationData)
}

func (options *Options) UseDisk() bool {
	return options.DbPath != ""
}

const defaultMaxSharedInteractions = 10000

var DefaultOptions = Options{
	MaxSize:               2500000,
	MaxSharedInteractions: defaultMaxSharedInteractions,
	EvictionStrategy:      EvictionStrategySliding,
}
