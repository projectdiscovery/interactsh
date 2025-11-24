package storage

import "time"

type EvictionStrategy int

const (
	EvictionStrategySliding EvictionStrategy = iota // expire-after-access
	EvictionStrategyFixed                           // expire-after-write
)

type Options struct {
	DbPath           string
	EvictionTTL      time.Duration
	MaxSize          int
	EvictionStrategy EvictionStrategy
}

func (options *Options) UseDisk() bool {
	return options.DbPath != ""
}

var DefaultOptions = Options{
	MaxSize:          2500000,
	EvictionStrategy: EvictionStrategySliding,
}
