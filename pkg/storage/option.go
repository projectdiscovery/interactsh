package storage

import "time"

type Options struct {
	DbPath        string
	EvictionTTL   time.Duration
	MaxSize       int
	MaxMemoryMB   uint64 // Maximum memory usage in MB for memory pressure monitoring
}

func (options *Options) UseDisk() bool {
	return options.DbPath != ""
}

var DefaultOptions = Options{
	MaxSize:     2500000,
	MaxMemoryMB: 1024, // Default 1GB memory limit
}
