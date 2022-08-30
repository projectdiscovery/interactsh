package server

import (
	"runtime"

	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/network"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

type Metrics struct {
	Dns      uint64                `json:"dns"`
	Ftp      uint64                `json:"ftp"`
	Http     uint64                `json:"http"`
	Ldap     uint64                `json:"ldap"`
	Smb      uint64                `json:"smb"`
	Smtp     uint64                `json:"smtp"`
	Sessions int64                 `json:"sessions"`
	Cache    *storage.CacheMetrics `json:"cache"`
	Memory   runtime.MemStats      `json:"memory"`
	Cpu      *cpu.Stats            `json:"cpu"`
	Network  []network.Stats       `json:"betwork"`
}

func GetCacheMetrics(options *Options) *storage.CacheMetrics {
	cacheMetrics, _ := options.Storage.GetCacheMetrics()
	return cacheMetrics
}

func GetMemoryMetrics() runtime.MemStats {
	var mStats runtime.MemStats
	runtime.ReadMemStats(&mStats)
	return mStats
}

func GetCpuMetrics() *cpu.Stats {
	cpuStats, _ := cpu.Get()
	return cpuStats
}

func GetNetworkMetrics() []network.Stats {
	networkStats, _ := network.Get()
	return networkStats
}
