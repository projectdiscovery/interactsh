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
	Memory   *MemoryMetrics        `json:"memory"`
	Cpu      *CpuStats             `json:"cpu"`
	Network  []NetworkStats        `json:"network"`
}

func GetCacheMetrics(options *Options) *storage.CacheMetrics {
	cacheMetrics, _ := options.Storage.GetCacheMetrics()
	return cacheMetrics
}

type MemoryMetrics struct {
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Sys          uint64 `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    uint64 `json:"heap_allo"`
	HeapSys      uint64 `json:"heap_sys"`
	HeapIdle     uint64 `json:"head_idle"`
	HeapInuse    uint64 `json:"heap_in_use"`
	HeapReleased uint64 `json:"heap_released"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInuse   uint64 `json:"stack_in_use"`
	StackSys     uint64 `json:"stack_sys"`
	MSpanInuse   uint64 `json:"mspan_in_use"`
	MSpanSys     uint64 `json:"mspan_sys"`
	MCacheInuse  uint64 `json:"mcache_in_use"`
	MCacheSys    uint64 `json:"mcache_sys"`
}

func GetMemoryMetrics() *MemoryMetrics {
	var mStats runtime.MemStats
	runtime.ReadMemStats(&mStats)
	return &MemoryMetrics{
		Alloc:        mStats.Alloc,
		TotalAlloc:   mStats.TotalAlloc,
		Sys:          mStats.Sys,
		Lookups:      mStats.Lookups,
		Mallocs:      mStats.Mallocs,
		Frees:        mStats.Frees,
		HeapAlloc:    mStats.HeapAlloc,
		HeapSys:      mStats.HeapSys,
		HeapIdle:     mStats.HeapIdle,
		HeapInuse:    mStats.HeapInuse,
		HeapReleased: mStats.HeapReleased,
		HeapObjects:  mStats.HeapObjects,
		StackInuse:   mStats.StackInuse,
		StackSys:     mStats.StackSys,
		MSpanInuse:   mStats.MSpanInuse,
		MSpanSys:     mStats.MSpanSys,
		MCacheInuse:  mStats.MCacheInuse,
		MCacheSys:    mStats.MCacheSys,
	}
}

type CpuStats struct {
	User   uint64 `json:"user"`
	System uint64 `json:"system"`
	Idle   uint64 `json:"idle"`
	Nice   uint64 `json:"nice"`
	Total  uint64 `json:"total"`
}

func GetCpuMetrics() (cpuStats *CpuStats) {
	if cs, err := cpu.Get(); err == nil {
		cpuStats = &CpuStats{
			User:   cs.User,
			System: cs.System,
			Idle:   cs.Idle,
			Nice:   cs.Nice,
			Total:  cs.Total,
		}
	}
	return
}

type NetworkStats struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"received"`
	TxBytes uint64 `json:"transmitted"`
}

func GetNetworkMetrics() (networkStats []NetworkStats) {
	if nss, err := network.Get(); err == nil {
		for _, ns := range nss {
			networkStats = append(networkStats, NetworkStats{
				Name:    ns.Name,
				TxBytes: ns.TxBytes,
				RxBytes: ns.RxBytes,
			})
		}
	}
	return
}
