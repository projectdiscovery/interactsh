//go:build !(darwin && !cgo)

package server

import (
	"github.com/mackerelio/go-osstat/cpu"
)

func getCPUStats() (*CpuStats, error) {
	cs, err := cpu.Get()
	if err != nil {
		return nil, err
	}
	cpuStats := &CpuStats{
		User:   cs.User,
		System: cs.System,
		Idle:   cs.Idle,
		Nice:   cs.Nice,
		Total:  cs.Total,
	}
	return cpuStats, nil
}
