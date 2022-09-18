//go:build darwin && arm64 && !cgo

package server

import (
	"errors"
)

func getCPUStats() (*CpuStats, error) {
	return nil, errors.New("not supported")
}
