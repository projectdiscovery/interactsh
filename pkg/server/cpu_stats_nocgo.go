//go:build darwin && !cgo

package server

import (
	"errors"
)

func getCPUStats() (*CpuStats, error) {
	return nil, errors.New("not supported")
}
