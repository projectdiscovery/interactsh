package storage

import (
	"context"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
)

// MemoryPressureLevel indicates the current memory pressure
type MemoryPressureLevel int

const (
	MemoryPressureNone MemoryPressureLevel = iota
	MemoryPressureLow
	MemoryPressureMedium
	MemoryPressureHigh
	MemoryPressureCritical
)

// MemoryMonitor provides real-time memory pressure detection and management
type MemoryMonitor struct {
	ctx                context.Context
	cancel             context.CancelFunc
	pressureLevel      int64 // atomic
	lastGCTime         int64 // atomic
	maxMemoryBytes     uint64
	warningThreshold   uint64
	criticalThreshold  uint64
	gcForceThreshold   uint64
	callbacks          []MemoryPressureCallback
	callbacksMutex     sync.RWMutex
	monitorInterval    time.Duration
	degradationEnabled int64 // atomic bool
}

// MemoryPressureCallback is called when memory pressure changes
type MemoryPressureCallback func(level MemoryPressureLevel, stats *runtime.MemStats)

// MemoryStats provides detailed memory statistics
type MemoryStats struct {
	AllocBytes      uint64
	TotalAllocBytes uint64
	SysBytes        uint64
	HeapAllocBytes  uint64
	HeapSysBytes    uint64
	HeapObjects     uint64
	GCCycles        uint32
	LastGCTime      time.Time
	PressureLevel   MemoryPressureLevel
}

// NewMemoryMonitor creates a new memory pressure monitor
func NewMemoryMonitor(maxMemoryMB uint64) *MemoryMonitor {
	maxBytes := maxMemoryMB * 1024 * 1024
	ctx, cancel := context.WithCancel(context.Background())
	
	monitor := &MemoryMonitor{
		ctx:               ctx,
		cancel:            cancel,
		maxMemoryBytes:    maxBytes,
		warningThreshold:  uint64(float64(maxBytes) * 0.7),  // 70%
		criticalThreshold: uint64(float64(maxBytes) * 0.85), // 85%
		gcForceThreshold:  uint64(float64(maxBytes) * 0.9),  // 90%
		monitorInterval:   time.Second * 5,
		degradationEnabled: 1,
	}
	
	// Start monitoring goroutine
	go monitor.monitorLoop()
	
	return monitor
}

// Start begins memory monitoring (called automatically by NewMemoryMonitor)
func (m *MemoryMonitor) Start() {
	go m.monitorLoop()
}

// Stop stops the memory monitor
func (m *MemoryMonitor) Stop() {
	m.cancel()
}

// GetCurrentStats returns current memory statistics
func (m *MemoryMonitor) GetCurrentStats() *MemoryStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	return &MemoryStats{
		AllocBytes:      memStats.Alloc,
		TotalAllocBytes: memStats.TotalAlloc,
		SysBytes:        memStats.Sys,
		HeapAllocBytes:  memStats.HeapAlloc,
		HeapSysBytes:    memStats.HeapSys,
		HeapObjects:     memStats.HeapObjects,
		GCCycles:        memStats.NumGC,
		LastGCTime:      time.Unix(0, int64(memStats.LastGC)),
		PressureLevel:   MemoryPressureLevel(atomic.LoadInt64(&m.pressureLevel)),
	}
}

// GetPressureLevel returns the current memory pressure level
func (m *MemoryMonitor) GetPressureLevel() MemoryPressureLevel {
	return MemoryPressureLevel(atomic.LoadInt64(&m.pressureLevel))
}

// IsMemoryPressureHigh returns true if memory pressure is high or critical
func (m *MemoryMonitor) IsMemoryPressureHigh() bool {
	level := m.GetPressureLevel()
	return level >= MemoryPressureHigh
}

// ShouldDegradePerformance returns true if we should degrade performance to save memory
func (m *MemoryMonitor) ShouldDegradePerformance() bool {
	return atomic.LoadInt64(&m.degradationEnabled) == 1 && m.IsMemoryPressureHigh()
}

// EnableDegradation enables/disables performance degradation under memory pressure
func (m *MemoryMonitor) EnableDegradation(enabled bool) {
	if enabled {
		atomic.StoreInt64(&m.degradationEnabled, 1)
	} else {
		atomic.StoreInt64(&m.degradationEnabled, 0)
	}
}

// AddCallback adds a callback for memory pressure changes
func (m *MemoryMonitor) AddCallback(callback MemoryPressureCallback) {
	m.callbacksMutex.Lock()
	defer m.callbacksMutex.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

// ForceGC forces garbage collection if memory pressure is high
func (m *MemoryMonitor) ForceGC() {
	now := time.Now().UnixNano()
	lastGC := atomic.LoadInt64(&m.lastGCTime)
	
	// Don't force GC more than once per 30 seconds
	if now-lastGC > int64(30*time.Second) {
		atomic.StoreInt64(&m.lastGCTime, now)
		runtime.GC()
		gologger.Info().Msg("Forced garbage collection due to memory pressure")
	}
}

// OptimizeForMemoryPressure applies memory optimizations based on current pressure
func (m *MemoryMonitor) OptimizeForMemoryPressure() {
	level := m.GetPressureLevel()
	
	switch level {
	case MemoryPressureHigh:
		// Force GC more aggressively
		runtime.GC()
		
		// Reduce GC target percentage to free memory faster
		debug.SetGCPercent(50)
		
	case MemoryPressureCritical:
		// Force immediate GC
		runtime.GC()
		runtime.GC() // Double GC to ensure cleanup
		
		// Very aggressive GC
		debug.SetGCPercent(25)
		
		gologger.Warning().Msg("Critical memory pressure detected - applying aggressive optimizations")
		
	default:
		// Normal GC settings
		debug.SetGCPercent(100)
	}
}

// monitorLoop runs the memory monitoring loop
func (m *MemoryMonitor) monitorLoop() {
	ticker := time.NewTicker(m.monitorInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkMemoryPressure()
		}
	}
}

// checkMemoryPressure evaluates current memory usage and updates pressure level
func (m *MemoryMonitor) checkMemoryPressure() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	currentAlloc := memStats.Alloc
	oldLevel := MemoryPressureLevel(atomic.LoadInt64(&m.pressureLevel))
	newLevel := m.calculatePressureLevel(currentAlloc)
	
	if newLevel != oldLevel {
		atomic.StoreInt64(&m.pressureLevel, int64(newLevel))
		m.notifyCallbacks(newLevel, &memStats)
		
		// Log pressure level changes
		switch newLevel {
		case MemoryPressureLow:
			gologger.Info().Msgf("Memory pressure: LOW (%.1f MB / %.1f MB)", 
				float64(currentAlloc)/1024/1024, float64(m.maxMemoryBytes)/1024/1024)
		case MemoryPressureMedium:
			gologger.Warning().Msgf("Memory pressure: MEDIUM (%.1f MB / %.1f MB)", 
				float64(currentAlloc)/1024/1024, float64(m.maxMemoryBytes)/1024/1024)
		case MemoryPressureHigh:
			gologger.Warning().Msgf("Memory pressure: HIGH (%.1f MB / %.1f MB)", 
				float64(currentAlloc)/1024/1024, float64(m.maxMemoryBytes)/1024/1024)
		case MemoryPressureCritical:
			gologger.Error().Msgf("Memory pressure: CRITICAL (%.1f MB / %.1f MB)", 
				float64(currentAlloc)/1024/1024, float64(m.maxMemoryBytes)/1024/1024)
		}
	}
	
	// Apply optimizations if needed
	if newLevel >= MemoryPressureHigh {
		m.OptimizeForMemoryPressure()
	}
	
	// Force GC if we're approaching critical levels
	if currentAlloc >= m.gcForceThreshold {
		m.ForceGC()
	}
}

// calculatePressureLevel determines the memory pressure level based on current allocation
func (m *MemoryMonitor) calculatePressureLevel(currentAlloc uint64) MemoryPressureLevel {
	if m.maxMemoryBytes == 0 {
		return MemoryPressureNone
	}
	
	ratio := float64(currentAlloc) / float64(m.maxMemoryBytes)
	
	switch {
	case ratio >= 0.9:
		return MemoryPressureCritical
	case ratio >= 0.8:
		return MemoryPressureHigh
	case ratio >= 0.6:
		return MemoryPressureMedium
	case ratio >= 0.4:
		return MemoryPressureLow
	default:
		return MemoryPressureNone
	}
}

// notifyCallbacks notifies all registered callbacks of pressure level changes
func (m *MemoryMonitor) notifyCallbacks(level MemoryPressureLevel, stats *runtime.MemStats) {
	m.callbacksMutex.RLock()
	defer m.callbacksMutex.RUnlock()
	
	for _, callback := range m.callbacks {
		go func(cb MemoryPressureCallback) {
			defer func() {
				if r := recover(); r != nil {
					gologger.Error().Msgf("Memory pressure callback panic: %v", r)
				}
			}()
			cb(level, stats)
		}(callback)
	}
}