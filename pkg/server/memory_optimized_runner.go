package server

import (
	"context"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

// MemoryOptimizedRunner provides memory-optimized server execution
type MemoryOptimizedRunner struct {
	options         *Options
	httpPool        *HTTPObjectPool
	memoryMonitor   *storage.MemoryMonitor
	gcTicker        *time.Ticker
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewMemoryOptimizedRunner creates a new memory-optimized runner
func NewMemoryOptimizedRunner(options *Options) *MemoryOptimizedRunner {
	ctx, cancel := context.WithCancel(context.Background())
	
	runner := &MemoryOptimizedRunner{
		options:   options,
		httpPool:  NewHTTPObjectPool(),
		ctx:       ctx,
		cancel:    cancel,
	}
	
	// Initialize memory monitor if storage has one
	if storage, ok := options.Storage.(*storage.StorageDB); ok {
		runner.memoryMonitor = storage.GetMemoryMonitor()
	}
	
	return runner
}

// OptimizeMemorySettings applies comprehensive memory optimizations
func (r *MemoryOptimizedRunner) OptimizeMemorySettings() {
	// Apply Go runtime memory optimizations
	r.optimizeGoRuntime()
	
	// Set up periodic garbage collection
	r.setupPeriodicGC()
	
	// Configure memory pressure monitoring
	r.setupMemoryPressureHandling()
	
	gologger.Info().Msg("Memory optimizations applied successfully")
}

// optimizeGoRuntime applies Go runtime memory optimizations
func (r *MemoryOptimizedRunner) optimizeGoRuntime() {
	// Set GOMAXPROCS if not explicitly set
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(runtime.NumCPU())
		gologger.Info().Msgf("Set GOMAXPROCS to %d", runtime.NumCPU())
	}
	
	// Configure GC percentage based on available memory
	gcPercent := 100 // Default
	if r.memoryMonitor != nil {
		switch r.memoryMonitor.GetPressureLevel() {
		case storage.MemoryPressureHigh:
			gcPercent = 50
		case storage.MemoryPressureCritical:
			gcPercent = 25
		}
	}
	debug.SetGCPercent(gcPercent)
	gologger.Info().Msgf("Set GC percentage to %d", gcPercent)
	
	// Set memory limit if GOMEMLIMIT is not set
	if os.Getenv("GOMEMLIMIT") == "" {
		// Calculate memory limit based on available system memory
		memLimit := r.calculateOptimalMemoryLimit()
		if memLimit > 0 {
			debug.SetMemoryLimit(int64(memLimit))
			gologger.Info().Msgf("Set memory limit to %.1f MB", float64(memLimit)/(1024*1024))
		}
	}
	
	// Enable scavenger for better memory release
	debug.SetGCPercent(gcPercent)
}

// calculateOptimalMemoryLimit calculates optimal memory limit
func (r *MemoryOptimizedRunner) calculateOptimalMemoryLimit() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Use 80% of system memory as limit
	systemMemory := memStats.Sys
	if systemMemory > 0 {
		return uint64(float64(systemMemory) * 0.8)
	}
	
	// Fallback to default limit
	return 1024 * 1024 * 1024 // 1GB
}

// setupPeriodicGC sets up periodic garbage collection
func (r *MemoryOptimizedRunner) setupPeriodicGC() {
	// Run GC every 5 minutes by default, or more frequently under pressure
	interval := 5 * time.Minute
	if r.memoryMonitor != nil && r.memoryMonitor.IsMemoryPressureHigh() {
		interval = 1 * time.Minute
	}
	
	r.gcTicker = time.NewTicker(interval)
	
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-r.gcTicker.C:
				r.performOptimizedGC()
			}
		}
	}()
	
	gologger.Info().Msgf("Periodic GC scheduled every %v", interval)
}

// performOptimizedGC performs memory-pressure-aware garbage collection
func (r *MemoryOptimizedRunner) performOptimizedGC() {
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)
	
	// Determine GC aggressiveness based on memory pressure
	if r.memoryMonitor != nil {
		switch r.memoryMonitor.GetPressureLevel() {
		case storage.MemoryPressureHigh:
			runtime.GC()
			debug.FreeOSMemory()
		case storage.MemoryPressureCritical:
			runtime.GC()
			runtime.GC() // Double GC for critical pressure
			debug.FreeOSMemory()
		default:
			runtime.GC()
		}
	} else {
		runtime.GC()
	}
	
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)
	
	freedBytes := memStatsBefore.Alloc - memStatsAfter.Alloc
	if freedBytes > 1024*1024 { // Only log if freed more than 1MB
		gologger.Debug().Msgf("GC freed %.1f MB (%.1f MB -> %.1f MB)", 
			float64(freedBytes)/(1024*1024),
			float64(memStatsBefore.Alloc)/(1024*1024),
			float64(memStatsAfter.Alloc)/(1024*1024))
	}
}

// setupMemoryPressureHandling configures memory pressure response
func (r *MemoryOptimizedRunner) setupMemoryPressureHandling() {
	if r.memoryMonitor == nil {
		return
	}
	
	r.memoryMonitor.AddCallback(func(level storage.MemoryPressureLevel, stats *runtime.MemStats) {
		switch level {
		case storage.MemoryPressureMedium:
			// Increase GC frequency
			r.adjustGCFrequency(2 * time.Minute)
			
		case storage.MemoryPressureHigh:
			// More aggressive GC and cleanup
			r.adjustGCFrequency(1 * time.Minute)
			runtime.GC()
			
		case storage.MemoryPressureCritical:
			// Emergency memory cleanup
			r.adjustGCFrequency(30 * time.Second)
			r.performEmergencyCleanup()
			
		default:
			// Normal operation
			r.adjustGCFrequency(5 * time.Minute)
		}
	})
}

// adjustGCFrequency adjusts the periodic GC frequency
func (r *MemoryOptimizedRunner) adjustGCFrequency(interval time.Duration) {
	if r.gcTicker != nil {
		r.gcTicker.Stop()
	}
	r.gcTicker = time.NewTicker(interval)
}

// performEmergencyCleanup performs emergency memory cleanup
func (r *MemoryOptimizedRunner) performEmergencyCleanup() {
	gologger.Warning().Msg("Performing emergency memory cleanup due to critical pressure")
	
	// Force immediate garbage collection
	runtime.GC()
	runtime.GC() // Double GC
	
	// Force OS memory release
	debug.FreeOSMemory()
	
	// Log memory stats after cleanup
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	gologger.Info().Msgf("Emergency cleanup complete - Current allocation: %.1f MB", 
		float64(memStats.Alloc)/(1024*1024))
}

// GetHTTPPool returns the HTTP object pool
func (r *MemoryOptimizedRunner) GetHTTPPool() *HTTPObjectPool {
	return r.httpPool
}

// GetMemoryMonitor returns the memory monitor
func (r *MemoryOptimizedRunner) GetMemoryMonitor() *storage.MemoryMonitor {
	return r.memoryMonitor
}

// GetMemoryStats returns current memory statistics
func (r *MemoryOptimizedRunner) GetMemoryStats() *storage.MemoryStats {
	if r.memoryMonitor != nil {
		return r.memoryMonitor.GetCurrentStats()
	}
	
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	return &storage.MemoryStats{
		AllocBytes:      memStats.Alloc,
		TotalAllocBytes: memStats.TotalAlloc,
		SysBytes:        memStats.Sys,
		HeapAllocBytes:  memStats.HeapAlloc,
		HeapSysBytes:    memStats.HeapSys,
		HeapObjects:     memStats.HeapObjects,
		GCCycles:        memStats.NumGC,
		LastGCTime:      time.Unix(0, int64(memStats.LastGC)),
		PressureLevel:   storage.MemoryPressureNone,
	}
}

// IsMemoryOptimized returns true if memory optimizations are active
func (r *MemoryOptimizedRunner) IsMemoryOptimized() bool {
	return r.memoryMonitor != nil
}

// Stop stops the memory-optimized runner
func (r *MemoryOptimizedRunner) Stop() {
	r.cancel()
	if r.gcTicker != nil {
		r.gcTicker.Stop()
	}
	if r.memoryMonitor != nil {
		r.memoryMonitor.Stop()
	}
}

// SetMemoryLimitFromEnv sets memory limit from environment variables
func SetMemoryLimitFromEnv() {
	// Check for INTERACTSH_MEMORY_LIMIT environment variable
	if limitStr := os.Getenv("INTERACTSH_MEMORY_LIMIT"); limitStr != "" {
		if limitMB, err := strconv.ParseUint(limitStr, 10, 64); err == nil {
			limitBytes := limitMB * 1024 * 1024
			debug.SetMemoryLimit(int64(limitBytes))
			gologger.Info().Msgf("Set memory limit from environment: %d MB", limitMB)
		}
	}
	
	// Check for INTERACTSH_GC_PERCENT environment variable
	if gcPercentStr := os.Getenv("INTERACTSH_GC_PERCENT"); gcPercentStr != "" {
		if gcPercent, err := strconv.Atoi(gcPercentStr); err == nil {
			debug.SetGCPercent(gcPercent)
			gologger.Info().Msgf("Set GC percentage from environment: %d", gcPercent)
		}
	}
}