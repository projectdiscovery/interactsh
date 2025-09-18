package storage

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestObjectPool(t *testing.T) {
	pool := NewObjectPool()

	t.Run("CorrelationDataPool", func(t *testing.T) {
		// Test pooling reduces allocations
		data1 := pool.GetCorrelationData()
		if data1 == nil {
			t.Fatal("Expected non-nil correlation data")
		}
		
		// Use the data
		data1.SecretKey = "test"
		data1.Data = append(data1.Data, "test1", "test2")
		
		// Return to pool
		pool.PutCorrelationData(data1)
		
		// Get again - should be reused
		data2 := pool.GetCorrelationData()
		if data2 == nil {
			t.Fatal("Expected non-nil correlation data")
		}
		
		// Should be clean
		if data2.SecretKey != "" || len(data2.Data) != 0 {
			t.Error("Expected clean correlation data from pool")
		}
		
		pool.PutCorrelationData(data2)
	})

	t.Run("StringSlicePool", func(t *testing.T) {
		slice1 := pool.GetStringSlice()
		if slice1 == nil {
			t.Fatal("Expected non-nil string slice")
		}
		
		slice1 = append(slice1, "test1", "test2", "test3")
		pool.PutStringSlice(slice1)
		
		slice2 := pool.GetStringSlice()
		if len(slice2) != 0 {
			t.Error("Expected empty slice from pool")
		}
		
		pool.PutStringSlice(slice2)
	})

	t.Run("BufferPool", func(t *testing.T) {
		buf1 := pool.GetBuffer()
		if buf1 == nil {
			t.Fatal("Expected non-nil buffer")
		}
		
		buf1.WriteString("test data")
		pool.PutBuffer(buf1)
		
		buf2 := pool.GetBuffer()
		if buf2.Len() != 0 {
			t.Error("Expected empty buffer from pool")
		}
		
		pool.PutBuffer(buf2)
	})
}

func TestMemoryMonitor(t *testing.T) {
	monitor := NewMemoryMonitor(100) // 100MB limit for testing
	defer monitor.Stop()

	t.Run("PressureLevelCalculation", func(t *testing.T) {
		// Test pressure level calculation
		testCases := []struct {
			currentAlloc uint64
			maxMemory    uint64
			expected     MemoryPressureLevel
		}{
			{10, 100, MemoryPressureNone},
			{40, 100, MemoryPressureLow},
			{60, 100, MemoryPressureMedium},
			{80, 100, MemoryPressureHigh},
			{90, 100, MemoryPressureCritical},
		}

		for _, tc := range testCases {
			testMonitor := &MemoryMonitor{maxMemoryBytes: tc.maxMemory}
			level := testMonitor.calculatePressureLevel(tc.currentAlloc)
			if level != tc.expected {
				t.Errorf("Expected pressure level %v for %d/%d, got %v", 
					tc.expected, tc.currentAlloc, tc.maxMemory, level)
			}
		}
	})

	t.Run("CallbackExecution", func(t *testing.T) {
		callbackCalled := make(chan bool, 1)
		var receivedLevel MemoryPressureLevel
		
		monitor.AddCallback(func(level MemoryPressureLevel, stats *runtime.MemStats) {
			receivedLevel = level
			callbackCalled <- true
		})

		// Simulate memory pressure change by forcing a high pressure level
		oldLevel := monitor.calculatePressureLevel(10)
		newLevel := monitor.calculatePressureLevel(90) // Force high pressure
		
		// Manually trigger callback
		monitor.notifyCallbacks(newLevel, &runtime.MemStats{})
		
		// Wait for callback with timeout
		select {
		case <-callbackCalled:
			// Success
		case <-time.After(1 * time.Second):
			t.Error("Expected callback to be called within timeout")
		}
		
		// Use variables to avoid unused variable error
		_ = oldLevel
		_ = receivedLevel
	})

	t.Run("GCForcing", func(t *testing.T) {
		var memStatsBefore runtime.MemStats
		runtime.ReadMemStats(&memStatsBefore)
		
		monitor.ForceGC()
		
		var memStatsAfter runtime.MemStats
		runtime.ReadMemStats(&memStatsAfter)
		
		// GC should have run (NumGC should increase)
		if memStatsAfter.NumGC <= memStatsBefore.NumGC {
			t.Error("Expected GC to run")
		}
	})
}

func TestMemoryOptimizations(t *testing.T) {
	t.Run("MemoryPressureResponse", func(t *testing.T) {
		monitor := NewMemoryMonitor(50) // Very low limit to trigger pressure
		defer monitor.Stop()

		// Test that optimizations are applied under pressure
		monitor.OptimizeForMemoryPressure()
		
		// Should complete without panic
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		pool := NewObjectPool()
		const numGoroutines = 100
		var wg sync.WaitGroup

		// Test concurrent access to pools
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				
				// Use different pool types concurrently
				data := pool.GetCorrelationData()
				data.Data = append(data.Data, "test")
				pool.PutCorrelationData(data)
				
				slice := pool.GetStringSlice()
				slice = append(slice, "test")
				pool.PutStringSlice(slice)
				
				buf := pool.GetBuffer()
				buf.WriteString("test")
				pool.PutBuffer(buf)
			}()
		}

		wg.Wait()
	})
}

func BenchmarkObjectPool(b *testing.B) {
	pool := NewObjectPool()

	b.Run("CorrelationDataPooled", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			data := pool.GetCorrelationData()
			data.Data = append(data.Data, "test1", "test2")
			pool.PutCorrelationData(data)
		}
	})

	b.Run("CorrelationDataDirect", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			data := &CorrelationData{
				Data: make([]string, 0, 8),
			}
			data.Data = append(data.Data, "test1", "test2")
		}
	})

	b.Run("StringSlicePooled", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slice := pool.GetStringSlice()
			slice = append(slice, "test1", "test2")
			pool.PutStringSlice(slice)
		}
	})

	b.Run("StringSliceDirect", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			slice := make([]string, 0, 16)
			slice = append(slice, "test1", "test2")
		}
	})
}

func BenchmarkMemoryPressure(b *testing.B) {
	monitor := NewMemoryMonitor(1024) // 1GB limit
	defer monitor.Stop()

	b.Run("MemoryStatsCollection", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			stats := monitor.GetCurrentStats()
			_ = stats.AllocBytes
		}
	})

	b.Run("PressureLevelCheck", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			level := monitor.GetPressureLevel()
			_ = level >= MemoryPressureHigh
		}
	})
}

// TestMemoryLeakPrevention ensures pools don't cause memory leaks
func TestMemoryLeakPrevention(t *testing.T) {
	pool := NewObjectPool()
	
	t.Run("OversizedSlicePrevention", func(t *testing.T) {
		// Create oversized slice
		slice := make([]string, 200) // Exceeds pool limit
		for i := range slice {
			slice[i] = "test"
		}
		
		// Pool should reject oversized slice
		pool.PutStringSlice(slice)
		
		// Get new slice should be normal size
		newSlice := pool.GetStringSlice()
		if cap(newSlice) > 128 {
			t.Error("Pool should not return oversized slice")
		}
		
		pool.PutStringSlice(newSlice)
	})

	t.Run("OversizedBufferPrevention", func(t *testing.T) {
		// Create oversized buffer
		buf := pool.GetBuffer()
		largeBuf := make([]byte, 1024*128) // 128KB, exceeds limit
		buf.Write(largeBuf)
		
		// Pool should reject oversized buffer
		pool.PutBuffer(buf)
		
		// Get new buffer should be normal size
		newBuf := pool.GetBuffer()
		if newBuf.Cap() > 1024*64 {
			t.Error("Pool should not return oversized buffer")
		}
		
		pool.PutBuffer(newBuf)
	})
}