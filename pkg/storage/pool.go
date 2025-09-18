package storage

import (
	"bytes"
	"sync"
)

// ObjectPool manages reusable objects to reduce GC pressure
type ObjectPool struct {
	correlationDataPool *sync.Pool
	stringSlicePool     *sync.Pool
	bytesBufferPool     *sync.Pool
	interactionPool     *sync.Pool
}

// NewObjectPool creates a new object pool for memory optimization
func NewObjectPool() *ObjectPool {
	return &ObjectPool{
		correlationDataPool: &sync.Pool{
			New: func() interface{} {
				return &CorrelationData{
					Data: make([]string, 0, 8), // Pre-allocate capacity
				}
			},
		},
		stringSlicePool: &sync.Pool{
			New: func() interface{} {
				return make([]string, 0, 16) // Pre-allocate capacity
			},
		},
		bytesBufferPool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
		interactionPool: &sync.Pool{
			New: func() interface{} {
				return make(map[string]interface{}, 8)
			},
		},
	}
}

// GetCorrelationData retrieves a reusable CorrelationData instance
func (p *ObjectPool) GetCorrelationData() *CorrelationData {
	data := p.correlationDataPool.Get().(*CorrelationData)
	// Reset to clean state
	data.Data = data.Data[:0]
	data.SecretKey = ""
	data.AESKeyEncrypted = ""
	data.AESKey = nil
	return data
}

// PutCorrelationData returns a CorrelationData instance to the pool
func (p *ObjectPool) PutCorrelationData(data *CorrelationData) {
	if data != nil && cap(data.Data) <= 64 { // Prevent memory leak from oversized slices
		p.correlationDataPool.Put(data)
	}
}

// GetStringSlice retrieves a reusable string slice
func (p *ObjectPool) GetStringSlice() []string {
	slice := p.stringSlicePool.Get().([]string)
	return slice[:0] // Reset length but keep capacity
}

// PutStringSlice returns a string slice to the pool
func (p *ObjectPool) PutStringSlice(slice []string) {
	if slice != nil && cap(slice) <= 128 { // Prevent memory leak from oversized slices
		p.stringSlicePool.Put(slice)
	}
}

// GetBuffer retrieves a reusable bytes.Buffer
func (p *ObjectPool) GetBuffer() *bytes.Buffer {
	buffer := p.bytesBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	return buffer
}

// PutBuffer returns a bytes.Buffer to the pool
func (p *ObjectPool) PutBuffer(buffer *bytes.Buffer) {
	if buffer != nil && buffer.Cap() <= 1024*64 { // Prevent memory leak from oversized buffers
		p.bytesBufferPool.Put(buffer)
	}
}

// GetInteractionMap retrieves a reusable map for interaction data
func (p *ObjectPool) GetInteractionMap() map[string]interface{} {
	m := p.interactionPool.Get().(map[string]interface{})
	// Clear the map
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutInteractionMap returns an interaction map to the pool
func (p *ObjectPool) PutInteractionMap(m map[string]interface{}) {
	if m != nil && len(m) <= 32 { // Prevent memory leak from oversized maps
		p.interactionPool.Put(m)
	}
}