package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// HTTPObjectPool manages reusable HTTP-related objects to reduce GC pressure
type HTTPObjectPool struct {
	requestPool  *sync.Pool
	responsePool *sync.Pool
	bufferPool   *sync.Pool
	mapPool      *sync.Pool
}

// HTTPPooledRequest represents a pooled HTTP request context
type HTTPPooledRequest struct {
	Request    *http.Request
	RemoteAddr string
	UserAgent  string
	Headers    map[string]string
	Body       []byte
}

// HTTPPooledResponse represents a pooled HTTP response
type HTTPPooledResponse struct {
	Writer     http.ResponseWriter
	StatusCode int
	Headers    map[string]string
	Body       *bytes.Buffer
}

// NewHTTPObjectPool creates a new HTTP object pool
func NewHTTPObjectPool() *HTTPObjectPool {
	return &HTTPObjectPool{
		requestPool: &sync.Pool{
			New: func() interface{} {
				return &HTTPPooledRequest{
					Headers: make(map[string]string, 8),
				}
			},
		},
		responsePool: &sync.Pool{
			New: func() interface{} {
				return &HTTPPooledResponse{
					Headers: make(map[string]string, 8),
					Body:    &bytes.Buffer{},
				}
			},
		},
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
		mapPool: &sync.Pool{
			New: func() interface{} {
				return make(map[string]interface{}, 16)
			},
		},
	}
}

// GetRequest retrieves a pooled HTTP request
func (p *HTTPObjectPool) GetRequest() *HTTPPooledRequest {
	req := p.requestPool.Get().(*HTTPPooledRequest)
	// Reset request
	req.Request = nil
	req.RemoteAddr = ""
	req.UserAgent = ""
	req.Body = nil
	// Clear headers map
	for k := range req.Headers {
		delete(req.Headers, k)
	}
	return req
}

// PutRequest returns a request to the pool
func (p *HTTPObjectPool) PutRequest(req *HTTPPooledRequest) {
	if req != nil && len(req.Headers) <= 32 { // Prevent memory leak from oversized maps
		p.requestPool.Put(req)
	}
}

// GetResponse retrieves a pooled HTTP response
func (p *HTTPObjectPool) GetResponse() *HTTPPooledResponse {
	resp := p.responsePool.Get().(*HTTPPooledResponse)
	// Reset response
	resp.Writer = nil
	resp.StatusCode = 0
	resp.Body.Reset()
	// Clear headers map
	for k := range resp.Headers {
		delete(resp.Headers, k)
	}
	return resp
}

// PutResponse returns a response to the pool
func (p *HTTPObjectPool) PutResponse(resp *HTTPPooledResponse) {
	if resp != nil && len(resp.Headers) <= 32 && resp.Body.Cap() <= 1024*64 {
		p.responsePool.Put(resp)
	}
}

// GetBuffer retrieves a pooled buffer
func (p *HTTPObjectPool) GetBuffer() *bytes.Buffer {
	buf := p.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// PutBuffer returns a buffer to the pool
func (p *HTTPObjectPool) PutBuffer(buf *bytes.Buffer) {
	if buf != nil && buf.Cap() <= 1024*64 { // Prevent memory leak from oversized buffers
		p.bufferPool.Put(buf)
	}
}

// GetJSONEncoder creates a new JSON encoder for the given writer
func (p *HTTPObjectPool) GetJSONEncoder(w io.Writer) *json.Encoder {
	return json.NewEncoder(w)
}

// GetJSONDecoder creates a new JSON decoder for the given reader
func (p *HTTPObjectPool) GetJSONDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}

// GetMap retrieves a pooled map
func (p *HTTPObjectPool) GetMap() map[string]interface{} {
	m := p.mapPool.Get().(map[string]interface{})
	// Clear the map
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutMap returns a map to the pool
func (p *HTTPObjectPool) PutMap(m map[string]interface{}) {
	if m != nil && len(m) <= 64 { // Prevent memory leak from oversized maps
		p.mapPool.Put(m)
	}
}