package storage

import (
	"sync"
	"time"
)

type GetInteractionsFunc func() []string

type CacheMetrics struct {
	HitCount         uint64        `json:"hit-count"`
	MissCount        uint64        `json:"miss-count"`
	LoadSuccessCount uint64        `json:"load-success-count"`
	LoadErrorCount   uint64        `json:"load-error-count"`
	TotalLoadTime    time.Duration `json:"total-load-time"`
	EvictionCount    uint64        `json:"eviction-count"`
}

// UploadedFile is metadata for a file uploaded by the owner of a correlation-id.
// The bytes themselves live on disk, managed by the server's upload store; this
// record exists so that cache eviction and deregistration can drive file cleanup.
type UploadedFile struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Timestamp time.Time `json:"timestamp"`
}

// CorrelationData is the data for a correlation-id.
type CorrelationData struct {
	sync.Mutex
	// data contains data for a correlation-id in AES encrypted json format.
	Data []string `json:"data"`
	// secretkey is a secret key for original user verification
	SecretKey string `json:"-"`
	// AESKey is the AES encryption key in encrypted format.
	AESKeyEncrypted string `json:"aes-key"`
	// decrypted AES key for signing
	AESKey      []byte               `json:"-"`
	ReadOffsets map[string]int       `json:"-"`
	LastSeen    map[string]time.Time `json:"-"`
	// Files is metadata for files uploaded against this correlation-id.
	// Guarded by the embedded Mutex. Not persisted: only interaction blobs
	// are written to disk, and uploads do not survive a restart.
	Files []UploadedFile `json:"-"`
}
