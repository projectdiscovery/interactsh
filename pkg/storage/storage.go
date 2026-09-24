// storage defines a storage mechanism
package storage

type Storage interface {
	GetCacheMetrics() (*CacheMetrics, error)
	SetIDPublicKey(correlationID, secretKey, publicKey string) error
	SetID(ID string) error
	AddInteraction(correlationID string, data []byte) error
	AddInteractionWithId(id string, data []byte) error
	GetInteractions(correlationID, secret string) ([]string, string, error)
	GetInteractionsWithId(id string) ([]string, error)
	GetInteractionsWithIdForConsumer(id, consumerID string) ([]string, error)
	RemoveConsumer(id, consumerID string) error
	RemoveID(correlationID, secret string) error
	GetCacheItem(token string) (*CorrelationData, error)
	Close() error
}

// UploadStorage is the optional capability of tracking per-session uploaded
// file metadata, implemented by StorageDB.
//
// It is deliberately kept out of Storage. The uploaded bytes live on the local
// filesystem of a single server instance and the capacity quota is an
// in-process counter, so the feature is only coherent for instance-local
// backends. A shared backend such as Redis would let one instance advertise
// files whose bytes only exist on another instance's disk, so it does not
// implement this and file hosting is refused when it is selected.
type UploadStorage interface {
	// UpdateUploads verifies the secret key for a correlation-id and then runs
	// fn under that correlation-id's lock, replacing the upload metadata with
	// whatever fn returns. Callers perform their disk writes inside fn so the
	// quota check and the commit are atomic against concurrent uploads for the
	// same session. fn is invoked at most once.
	UpdateUploads(correlationID, secret string, fn func([]UploadedFile) ([]UploadedFile, error)) error
	// ListUploads returns the upload metadata for a correlation-id, and whether
	// the correlation-id is known at all.
	ListUploads(correlationID string) ([]UploadedFile, bool)
}
