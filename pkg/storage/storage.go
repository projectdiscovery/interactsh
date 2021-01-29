// Package storage implements a encrypted storage mechanism
// for interactsh external interaction data.
package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"sync"
	"time"

	"github.com/karlseguin/ccache/v2"
	"github.com/pkg/errors"
)

// Storage is an storage for interactsh interaction data as well
// as correlation-id -> rsa-public-key data.
type Storage struct {
	cache       *ccache.Cache
	evictionTTL time.Duration
}

// CorrelationData is the data for a correlation-id.
type CorrelationData struct {
	// data contains data for a correlation-id in AES encrypted json format.
	Data [][]byte `json:"data"`
	// dataMutex is a mutex for the data slice.
	dataMutex *sync.Mutex `json:"-"`
	// publicKey is the public RSA key for a correlation client.
	publicKey *rsa.PublicKey `json:"-"`
}

// New creates a new storage instance for interactsh data.
func New(evictionTTL time.Duration) *Storage {
	return &Storage{cache: ccache.New(ccache.Configure()), evictionTTL: evictionTTL}
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *Storage) SetIDPublicKey(correlationID string, publicKey []byte) error {
	key := &rsa.PublicKey{}
	if err := gob.NewDecoder(bytes.NewReader(publicKey)).Decode(key); err != nil {
		return errors.Wrap(err, "could not decode rsa public key")
	}
	data := &CorrelationData{
		Data:      make([][]byte, 0),
		publicKey: key,
		dataMutex: &sync.Mutex{},
	}
	s.cache.Set(correlationID, data, s.evictionTTL)
	return nil
}

// AddInteraction adds an interaction data to the correlation ID after encrypting
// it with Public Key for the provided correlation ID.
func (s *Storage) AddInteraction(correlationID string, data []byte) error {
	item := s.cache.Get(correlationID)
	if item == nil {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, value.publicKey, data, nil)
	if err != nil {
		return errors.Wrap(err, "could not encrypt data with RSA public key")
	}

	value.dataMutex.Lock()
	value.Data = append(value.Data, encryptedBytes)
	value.dataMutex.Unlock()
	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage.
func (s *Storage) GetInteractions(correlationID string) ([][]byte, error) {
	item := s.cache.Get(correlationID)
	if item == nil {
		return nil, errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid correlation-id cache value found")
	}

	value.dataMutex.Lock()
	data := value.Data
	value.Data = make([][]byte, 0)
	value.dataMutex.Unlock()
	return data, nil
}
