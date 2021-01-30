// Package storage implements a encrypted storage mechanism
// for interactsh external interaction data.
package storage

import (
	"bytes"
	"strings"
	"sync"
	"time"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
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
	// secretkey is a secret key for original user verification
	secretKey string `json:"-"`
	// publicKey is the public RSA key for a correlation client.
	publicKey tink.HybridEncrypt `json:"-"`
}

// New creates a new storage instance for interactsh data.
func New(evictionTTL time.Duration) *Storage {
	return &Storage{cache: ccache.New(ccache.Configure()), evictionTTL: evictionTTL}
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *Storage) SetIDPublicKey(correlationID, secretKey string, publicKey []byte) error {
	khPub, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(publicKey)))

	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		return errors.Wrap(err, "could not create encrypter")
	}
	data := &CorrelationData{
		Data:      make([][]byte, 0),
		publicKey: he,
		secretKey: secretKey,
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

	ct, err := value.publicKey.Encrypt(data, nil)
	if err != nil {
		return errors.New("could not encrypt event data")
	}
	value.dataMutex.Lock()
	value.Data = append(value.Data, ct)
	value.dataMutex.Unlock()
	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage.
func (s *Storage) GetInteractions(correlationID, secret string) ([][]byte, error) {
	item := s.cache.Get(correlationID)
	if item == nil {
		return nil, errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.secretKey, secret) {
		return nil, errors.New("invalid secret key passed for user")
	}
	value.dataMutex.Lock()
	data := value.Data
	value.Data = make([][]byte, 0)
	value.dataMutex.Unlock()
	return data, nil
}

// RemoveID removes data for a correlation ID and data related to it.
func (s *Storage) RemoveID(correlationID string) error {
	item := s.cache.Get(correlationID)
	if item == nil {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}
	value.dataMutex.Lock()
	value.Data = nil
	value.dataMutex.Unlock()
	s.cache.Delete(correlationID)
	return nil
}
