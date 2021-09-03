// Package storage implements a encrypted storage mechanism
// for interactsh external interaction data.
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	Data []string `json:"data"`
	// dataMutex is a mutex for the data slice.
	dataMutex *sync.Mutex
	// secretkey is a secret key for original user verification
	secretKey string
	// AESKey is the AES encryption key in encrypted format.
	AESKey string `json:"aes-key"`
	aesKey []byte // decrypted AES key for signing
}

// New creates a new storage instance for interactsh data.
func New(evictionTTL time.Duration) *Storage {
	return &Storage{cache: ccache.New(ccache.Configure()), evictionTTL: evictionTTL}
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *Storage) SetIDPublicKey(correlationID, secretKey string, publicKey string) error {
	// If we already have this correlation ID, return.
	if s.cache.Get(correlationID) != nil {
		return nil
	}
	publicKeyData, err := parseB64RSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return errors.Wrap(err, "could not read public Key")
	}
	aesKey := uuid.New().String()[:32]

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyData, []byte(aesKey), []byte(""))
	if err != nil {
		return errors.New("could not encrypt event data")
	}

	data := &CorrelationData{
		Data:      make([]string, 0),
		secretKey: secretKey,
		dataMutex: &sync.Mutex{},
		aesKey:    []byte(aesKey),
		AESKey:    base64.StdEncoding.EncodeToString(ciphertext),
	}
	s.cache.Set(correlationID, data, s.evictionTTL)
	return nil
}

func (s *Storage) SetID(ID string) error {
	data := &CorrelationData{
		Data:      make([]string, 0),
		dataMutex: &sync.Mutex{},
	}
	s.cache.Set(ID, data, s.evictionTTL)
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

	ct, err := aesEncrypt(value.aesKey, data)
	if err != nil {
		return errors.Wrap(err, "could not encrypt event data")
	}
	value.dataMutex.Lock()
	value.Data = append(value.Data, ct)
	value.dataMutex.Unlock()
	return nil
}

func (s *Storage) AddRootTLD(rootTLD string, data []byte) error {
	item := s.cache.Get(rootTLD)
	if item == nil {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	value.dataMutex.Lock()
	value.Data = append(value.Data, string(data))
	value.dataMutex.Unlock()
	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage. It also returns AES Encrypted Key for the IDs.
func (s *Storage) GetInteractions(correlationID, secret string) ([]string, string, error) {
	item := s.cache.Get(correlationID)
	if item == nil {
		return nil, "", errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return nil, "", errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.secretKey, secret) {
		return nil, "", errors.New("invalid secret key passed for user")
	}
	value.dataMutex.Lock()
	data := value.Data
	value.Data = make([]string, 0)
	value.dataMutex.Unlock()
	return data, value.AESKey, nil
}

func (s *Storage) GetRootTLDInteractions(ID string) ([]string, error) {
	item := s.cache.Get(ID)
	if item == nil {
		return nil, errors.New("could not get id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid id cache value found")
	}

	value.dataMutex.Lock()
	data := value.Data
	value.Data = make([]string, 0)
	value.dataMutex.Unlock()
	return data, nil
}

// RemoveID removes data for a correlation ID and data related to it.
func (s *Storage) RemoveID(correlationID, secret string) error {
	item := s.cache.Get(correlationID)
	if item == nil {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.Value().(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.secretKey, secret) {
		return errors.New("invalid secret key passed for deregister")
	}
	value.dataMutex.Lock()
	value.Data = nil
	value.dataMutex.Unlock()
	s.cache.Delete(correlationID)
	return nil
}

// parseB64RSAPublicKeyFromPEM parses a base64 encoded rsa pem to a public key structure
func parseB64RSAPublicKeyFromPEM(pubPEM string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(pubPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

// aesEncrypt encrypts a message using AES and puts IV at the beginning of ciphertext.
func aesEncrypt(key []byte, message []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// It's common to put IV at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], message)

	encMessage := base64.StdEncoding.EncodeToString(cipherText)
	return encMessage, nil
}
