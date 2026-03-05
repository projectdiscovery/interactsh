// storage implements a encrypted memory mechanism
package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goburrow/cache"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	permissionutil "github.com/projectdiscovery/utils/permission"
	"github.com/rs/xid"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"go.uber.org/multierr"
)

// Storage is an storage for interactsh interaction data as well
// as correlation-id -> rsa-public-key data.
type StorageDB struct {
	Options *Options
	cache   cache.Cache
	db      *leveldb.DB
	dbpath  string
}

// New creates a new storage instance for interactsh data.
func New(options *Options) (*StorageDB, error) {
	if options.MaxSharedInteractions <= 0 {
		options.MaxSharedInteractions = defaultMaxSharedInteractions
	}
	storageDB := &StorageDB{Options: options}
	cacheOptions := []cache.Option{
		cache.WithMaximumSize(options.MaxSize),
	}
	if options.EvictionTTL > 0 {
		switch options.EvictionStrategy {
		case EvictionStrategyFixed:
			cacheOptions = append(cacheOptions, cache.WithExpireAfterWrite(options.EvictionTTL))
		case EvictionStrategySliding:
			fallthrough
		default:
			cacheOptions = append(cacheOptions, cache.WithExpireAfterAccess(options.EvictionTTL))
		}
	}
	if options.UseDisk() {
		cacheOptions = append(cacheOptions, cache.WithRemovalListener(storageDB.OnCacheRemovalCallback))
	}
	cacheDb := cache.New(cacheOptions...)
	storageDB.cache = cacheDb

	if options.UseDisk() {
		// if the path exists we create a random temporary subfolder
		if !fileutil.FolderExists(options.DbPath) {
			return nil, errors.New("folder doesn't exist")
		}
		dbpath := filepath.Join(options.DbPath, xid.New().String())

		if err := os.MkdirAll(dbpath, permissionutil.ConfigFolderPermission); err != nil {
			return nil, err
		}
		levDb, err := leveldb.OpenFile(dbpath, &opt.Options{})
		if err != nil {
			return nil, err
		}
		storageDB.dbpath = dbpath
		storageDB.db = levDb
	}

	return storageDB, nil
}

func (s *StorageDB) OnCacheRemovalCallback(key cache.Key, value cache.Value) {
	if k, ok := key.(string); ok {
		_ = s.db.Delete([]byte(k), &opt.WriteOptions{})
	}
}

func (s *StorageDB) GetCacheMetrics() (*CacheMetrics, error) {
	info := &cache.Stats{}
	s.cache.Stats(info)

	cacheMetrics := &CacheMetrics{
		HitCount:         info.HitCount,
		MissCount:        info.MissCount,
		LoadSuccessCount: info.LoadSuccessCount,
		LoadErrorCount:   info.LoadErrorCount,
		TotalLoadTime:    info.TotalLoadTime,
		EvictionCount:    info.EvictionCount,
	}

	return cacheMetrics, nil
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *StorageDB) SetIDPublicKey(correlationID, secretKey, publicKey string) error {
	// If we already have this correlation ID, return.
	_, found := s.cache.GetIfPresent(correlationID)
	if found {
		return errors.New("correlation-id provided already exists")
	}
	publicKeyData, err := ParseB64RSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return errors.Wrap(err, "could not read public Key")
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return errors.Wrap(err, "could not generate AES key")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyData, aesKey, []byte(""))
	if err != nil {
		return errors.New("could not encrypt event data")
	}

	data := &CorrelationData{
		SecretKey:       secretKey,
		AESKey:          aesKey,
		AESKeyEncrypted: base64.StdEncoding.EncodeToString(ciphertext),
	}
	// Clear any stale data from a previous registration (e.g. after cache eviction
	// and session restore). Old data would be encrypted with a different AES key
	// and cause decryption failures on the client.
	if s.Options.UseDisk() {
		_ = s.db.Delete([]byte(correlationID), nil)
	}
	s.cache.Put(correlationID, data)
	return nil
}

func (s *StorageDB) SetID(ID string) error {
	data := &CorrelationData{}

	s.cache.Put(ID, data)
	return nil
}

// AddInteraction adds an interaction data to the correlation ID after encrypting
// it with Public Key for the provided correlation ID.
func (s *StorageDB) AddInteraction(correlationID string, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	item, found := s.cache.GetIfPresent(correlationID)
	if !found {
		return ErrCorrelationIdNotFound
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	if s.Options.UseDisk() {
		ct := string(data)
		if len(value.AESKey) > 0 {
			var err error
			ct, err = AESEncrypt(value.AESKey, data)
			if err != nil {
				return errors.Wrap(err, "could not encrypt event data")
			}
		}

		value.Lock()
		existingData, _ := s.db.Get([]byte(correlationID), nil)
		_ = s.db.Put([]byte(correlationID), AppendMany("\n", existingData, []byte(ct)), nil)
		value.Unlock()
	} else {
		value.Lock()
		value.Data = append(value.Data, string(data))
		value.Unlock()
	}

	return nil
}

// AddInteractionWithId adds an interaction data to the id bucket
func (s *StorageDB) AddInteractionWithId(id string, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return ErrCorrelationIdNotFound
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	if s.Options.UseDisk() {
		ct := string(data)
		if len(value.AESKey) > 0 {
			var err error
			ct, err = AESEncrypt(value.AESKey, data)
			if err != nil {
				return errors.Wrap(err, "could not encrypt event data")
			}
		}

		value.Lock()
		existingData, _ := s.db.Get([]byte(id), nil)
		_ = s.db.Put([]byte(id), AppendMany("\n", existingData, []byte(ct)), nil)
		value.Unlock()
	} else {
		value.Lock()
		value.Data = append(value.Data, string(data))
		value.Unlock()
	}

	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage. It also returns AES Encrypted Key for the IDs.
func (s *StorageDB) GetInteractions(correlationID, secret string) ([]string, string, error) {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return nil, "", ErrCorrelationIdNotFound
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, "", errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.SecretKey, secret) {
		return nil, "", errors.New("invalid secret key passed for user")
	}
	data, err := s.getInteractions(value, correlationID)
	return data, value.AESKeyEncrypted, err
}

// GetInteractions returns the interactions for a id and empty the cache
func (s *StorageDB) GetInteractionsWithId(id string) ([]string, error) {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return nil, errors.New("could not get id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid id cache value found")
	}
	return s.getInteractions(value, id)
}

// GetInteractionsWithIdForConsumer returns unseen interactions for a consumer
// using per-consumer read offsets.
func (s *StorageDB) GetInteractionsWithIdForConsumer(id, consumerID string) ([]string, error) {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return nil, errors.New("could not get id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid id cache value found")
	}

	value.Lock()
	defer value.Unlock()

	if value.ReadOffsets == nil {
		value.ReadOffsets = make(map[string]int)
	}
	if value.LastSeen == nil {
		value.LastSeen = make(map[string]time.Time)
	}

	var allData []string
	switch {
	case s.Options.UseDisk():
		raw, err := s.db.Get([]byte(id), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return nil, nil
			}
			return nil, err
		}
		for _, d := range bytes.Split(raw, []byte("\n")) {
			if len(d) > 0 {
				allData = append(allData, string(d))
			}
		}
	default:
		allData = value.Data
	}

	offset := min(value.ReadOffsets[consumerID], len(allData))

	var unseen []string
	if offset < len(allData) {
		unseen = make([]string, len(allData)-offset)
		copy(unseen, allData[offset:])
	}

	value.ReadOffsets[consumerID] = len(allData)
	value.LastSeen[consumerID] = time.Now()

	s.evictAndEnforceBuffer(value, id)

	return unseen, nil
}

// RemoveConsumer removes a consumer's read offset and compacts consumed data.
func (s *StorageDB) RemoveConsumer(id, consumerID string) error {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return nil
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil
	}

	value.Lock()
	defer value.Unlock()

	delete(value.ReadOffsets, consumerID)
	delete(value.LastSeen, consumerID)

	s.compactConsumedData(value, id)
	return nil
}

func (s *StorageDB) evictAndEnforceBuffer(value *CorrelationData, id string) {
	s.evictStaleConsumers(value, id)
	s.enforceMaxBuffer(value, id)
}

func (s *StorageDB) compactConsumedData(value *CorrelationData, id string) {
	s.evictStaleConsumers(value, id)
	if len(value.ReadOffsets) == 0 {
		return
	}

	minOffset := -1
	for _, off := range value.ReadOffsets {
		if minOffset < 0 || off < minOffset {
			minOffset = off
		}
	}
	if minOffset > 0 {
		s.applyTrim(value, id, minOffset)
	}
	s.enforceMaxBuffer(value, id)
}

func (s *StorageDB) evictStaleConsumers(value *CorrelationData, id string) {
	if s.Options.EvictionTTL > 0 {
		now := time.Now()
		for cid, lastSeen := range value.LastSeen {
			if now.Sub(lastSeen) > s.Options.EvictionTTL {
				delete(value.ReadOffsets, cid)
				delete(value.LastSeen, cid)
			}
		}
	}

	if len(value.ReadOffsets) == 0 {
		value.Data = nil
		if s.Options.UseDisk() {
			_ = s.db.Delete([]byte(id), nil)
		}
	}
}

func (s *StorageDB) enforceMaxBuffer(value *CorrelationData, id string) {
	dataLen := s.dataLen(value, id)
	if dataLen <= s.Options.MaxSharedInteractions {
		return
	}
	excess := dataLen - s.Options.MaxSharedInteractions
	s.applyTrim(value, id, excess)
}

func (s *StorageDB) applyTrim(value *CorrelationData, id string, trimCount int) {
	switch {
	case s.Options.UseDisk():
		raw, err := s.db.Get([]byte(id), nil)
		if err != nil {
			return
		}
		var allData []string
		for _, d := range bytes.Split(raw, []byte("\n")) {
			if len(d) > 0 {
				allData = append(allData, string(d))
			}
		}
		if trimCount >= len(allData) {
			_ = s.db.Delete([]byte(id), nil)
		} else {
			remaining := allData[trimCount:]
			_ = s.db.Put([]byte(id), []byte(strings.Join(remaining, "\n")), nil)
		}
	default:
		if trimCount >= len(value.Data) {
			value.Data = nil
		} else {
			value.Data = value.Data[trimCount:]
		}
	}

	for cid, off := range value.ReadOffsets {
		value.ReadOffsets[cid] = max(off-trimCount, 0)
	}
}

func (s *StorageDB) dataLen(value *CorrelationData, id string) int {
	if s.Options.UseDisk() {
		raw, err := s.db.Get([]byte(id), nil)
		if err != nil {
			return 0
		}
		count := 0
		for _, d := range bytes.Split(raw, []byte("\n")) {
			if len(d) > 0 {
				count++
			}
		}
		return count
	}
	return len(value.Data)
}

// RemoveID removes data for a correlation ID and data related to it.
func (s *StorageDB) RemoveID(correlationID, secret string) error {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return ErrCorrelationIdNotFound
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.SecretKey, secret) {
		return errors.New("invalid secret key passed for deregister")
	}
	value.Lock()
	value.Data = nil
	value.Unlock()
	s.cache.Invalidate(correlationID)

	if s.Options.UseDisk() {
		return s.db.Delete([]byte(correlationID), nil)
	}
	return nil
}

// GetCacheItem returns an item as is
func (s *StorageDB) GetCacheItem(token string) (*CorrelationData, error) {
	item, ok := s.cache.GetIfPresent(token)
	if !ok {
		return nil, errors.New("cache item not found")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("cache item not found")
	}
	return value, nil
}

func (s *StorageDB) getInteractions(correlationData *CorrelationData, id string) ([]string, error) {
	correlationData.Lock()
	defer correlationData.Unlock()

	switch {
	case s.Options.UseDisk():
		data, err := s.db.Get([]byte(id), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				err = nil
			}
			return nil, err
		}
		var dataString []string
		for _, d := range bytes.Split(data, []byte("\n")) {
			if len(d) == 0 {
				continue
			}
			dataString = append(dataString, string(d))
		}
		_ = s.db.Delete([]byte(id), nil)
		return dataString, nil
	default:
		// in memory data
		var errs []error
		data := correlationData.Data
		correlationData.Data = nil
		if len(data) == 0 {
			return nil, nil
		}

		for i, dataItem := range data {
			encryptedDataItem, err := AESEncrypt(correlationData.AESKey, []byte(dataItem))
			if err != nil {
				errs = append(errs, errors.Wrap(err, "could not encrypt event data"))
				data[i] = dataItem
			} else {
				data[i] = encryptedDataItem
			}
		}
		return data, multierr.Combine(errs...)
	}
}

func (s *StorageDB) Close() error {
	var errdbClosed error
	if s.db != nil {
		errdbClosed = s.db.Close()
	}
	return multierr.Combine(
		s.cache.Close(),
		errdbClosed,
		os.RemoveAll(s.dbpath),
	)
}
