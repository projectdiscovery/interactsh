// Package storage - Redis-backed implementation of the Storage interface.
//
// This file adds an additive, optional backend used when multiple interactsh
// server instances need to share state behind a load balancer. It does not
// replace or alter the default in-memory/LevelDB StorageDB; both backends
// coexist and the caller decides which one to construct.
package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisOptions configures the Redis-backed Storage.
//
// All eviction-related fields mirror the semantics of the local Options struct;
// they are duplicated here intentionally so that adding the Redis backend does
// not touch the existing Options/StorageDB code paths.
type RedisOptions struct {
	// URL is a redis connection string, e.g. redis://user:pass@host:6379/0
	URL string
	// KeyPrefix is prepended to every key. Defaults to "interactsh:".
	KeyPrefix string
	// TLS, when non-nil, enables TLS with the provided config.
	TLS *tls.Config
	// EvictionTTL controls how long correlation state survives without activity.
	// A value <= 0 disables TTL.
	EvictionTTL time.Duration
	// EvictionStrategy mirrors storage.Options.EvictionStrategy:
	//   - sliding: TTL is refreshed on access (default)
	//   - fixed:   TTL is set on write and not refreshed
	EvictionStrategy EvictionStrategy
	// MaxSharedInteractions caps the per-id buffer length when multiple
	// consumers share an id. <= 0 means unlimited.
	MaxSharedInteractions int
	// Client is an already-configured *redis.Client. If set, URL/TLS are ignored.
	// Useful for tests with miniredis.
	Client *redis.Client
}

// StorageRedis implements Storage backed by a Redis server (or compatible).
//
// Key layout (all keys are placed in the same hash slot via the {id} hash tag
// so the implementation is safe under Redis Cluster as well):
//
//	<prefix>meta:{<id>}        HASH   secret, aes_key, aes_key_enc
//	<prefix>data:{<id>}        LIST   ordered AES-encrypted interaction strings
//	<prefix>consumers:{<id>}   SET    consumer ids currently subscribed
//	<prefix>off:{<id>}:<cid>   STRING per-consumer read offset (integer)
//	<prefix>seen:{<id>}:<cid>  STRING per-consumer last-seen unix nano
type StorageRedis struct {
	options *RedisOptions
	client  *redis.Client
	// metrics counters - tracked locally because Redis cannot give us
	// per-Storage hit/miss stats; values are best-effort per-instance.
	hitCount  uint64
	missCount uint64
}

// NewRedis builds a Redis-backed Storage. The caller is responsible for
// keeping the underlying Redis server reachable for the lifetime of the
// returned instance.
func NewRedis(options *RedisOptions) (*StorageRedis, error) {
	if options == nil {
		return nil, errors.New("redis storage options are required")
	}
	if options.KeyPrefix == "" {
		options.KeyPrefix = "interactsh:"
	}
	if options.MaxSharedInteractions <= 0 {
		options.MaxSharedInteractions = defaultMaxSharedInteractions
	}

	client := options.Client
	if client == nil {
		if options.URL == "" {
			return nil, errors.New("redis URL is required when no client is provided")
		}
		opt, err := redis.ParseURL(options.URL)
		if err != nil {
			return nil, fmt.Errorf("could not parse redis URL: %w", err)
		}
		if options.TLS != nil {
			opt.TLSConfig = options.TLS
		}
		client = redis.NewClient(opt)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("could not connect to redis: %w", err)
	}

	return &StorageRedis{options: options, client: client}, nil
}

// ---- key helpers ------------------------------------------------------------

func (s *StorageRedis) metaKey(id string) string {
	return s.options.KeyPrefix + "meta:{" + id + "}"
}

func (s *StorageRedis) dataKey(id string) string {
	return s.options.KeyPrefix + "data:{" + id + "}"
}

func (s *StorageRedis) consumersKey(id string) string {
	return s.options.KeyPrefix + "consumers:{" + id + "}"
}

func (s *StorageRedis) offsetKey(id, consumerID string) string {
	return s.options.KeyPrefix + "off:{" + id + "}:" + consumerID
}

func (s *StorageRedis) seenKey(id, consumerID string) string {
	return s.options.KeyPrefix + "seen:{" + id + "}:" + consumerID
}

// ttlMillis returns the TTL in milliseconds; 0 means "no TTL".
func (s *StorageRedis) ttlMillis() int64 {
	if s.options.EvictionTTL <= 0 {
		return 0
	}
	return s.options.EvictionTTL.Milliseconds()
}

// shouldRefreshTTL is true when the eviction strategy expects TTL to be
// extended on access (sliding); for fixed it is set once at write time only.
func (s *StorageRedis) shouldRefreshTTL() bool {
	return s.options.EvictionStrategy == EvictionStrategySliding
}

// applyWriteTTL sets TTL on the provided keys when a TTL is configured.
// Called after writes so that newly created keys always carry expiry.
func (s *StorageRedis) applyWriteTTL(ctx context.Context, pipe redis.Cmdable, keys ...string) {
	ms := s.ttlMillis()
	if ms <= 0 {
		return
	}
	for _, k := range keys {
		pipe.PExpire(ctx, k, time.Duration(ms)*time.Millisecond)
	}
}

// refreshTTL extends TTL on access when the sliding strategy is configured.
func (s *StorageRedis) refreshTTL(ctx context.Context, keys ...string) {
	if !s.shouldRefreshTTL() {
		return
	}
	ms := s.ttlMillis()
	if ms <= 0 {
		return
	}
	pipe := s.client.Pipeline()
	for _, k := range keys {
		pipe.PExpire(ctx, k, time.Duration(ms)*time.Millisecond)
	}
	_, _ = pipe.Exec(ctx)
}

// ---- Storage interface ------------------------------------------------------

func (s *StorageRedis) GetCacheMetrics() (*CacheMetrics, error) {
	return &CacheMetrics{
		HitCount:  s.hitCount,
		MissCount: s.missCount,
	}, nil
}

// SetIDPublicKey registers a correlation id along with its RSA public key.
// Any pre-existing keyspace for the id is cleared first to mirror the
// StorageDB behaviour after cache eviction + session restore.
func (s *StorageRedis) SetIDPublicKey(correlationID, secretKey, publicKey string) error {
	ctx := context.Background()
	exists, err := s.client.Exists(ctx, s.metaKey(correlationID)).Result()
	if err != nil {
		return fmt.Errorf("redis exists check failed: %w", err)
	}
	if exists > 0 {
		return errors.New("correlation-id provided already exists")
	}

	pub, err := ParseB64RSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return fmt.Errorf("could not read public key: %w", err)
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("could not generate AES key: %w", err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, []byte(""))
	if err != nil {
		return errors.New("could not encrypt event data")
	}
	aesKeyEnc := base64.StdEncoding.EncodeToString(ciphertext)

	pipe := s.client.TxPipeline()
	// clear any stale per-id keyspace before re-registering
	pipe.Del(ctx, s.metaKey(correlationID), s.dataKey(correlationID), s.consumersKey(correlationID))
	pipe.HSet(ctx, s.metaKey(correlationID), map[string]any{
		"secret":      secretKey,
		"aes_key":     aesKey,
		"aes_key_enc": aesKeyEnc,
	})
	s.applyWriteTTL(ctx, pipe, s.metaKey(correlationID))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis register failed: %w", err)
	}
	return nil
}

// SetID registers a correlation id without an associated public key.
// Used for the wildcard / auth-token path.
func (s *StorageRedis) SetID(id string) error {
	ctx := context.Background()
	pipe := s.client.TxPipeline()
	pipe.HSetNX(ctx, s.metaKey(id), "secret", "")
	s.applyWriteTTL(ctx, pipe, s.metaKey(id))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis SetID failed: %w", err)
	}
	return nil
}

// AddInteraction encrypts and appends an interaction for the given
// correlation id.
func (s *StorageRedis) AddInteraction(correlationID string, data []byte) error {
	return s.addInteraction(correlationID, data)
}

// AddInteractionWithId mirrors AddInteraction; the distinction in the
// original StorageDB is purely semantic.
func (s *StorageRedis) AddInteractionWithId(id string, data []byte) error {
	return s.addInteraction(id, data)
}

func (s *StorageRedis) addInteraction(id string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	ctx := context.Background()

	// EXISTS distinguishes "id never registered" from "id registered without
	// an AES key" (the wildcard / SetID path) so that ErrCorrelationIdNotFound
	// keeps the same meaning as in StorageDB.
	exists, err := s.client.Exists(ctx, s.metaKey(id)).Result()
	if err != nil {
		return fmt.Errorf("redis exists check failed: %w", err)
	}
	if exists == 0 {
		s.missCount++
		return ErrCorrelationIdNotFound
	}
	s.hitCount++

	aesKey, err := s.client.HGet(ctx, s.metaKey(id), "aes_key").Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis HGet aes_key failed: %w", err)
	}

	payload := string(data)
	if len(aesKey) > 0 {
		ct, err := AESEncrypt(aesKey, data)
		if err != nil {
			return fmt.Errorf("could not encrypt event data: %w", err)
		}
		payload = ct
	}

	pipe := s.client.TxPipeline()
	pipe.RPush(ctx, s.dataKey(id), payload)
	s.applyWriteTTL(ctx, pipe, s.dataKey(id))
	if s.shouldRefreshTTL() {
		s.applyWriteTTL(ctx, pipe, s.metaKey(id))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis RPush failed: %w", err)
	}
	return nil
}

// GetInteractions returns all buffered interactions for the correlation id
// and atomically clears the buffer (preserving the legacy single-consumer
// semantics of GetInteractions).
func (s *StorageRedis) GetInteractions(correlationID, secret string) ([]string, string, error) {
	ctx := context.Background()
	res, err := s.client.HMGet(ctx, s.metaKey(correlationID), "secret", "aes_key_enc").Result()
	if err != nil {
		return nil, "", fmt.Errorf("redis HMGet failed: %w", err)
	}
	if res[0] == nil {
		s.missCount++
		return nil, "", ErrCorrelationIdNotFound
	}
	s.hitCount++
	storedSecret, _ := res[0].(string)
	if !strings.EqualFold(storedSecret, secret) {
		return nil, "", errors.New("invalid secret key passed for user")
	}
	aesKeyEnc, _ := res[1].(string)

	data, err := s.consumeAll(ctx, correlationID)
	if err != nil {
		return nil, "", err
	}
	s.refreshTTL(ctx, s.metaKey(correlationID))
	return data, aesKeyEnc, nil
}

// GetInteractionsWithId returns and drains the buffered interactions for an id.
func (s *StorageRedis) GetInteractionsWithId(id string) ([]string, error) {
	ctx := context.Background()
	if exists, _ := s.client.Exists(ctx, s.metaKey(id)).Result(); exists == 0 {
		s.missCount++
		return nil, errors.New("could not get id from cache")
	}
	s.hitCount++
	data, err := s.consumeAll(ctx, id)
	if err != nil {
		return nil, err
	}
	s.refreshTTL(ctx, s.metaKey(id))
	return data, nil
}

// consumeAll atomically LRANGEs and DELs the data list for id.
func (s *StorageRedis) consumeAll(ctx context.Context, id string) ([]string, error) {
	pipe := s.client.TxPipeline()
	rangeCmd := pipe.LRange(ctx, s.dataKey(id), 0, -1)
	pipe.Del(ctx, s.dataKey(id))
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("redis consume failed: %w", err)
	}
	data, err := rangeCmd.Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}

// GetInteractionsWithIdForConsumer returns unseen interactions for the given
// consumer, advancing its offset and evicting stale consumers atomically via
// a Lua script.
func (s *StorageRedis) GetInteractionsWithIdForConsumer(id, consumerID string) ([]string, error) {
	ctx := context.Background()
	if exists, _ := s.client.Exists(ctx, s.metaKey(id)).Result(); exists == 0 {
		s.missCount++
		return nil, errors.New("could not get id from cache")
	}
	s.hitCount++

	now := time.Now().UnixNano()
	evictionNanos := int64(0)
	if s.options.EvictionTTL > 0 {
		evictionNanos = s.options.EvictionTTL.Nanoseconds()
	}

	keys := []string{s.dataKey(id), s.consumersKey(id)}
	args := []any{
		consumerID,
		now,
		evictionNanos,
		s.options.MaxSharedInteractions,
		s.options.KeyPrefix + "off:{" + id + "}:",
		s.options.KeyPrefix + "seen:{" + id + "}:",
	}
	raw, err := consumerReadScript.Run(ctx, s.client, keys, args...).StringSlice()
	if err != nil {
		return nil, fmt.Errorf("redis consumer read failed: %w", err)
	}
	if s.shouldRefreshTTL() {
		s.refreshTTL(ctx, s.metaKey(id), s.dataKey(id), s.consumersKey(id),
			s.offsetKey(id, consumerID), s.seenKey(id, consumerID))
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return raw, nil
}

// RemoveConsumer drops the consumer's offset/last-seen tracking and compacts
// the underlying data list when possible.
func (s *StorageRedis) RemoveConsumer(id, consumerID string) error {
	ctx := context.Background()
	keys := []string{s.dataKey(id), s.consumersKey(id)}
	args := []any{
		consumerID,
		time.Now().UnixNano(),
		int64(s.options.EvictionTTL),
		s.options.MaxSharedInteractions,
		s.options.KeyPrefix + "off:{" + id + "}:",
		s.options.KeyPrefix + "seen:{" + id + "}:",
	}
	_, err := removeConsumerScript.Run(ctx, s.client, keys, args...).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis remove consumer failed: %w", err)
	}
	return nil
}

// RemoveID drops every key associated with the correlation id after secret
// verification.
func (s *StorageRedis) RemoveID(correlationID, secret string) error {
	ctx := context.Background()
	storedSecret, err := s.client.HGet(ctx, s.metaKey(correlationID), "secret").Result()
	if errors.Is(err, redis.Nil) {
		return ErrCorrelationIdNotFound
	}
	if err != nil {
		return fmt.Errorf("redis HGet secret failed: %w", err)
	}
	if !strings.EqualFold(storedSecret, secret) {
		return errors.New("invalid secret key passed for deregister")
	}

	consumers, err := s.client.SMembers(ctx, s.consumersKey(correlationID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis SMembers failed: %w", err)
	}

	pipe := s.client.TxPipeline()
	pipe.Del(ctx, s.metaKey(correlationID), s.dataKey(correlationID), s.consumersKey(correlationID))
	for _, cid := range consumers {
		pipe.Del(ctx, s.offsetKey(correlationID, cid), s.seenKey(correlationID, cid))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis RemoveID failed: %w", err)
	}
	return nil
}

// GetCacheItem returns the CorrelationData associated with the token. Only the
// fields stored in the meta hash are populated; per-consumer offsets live in
// separate keys.
func (s *StorageRedis) GetCacheItem(token string) (*CorrelationData, error) {
	ctx := context.Background()
	res, err := s.client.HGetAll(ctx, s.metaKey(token)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis HGetAll failed: %w", err)
	}
	if len(res) == 0 {
		return nil, errors.New("cache item not found")
	}
	data := &CorrelationData{
		SecretKey:       res["secret"],
		AESKeyEncrypted: res["aes_key_enc"],
	}
	if raw, ok := res["aes_key"]; ok {
		data.AESKey = []byte(raw)
	}
	return data, nil
}

// Close releases the redis client. Existing data in Redis is preserved so
// that the next instance can resume; this matches the multi-instance use
// case the Redis backend was introduced for.
func (s *StorageRedis) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}

var _ Storage = (*StorageRedis)(nil)
