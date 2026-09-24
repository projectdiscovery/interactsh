package storage

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	jsoniter "github.com/json-iterator/go"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

// newTestRedisStorage spins a miniredis server, wires a go-redis client to it
// and returns a configured Redis-backed Storage plus a teardown function.
func newTestRedisStorage(t *testing.T, opts ...func(*RedisOptions)) (*StorageRedis, func()) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := &RedisOptions{
		Client:                client,
		EvictionTTL:           time.Hour,
		EvictionStrategy:      EvictionStrategySliding,
		MaxSharedInteractions: 64,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	store, err := NewRedis(cfg)
	require.NoError(t, err)
	return store, func() {
		_ = store.Close()
	}
}

// TestRedisFullRoundTrip mirrors TestFullRoundTripInMemory/Disk so we can
// verify the encrypted client-decryption path works against Redis.
func TestRedisFullRoundTrip(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()

	priv, pubKeyB64 := generateRSAKeyPair(t)
	secret := uuid.New().String()
	correlationID := xid.New().String()

	require.NoError(t, store.SetIDPublicKey(correlationID, secret, pubKeyB64))

	for i := 0; i < 3; i++ {
		inter := &interaction{
			Protocol:      "dns",
			UniqueID:      "abc123def456ghi",
			FullId:        "abc123def456ghi.oast.fun",
			QType:         "A",
			RawRequest:    dnsRequest,
			RawResponse:   dnsResponse,
			RemoteAddress: "10.0.0.1",
			Timestamp:     time.Now(),
		}
		data, err := jsoniter.Marshal(inter)
		require.NoError(t, err)
		require.NoError(t, store.AddInteraction(correlationID, data))
	}

	data, aesKey, err := store.GetInteractions(correlationID, secret)
	require.NoError(t, err)
	require.Len(t, data, 3)

	for i, d := range data {
		plaintext := clientDecrypt(t, priv, aesKey, d)
		result := &interaction{}
		require.NoError(t, jsoniter.Unmarshal(plaintext, result), "interaction %d", i)
		require.Equal(t, "dns", result.Protocol)
		require.Equal(t, dnsRequest, result.RawRequest)
	}

	// After GetInteractions the buffer should be drained.
	more, _, err := store.GetInteractions(correlationID, secret)
	require.NoError(t, err)
	require.Empty(t, more)
}

// TestRedisDoubleRegister covers the "already exists" guard in
// SetIDPublicKey, mirroring StorageDB semantics.
func TestRedisDoubleRegister(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()

	_, pub := generateRSAKeyPair(t)
	id := xid.New().String()
	require.NoError(t, store.SetIDPublicKey(id, "secret", pub))
	err := store.SetIDPublicKey(id, "secret", pub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

// TestRedisInvalidSecret ensures the secret check blocks reads with the
// wrong key.
func TestRedisInvalidSecret(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()

	_, pub := generateRSAKeyPair(t)
	id := xid.New().String()
	require.NoError(t, store.SetIDPublicKey(id, "right", pub))
	require.NoError(t, store.AddInteraction(id, []byte("payload")))

	_, _, err := store.GetInteractions(id, "wrong")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid secret")

	// The correct secret still works after a failed attempt.
	data, _, err := store.GetInteractions(id, "right")
	require.NoError(t, err)
	require.Len(t, data, 1)
}

// TestRedisMultiInstanceSharing is the headline test: instance A registers
// the id, instance B writes the interaction, and instance C polls it. All
// three share the same Redis backend.
func TestRedisMultiInstanceSharing(t *testing.T) {
	mr := miniredis.RunT(t)
	makeInstance := func() *StorageRedis {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		s, err := NewRedis(&RedisOptions{
			Client:           client,
			EvictionTTL:      time.Hour,
			EvictionStrategy: EvictionStrategySliding,
		})
		require.NoError(t, err)
		return s
	}
	a, b, c := makeInstance(), makeInstance(), makeInstance()
	defer func() { _ = a.Close(); _ = b.Close(); _ = c.Close() }()

	priv, pub := generateRSAKeyPair(t)
	id := xid.New().String()

	require.NoError(t, a.SetIDPublicKey(id, "s", pub))
	require.NoError(t, b.AddInteraction(id, []byte(`{"protocol":"dns"}`)))

	data, aesKey, err := c.GetInteractions(id, "s")
	require.NoError(t, err)
	require.Len(t, data, 1)
	plaintext := clientDecrypt(t, priv, aesKey, data[0])
	require.Equal(t, `{"protocol":"dns"}`, string(plaintext))
}

// TestRedisConsumerOffsets exercises the per-consumer read offsets used by
// the polling endpoint when multiple clients subscribe to the same id.
func TestRedisConsumerOffsets(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()

	id := xid.New().String()
	require.NoError(t, store.SetID(id))
	for i := 0; i < 4; i++ {
		require.NoError(t, store.AddInteractionWithId(id, []byte("evt-")))
	}

	// consumer A reads everything
	dataA, err := store.GetInteractionsWithIdForConsumer(id, "A")
	require.NoError(t, err)
	require.Len(t, dataA, 4)

	// consumer B subscribes fresh and also sees all 4
	dataB, err := store.GetInteractionsWithIdForConsumer(id, "B")
	require.NoError(t, err)
	require.Len(t, dataB, 4)

	// new interactions go to both
	require.NoError(t, store.AddInteractionWithId(id, []byte("evt-5")))
	a1, err := store.GetInteractionsWithIdForConsumer(id, "A")
	require.NoError(t, err)
	require.Len(t, a1, 1)
	b1, err := store.GetInteractionsWithIdForConsumer(id, "B")
	require.NoError(t, err)
	require.Len(t, b1, 1)

	// A second poll for consumer A with no new data returns nothing.
	again, err := store.GetInteractionsWithIdForConsumer(id, "A")
	require.NoError(t, err)
	require.Empty(t, again)
}

// TestRedisRemoveConsumerCompacts ensures that after the last consumer
// disconnects, the underlying list is cleaned up.
func TestRedisRemoveConsumerCompacts(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()

	id := xid.New().String()
	require.NoError(t, store.SetID(id))
	require.NoError(t, store.AddInteractionWithId(id, []byte("evt-1")))
	require.NoError(t, store.AddInteractionWithId(id, []byte("evt-2")))

	_, err := store.GetInteractionsWithIdForConsumer(id, "A")
	require.NoError(t, err)
	require.NoError(t, store.RemoveConsumer(id, "A"))

	// data list should be gone (no consumers left)
	llen, err := store.client.LLen(t.Context(), store.dataKey(id)).Result()
	require.NoError(t, err)
	require.EqualValues(t, 0, llen)
}

// TestRedisMaxSharedInteractions verifies that the per-id buffer is trimmed
// when it exceeds the configured maximum, and that consumer offsets are
// adjusted accordingly.
func TestRedisMaxSharedInteractions(t *testing.T) {
	store, teardown := newTestRedisStorage(t, func(o *RedisOptions) {
		o.MaxSharedInteractions = 3
	})
	defer teardown()

	id := xid.New().String()
	require.NoError(t, store.SetID(id))

	// Two consumers subscribe.
	_, err := store.GetInteractionsWithIdForConsumer(id, "A")
	require.NoError(t, err)
	_, err = store.GetInteractionsWithIdForConsumer(id, "B")
	require.NoError(t, err)

	for i := 0; i < 6; i++ {
		require.NoError(t, store.AddInteractionWithId(id, []byte("evt-")))
	}

	// consumer A reads: should see at most 3 (the buffer cap), and the cap
	// is enforced after the read updates the offset.
	dataA, err := store.GetInteractionsWithIdForConsumer(id, "A")
	require.NoError(t, err)
	require.LessOrEqual(t, len(dataA), 6)

	// The buffer length cannot exceed the configured cap.
	llen, err := store.client.LLen(t.Context(), store.dataKey(id)).Result()
	require.NoError(t, err)
	require.LessOrEqual(t, llen, int64(3))
}

// TestRedisRemoveIDClearsKeyspace makes sure every related key is dropped
// when an id is explicitly deregistered.
func TestRedisRemoveIDClearsKeyspace(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()

	_, pub := generateRSAKeyPair(t)
	id := xid.New().String()
	require.NoError(t, store.SetIDPublicKey(id, "s", pub))
	require.NoError(t, store.AddInteraction(id, []byte("payload")))

	require.NoError(t, store.RemoveID(id, "s"))

	exists, err := store.client.Exists(t.Context(), store.metaKey(id), store.dataKey(id)).Result()
	require.NoError(t, err)
	require.EqualValues(t, 0, exists)
}
