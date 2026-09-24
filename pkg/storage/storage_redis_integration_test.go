//go:build integration_redis

// This file runs the Redis backend's parity tests against a real Redis
// server. Enable with:
//
//	INTERACTSH_REDIS_URL=redis://localhost:16379 go test -tags integration_redis ./pkg/storage/...
//
// The default unit-test suite (without the tag) uses miniredis and does not
// require Docker.
package storage

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

// requireRedisURL ensures the test is skipped when INTERACTSH_REDIS_URL is
// not configured, keeping the integration suite opt-in.
func requireRedisURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("INTERACTSH_REDIS_URL")
	if url == "" {
		t.Skip("INTERACTSH_REDIS_URL is not set; skipping real-redis integration test")
	}
	return url
}

// TestRedisIntegrationMultiInstance verifies the headline use case (one
// instance registers, another writes, a third polls) against a real Redis.
func TestRedisIntegrationMultiInstance(t *testing.T) {
	url := requireRedisURL(t)

	prefix := "interactsh-it-" + xid.New().String() + ":"
	mk := func() *StorageRedis {
		store, err := NewRedis(&RedisOptions{
			URL:                   url,
			KeyPrefix:             prefix,
			EvictionTTL:           time.Hour,
			EvictionStrategy:      EvictionStrategySliding,
			MaxSharedInteractions: 64,
		})
		require.NoError(t, err)
		return store
	}
	a, b, c := mk(), mk(), mk()
	defer func() { _ = a.Close(); _ = b.Close(); _ = c.Close() }()

	priv, pub := generateRSAKeyPair(t)
	id := xid.New().String()
	secret := uuid.New().String()

	require.NoError(t, a.SetIDPublicKey(id, secret, pub))
	require.NoError(t, b.AddInteraction(id, []byte(`{"protocol":"dns"}`)))

	data, aesKey, err := c.GetInteractions(id, secret)
	require.NoError(t, err)
	require.Len(t, data, 1)
	plaintext := clientDecrypt(t, priv, aesKey, data[0])
	require.Equal(t, `{"protocol":"dns"}`, string(plaintext))

	// Cleanup the keyspace we created.
	require.NoError(t, c.RemoveID(id, secret))
}
