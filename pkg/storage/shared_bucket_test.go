package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Shared buckets created by SetID have no secret. A client must not be able
// to deregister, poll or upload to them with an empty secret.
func testSharedBucketGuard(t *testing.T, store Storage) {
	t.Helper()
	for _, id := range []string{"oast.test", "teamtoken"} {
		require.NoError(t, store.SetID(id))
		require.NoError(t, store.AddInteractionWithId(id, []byte(`{"protocol":"http"}`)))

		require.Error(t, store.RemoveID(id, ""), "shared bucket deregistered with an empty secret")
		_, _, err := store.GetInteractions(id, "")
		require.Error(t, err, "shared bucket polled with an empty secret")

		// the bucket still works for the server
		require.NoError(t, store.AddInteractionWithId(id, []byte(`{"protocol":"dns"}`)))
		data, err := store.GetInteractionsWithIdForConsumer(id, "consumer")
		require.NoError(t, err)
		require.Len(t, data, 2)
	}
}

func TestSharedBucketGuardInMemory(t *testing.T) {
	store, err := New(&Options{EvictionTTL: time.Hour})
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck
	testSharedBucketGuard(t, store)

	require.Error(t, store.UpdateUploads("teamtoken", "", func(f []UploadedFile) ([]UploadedFile, error) { return f, nil }))
}

func TestSharedBucketGuardRedis(t *testing.T) {
	store, teardown := newTestRedisStorage(t)
	defer teardown()
	testSharedBucketGuard(t, store)
}

func TestEmptySecretNeverMatches(t *testing.T) {
	require.False(t, secretMatches("", ""))
	require.False(t, secretMatches("s", ""))
	require.False(t, secretMatches("", "s"))
	require.True(t, secretMatches("Secret", "secret"))
}
